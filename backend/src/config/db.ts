import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const ssl = process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : undefined;

export const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl,
    })
  : new Pool({
      user: process.env.DB_USER || 'postgres',
      host: process.env.DB_HOST || 'localhost',
      database: process.env.DB_NAME || 'sbom_db',
      password: process.env.DB_PASSWORD || 'secret',
      port: parseInt(process.env.DB_PORT || '5432', 10),
      ssl,
    });

export const checkDbConnection = async () => {
  try {
    const client = await pool.connect();
    console.log('Successfully connected to the PostgreSQL database.');
    client.release();
  } catch (err) {
    console.error('Error connecting to PostgreSQL:', err);
    process.exit(1);
  }
};

export const ensureVulnerabilitySchema = async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      ALTER TABLE vulnerability
        ADD COLUMN IF NOT EXISTS name VARCHAR(255),
        ADD COLUMN IF NOT EXISTS installed VARCHAR(100),
        ADD COLUMN IF NOT EXISTS fixed_in VARCHAR(100),
        ADD COLUMN IF NOT EXISTS package_type VARCHAR(100),
        ADD COLUMN IF NOT EXISTS vulnerability VARCHAR(255),
        ADD COLUMN IF NOT EXISTS epss NUMERIC(6,5),
        ADD COLUMN IF NOT EXISTS risk VARCHAR(50)
    `);
    // Ensure systems table exists and sbom_metadata has system_id
    await client.query(`
      CREATE TABLE IF NOT EXISTS system (
        system_id SERIAL PRIMARY KEY,
        name VARCHAR(255) UNIQUE NOT NULL,
        description TEXT,
        created_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_uploaded_at TIMESTAMP
      );
    `);
    await client.query(`
      ALTER TABLE system
        ADD COLUMN IF NOT EXISTS description TEXT,
        ADD COLUMN IF NOT EXISTS last_uploaded_at TIMESTAMP;
    `);
    await client.query(`
      UPDATE system s
      SET last_uploaded_at = (
        SELECT MAX(m.created_timestamp)
        FROM sbom_metadata m
        WHERE m.system_id = s.system_id
      )
      WHERE EXISTS (
        SELECT 1
        FROM sbom_metadata m
        WHERE m.system_id = s.system_id
      );
    `);

    await client.query(`
      ALTER TABLE sbom_metadata
        ADD COLUMN IF NOT EXISTS system_id INTEGER;
    `);
    await client.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1
          FROM information_schema.table_constraints
          WHERE constraint_name = 'fk_sbom_system'
            AND table_name = 'sbom_metadata'
        ) THEN
          ALTER TABLE sbom_metadata
            ADD CONSTRAINT fk_sbom_system
            FOREIGN KEY (system_id) REFERENCES system(system_id) ON DELETE SET NULL;
        END IF;
      END
      $$;
    `);
  } finally {
    client.release();
  }
};

export const ensureSbomAlgorithmSchema = async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS project_artifacts (
        artifact_id SERIAL PRIMARY KEY,
        project_id INTEGER NOT NULL,
        artifact_path VARCHAR(500) NOT NULL,
        artifact_name VARCHAR(255),
        artifact_type VARCHAR(100),
        content TEXT NOT NULL,
        hash VARCHAR(64) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (project_id) REFERENCES system(system_id) ON DELETE CASCADE,
        UNIQUE (project_id, artifact_path)
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS sbom_snapshots (
        snapshot_id VARCHAR(255) PRIMARY KEY,
        project_id INTEGER NOT NULL,
        version_number INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        source_type VARCHAR(50) NOT NULL,
        base_snapshot_id VARCHAR(255),
        summary JSONB,
        FOREIGN KEY (project_id) REFERENCES system(system_id) ON DELETE CASCADE,
        FOREIGN KEY (base_snapshot_id) REFERENCES sbom_snapshots(snapshot_id) ON DELETE SET NULL,
        UNIQUE (project_id, version_number)
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS sbom_components (
        component_id SERIAL PRIMARY KEY,
        snapshot_id VARCHAR(255) NOT NULL,
        stable_key VARCHAR(500) NOT NULL,
        component_ref VARCHAR(255),
        name VARCHAR(255) NOT NULL,
        version VARCHAR(100),
        purl VARCHAR(500),
        ecosystem VARCHAR(100),
        supplier_name VARCHAR(255),
        licenses VARCHAR,
        hashes VARCHAR,
        status VARCHAR(30) DEFAULT 'ACTIVE',
        FOREIGN KEY (snapshot_id) REFERENCES sbom_snapshots(snapshot_id) ON DELETE CASCADE,
        UNIQUE (snapshot_id, stable_key)
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS sbom_dependencies (
        dependency_id SERIAL PRIMARY KEY,
        snapshot_id VARCHAR(255) NOT NULL,
        source_key VARCHAR(500) NOT NULL,
        target_key VARCHAR(500) NOT NULL,
        relationship VARCHAR(100) DEFAULT 'DEPENDS_ON',
        is_transitive BOOLEAN DEFAULT FALSE,
        has_cycle BOOLEAN DEFAULT FALSE,
        FOREIGN KEY (snapshot_id) REFERENCES sbom_snapshots(snapshot_id) ON DELETE CASCADE
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS sbom_artifact_fingerprints (
        fingerprint_id SERIAL PRIMARY KEY,
        project_id INTEGER NOT NULL,
        artifact_path VARCHAR(500),
        artifact_name VARCHAR(255),
        artifact_type VARCHAR(100),
        hash VARCHAR(64) NOT NULL,
        last_scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        snapshot_id VARCHAR(255) NOT NULL,
        FOREIGN KEY (project_id) REFERENCES system(system_id) ON DELETE CASCADE,
        FOREIGN KEY (snapshot_id) REFERENCES sbom_snapshots(snapshot_id) ON DELETE CASCADE
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS sbom_change_logs (
        change_id SERIAL PRIMARY KEY,
        snapshot_id VARCHAR(255) NOT NULL,
        change_type VARCHAR(30) NOT NULL,
        entity_type VARCHAR(30) NOT NULL,
        entity_key VARCHAR(600) NOT NULL,
        component_name VARCHAR(255),
        previous_value JSONB,
        current_value JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (snapshot_id) REFERENCES sbom_snapshots(snapshot_id) ON DELETE CASCADE
      );
    `);
  } finally {
    client.release();
  }
};

export const ensureCicdSchema = async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS dev_tasks (
        task_id SERIAL PRIMARY KEY,
        project_id INTEGER NOT NULL,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        status VARCHAR(30) DEFAULT 'TODO',
        priority VARCHAR(30) DEFAULT 'MEDIUM',
        assigned_to VARCHAR(255),
        related_pipeline_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (project_id) REFERENCES system(system_id) ON DELETE CASCADE
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS cicd_pipelines (
        pipeline_id SERIAL PRIMARY KEY,
        project_id INTEGER NOT NULL,
        name VARCHAR(255) NOT NULL,
        provider VARCHAR(50) DEFAULT 'INTERNAL',
        branch VARCHAR(100) DEFAULT 'main',
        trigger_type VARCHAR(50) DEFAULT 'MANUAL',
        repo_url VARCHAR(500),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (project_id) REFERENCES system(system_id) ON DELETE CASCADE
      );
    `);

    await client.query(`
      ALTER TABLE cicd_pipelines
        ADD COLUMN IF NOT EXISTS repo_url VARCHAR(500);
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS cicd_pipeline_runs (
        run_id SERIAL PRIMARY KEY,
        pipeline_id INTEGER NOT NULL,
        project_id INTEGER NOT NULL,
        run_number INTEGER NOT NULL,
        status VARCHAR(30) DEFAULT 'PENDING',
        commit_hash VARCHAR(100),
        branch VARCHAR(100),
        started_at TIMESTAMP,
        finished_at TIMESTAMP,
        duration_ms INTEGER,
        triggered_by VARCHAR(255),
        generated_sbom_snapshot_id VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (pipeline_id) REFERENCES cicd_pipelines(pipeline_id) ON DELETE CASCADE,
        FOREIGN KEY (project_id) REFERENCES system(system_id) ON DELETE CASCADE,
        FOREIGN KEY (generated_sbom_snapshot_id) REFERENCES sbom_snapshots(snapshot_id) ON DELETE SET NULL,
        UNIQUE (pipeline_id, run_number)
      );
    `);

    await client.query(`
      ALTER TABLE cicd_pipeline_runs
        ADD COLUMN IF NOT EXISTS validation_report JSONB;
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS cicd_pipeline_steps (
        step_id SERIAL PRIMARY KEY,
        pipeline_run_id INTEGER NOT NULL,
        name VARCHAR(255) NOT NULL,
        step_order INTEGER NOT NULL,
        status VARCHAR(30) DEFAULT 'PENDING',
        started_at TIMESTAMP,
        finished_at TIMESTAMP,
        logs TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (pipeline_run_id) REFERENCES cicd_pipeline_runs(run_id) ON DELETE CASCADE
      );
    `);

    await client.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1
          FROM information_schema.table_constraints
          WHERE constraint_name = 'fk_dev_tasks_related_pipeline'
            AND table_name = 'dev_tasks'
        ) THEN
          ALTER TABLE dev_tasks
            ADD CONSTRAINT fk_dev_tasks_related_pipeline
            FOREIGN KEY (related_pipeline_id) REFERENCES cicd_pipelines(pipeline_id) ON DELETE SET NULL;
        END IF;
      END
      $$;
    `);
  } finally {
    client.release();
  }
};

export const ensureSbomValidationScenarioSchema = async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS sbom_validation_runs (
        run_id VARCHAR(80) PRIMARY KEY,
        scenario_id VARCHAR(80) NOT NULL,
        project_name VARCHAR(255) NOT NULL,
        github_url VARCHAR(500) NOT NULL,
        application_type VARCHAR(80) NOT NULL DEFAULT 'Web Application',
        repo_scope VARCHAR(80) NOT NULL DEFAULT 'Single Repository',
        architecture_type VARCHAR(255),
        status VARCHAR(40) NOT NULL DEFAULT 'CATALOG_READY',
        source_path VARCHAR(1000),
        sbom_id VARCHAR(255),
        sbom_path VARCHAR(1000),
        faulty_sbom_path VARCHAR(1000),
        confirmed BOOLEAN NOT NULL DEFAULT FALSE,
        analysis JSONB,
        graph JSONB,
        verification_report JSONB,
        test_report JSONB,
        error_message TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_sbom_validation_runs_scenario_id
      ON sbom_validation_runs (scenario_id);
    `);
  } finally {
    client.release();
  }
};
