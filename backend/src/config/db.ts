import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const ssl = process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : undefined;
const poolOptions = { ssl, options: '-c search_path=public' };

export const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ...poolOptions,
    })
  : new Pool({
      user: process.env.DB_USER || 'postgres',
      host: process.env.DB_HOST || 'localhost',
      database: process.env.DB_NAME || 'sbom_db',
      password: process.env.DB_PASSWORD || 'secret',
      port: parseInt(process.env.DB_PORT || '5432', 10),
      ...poolOptions,
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

export const ensureCoreSchema = async () => {
  const client = await pool.connect();
  try {
    await client.query('CREATE SCHEMA IF NOT EXISTS public');
    await client.query('SET search_path TO public');

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
      CREATE TABLE IF NOT EXISTS sbom_metadata (
        sbom_id VARCHAR(255) PRIMARY KEY,
        authors VARCHAR,
        created_timestamp TIMESTAMP,
        system_id INTEGER,
        tool_components VARCHAR,
        tool_services VARCHAR,
        lifecycle_phase TEXT
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS component (
        component_id VARCHAR(255) PRIMARY KEY,
        sbom_id VARCHAR(255) NOT NULL,
        supplier_name VARCHAR(255),
        name VARCHAR(255) NOT NULL,
        version TEXT,
        purl VARCHAR(500),
        cpe VARCHAR(500),
        hashes VARCHAR,
        licenses VARCHAR,
        support_level TEXT,
        end_of_support DATE,
        FOREIGN KEY (sbom_id) REFERENCES sbom_metadata(sbom_id) ON DELETE CASCADE
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS dependency (
        dependency_id SERIAL PRIMARY KEY,
        sbom_id VARCHAR(255) NOT NULL,
        component_ref VARCHAR(255) NOT NULL,
        depends_on_ref VARCHAR(255) NOT NULL,
        FOREIGN KEY (sbom_id) REFERENCES sbom_metadata(sbom_id) ON DELETE CASCADE,
        FOREIGN KEY (component_ref) REFERENCES component(component_id),
        FOREIGN KEY (depends_on_ref) REFERENCES component(component_id)
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS vulnerability (
        vuln_id SERIAL PRIMARY KEY,
        sbom_id VARCHAR(255) NOT NULL,
        name VARCHAR(255),
        installed TEXT,
        fixed_in TEXT,
        package_type TEXT,
        vulnerability VARCHAR(255),
        severity VARCHAR(50),
        epss NUMERIC(6,5),
        risk VARCHAR(50),
        cve_id TEXT,
        description VARCHAR,
        affected_component_ref VARCHAR(255),
        FOREIGN KEY (sbom_id) REFERENCES sbom_metadata(sbom_id) ON DELETE CASCADE,
        FOREIGN KEY (affected_component_ref) REFERENCES component(component_id)
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS composition (
        composition_id SERIAL PRIMARY KEY,
        sbom_id VARCHAR(255) NOT NULL,
        aggregate_type VARCHAR(100),
        assemblies VARCHAR,
        dependencies VARCHAR,
        FOREIGN KEY (sbom_id) REFERENCES sbom_metadata(sbom_id) ON DELETE CASCADE
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS formulation (
        formulation_id SERIAL PRIMARY KEY,
        sbom_id VARCHAR(255) NOT NULL,
        components VARCHAR,
        workflows VARCHAR,
        tools VARCHAR,
        FOREIGN KEY (sbom_id) REFERENCES sbom_metadata(sbom_id) ON DELETE CASCADE
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS annotation (
        annotation_id SERIAL PRIMARY KEY,
        sbom_id VARCHAR(255) NOT NULL,
        annotator VARCHAR(255),
        created_timestamp TIMESTAMP,
        text TEXT NOT NULL,
        subjects VARCHAR,
        FOREIGN KEY (sbom_id) REFERENCES sbom_metadata(sbom_id) ON DELETE CASCADE
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS declaration (
        declaration_id SERIAL PRIMARY KEY,
        sbom_id VARCHAR(255) NOT NULL,
        issuer VARCHAR(255),
        claims VARCHAR,
        FOREIGN KEY (sbom_id) REFERENCES sbom_metadata(sbom_id) ON DELETE CASCADE
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS citation (
        citation_id SERIAL PRIMARY KEY,
        sbom_id VARCHAR(255) NOT NULL,
        title VARCHAR(255),
        url VARCHAR(500) NOT NULL,
        description VARCHAR,
        FOREIGN KEY (sbom_id) REFERENCES sbom_metadata(sbom_id) ON DELETE CASCADE
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS definition (
        definition_id SERIAL PRIMARY KEY,
        sbom_id VARCHAR(255) NOT NULL,
        components VARCHAR,
        services VARCHAR,
        FOREIGN KEY (sbom_id) REFERENCES sbom_metadata(sbom_id) ON DELETE CASCADE
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS service (
        service_id SERIAL PRIMARY KEY,
        sbom_id VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        version TEXT,
        description VARCHAR,
        FOREIGN KEY (sbom_id) REFERENCES sbom_metadata(sbom_id) ON DELETE CASCADE
      );
    `);
  } finally {
    client.release();
  }
};

export const ensureVulnerabilitySchema = async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      ALTER TABLE vulnerability
        ADD COLUMN IF NOT EXISTS name VARCHAR(255),
        ADD COLUMN IF NOT EXISTS installed TEXT,
        ADD COLUMN IF NOT EXISTS fixed_in TEXT,
        ADD COLUMN IF NOT EXISTS package_type TEXT,
        ADD COLUMN IF NOT EXISTS vulnerability VARCHAR(255),
        ADD COLUMN IF NOT EXISTS epss NUMERIC(6,5),
        ADD COLUMN IF NOT EXISTS risk VARCHAR(50)
    `);
    await client.query(`
      ALTER TABLE IF EXISTS sbom_metadata
        ALTER COLUMN lifecycle_phase TYPE TEXT;
    `);
    await client.query(`
      ALTER TABLE IF EXISTS component
        ALTER COLUMN version TYPE TEXT,
        ALTER COLUMN purl TYPE TEXT,
        ALTER COLUMN cpe TYPE TEXT,
        ALTER COLUMN support_level TYPE TEXT;
    `);
    await client.query(`
      ALTER TABLE IF EXISTS vulnerability
        ALTER COLUMN installed TYPE TEXT,
        ALTER COLUMN fixed_in TYPE TEXT,
        ALTER COLUMN package_type TYPE TEXT,
        ALTER COLUMN cve_id TYPE TEXT;
    `);
    await client.query(`
      ALTER TABLE IF EXISTS service
        ALTER COLUMN version TYPE TEXT;
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
        version TEXT,
        purl VARCHAR(500),
        ecosystem TEXT,
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
      ALTER TABLE IF EXISTS sbom_components
        ALTER COLUMN version TYPE TEXT,
        ALTER COLUMN ecosystem TYPE TEXT;
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
        ADD COLUMN IF NOT EXISTS repo_url VARCHAR(500),
        ADD COLUMN IF NOT EXISTS workflow_file VARCHAR(255) DEFAULT 'sbom.yml';
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
        ADD COLUMN IF NOT EXISTS validation_report JSONB,
        ADD COLUMN IF NOT EXISTS external_run_id BIGINT,
        ADD COLUMN IF NOT EXISTS external_run_attempt INTEGER,
        ADD COLUMN IF NOT EXISTS external_run_url VARCHAR(1000),
        ADD COLUMN IF NOT EXISTS event_name VARCHAR(80),
        ADD COLUMN IF NOT EXISTS conclusion VARCHAR(80),
        ADD COLUMN IF NOT EXISTS dispatch_request_id VARCHAR(80),
        ADD COLUMN IF NOT EXISTS sbom_id VARCHAR(255);
    `);

    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS idx_cicd_pipeline_runs_external_run
      ON cicd_pipeline_runs(external_run_id)
      WHERE external_run_id IS NOT NULL;
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
      CREATE TABLE IF NOT EXISTS sbom_repositories (
        repository_id VARCHAR(80) PRIMARY KEY,
        system_id INTEGER REFERENCES system(system_id) ON DELETE SET NULL,
        name VARCHAR(255) NOT NULL,
        github_url VARCHAR(500) UNIQUE NOT NULL,
        architecture_type VARCHAR(255) NOT NULL,
        tech_stack JSONB NOT NULL DEFAULT '[]'::jsonb,
        package_managers JSONB NOT NULL DEFAULT '[]'::jsonb,
        expected_dependency_files JSONB NOT NULL DEFAULT '[]'::jsonb,
        application_type VARCHAR(80) NOT NULL DEFAULT 'Web Application',
        repo_scope VARCHAR(80) NOT NULL DEFAULT 'Single Repository',
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await client.query(`
      ALTER TABLE cicd_pipeline_steps
        ADD COLUMN IF NOT EXISTS external_job_id BIGINT;
    `);

    await client.query('DROP INDEX IF EXISTS idx_cicd_pipeline_steps_external;');
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS idx_cicd_pipeline_steps_external
      ON cicd_pipeline_steps(pipeline_run_id, external_job_id, step_order);
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS github_webhook_deliveries (
        delivery_id VARCHAR(100) PRIMARY KEY,
        event_name VARCHAR(100) NOT NULL,
        payload JSONB,
        received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await client.query(`
      INSERT INTO sbom_repositories
        (repository_id, name, github_url, architecture_type, tech_stack, package_managers, expected_dependency_files, description)
      VALUES
        ('spring-petclinic', 'Spring PetClinic', 'https://github.com/spring-projects/spring-petclinic', 'Monolithic Spring Boot web application', '["Java","Spring Boot"]', '["Maven"]', '["pom.xml"]', 'Reference Spring Boot web application used for PetClinic demos.'),
        ('ghost', 'Ghost CMS', 'https://github.com/TryGhost/Ghost', 'Node.js CMS web application', '["Node.js","Ember.js"]', '["Yarn","npm"]', '["package.json","yarn.lock"]', 'Open-source publishing and CMS platform.'),
        ('nodebb', 'NodeBB', 'https://github.com/NodeBB/NodeBB', 'Node.js forum web application', '["Node.js","Express"]', '["npm"]', '["package.json","package-lock.json"]', 'Modern web forum software built on Node.js.'),
        ('bookstack', 'BookStack', 'https://github.com/BookStackApp/BookStack', 'Laravel monolithic web application', '["PHP","Laravel","Vue"]', '["Composer","npm"]', '["composer.json","composer.lock","package.json"]', 'Documentation and wiki web application.'),
        ('discourse', 'Discourse', 'https://github.com/discourse/discourse', 'Rails web application', '["Ruby","Rails","Ember.js"]', '["Bundler","Yarn"]', '["Gemfile","Gemfile.lock","package.json"]', 'Open-source discussion platform.'),
        ('gitea', 'Gitea', 'https://github.com/go-gitea/gitea', 'Go web application', '["Go","Vue"]', '["Go Modules","npm"]', '["go.mod","go.sum","package.json"]', 'Self-hosted Git service web application.'),
        ('flasky', 'Flasky', 'https://github.com/miguelgrinberg/flasky', 'Flask monolithic web application', '["Python","Flask"]', '["pip"]', '["requirements.txt"]', 'Example Flask web application from Flask Web Development.'),
        ('react-redux-realworld', 'RealWorld React', 'https://github.com/gothinkster/react-redux-realworld-example-app', 'Single-page React web application', '["React","Redux"]', '["npm"]', '["package.json","package-lock.json"]', 'RealWorld frontend implementation using React and Redux.'),
        ('vue-realworld', 'RealWorld Vue', 'https://github.com/gothinkster/vue-realworld-example-app', 'Single-page Vue web application', '["Vue.js"]', '["npm"]', '["package.json","package-lock.json"]', 'RealWorld frontend implementation using Vue.'),
        ('juice-shop', 'OWASP Juice Shop', 'https://github.com/juice-shop/juice-shop', 'Node.js/Angular web application', '["Node.js","Angular"]', '["npm"]', '["package.json","package-lock.json"]', 'Intentionally vulnerable web application for security training.')
      ON CONFLICT (repository_id) DO UPDATE SET
        name = EXCLUDED.name,
        github_url = EXCLUDED.github_url,
        architecture_type = EXCLUDED.architecture_type,
        tech_stack = EXCLUDED.tech_stack,
        package_managers = EXCLUDED.package_managers,
        expected_dependency_files = EXCLUDED.expected_dependency_files,
        description = EXCLUDED.description,
        updated_at = CURRENT_TIMESTAMP;
    `);

    await client.query(`
      ALTER TABLE sbom_metadata
        ADD COLUMN IF NOT EXISTS repository_id VARCHAR(80),
        ADD COLUMN IF NOT EXISTS source_commit VARCHAR(100),
        ADD COLUMN IF NOT EXISTS analyzed_at TIMESTAMP,
        ADD COLUMN IF NOT EXISTS source_repository_url VARCHAR(500);
    `);
    await client.query(`
      UPDATE sbom_repositories r
      SET system_id = p.project_id
      FROM cicd_pipelines p
      WHERE lower(regexp_replace(p.repo_url, '\\.git/?$', '')) = lower(regexp_replace(r.github_url, '\\.git/?$', ''))
        AND r.system_id IS NULL;
    `);
    await client.query(`
      UPDATE sbom_metadata m
      SET repository_id = r.repository_id,
          source_repository_url = COALESCE(m.source_repository_url, r.github_url),
          analyzed_at = COALESCE(m.analyzed_at, m.created_timestamp)
      FROM sbom_repositories r
      WHERE m.system_id = r.system_id AND m.repository_id IS NULL;
    `);
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
