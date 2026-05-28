"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ensureSbomAlgorithmSchema = exports.ensureVulnerabilitySchema = exports.checkDbConnection = exports.pool = void 0;
const pg_1 = require("pg");
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
exports.pool = new pg_1.Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_NAME || 'sbom_db',
    password: process.env.DB_PASSWORD || 'secret',
    port: parseInt(process.env.DB_PORT || '5432', 10),
});
const checkDbConnection = async () => {
    try {
        const client = await exports.pool.connect();
        console.log('Successfully connected to the PostgreSQL database.');
        client.release();
    }
    catch (err) {
        console.error('Error connecting to PostgreSQL:', err);
        process.exit(1);
    }
};
exports.checkDbConnection = checkDbConnection;
const ensureVulnerabilitySchema = async () => {
    const client = await exports.pool.connect();
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
    }
    finally {
        client.release();
    }
};
exports.ensureVulnerabilitySchema = ensureVulnerabilitySchema;
const ensureSbomAlgorithmSchema = async () => {
    const client = await exports.pool.connect();
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
    }
    finally {
        client.release();
    }
};
exports.ensureSbomAlgorithmSchema = ensureSbomAlgorithmSchema;
