import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

export const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'sbom_db',
  password: process.env.DB_PASSWORD || 'secret',
  port: parseInt(process.env.DB_PORT || '5432', 10),
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
        created_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
