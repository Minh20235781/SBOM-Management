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
