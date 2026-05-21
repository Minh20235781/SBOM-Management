import { Request, Response, NextFunction } from 'express';
import { pool } from '../config/db';

export const systemController = {
  list: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { rows } = await pool.query('SELECT * FROM system ORDER BY created_timestamp DESC');
      res.json(rows);
    } catch (err) {
      next(err);
    }
  },

  create: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { name, description } = req.body;
      if (!name) return res.status(400).json({ error: 'Missing name' });

      // Try to find existing
      const existing = await pool.query('SELECT * FROM system WHERE name = $1', [name]);
      if (existing.rows.length > 0) return res.json(existing.rows[0]);

      const { rows } = await pool.query(
        'INSERT INTO system (name, description) VALUES ($1, $2) RETURNING *',
        [name, description || null]
      );
      res.status(201).json(rows[0]);
    } catch (err) {
      next(err);
    }
  }
,
  delete: async (req: Request, res: Response, next: NextFunction) => {
    const id = Number(req.params.id);
    if (!id || Number.isNaN(id)) return res.status(400).json({ error: 'Invalid id' });
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('DELETE FROM sbom_metadata WHERE system_id = $1', [id]);
      const result = await client.query('DELETE FROM system WHERE system_id = $1 RETURNING *', [id]);
      await client.query('COMMIT');
      if (result.rowCount === 0) return res.status(404).json({ error: 'System not found' });
      res.json({ deleted: true, system: result.rows[0] });
    } catch (err) {
      await client.query('ROLLBACK');
      next(err);
    } finally {
      client.release();
    }
  }
};
