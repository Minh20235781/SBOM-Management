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
};
