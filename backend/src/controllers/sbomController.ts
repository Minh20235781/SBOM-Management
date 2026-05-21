import { Request, Response, NextFunction } from 'express';
import { pool } from '../config/db';
import { parseAndSaveSBOM } from '../services/sbomParserService';

export const sbomController = {
  upload: async (req: Request, res: Response, next: NextFunction) => {
    const client = await pool.connect();
    try {
      if (!req.body || Object.keys(req.body).length === 0) {
        return res.status(400).json({ error: 'No data provided' });
      }
      await client.query('BEGIN');
      // Support payload: { sbom: <object>, system_id: <int> } or raw SBOM object
      const payload = (req.body && req.body.sbom) ? req.body : { sbom: req.body };
      // If caller provided systemName instead of system_id, create/find it server-side
      const providedSystemName = (req.body && (req.body.systemName || (req.body.sbom && req.body.sbom.systemName)))
        ? (req.body.systemName || (req.body.sbom && req.body.sbom.systemName))
        : null;
      if (!payload.system_id && providedSystemName) {
        // try find
        const existing = await pool.query('SELECT * FROM system WHERE name = $1', [providedSystemName]);
        if (existing.rows.length > 0) {
          payload.system_id = existing.rows[0].system_id;
        } else {
          const ins = await pool.query('INSERT INTO system (name) VALUES ($1) RETURNING *', [providedSystemName]);
          payload.system_id = ins.rows[0].system_id;
        }
      }
      const sbomId = await parseAndSaveSBOM(client, payload);
      await client.query('COMMIT');
      res.status(201).json({ success: true, sbomId });
    } catch (error) {
      await client.query('ROLLBACK');
      next(error);
    } finally {
      client.release();
    }
  },

  list: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await pool.query('SELECT * FROM sbom_metadata');
      res.json(result.rows);
    } catch (error) {
      next(error);
    }
  },

  getById: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { id } = req.params;
      const result = await pool.query('SELECT * FROM sbom_metadata WHERE sbom_id = $1', [id]);
      if (result.rows.length === 0) return res.status(404).json({ error: 'Not found' });
      res.json(result.rows[0]);
    } catch (error) {
      next(error);
    }
  },

  getComponents: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { id } = req.params;
      const result = await pool.query('SELECT * FROM component WHERE sbom_id = $1', [id]);
      res.json(result.rows);
    } catch (error) {
      next(error);
    }
  },

  getDependencies: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { id } = req.params;
      const { rows } = await pool.query('SELECT * FROM dependency WHERE sbom_id = $1', [id]);
      res.json(rows);
    } catch (error) {
      next(error);
    }
  },

  getVulnerabilities: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { id } = req.params;
      const { rows } = await pool.query('SELECT * FROM vulnerability WHERE sbom_id = $1', [id]);
      res.json(rows);
    } catch (error) {
      next(error);
    }
  }
};
