import { Request, Response, NextFunction } from 'express';
import { pool } from '../config/db';

export const systemController = {
  list: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { rows } = await pool.query(`
        SELECT
          s.*,
          GREATEST(COALESCE(m.sbom_count, 0), COALESCE(ss.snapshot_count, 0))::int AS sbom_count,
          COALESCE(
            NULLIF(
              GREATEST(
                COALESCE(s.last_uploaded_at, TIMESTAMP 'epoch'),
                COALESCE(m.latest_metadata_timestamp, TIMESTAMP 'epoch'),
                COALESCE(ss.latest_snapshot_timestamp, TIMESTAMP 'epoch')
              ),
              TIMESTAMP 'epoch'
            ),
            s.created_timestamp
          ) AS latest_sbom_timestamp
        FROM system s
        LEFT JOIN (
          SELECT
            system_id,
            COUNT(DISTINCT sbom_id)::int AS sbom_count,
            MAX(created_timestamp) AS latest_metadata_timestamp
          FROM sbom_metadata
          GROUP BY system_id
        ) m ON m.system_id = s.system_id
        LEFT JOIN (
          SELECT
            project_id,
            COUNT(*)::int AS snapshot_count,
            MAX(created_at) AS latest_snapshot_timestamp
          FROM sbom_snapshots
          GROUP BY project_id
        ) ss ON ss.project_id = s.system_id
        ORDER BY latest_sbom_timestamp DESC
      `);
      res.json(rows);
    } catch (err) {
      next(err);
    }
  },

  create: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { name, description } = req.body;
      const normalizedName = typeof name === 'string' ? name.trim() : '';
      if (!normalizedName) return res.status(400).json({ error: 'Missing name' });

      // Try to find existing
      const existing = await pool.query('SELECT * FROM system WHERE LOWER(name) = LOWER($1) LIMIT 1', [normalizedName]);
      if (existing.rows.length > 0) {
        const { rows } = await pool.query(
          `UPDATE system
           SET description = COALESCE($2, description)
           WHERE system_id = $1
           RETURNING *`,
          [existing.rows[0].system_id, description || null]
        );
        return res.json(rows[0]);
      }

      const { rows } = await pool.query(
        'INSERT INTO system (name, description, last_uploaded_at) VALUES ($1, $2, NULL) RETURNING *',
        [normalizedName, description || null]
      );
      res.status(201).json(rows[0]);
    } catch (err) {
      next(err);
    }
  },

  getDetail: async (req: Request, res: Response, next: NextFunction) => {
    const id = Number(req.params.id);
    if (!id || Number.isNaN(id)) return res.status(400).json({ error: 'Invalid id' });
    try {
      const systemResult = await pool.query('SELECT * FROM system WHERE system_id = $1', [id]);
      if (systemResult.rows.length === 0) return res.status(404).json({ error: 'System not found' });

      const sboms = await pool.query(
        `SELECT
          m.*,
          (SELECT COUNT(*)::int FROM component c WHERE c.sbom_id = m.sbom_id) AS component_count,
          (SELECT COUNT(*)::int FROM dependency d WHERE d.sbom_id = m.sbom_id) AS dependency_count,
          (SELECT COUNT(*)::int FROM vulnerability v WHERE v.sbom_id = m.sbom_id) AS vulnerability_count
        FROM sbom_metadata m
        WHERE m.system_id = $1
        ORDER BY m.created_timestamp DESC NULLS LAST`,
        [id]
      );

      const snapshots = await pool.query(
        'SELECT * FROM sbom_snapshots WHERE project_id = $1 ORDER BY version_number DESC',
        [id]
      );

      const unlinkedSboms = await pool.query(
        `SELECT sbom_id, created_timestamp, tool_components, lifecycle_phase
         FROM sbom_metadata
         WHERE system_id IS NULL
         ORDER BY created_timestamp DESC NULLS LAST
         LIMIT 50`
      );

      res.json({
        system: systemResult.rows[0],
        sboms: sboms.rows,
        snapshots: snapshots.rows,
        unlinkedSboms: unlinkedSboms.rows,
      });
    } catch (err) {
      next(err);
    }
  },

  linkSbom: async (req: Request, res: Response, next: NextFunction) => {
    const id = Number(req.params.id);
    const { sbomId } = req.body;
    if (!id || Number.isNaN(id)) return res.status(400).json({ error: 'Invalid id' });
    if (!sbomId) return res.status(400).json({ error: 'Missing sbomId' });

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const systemResult = await client.query('SELECT * FROM system WHERE system_id = $1', [id]);
      if (systemResult.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'System not found' });
      }

      const sbomResult = await client.query(
        'UPDATE sbom_metadata SET system_id = $1 WHERE sbom_id = $2 RETURNING *',
        [id, sbomId]
      );
      if (sbomResult.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'SBOM not found' });
      }

      await client.query('UPDATE system SET last_uploaded_at = CURRENT_TIMESTAMP WHERE system_id = $1', [id]);
      await client.query('COMMIT');
      res.json({ linked: true, system: systemResult.rows[0], sbom: sbomResult.rows[0] });
    } catch (err) {
      await client.query('ROLLBACK');
      next(err);
    } finally {
      client.release();
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
