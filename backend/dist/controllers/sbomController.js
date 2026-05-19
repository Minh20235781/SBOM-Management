"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sbomController = void 0;
const db_1 = require("../config/db");
const sbomParserService_1 = require("../services/sbomParserService");
exports.sbomController = {
    upload: async (req, res, next) => {
        const client = await db_1.pool.connect();
        try {
            if (!req.body || Object.keys(req.body).length === 0) {
                return res.status(400).json({ error: 'No data provided' });
            }
            await client.query('BEGIN');
            const sbomId = await (0, sbomParserService_1.parseAndSaveSBOM)(client, req.body);
            await client.query('COMMIT');
            res.status(201).json({ success: true, sbomId });
        }
        catch (error) {
            await client.query('ROLLBACK');
            next(error);
        }
        finally {
            client.release();
        }
    },
    list: async (req, res, next) => {
        try {
            const result = await db_1.pool.query('SELECT * FROM sbom_metadata');
            res.json(result.rows);
        }
        catch (error) {
            next(error);
        }
    },
    getById: async (req, res, next) => {
        try {
            const { id } = req.params;
            const result = await db_1.pool.query('SELECT * FROM sbom_metadata WHERE sbom_id = $1', [id]);
            if (result.rows.length === 0)
                return res.status(404).json({ error: 'Not found' });
            res.json(result.rows[0]);
        }
        catch (error) {
            next(error);
        }
    },
    getComponents: async (req, res, next) => {
        try {
            const { id } = req.params;
            const result = await db_1.pool.query('SELECT * FROM component WHERE sbom_id = $1', [id]);
            res.json(result.rows);
        }
        catch (error) {
            next(error);
        }
    },
    getDependencies: async (req, res, next) => {
        try {
            const { id } = req.params;
            const { rows } = await db_1.pool.query('SELECT * FROM dependency WHERE sbom_id = $1', [id]);
            res.json(rows);
        }
        catch (error) {
            next(error);
        }
    },
    getVulnerabilities: async (req, res, next) => {
        try {
            const { id } = req.params;
            const { rows } = await db_1.pool.query('SELECT * FROM vulnerability WHERE sbom_id = $1', [id]);
            res.json(rows);
        }
        catch (error) {
            next(error);
        }
    }
};
