"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sbomSnapshotController = void 0;
const db_1 = require("../config/db");
const incrementalSbomService_1 = require("../services/incrementalSbomService");
const sbomGraphService_1 = require("../services/sbomGraphService");
const artifactScannerService_1 = require("../services/artifactScannerService");
const firstParam = (value) => Array.isArray(value) ? value[0] : value;
const parseProjectId = (value) => {
    const rawValue = firstParam(value);
    if (!rawValue)
        return null;
    const projectId = Number(rawValue);
    return Number.isInteger(projectId) && projectId > 0 ? projectId : null;
};
exports.sbomSnapshotController = {
    incrementalGenerate: async (req, res, next) => {
        const projectId = parseProjectId(req.params.projectId);
        if (!projectId)
            return res.status(400).json({ error: 'Invalid projectId' });
        const client = await db_1.pool.connect();
        try {
            await client.query('BEGIN');
            const result = await incrementalSbomService_1.incrementalSbomService.generate(client, projectId, req.body || {});
            await client.query('COMMIT');
            res.status(201).json(result);
        }
        catch (error) {
            await client.query('ROLLBACK');
            next(error);
        }
        finally {
            client.release();
        }
    },
    listSnapshots: async (req, res, next) => {
        const projectId = parseProjectId(req.params.projectId);
        if (!projectId)
            return res.status(400).json({ error: 'Invalid projectId' });
        const client = await db_1.pool.connect();
        try {
            res.json(await incrementalSbomService_1.incrementalSbomService.listSnapshots(client, projectId));
        }
        catch (error) {
            next(error);
        }
        finally {
            client.release();
        }
    },
    saveArtifacts: async (req, res, next) => {
        const projectId = parseProjectId(req.params.projectId);
        if (!projectId)
            return res.status(400).json({ error: 'Invalid projectId' });
        const files = req.body?.dependencyFiles || req.body?.projectFiles || req.body?.artifactFiles || [];
        if (!Array.isArray(files) || files.length === 0) {
            return res.status(400).json({ error: 'Missing dependencyFiles/projectFiles' });
        }
        const client = await db_1.pool.connect();
        try {
            await client.query('BEGIN');
            const artifacts = await artifactScannerService_1.artifactScannerService.saveProjectArtifacts(client, projectId, files);
            await client.query('COMMIT');
            res.status(201).json({ projectId, artifacts });
        }
        catch (error) {
            await client.query('ROLLBACK');
            next(error);
        }
        finally {
            client.release();
        }
    },
    listArtifacts: async (req, res, next) => {
        const projectId = parseProjectId(req.params.projectId);
        if (!projectId)
            return res.status(400).json({ error: 'Invalid projectId' });
        const client = await db_1.pool.connect();
        try {
            const { rows } = await client.query(`SELECT artifact_id, project_id, artifact_path, artifact_name, artifact_type, hash, created_at, updated_at
         FROM project_artifacts
         WHERE project_id = $1
         ORDER BY artifact_path`, [projectId]);
            res.json(rows);
        }
        catch (error) {
            next(error);
        }
        finally {
            client.release();
        }
    },
    getChanges: async (req, res, next) => {
        const client = await db_1.pool.connect();
        try {
            res.json(await incrementalSbomService_1.incrementalSbomService.getChanges(client, firstParam(req.params.snapshotId) || ''));
        }
        catch (error) {
            next(error);
        }
        finally {
            client.release();
        }
    },
    exportSnapshot: async (req, res, next) => {
        const client = await db_1.pool.connect();
        try {
            res.json(await incrementalSbomService_1.incrementalSbomService.exportSnapshot(client, firstParam(req.params.snapshotId) || ''));
        }
        catch (error) {
            next(error);
        }
        finally {
            client.release();
        }
    },
    getGraph: async (req, res, next) => {
        const client = await db_1.pool.connect();
        try {
            const graph = await sbomGraphService_1.sbomGraphService.buildGraph(client, firstParam(req.params.snapshotId) || '', {
                depth: req.query.depth ? Number(req.query.depth) : undefined,
                onlyVulnerable: req.query.onlyVulnerable === 'true',
                search: typeof req.query.search === 'string' ? req.query.search : undefined,
            });
            res.json({
                snapshotId: graph.snapshotId,
                nodes: graph.nodes,
                edges: graph.edges,
                summary: graph.summary,
            });
        }
        catch (error) {
            next(error);
        }
        finally {
            client.release();
        }
    },
};
