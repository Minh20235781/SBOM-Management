"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sbomController = void 0;
const db_1 = require("../config/db");
const sbomParserService_1 = require("../services/sbomParserService");
const syftGeneratorService_1 = require("../services/syftGeneratorService");
const getIncomingSbomId = (data) => {
    const payload = data && data.sbom ? data.sbom : data;
    if (!payload || typeof payload !== 'object')
        return null;
    return payload.serialNumber || payload.documentNamespace || payload.SPDXID || null;
};
const normalizeSystemId = (payload) => {
    if (payload.system_id && typeof payload.system_id === 'string') {
        const parsedSystemId = Number(payload.system_id);
        payload.system_id = Number.isInteger(parsedSystemId) && parsedSystemId > 0 ? parsedSystemId : null;
    }
};
const findOrCreateSystem = async (client, name) => {
    const normalizedName = name.trim();
    const existing = await client.query('SELECT * FROM system WHERE LOWER(name) = LOWER($1) LIMIT 1', [normalizedName]);
    if (existing.rows.length > 0) {
        return existing.rows[0].system_id;
    }
    const inserted = await client.query('INSERT INTO system (name, last_uploaded_at) VALUES ($1, NULL) RETURNING *', [normalizedName]);
    return inserted.rows[0].system_id;
};
const countCycloneDxDependencyEdges = (sbom) => {
    const dependencies = Array.isArray(sbom?.dependencies) ? sbom.dependencies : [];
    return dependencies.reduce((sum, dep) => sum + (Array.isArray(dep.dependsOn) ? dep.dependsOn.length : 0), 0);
};
const extractCycloneDxEcosystems = (sbom) => {
    const components = Array.isArray(sbom?.components) ? sbom.components : [];
    const ecosystems = new Set();
    for (const component of components) {
        const purl = typeof component?.purl === 'string' ? component.purl : '';
        if (purl.startsWith('pkg:')) {
            const slash = purl.indexOf('/');
            ecosystems.add(slash > 4 ? purl.slice(4, slash) : 'unknown');
        }
        else if (component?.type) {
            ecosystems.add(String(component.type));
        }
    }
    return [...ecosystems].sort();
};
const ensureRepositoryPipeline = async (client, systemId, repoUrl) => {
    const normalizedRepoUrl = String(repoUrl || '').trim();
    if (!normalizedRepoUrl)
        return;
    const existing = await client.query(`SELECT pipeline_id
     FROM cicd_pipelines
     WHERE project_id = $1
       AND repo_url IS NOT NULL
       AND btrim(repo_url) <> ''
     ORDER BY updated_at DESC NULLS LAST, created_at DESC NULLS LAST, pipeline_id DESC
     LIMIT 1`, [systemId]);
    if (existing.rows[0]) {
        await client.query(`UPDATE cicd_pipelines
       SET repo_url = $2, updated_at = CURRENT_TIMESTAMP
       WHERE pipeline_id = $1`, [existing.rows[0].pipeline_id, normalizedRepoUrl]);
        return;
    }
    await client.query(`INSERT INTO cicd_pipelines
      (project_id, name, provider, branch, trigger_type, repo_url)
     VALUES ($1, $2, 'INTERNAL', 'main', 'MANUAL', $3)`, [systemId, 'sbom-validation-source', normalizedRepoUrl]);
};
exports.sbomController = {
    upload: async (req, res, next) => {
        const client = await db_1.pool.connect();
        try {
            if (!req.body || Object.keys(req.body).length === 0) {
                return res.status(400).json({ error: 'No data provided' });
            }
            await client.query('BEGIN');
            // Support payload: { sbom: <object>, system_id: <int> } or raw SBOM object
            const payload = (req.body && req.body.sbom) ? req.body : { sbom: req.body };
            normalizeSystemId(payload);
            const incomingSbomId = getIncomingSbomId(payload);
            const existingSbom = incomingSbomId
                ? await client.query('SELECT sbom_id, system_id FROM sbom_metadata WHERE sbom_id = $1', [incomingSbomId])
                : null;
            // If caller provided systemName instead of system_id, create/find it server-side
            const providedSystemName = (req.body && (req.body.systemName || (req.body.sbom && req.body.sbom.systemName)))
                ? String(req.body.systemName || (req.body.sbom && req.body.sbom.systemName)).trim()
                : null;
            if (!payload.system_id && providedSystemName) {
                payload.system_id = await findOrCreateSystem(client, providedSystemName);
            }
            const providedRepoUrl = typeof req.body?.repoUrl === 'string' ? req.body.repoUrl : null;
            if (payload.system_id && providedRepoUrl) {
                await ensureRepositoryPipeline(client, payload.system_id, providedRepoUrl);
            }
            const sbomId = await (0, sbomParserService_1.parseAndSaveSBOM)(client, payload);
            const systemSbomCount = payload.system_id
                ? await client.query('SELECT COUNT(DISTINCT sbom_id)::int AS count FROM sbom_metadata WHERE system_id = $1', [payload.system_id])
                : null;
            await client.query('COMMIT');
            res.status(201).json({
                success: true,
                sbomId,
                systemId: payload.system_id || null,
                createdNewSbom: existingSbom ? existingSbom.rows.length === 0 : true,
                systemSbomCount: systemSbomCount?.rows[0]?.count ?? null,
            });
        }
        catch (error) {
            await client.query('ROLLBACK');
            next(error);
        }
        finally {
            client.release();
        }
    },
    analyzeGitHub: async (req, res, next) => {
        try {
            const { repoUrl } = req.body || {};
            const started = Date.now();
            const generated = await (0, syftGeneratorService_1.generateSbomFromGitHubRepo)(repoUrl);
            const sbomText = JSON.stringify(generated.sbom, null, 2);
            const components = Array.isArray(generated.sbom?.components) ? generated.sbom.components : [];
            const dependencyEntries = Array.isArray(generated.sbom?.dependencies) ? generated.sbom.dependencies : [];
            res.json({
                success: true,
                sbom: generated.sbom,
                repoUrl: generated.normalizedRepoUrl,
                repoName: generated.repoName,
                hasExistingSbom: generated.detectedSbomFiles.length > 0,
                detectedSbomFiles: generated.detectedSbomFiles,
                detectedManifestFiles: generated.detectedManifestFiles,
                message: generated.detectedSbomFiles.length > 0
                    ? 'Detected existing SBOM files in repository.'
                    : 'No existing SBOM file detected in repository.',
                analysis: {
                    repoUrl: generated.normalizedRepoUrl,
                    repoName: generated.repoName,
                    bomFormat: generated.sbom?.bomFormat || 'CycloneDX',
                    specVersion: generated.sbom?.specVersion || null,
                    serialNumber: generated.sbom?.serialNumber || null,
                    componentCount: components.length,
                    dependencyCount: countCycloneDxDependencyEdges(generated.sbom),
                    dependencyReferenceCount: dependencyEntries.length,
                    ecosystems: extractCycloneDxEcosystems(generated.sbom),
                    toolInfo: 'Syft CycloneDX JSON',
                    createdTimestamp: generated.sbom?.metadata?.timestamp || new Date().toISOString(),
                    sbomSizeBytes: Buffer.byteLength(sbomText, 'utf8'),
                    analysisDurationMs: Date.now() - started,
                    inferredMetadata: generated.inferredMetadata || null,
                    hasExistingSbom: generated.detectedSbomFiles.length > 0,
                    detectedSbomFiles: generated.detectedSbomFiles,
                    detectedManifestFiles: generated.detectedManifestFiles,
                },
            });
        }
        catch (error) {
            next(error);
        }
    },
    generateFromGitHub: async (req, res, next) => {
        const client = await db_1.pool.connect();
        try {
            const { repoUrl, systemName } = req.body || {};
            const generated = await (0, syftGeneratorService_1.generateSbomFromGitHubRepo)(repoUrl);
            await client.query('BEGIN');
            const payload = {
                sbom: generated.sbom,
                system_id: null,
            };
            const providedSystemName = typeof systemName === 'string' && systemName.trim()
                ? systemName.trim()
                : generated.repoName;
            payload.system_id = await findOrCreateSystem(client, providedSystemName);
            await ensureRepositoryPipeline(client, payload.system_id, generated.normalizedRepoUrl);
            const incomingSbomId = getIncomingSbomId(payload);
            const existingSbom = incomingSbomId
                ? await client.query('SELECT sbom_id, system_id FROM sbom_metadata WHERE sbom_id = $1', [incomingSbomId])
                : null;
            const sbomId = await (0, sbomParserService_1.parseAndSaveSBOM)(client, payload);
            const systemSbomCount = await client.query('SELECT COUNT(DISTINCT sbom_id)::int AS count FROM sbom_metadata WHERE system_id = $1', [payload.system_id]);
            await client.query('COMMIT');
            res.status(201).json({
                success: true,
                sbomId,
                systemId: payload.system_id,
                repoUrl: generated.normalizedRepoUrl,
                createdNewSbom: existingSbom ? existingSbom.rows.length === 0 : true,
                systemSbomCount: systemSbomCount.rows[0]?.count ?? null,
            });
        }
        catch (error) {
            await client.query('ROLLBACK').catch(() => undefined);
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
