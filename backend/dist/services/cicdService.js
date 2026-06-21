"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.cicdService = void 0;
const incrementalSbomService_1 = require("./incrementalSbomService");
const sbomValidationService_1 = require("./sbomValidationService");
const syftGeneratorService_1 = require("./syftGeneratorService");
const sbomParserService_1 = require("./sbomParserService");
const runSteps = [
    'Clone / fetch repository',
    'Detect dependency manifests',
    'Detect existing SBOM',
    'Generate SBOM with Syft',
    'Store SBOM data',
    'Scan vulnerabilities with Grype',
    'Validate SBOM against source',
    'Update dependency graph',
    'Generate pipeline report',
];
const parseId = (value) => {
    const id = Number(value);
    return Number.isInteger(id) && id > 0 ? id : null;
};
const normalizeStatus = (value, fallback) => {
    const normalized = typeof value === 'string' ? value.trim().toUpperCase() : '';
    return normalized || fallback;
};
exports.cicdService = {
    listTasks: async (client, projectId) => {
        const { rows } = await client.query(`SELECT t.*,
        p.name AS related_pipeline_name,
        latest.run_id AS latest_run_id,
        latest.status AS latest_run_status,
        latest.generated_sbom_snapshot_id AS latest_snapshot_id,
        s.version_number AS latest_snapshot_version
       FROM dev_tasks t
       LEFT JOIN cicd_pipelines p ON p.pipeline_id = t.related_pipeline_id
       LEFT JOIN LATERAL (
         SELECT run_id, status, generated_sbom_snapshot_id
         FROM cicd_pipeline_runs r
         WHERE r.pipeline_id = t.related_pipeline_id
         ORDER BY r.run_number DESC
         LIMIT 1
       ) latest ON true
       LEFT JOIN sbom_snapshots s ON s.snapshot_id = latest.generated_sbom_snapshot_id
       WHERE t.project_id = $1
       ORDER BY t.created_at DESC, t.task_id DESC`, [projectId]);
        return rows;
    },
    createTask: async (client, projectId, body) => {
        const { rows } = await client.query(`INSERT INTO dev_tasks
        (project_id, title, description, status, priority, assigned_to, related_pipeline_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING *`, [
            projectId,
            String(body?.title || '').trim() || 'Update axios dependency',
            body?.description || null,
            normalizeStatus(body?.status, 'TODO'),
            normalizeStatus(body?.priority, 'MEDIUM'),
            body?.assignedTo || body?.assigned_to || 'Developer',
            parseId(body?.relatedPipelineId || body?.related_pipeline_id),
        ]);
        return rows[0];
    },
    updateTask: async (client, taskId, body) => {
        const { rows } = await client.query(`UPDATE dev_tasks SET
        title = COALESCE($2, title),
        description = COALESCE($3, description),
        status = COALESCE($4, status),
        priority = COALESCE($5, priority),
        assigned_to = COALESCE($6, assigned_to),
        related_pipeline_id = COALESCE($7, related_pipeline_id),
        updated_at = CURRENT_TIMESTAMP
       WHERE task_id = $1
       RETURNING *`, [
            taskId,
            body?.title || null,
            body?.description || null,
            body?.status ? normalizeStatus(body.status, 'TODO') : null,
            body?.priority ? normalizeStatus(body.priority, 'MEDIUM') : null,
            body?.assignedTo || body?.assigned_to || null,
            parseId(body?.relatedPipelineId || body?.related_pipeline_id),
        ]);
        return rows[0] || null;
    },
    deleteTask: async (client, taskId) => {
        const { rows } = await client.query('DELETE FROM dev_tasks WHERE task_id = $1 RETURNING *', [taskId]);
        return rows[0] || null;
    },
    listPipelines: async (client, projectId) => {
        const { rows } = await client.query(`SELECT p.*,
        latest.run_id AS latest_run_id,
        latest.status AS latest_status,
        latest.generated_sbom_snapshot_id AS latest_snapshot_id,
        latest.run_number AS latest_run_number
       FROM cicd_pipelines p
       LEFT JOIN LATERAL (
         SELECT run_id, status, generated_sbom_snapshot_id, run_number
         FROM cicd_pipeline_runs r
         WHERE r.pipeline_id = p.pipeline_id
         ORDER BY r.run_number DESC
         LIMIT 1
       ) latest ON true
       WHERE p.project_id = $1
       ORDER BY p.created_at DESC, p.pipeline_id DESC`, [projectId]);
        return rows;
    },
    createPipeline: async (client, projectId, body) => {
        const { rows } = await client.query(`INSERT INTO cicd_pipelines
        (project_id, name, provider, branch, trigger_type, repo_url)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING *`, [
            projectId,
            String(body?.name || '').trim() || 'sbom-incremental-scan',
            normalizeStatus(body?.provider, 'INTERNAL'),
            String(body?.branch || 'main').trim(),
            normalizeStatus(body?.triggerType || body?.trigger_type, 'MANUAL'),
            String(body?.repoUrl || body?.repo_url || '').trim() || null,
        ]);
        return rows[0];
    },
    listRuns: async (client, pipelineId) => {
        const { rows } = await client.query(`SELECT r.*, s.version_number AS generated_snapshot_version, s.summary AS snapshot_summary,
        (SELECT COUNT(*)::int FROM sbom_components c WHERE c.snapshot_id = r.generated_sbom_snapshot_id) AS component_count,
        (SELECT COUNT(*)::int FROM sbom_dependencies d WHERE d.snapshot_id = r.generated_sbom_snapshot_id) AS dependency_count,
        (SELECT COUNT(*)::int FROM vulnerability v JOIN sbom_metadata m ON m.sbom_id = v.sbom_id WHERE m.system_id = r.project_id) AS vulnerability_count
       FROM cicd_pipeline_runs r
       LEFT JOIN sbom_snapshots s ON s.snapshot_id = r.generated_sbom_snapshot_id
       WHERE r.pipeline_id = $1
       ORDER BY r.run_number DESC`, [pipelineId]);
        return rows;
    },
    getRunDetail: async (client, runId) => {
        const runResult = await client.query(`SELECT r.*, p.name AS pipeline_name, p.repo_url, p.provider, p.trigger_type,
        s.version_number AS generated_snapshot_version, s.summary AS snapshot_summary,
        (SELECT COUNT(*)::int FROM sbom_components c WHERE c.snapshot_id = r.generated_sbom_snapshot_id) AS component_count,
        (SELECT COUNT(*)::int FROM sbom_dependencies d WHERE d.snapshot_id = r.generated_sbom_snapshot_id) AS dependency_count,
        (SELECT COUNT(*)::int FROM vulnerability v JOIN sbom_metadata m ON m.sbom_id = v.sbom_id WHERE m.system_id = r.project_id) AS vulnerability_count
       FROM cicd_pipeline_runs r
       JOIN cicd_pipelines p ON p.pipeline_id = r.pipeline_id
       LEFT JOIN sbom_snapshots s ON s.snapshot_id = r.generated_sbom_snapshot_id
       WHERE r.run_id = $1`, [runId]);
        const run = runResult.rows[0];
        if (!run)
            return null;
        const steps = await exports.cicdService.getRunSteps(client, runId);
        return { ...run, steps };
    },
    getRunSteps: async (client, runId) => {
        const { rows } = await client.query('SELECT * FROM cicd_pipeline_steps WHERE pipeline_run_id = $1 ORDER BY step_order ASC', [runId]);
        return rows;
    },
    runPipeline: async (client, pipelineId, body = {}) => {
        const pipelineResult = await client.query(`SELECT p.*, s.name AS project_name
       FROM cicd_pipelines p
       JOIN system s ON s.system_id = p.project_id
       WHERE p.pipeline_id = $1`, [pipelineId]);
        const pipeline = pipelineResult.rows[0];
        if (!pipeline)
            return null;
        const runNumberResult = await client.query('SELECT COALESCE(MAX(run_number), 0) + 1 AS run_number FROM cicd_pipeline_runs WHERE pipeline_id = $1', [pipelineId]);
        const runNumber = Number(runNumberResult.rows[0].run_number);
        const runResult = await client.query(`INSERT INTO cicd_pipeline_runs
        (pipeline_id, project_id, run_number, status, commit_hash, branch, started_at, triggered_by)
       VALUES ($1,$2,$3,'RUNNING',$4,$5,CURRENT_TIMESTAMP,$6)
       RETURNING *`, [
            pipelineId,
            pipeline.project_id,
            runNumber,
            body?.commitHash || body?.commit_hash || null,
            body?.branch || pipeline.branch,
            body?.triggeredBy || body?.triggered_by || 'Developer',
        ]);
        const run = runResult.rows[0];
        for (const [index, name] of runSteps.entries()) {
            await client.query(`INSERT INTO cicd_pipeline_steps (pipeline_run_id, name, step_order, status, logs)
         VALUES ($1,$2,$3,'PENDING','Waiting for previous step')`, [run.run_id, name, index + 1]);
        }
        let generatedSnapshotId = null;
        let generated = null;
        let storedSbomId = null;
        try {
            for (const [index, name] of runSteps.entries()) {
                await client.query(`UPDATE cicd_pipeline_steps
           SET status = 'RUNNING', started_at = CURRENT_TIMESTAMP, logs = $3
           WHERE pipeline_run_id = $1 AND step_order = $2`, [run.run_id, index + 1, `${name} started.`]);
                let logs = `${name} completed successfully.`;
                if (name === 'Clone / fetch repository') {
                    if (!pipeline.repo_url)
                        throw new Error('Pipeline repository URL is required.');
                    generated = await (0, syftGeneratorService_1.generateSbomFromGitHubRepo)(pipeline.repo_url);
                    logs = `Repository fetched successfully: ${generated.normalizedRepoUrl}`;
                }
                if (name === 'Detect dependency manifests') {
                    if (!generated)
                        throw new Error('Repository has not been fetched.');
                    logs = generated.detectedManifestFiles.length > 0
                        ? `Detected ${generated.detectedManifestFiles.length} manifest(s): ${generated.detectedManifestFiles.join(', ')}`
                        : 'No supported dependency manifest was detected.';
                }
                if (name === 'Detect existing SBOM') {
                    if (!generated)
                        throw new Error('Repository has not been fetched.');
                    logs = generated.detectedSbomFiles.length > 0
                        ? `Detected existing SBOM: ${generated.detectedSbomFiles.join(', ')}`
                        : 'No existing SBOM detected; a new SBOM will be generated from source.';
                }
                if (name === 'Generate SBOM with Syft') {
                    if (!generated)
                        throw new Error('Repository has not been fetched.');
                    const result = await incrementalSbomService_1.incrementalSbomService.generate(client, pipeline.project_id, { sbom: generated.sbom });
                    generatedSnapshotId = result.snapshotId;
                    logs = result.skipped
                        ? `No dependency change. Reusing snapshot ${result.snapshotId}.`
                        : `SBOM snapshot generated. Added: ${result.summary.added}, Updated: ${result.summary.updated}, Removed: ${result.summary.removed}, Unchanged: ${result.summary.unchanged}.`;
                    await client.query('UPDATE cicd_pipeline_runs SET generated_sbom_snapshot_id = $1 WHERE run_id = $2', [generatedSnapshotId, run.run_id]);
                }
                if (name === 'Store SBOM data') {
                    if (!generated)
                        throw new Error('SBOM has not been generated.');
                    storedSbomId = await (0, sbomParserService_1.parseAndSaveSBOM)(client, { sbom: generated.sbom, system_id: pipeline.project_id });
                    const componentCount = Array.isArray(generated.sbom?.components) ? generated.sbom.components.length : 0;
                    const dependencyCount = Array.isArray(generated.sbom?.dependencies)
                        ? generated.sbom.dependencies.reduce((sum, item) => sum + (Array.isArray(item.dependsOn) ? item.dependsOn.length : 0), 0)
                        : 0;
                    logs = `Stored SBOM ${storedSbomId}: ${componentCount} components, ${dependencyCount} dependencies.`;
                }
                if (name === 'Scan vulnerabilities with Grype') {
                    if (!storedSbomId)
                        throw new Error('Stored SBOM is required before vulnerability scanning.');
                    const result = await client.query('SELECT COUNT(*)::int AS count FROM vulnerability WHERE sbom_id = $1', [storedSbomId]);
                    logs = `Grype scan completed: ${result.rows[0]?.count || 0} vulnerability finding(s).`;
                }
                if (name === 'Validate SBOM against source' && generatedSnapshotId) {
                    const validation = await sbomValidationService_1.sbomValidationService.validateSnapshotAgainstSource(client, pipeline.project_id, generatedSnapshotId);
                    logs = `Compatibility ${validation.status}: ${validation.score}% (${validation.matchedCount}/${validation.sourceComponentCount} source components matched). Missing: ${validation.missingFromSbom.length}, Extra: ${validation.extraInSbom.length}, Version mismatch: ${validation.versionMismatches.length}.`;
                    await client.query('UPDATE cicd_pipeline_runs SET validation_report = $1 WHERE run_id = $2', [JSON.stringify(validation), run.run_id]);
                }
                if (name === 'Update dependency graph' && generatedSnapshotId) {
                    const changes = await incrementalSbomService_1.incrementalSbomService.getChanges(client, generatedSnapshotId);
                    logs = `Dependency graph updated from snapshot ${generatedSnapshotId}; ${changes.length} change item(s).`;
                }
                if (name === 'Generate pipeline report') {
                    const componentCount = generated && Array.isArray(generated.sbom?.components) ? generated.sbom.components.length : 0;
                    const vulnerabilityResult = storedSbomId
                        ? await client.query('SELECT COUNT(*)::int AS count FROM vulnerability WHERE sbom_id = $1', [storedSbomId])
                        : { rows: [{ count: 0 }] };
                    logs = `Pipeline completed. Components: ${componentCount}; vulnerabilities: ${vulnerabilityResult.rows[0]?.count || 0}; snapshot: ${generatedSnapshotId || 'none'}.`;
                }
                await client.query(`UPDATE cicd_pipeline_steps
           SET status = 'SUCCESS', finished_at = CURRENT_TIMESTAMP, logs = $3
           WHERE pipeline_run_id = $1 AND step_order = $2`, [run.run_id, index + 1, logs]);
            }
            await client.query(`UPDATE cicd_pipeline_runs
         SET status = 'SUCCESS',
          finished_at = CURRENT_TIMESTAMP,
          duration_ms = EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - started_at))::int * 1000
         WHERE run_id = $1`, [run.run_id]);
            await client.query(`UPDATE dev_tasks
         SET status = CASE WHEN status IN ('TODO', 'IN_PROGRESS') THEN 'DONE' ELSE status END,
             related_pipeline_id = COALESCE(related_pipeline_id, $1),
             updated_at = CURRENT_TIMESTAMP
         WHERE project_id = $2
           AND (related_pipeline_id = $1 OR related_pipeline_id IS NULL)
           AND status IN ('TODO', 'IN_PROGRESS')`, [pipelineId, pipeline.project_id]);
        }
        catch (error) {
            const message = error instanceof Error ? error.message : 'Pipeline failed';
            await client.query(`UPDATE cicd_pipeline_steps
         SET status = 'FAILED', finished_at = CURRENT_TIMESTAMP, logs = $2
         WHERE pipeline_run_id = $1 AND status = 'RUNNING'`, [run.run_id, message]);
            await client.query(`UPDATE cicd_pipeline_runs
         SET status = 'FAILED',
          finished_at = CURRENT_TIMESTAMP,
          duration_ms = EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - started_at))::int * 1000
         WHERE run_id = $1`, [run.run_id]);
            await client.query(`UPDATE dev_tasks
         SET status = 'BLOCKED',
             related_pipeline_id = COALESCE(related_pipeline_id, $1),
             updated_at = CURRENT_TIMESTAMP
         WHERE project_id = $2
           AND (related_pipeline_id = $1 OR related_pipeline_id IS NULL)
           AND status IN ('TODO', 'IN_PROGRESS')`, [pipelineId, pipeline.project_id]);
        }
        return exports.cicdService.getRunDetail(client, run.run_id);
    },
};
