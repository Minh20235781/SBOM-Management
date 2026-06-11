import { PoolClient } from 'pg';
import { incrementalSbomService } from './incrementalSbomService';
import { artifactScannerService, ProjectArtifactFile } from './artifactScannerService';

const runSteps = [
  'Checkout source code',
  'Read dependency files',
  'Generate / Update SBOM',
  'Compare SBOM snapshot',
  'Store SBOM snapshot',
  'Update dependency graph',
];

const sampleArtifacts = (projectName: string, runNumber: number): ProjectArtifactFile[] => {
  const dependencies = runNumber <= 1
    ? {
        react: '^19.2.5',
        vite: '^8.0.10',
        lodash: '^4.17.20',
        moment: '^2.29.4',
      }
    : {
        react: '^19.2.5',
        vite: '^8.0.10',
        axios: '^1.16.0',
        lodash: '^4.17.21',
      };

  return [{
    artifactPath: 'package.json',
    artifactName: 'package.json',
    artifactType: 'package.json',
    content: JSON.stringify({
      name: projectName.toLowerCase().replace(/[^a-z0-9-]+/g, '-') || 'demo-project',
      version: '1.0.0',
      dependencies,
    }, null, 2),
  }];
};

const parseId = (value: unknown) => {
  const id = Number(value);
  return Number.isInteger(id) && id > 0 ? id : null;
};

const normalizeStatus = (value: unknown, fallback: string) => {
  const normalized = typeof value === 'string' ? value.trim().toUpperCase() : '';
  return normalized || fallback;
};

export const cicdService = {
  listTasks: async (client: PoolClient, projectId: number) => {
    const { rows } = await client.query(
      'SELECT * FROM dev_tasks WHERE project_id = $1 ORDER BY created_at DESC, task_id DESC',
      [projectId]
    );
    return rows;
  },

  createTask: async (client: PoolClient, projectId: number, body: any) => {
    const { rows } = await client.query(
      `INSERT INTO dev_tasks
        (project_id, title, description, status, priority, assigned_to, related_pipeline_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING *`,
      [
        projectId,
        String(body?.title || '').trim() || 'Update axios dependency',
        body?.description || null,
        normalizeStatus(body?.status, 'TODO'),
        normalizeStatus(body?.priority, 'MEDIUM'),
        body?.assignedTo || body?.assigned_to || 'Developer',
        parseId(body?.relatedPipelineId || body?.related_pipeline_id),
      ]
    );
    return rows[0];
  },

  updateTask: async (client: PoolClient, taskId: number, body: any) => {
    const { rows } = await client.query(
      `UPDATE dev_tasks SET
        title = COALESCE($2, title),
        description = COALESCE($3, description),
        status = COALESCE($4, status),
        priority = COALESCE($5, priority),
        assigned_to = COALESCE($6, assigned_to),
        related_pipeline_id = COALESCE($7, related_pipeline_id),
        updated_at = CURRENT_TIMESTAMP
       WHERE task_id = $1
       RETURNING *`,
      [
        taskId,
        body?.title || null,
        body?.description || null,
        body?.status ? normalizeStatus(body.status, 'TODO') : null,
        body?.priority ? normalizeStatus(body.priority, 'MEDIUM') : null,
        body?.assignedTo || body?.assigned_to || null,
        parseId(body?.relatedPipelineId || body?.related_pipeline_id),
      ]
    );
    return rows[0] || null;
  },

  deleteTask: async (client: PoolClient, taskId: number) => {
    const { rows } = await client.query('DELETE FROM dev_tasks WHERE task_id = $1 RETURNING *', [taskId]);
    return rows[0] || null;
  },

  listPipelines: async (client: PoolClient, projectId: number) => {
    const { rows } = await client.query(
      `SELECT p.*,
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
       ORDER BY p.created_at DESC, p.pipeline_id DESC`,
      [projectId]
    );
    return rows;
  },

  createPipeline: async (client: PoolClient, projectId: number, body: any) => {
    const { rows } = await client.query(
      `INSERT INTO cicd_pipelines
        (project_id, name, provider, branch, trigger_type, repo_url)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING *`,
      [
        projectId,
        String(body?.name || '').trim() || 'sbom-incremental-scan',
        normalizeStatus(body?.provider, 'INTERNAL'),
        String(body?.branch || 'main').trim(),
        normalizeStatus(body?.triggerType || body?.trigger_type, 'MANUAL'),
        String(body?.repoUrl || body?.repo_url || '').trim() || null,
      ]
    );
    return rows[0];
  },

  listRuns: async (client: PoolClient, pipelineId: number) => {
    const { rows } = await client.query(
      `SELECT r.*, s.version_number AS generated_snapshot_version
       FROM cicd_pipeline_runs r
       LEFT JOIN sbom_snapshots s ON s.snapshot_id = r.generated_sbom_snapshot_id
       WHERE r.pipeline_id = $1
       ORDER BY r.run_number DESC`,
      [pipelineId]
    );
    return rows;
  },

  getRunDetail: async (client: PoolClient, runId: number) => {
    const runResult = await client.query(
      `SELECT r.*, p.name AS pipeline_name, p.repo_url, s.version_number AS generated_snapshot_version, s.summary AS snapshot_summary
       FROM cicd_pipeline_runs r
       JOIN cicd_pipelines p ON p.pipeline_id = r.pipeline_id
       LEFT JOIN sbom_snapshots s ON s.snapshot_id = r.generated_sbom_snapshot_id
       WHERE r.run_id = $1`,
      [runId]
    );
    const run = runResult.rows[0];
    if (!run) return null;

    const steps = await cicdService.getRunSteps(client, runId);
    return { ...run, steps };
  },

  getRunSteps: async (client: PoolClient, runId: number) => {
    const { rows } = await client.query(
      'SELECT * FROM cicd_pipeline_steps WHERE pipeline_run_id = $1 ORDER BY step_order ASC',
      [runId]
    );
    return rows;
  },

  runPipeline: async (client: PoolClient, pipelineId: number, body: any = {}) => {
    const pipelineResult = await client.query(
      `SELECT p.*, s.name AS project_name
       FROM cicd_pipelines p
       JOIN system s ON s.system_id = p.project_id
       WHERE p.pipeline_id = $1`,
      [pipelineId]
    );
    const pipeline = pipelineResult.rows[0];
    if (!pipeline) return null;

    const runNumberResult = await client.query(
      'SELECT COALESCE(MAX(run_number), 0) + 1 AS run_number FROM cicd_pipeline_runs WHERE pipeline_id = $1',
      [pipelineId]
    );
    const runNumber = Number(runNumberResult.rows[0].run_number);

    const runResult = await client.query(
      `INSERT INTO cicd_pipeline_runs
        (pipeline_id, project_id, run_number, status, commit_hash, branch, started_at, triggered_by)
       VALUES ($1,$2,$3,'RUNNING',$4,$5,CURRENT_TIMESTAMP,$6)
       RETURNING *`,
      [
        pipelineId,
        pipeline.project_id,
        runNumber,
        body?.commitHash || body?.commit_hash || `demo-${String(runNumber).padStart(4, '0')}`,
        body?.branch || pipeline.branch,
        body?.triggeredBy || body?.triggered_by || 'Developer',
      ]
    );
    const run = runResult.rows[0];

    for (const [index, name] of runSteps.entries()) {
      await client.query(
        `INSERT INTO cicd_pipeline_steps (pipeline_run_id, name, step_order, status, logs)
         VALUES ($1,$2,$3,'PENDING','Waiting for previous step')`,
        [run.run_id, name, index + 1]
      );
    }

    let generatedSnapshotId: string | null = null;
    try {
      for (const [index, name] of runSteps.entries()) {
        await client.query(
          `UPDATE cicd_pipeline_steps
           SET status = 'RUNNING', started_at = CURRENT_TIMESTAMP, logs = $3
           WHERE pipeline_run_id = $1 AND step_order = $2`,
          [run.run_id, index + 1, `${name} started.`]
        );

        let logs = `${name} completed successfully.`;
        if (name === 'Read dependency files') {
          const artifacts = await artifactScannerService.loadProjectArtifacts(client, pipeline.project_id);
          if (artifacts.length === 0) {
            const seeded = sampleArtifacts(pipeline.project_name, runNumber);
            await artifactScannerService.saveProjectArtifacts(client, pipeline.project_id, seeded);
            logs = `No stored dependency files found. Seeded demo package.json from ${pipeline.repo_url || 'repo URL'}.`;
          } else if (runNumber === 2) {
            await artifactScannerService.saveProjectArtifacts(client, pipeline.project_id, sampleArtifacts(pipeline.project_name, runNumber));
            logs = 'Detected dependency manifest change: added axios, updated lodash, removed moment.';
          } else {
            logs = `Read ${artifacts.length} dependency file(s) for ${pipeline.project_name}.`;
          }
        }

        if (name === 'Generate / Update SBOM') {
          const result = await incrementalSbomService.generate(client, pipeline.project_id, {});
          generatedSnapshotId = result.snapshotId;
          logs = result.skipped
            ? `No dependency change. Reusing snapshot ${result.snapshotId}.`
            : `SBOM snapshot generated. Added: ${result.summary.added}, Updated: ${result.summary.updated}, Removed: ${result.summary.removed}, Unchanged: ${result.summary.unchanged}.`;
          await client.query(
            'UPDATE cicd_pipeline_runs SET generated_sbom_snapshot_id = $1 WHERE run_id = $2',
            [generatedSnapshotId, run.run_id]
          );
        }

        if (name === 'Compare SBOM snapshot' && generatedSnapshotId) {
          const changes = await incrementalSbomService.getChanges(client, generatedSnapshotId);
          logs = `Change log contains ${changes.length} item(s).`;
        }

        if (name === 'Store SBOM snapshot' && generatedSnapshotId) {
          logs = `Stored generated snapshot ${generatedSnapshotId}.`;
        }

        await client.query(
          `UPDATE cicd_pipeline_steps
           SET status = 'SUCCESS', finished_at = CURRENT_TIMESTAMP, logs = $3
           WHERE pipeline_run_id = $1 AND step_order = $2`,
          [run.run_id, index + 1, logs]
        );
      }

      await client.query(
        `UPDATE cicd_pipeline_runs
         SET status = 'SUCCESS',
          finished_at = CURRENT_TIMESTAMP,
          duration_ms = EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - started_at))::int * 1000
         WHERE run_id = $1`,
        [run.run_id]
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Pipeline failed';
      await client.query(
        `UPDATE cicd_pipeline_steps
         SET status = 'FAILED', finished_at = CURRENT_TIMESTAMP, logs = $2
         WHERE pipeline_run_id = $1 AND status = 'RUNNING'`,
        [run.run_id, message]
      );
      await client.query(
        `UPDATE cicd_pipeline_runs
         SET status = 'FAILED',
          finished_at = CURRENT_TIMESTAMP,
          duration_ms = EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - started_at))::int * 1000
         WHERE run_id = $1`,
        [run.run_id]
      );
    }

    return cicdService.getRunDetail(client, run.run_id);
  },
};
