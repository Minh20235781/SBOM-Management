import crypto from 'crypto';
import { PoolClient } from 'pg';
import { incrementalSbomService } from './incrementalSbomService';
import { parseAndSaveSBOM } from './sbomParserService';

type GitHubRepository = { owner: string; repo: string };

const githubApiBase = process.env.GITHUB_API_URL || 'https://api.github.com';

const normalizeRepositoryUrl = (value: unknown) => String(value || '')
  .trim()
  .replace(/\.git\/?$/i, '')
  .replace(/\/$/, '')
  .toLowerCase();

const parseGitHubRepository = (repoUrl: unknown): GitHubRepository => {
  const value = String(repoUrl || '').trim();
  const match = value.match(/^(?:https?:\/\/github\.com\/|git@github\.com:)([^/\s]+)\/([^/\s]+?)(?:\.git)?\/?$/i);
  if (!match) throw new Error('INVALID_GITHUB_REPOSITORY: GitHub repository URL is invalid.');
  return { owner: match[1], repo: match[2] };
};

const mapRunStatus = (status: unknown, conclusion: unknown) => {
  const normalizedStatus = String(status || '').toLowerCase();
  const normalizedConclusion = String(conclusion || '').toLowerCase();
  if (normalizedStatus !== 'completed') return normalizedStatus === 'queued' ? 'PENDING' : 'RUNNING';
  if (normalizedConclusion === 'success') return 'SUCCESS';
  if (normalizedConclusion === 'cancelled' || normalizedConclusion === 'skipped') return 'CANCELLED';
  return 'FAILED';
};

const mapStepStatus = (status: unknown, conclusion: unknown) => {
  const runStatus = mapRunStatus(status, conclusion);
  return runStatus === 'CANCELLED' ? 'SKIPPED' : runStatus;
};

const nextRunNumber = async (client: PoolClient, pipelineId: number) => {
  const result = await client.query(
    'SELECT COALESCE(MAX(run_number), 0) + 1 AS run_number FROM cicd_pipeline_runs WHERE pipeline_id = $1',
    [pipelineId]
  );
  return Number(result.rows[0].run_number);
};

const findPipeline = async (client: PoolClient, payload: any) => {
  const explicitId = Number(payload?.pipelineId || payload?.pipeline_id);
  if (Number.isInteger(explicitId) && explicitId > 0) {
    const explicit = await client.query('SELECT * FROM cicd_pipelines WHERE pipeline_id = $1', [explicitId]);
    if (explicit.rows[0]) return explicit.rows[0];
  }

  const repositoryUrl = normalizeRepositoryUrl(
    payload?.repositoryUrl
      || payload?.repository_url
      || payload?.repository?.html_url
      || (payload?.repository?.full_name ? `https://github.com/${payload.repository.full_name}` : payload?.repository)
  );
  if (!repositoryUrl) return null;
  const result = await client.query(
    `SELECT * FROM cicd_pipelines
     WHERE provider = 'GITHUB_ACTIONS'
       AND lower(regexp_replace(repo_url, '\\.git/?$', '')) = $1
     ORDER BY updated_at DESC, pipeline_id DESC
     LIMIT 1`,
    [repositoryUrl]
  );
  return result.rows[0] || null;
};

const upsertExternalRun = async (client: PoolClient, pipeline: any, run: any) => {
  const externalRunId = String(run?.id || run?.runId || run?.run_id || '');
  if (!externalRunId) throw new Error('INVALID_GITHUB_RUN: GitHub run id is required.');

  const existing = await client.query(
    'SELECT * FROM cicd_pipeline_runs WHERE external_run_id = $1 LIMIT 1',
    [externalRunId]
  );
  const status = mapRunStatus(run?.status || 'completed', run?.conclusion || run?.result || 'success');
  const startedAt = run?.run_started_at || run?.startedAt || run?.created_at || new Date().toISOString();
  const finishedAt = status === 'RUNNING' || status === 'PENDING'
    ? null
    : (run?.updated_at || run?.finishedAt || new Date().toISOString());

  if (existing.rows[0]) {
    const updated = await client.query(
      `UPDATE cicd_pipeline_runs SET
        status = $2,
        commit_hash = COALESCE($3, commit_hash),
        branch = COALESCE($4, branch),
        started_at = COALESCE(started_at, $5),
        finished_at = COALESCE($6, finished_at),
        triggered_by = COALESCE($7, triggered_by),
        external_run_attempt = COALESCE($8, external_run_attempt),
        external_run_url = COALESCE($9, external_run_url),
        event_name = COALESCE($10, event_name),
        conclusion = COALESCE($11, conclusion),
        duration_ms = CASE WHEN $6::timestamptz IS NOT NULL
          THEN GREATEST(0, (EXTRACT(EPOCH FROM ($6::timestamptz - COALESCE(started_at, $5::timestamptz))) * 1000)::int)
          ELSE duration_ms END
       WHERE run_id = $1 RETURNING *`,
      [
        existing.rows[0].run_id,
        status,
        run?.head_sha || run?.commitSha || run?.commit_hash || null,
        run?.head_branch || run?.branch || pipeline.branch,
        startedAt,
        finishedAt,
        run?.actor?.login || run?.triggeredBy || null,
        Number(run?.run_attempt || run?.runAttempt) || null,
        run?.html_url || run?.runUrl || null,
        run?.event || run?.eventName || null,
        run?.conclusion || run?.result || null,
      ]
    );
    return updated.rows[0];
  }

  // workflow_dispatch returns no run id. Reuse the most recent queued local dispatch when possible.
  const queued = await client.query(
    `SELECT * FROM cicd_pipeline_runs
     WHERE pipeline_id = $1 AND external_run_id IS NULL AND status = 'PENDING'
     ORDER BY created_at DESC LIMIT 1`,
    [pipeline.pipeline_id]
  );
  if (queued.rows[0]) {
    const linked = await client.query(
      `UPDATE cicd_pipeline_runs SET
        external_run_id = $2, status = $3, commit_hash = $4, branch = $5,
        started_at = $6, finished_at = $7, triggered_by = COALESCE($8, triggered_by),
        external_run_attempt = $9, external_run_url = $10, event_name = $11, conclusion = $12
       WHERE run_id = $1 RETURNING *`,
      [queued.rows[0].run_id, externalRunId, status, run?.head_sha || null,
        run?.head_branch || pipeline.branch, startedAt, finishedAt,
        run?.actor?.login || null, Number(run?.run_attempt) || null,
        run?.html_url || null, run?.event || null, run?.conclusion || null]
    );
    return linked.rows[0];
  }

  const runNumber = await nextRunNumber(client, pipeline.pipeline_id);
  const inserted = await client.query(
    `INSERT INTO cicd_pipeline_runs
      (pipeline_id, project_id, run_number, status, commit_hash, branch, started_at, finished_at,
       triggered_by, external_run_id, external_run_attempt, external_run_url, event_name, conclusion)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
     RETURNING *`,
    [pipeline.pipeline_id, pipeline.project_id, runNumber, status,
      run?.head_sha || run?.commitSha || null, run?.head_branch || run?.branch || pipeline.branch,
      startedAt, finishedAt, run?.actor?.login || run?.triggeredBy || 'GitHub Actions', externalRunId,
      Number(run?.run_attempt || run?.runAttempt) || null, run?.html_url || run?.runUrl || null,
      run?.event || run?.eventName || null, run?.conclusion || run?.result || null]
  );
  return inserted.rows[0];
};

const githubRequest = async (path: string, init: RequestInit = {}) => {
  const token = process.env.GITHUB_TOKEN || process.env.GITHUB_ACTIONS_TOKEN;
  if (!token) throw new Error('GITHUB_TOKEN_NOT_CONFIGURED: Configure GITHUB_TOKEN on the backend.');
  const response = await fetch(`${githubApiBase}${path}`, {
    ...init,
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'SBOM-Management',
      ...(init.headers || {}),
    },
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`GITHUB_API_ERROR: GitHub API ${response.status}: ${detail.slice(0, 500)}`);
  }
  return response;
};

export const githubActionsService = {
  verifyWebhookSignature: (rawBody: Buffer | undefined, signature: string | undefined) => {
    const secret = process.env.GITHUB_WEBHOOK_SECRET;
    if (!secret) throw new Error('GITHUB_WEBHOOK_SECRET_NOT_CONFIGURED: Configure GITHUB_WEBHOOK_SECRET.');
    if (!rawBody || !signature) return false;
    const expected = `sha256=${crypto.createHmac('sha256', secret).update(rawBody).digest('hex')}`;
    const left = Buffer.from(expected);
    const right = Buffer.from(signature);
    return left.length === right.length && crypto.timingSafeEqual(left, right);
  },

  verifyPipelineToken: (authorization: string | undefined) => {
    const expected = process.env.SBOM_PIPELINE_TOKEN;
    if (!expected) throw new Error('SBOM_PIPELINE_TOKEN_NOT_CONFIGURED: Configure SBOM_PIPELINE_TOKEN.');
    const actual = authorization?.replace(/^Bearer\s+/i, '') || '';
    const left = Buffer.from(expected);
    const right = Buffer.from(actual);
    return left.length === right.length && crypto.timingSafeEqual(left, right);
  },

  dispatch: async (client: PoolClient, pipelineId: number, body: any = {}) => {
    const result = await client.query('SELECT * FROM cicd_pipelines WHERE pipeline_id = $1', [pipelineId]);
    const pipeline = result.rows[0];
    if (!pipeline) return null;
    if (pipeline.provider !== 'GITHUB_ACTIONS') throw new Error('INVALID_PIPELINE_PROVIDER: Pipeline is not configured for GitHub Actions.');
    const { owner, repo } = parseGitHubRepository(pipeline.repo_url);
    const runNumber = await nextRunNumber(client, pipelineId);
    const requestId = crypto.randomUUID();
    const localRun = await client.query(
      `INSERT INTO cicd_pipeline_runs
        (pipeline_id, project_id, run_number, status, branch, triggered_by, dispatch_request_id)
       VALUES ($1,$2,$3,'PENDING',$4,$5,$6) RETURNING *`,
      [pipelineId, pipeline.project_id, runNumber, body?.branch || pipeline.branch,
        body?.triggeredBy || 'Developer', requestId]
    );
    try {
      const workflow = encodeURIComponent(pipeline.workflow_file || 'sbom.yml');
      await githubRequest(`/repos/${owner}/${repo}/actions/workflows/${workflow}/dispatches`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ref: body?.branch || pipeline.branch }),
      });
    } catch (error) {
      await client.query(
        `UPDATE cicd_pipeline_runs SET status = 'FAILED', conclusion = 'dispatch_failed',
         finished_at = CURRENT_TIMESTAMP WHERE run_id = $1`,
        [localRun.rows[0].run_id]
      );
      throw error;
    }
    return { ...localRun.rows[0], dispatch_request_id: requestId, provider: 'GITHUB_ACTIONS' };
  },

  handleWebhook: async (client: PoolClient, event: string, deliveryId: string | undefined, payload: any) => {
    if (deliveryId) {
      const inserted = await client.query(
        `INSERT INTO github_webhook_deliveries (delivery_id, event_name, payload)
         VALUES ($1,$2,$3) ON CONFLICT (delivery_id) DO NOTHING RETURNING delivery_id`,
        [deliveryId, event, payload]
      );
      if (!inserted.rows[0]) return { duplicate: true };
    }

    if (event === 'ping') return { pong: true };
    if (event === 'workflow_run') {
      const pipeline = await findPipeline(client, payload?.workflow_run ? { ...payload, repository: payload.repository } : payload);
      if (!pipeline) return { ignored: true, reason: 'pipeline_not_registered' };
      const run = await upsertExternalRun(client, pipeline, payload.workflow_run);
      return { run };
    }
    if (event === 'workflow_job') {
      const pipeline = await findPipeline(client, payload);
      if (!pipeline) return { ignored: true, reason: 'pipeline_not_registered' };
      const job = payload.workflow_job || {};
      const externalRun = await upsertExternalRun(client, pipeline, {
        id: job.run_id,
        run_attempt: job.run_attempt,
        status: job.status,
        conclusion: job.conclusion,
        head_sha: job.head_sha,
        head_branch: job.head_branch,
        html_url: job.html_url,
      });
      const steps = Array.isArray(job.steps) ? job.steps : [];
      if (steps.length === 0) {
        await client.query(
          `INSERT INTO cicd_pipeline_steps
            (pipeline_run_id, name, step_order, status, started_at, finished_at, logs, external_job_id)
           VALUES ($1,$2,1,$3,$4,$5,$6,$7)
           ON CONFLICT (pipeline_run_id, external_job_id, step_order) DO UPDATE SET
             status = EXCLUDED.status, started_at = EXCLUDED.started_at,
             finished_at = EXCLUDED.finished_at, logs = EXCLUDED.logs`,
          [externalRun.run_id, job.name || 'GitHub Actions job', mapStepStatus(job.status, job.conclusion),
            job.started_at || null, job.completed_at || null, job.html_url || null, String(job.id)]
        );
      } else {
        for (const step of steps) {
          await client.query(
            `INSERT INTO cicd_pipeline_steps
              (pipeline_run_id, name, step_order, status, started_at, finished_at, logs, external_job_id)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
             ON CONFLICT (pipeline_run_id, external_job_id, step_order) DO UPDATE SET
               name = EXCLUDED.name, status = EXCLUDED.status,
               started_at = EXCLUDED.started_at, finished_at = EXCLUDED.finished_at,
               logs = EXCLUDED.logs`,
            [externalRun.run_id, step.name, Number(step.number) || 1,
              mapStepStatus(step.status, step.conclusion), step.started_at || null, step.completed_at || null,
              job.html_url || null, String(job.id)]
          );
        }
      }
      return { run: externalRun, jobId: String(job.id) };
    }
    return { ignored: true, reason: 'unsupported_event' };
  },

  receiveResult: async (client: PoolClient, body: any) => {
    const pipeline = await findPipeline(client, body);
    if (!pipeline) throw new Error('PIPELINE_NOT_FOUND: No GitHub Actions pipeline matches this repository.');
    if (!body?.sbom || typeof body.sbom !== 'object') throw new Error('INVALID_SBOM: A CycloneDX or SPDX payload is required.');
    const run = await upsertExternalRun(client, pipeline, {
      id: body.runId || body.run_id,
      runAttempt: body.runAttempt || body.run_attempt,
      status: 'completed',
      result: body.conclusion || 'success',
      commitSha: body.commitSha || body.commit_hash,
      branch: body.branch,
      runUrl: body.runUrl || body.run_url,
      eventName: body.eventName || body.event_name,
      triggeredBy: body.triggeredBy || body.actor || 'GitHub Actions',
      startedAt: body.startedAt,
      finishedAt: body.finishedAt,
    });

    const sbomId = await parseAndSaveSBOM(client, { sbom: body.sbom, system_id: pipeline.project_id });
    const snapshot = await incrementalSbomService.generate(client, pipeline.project_id, {
      sbom: body.sbom,
      artifactName: `github-actions-${body.runId || body.run_id}-sbom.json`,
      artifactPath: '.github/artifacts/sbom.cdx.json',
    });
    await client.query(
      `UPDATE cicd_pipeline_runs SET
        status = $2, conclusion = $3, commit_hash = COALESCE($4, commit_hash),
        branch = COALESCE($5, branch), external_run_url = COALESCE($6, external_run_url),
        generated_sbom_snapshot_id = $7, sbom_id = $8,
        finished_at = COALESCE(finished_at, CURRENT_TIMESTAMP)
       WHERE run_id = $1`,
      [run.run_id, body.conclusion === 'failure' ? 'FAILED' : 'SUCCESS', body.conclusion || 'success',
        body.commitSha || body.commit_hash || null, body.branch || null, body.runUrl || body.run_url || null,
        snapshot.snapshotId, sbomId]
    );
    return { success: true, runId: run.run_id, externalRunId: String(body.runId || body.run_id), sbomId, snapshotId: snapshot.snapshotId, summary: snapshot.summary };
  },

  monitoring: async (client: PoolClient, projectId?: number | null) => {
    const params: any[] = [];
    const where = projectId ? 'WHERE r.project_id = $1' : '';
    if (projectId) params.push(projectId);
    const [summary, recent, trend] = await Promise.all([
      client.query(
        `SELECT
          COUNT(*)::int AS total_runs,
          COUNT(*) FILTER (WHERE r.status = 'RUNNING')::int AS running_runs,
          COUNT(*) FILTER (WHERE r.status = 'PENDING')::int AS pending_runs,
          COUNT(*) FILTER (WHERE r.status = 'SUCCESS')::int AS successful_runs,
          COUNT(*) FILTER (WHERE r.status = 'FAILED')::int AS failed_runs,
          COALESCE(ROUND(AVG(r.duration_ms))::int, 0) AS average_duration_ms,
          COALESCE(ROUND(100.0 * COUNT(*) FILTER (WHERE r.status = 'SUCCESS') /
            NULLIF(COUNT(*) FILTER (WHERE r.status IN ('SUCCESS','FAILED','CANCELLED')), 0), 2), 0) AS success_rate,
          MAX(r.finished_at) AS last_completed_at,
          COUNT(DISTINCT r.project_id)::int AS monitored_projects
         FROM cicd_pipeline_runs r ${where}`,
        params
      ),
      client.query(
        `SELECT r.*, p.name AS pipeline_name, p.provider, p.repo_url, p.workflow_file,
                s.version_number AS generated_snapshot_version
         FROM cicd_pipeline_runs r
         JOIN cicd_pipelines p ON p.pipeline_id = r.pipeline_id
         LEFT JOIN sbom_snapshots s ON s.snapshot_id = r.generated_sbom_snapshot_id
         ${where}
         ORDER BY r.created_at DESC LIMIT 30`,
        params
      ),
      client.query(
        `SELECT TO_CHAR(DATE_TRUNC('day', r.created_at), 'YYYY-MM-DD') AS day,
          COUNT(*)::int AS total,
          COUNT(*) FILTER (WHERE r.status = 'SUCCESS')::int AS success,
          COUNT(*) FILTER (WHERE r.status = 'FAILED')::int AS failed
         FROM cicd_pipeline_runs r ${where}
         GROUP BY DATE_TRUNC('day', r.created_at)
         ORDER BY DATE_TRUNC('day', r.created_at) DESC LIMIT 14`,
        params
      ),
    ]);
    return { summary: summary.rows[0], recentRuns: recent.rows, trend: trend.rows.reverse() };
  },
};

