import { Request, Response, NextFunction } from 'express';
import { PoolClient } from 'pg';
import { pool } from '../config/db';
import { cicdService } from '../services/cicdService';
import { githubActionsService } from '../services/githubActionsService';

const parseId = (value: string | string[] | undefined) => {
  const raw = Array.isArray(value) ? value[0] : value;
  const id = Number(raw);
  return Number.isInteger(id) && id > 0 ? id : null;
};

const withClient = async (
  next: NextFunction,
  handler: (client: PoolClient) => Promise<unknown>
) => {
  const client = await pool.connect();
  try {
    await handler(client);
  } catch (error) {
    next(error);
  } finally {
    client.release();
  }
};

const withTransaction = async (
  next: NextFunction,
  handler: (client: PoolClient) => Promise<unknown>
) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await handler(client);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    next(error);
  } finally {
    client.release();
  }
};

export const cicdController = {
  listTasks: async (req: Request, res: Response, next: NextFunction) => {
    const projectId = parseId(req.params.projectId);
    if (!projectId) return res.status(400).json({ error: 'Invalid projectId' });
    await withClient(next, async client => {
      res.json(await cicdService.listTasks(client, projectId));
    });
  },

  createTask: async (req: Request, res: Response, next: NextFunction) => {
    const projectId = parseId(req.params.projectId);
    if (!projectId) return res.status(400).json({ error: 'Invalid projectId' });
    await withTransaction(next, async client => {
      res.status(201).json(await cicdService.createTask(client, projectId, req.body || {}));
    });
  },

  updateTask: async (req: Request, res: Response, next: NextFunction) => {
    const taskId = parseId(req.params.taskId);
    if (!taskId) return res.status(400).json({ error: 'Invalid taskId' });
    await withTransaction(next, async client => {
      const task = await cicdService.updateTask(client, taskId, req.body || {});
      if (!task) return res.status(404).json({ error: 'Task not found' });
      res.json(task);
    });
  },

  deleteTask: async (req: Request, res: Response, next: NextFunction) => {
    const taskId = parseId(req.params.taskId);
    if (!taskId) return res.status(400).json({ error: 'Invalid taskId' });
    await withTransaction(next, async client => {
      const task = await cicdService.deleteTask(client, taskId);
      if (!task) return res.status(404).json({ error: 'Task not found' });
      res.json({ deleted: true, task });
    });
  },

  listPipelines: async (req: Request, res: Response, next: NextFunction) => {
    const projectId = parseId(req.params.projectId);
    if (!projectId) return res.status(400).json({ error: 'Invalid projectId' });
    await withClient(next, async client => {
      res.json(await cicdService.listPipelines(client, projectId));
    });
  },

  createPipeline: async (req: Request, res: Response, next: NextFunction) => {
    const projectId = parseId(req.params.projectId);
    if (!projectId) return res.status(400).json({ error: 'Invalid projectId' });
    await withTransaction(next, async client => {
      res.status(201).json(await cicdService.createPipeline(client, projectId, req.body || {}));
    });
  },

  listRuns: async (req: Request, res: Response, next: NextFunction) => {
    const pipelineId = parseId(req.params.pipelineId);
    if (!pipelineId) return res.status(400).json({ error: 'Invalid pipelineId' });
    await withClient(next, async client => {
      res.json(await cicdService.listRuns(client, pipelineId));
    });
  },

  runPipeline: async (req: Request, res: Response, next: NextFunction) => {
    const pipelineId = parseId(req.params.pipelineId);
    if (!pipelineId) return res.status(400).json({ error: 'Invalid pipelineId' });
    await withTransaction(next, async client => {
      const pipelineResult = await client.query('SELECT provider FROM cicd_pipelines WHERE pipeline_id = $1', [pipelineId]);
      const run = pipelineResult.rows[0]?.provider === 'GITHUB_ACTIONS'
        ? await githubActionsService.dispatch(client, pipelineId, req.body || {})
        : await cicdService.runPipeline(client, pipelineId, req.body || {});
      if (!run) return res.status(404).json({ error: 'Pipeline not found' });
      res.status(pipelineResult.rows[0]?.provider === 'GITHUB_ACTIONS' ? 202 : 201).json(run);
    });
  },

  getRunDetail: async (req: Request, res: Response, next: NextFunction) => {
    const runId = parseId(req.params.runId);
    if (!runId) return res.status(400).json({ error: 'Invalid runId' });
    await withClient(next, async client => {
      const run = await cicdService.getRunDetail(client, runId);
      if (!run) return res.status(404).json({ error: 'Pipeline run not found' });
      res.json(run);
    });
  },

  getRunSteps: async (req: Request, res: Response, next: NextFunction) => {
    const runId = parseId(req.params.runId);
    if (!runId) return res.status(400).json({ error: 'Invalid runId' });
    await withClient(next, async client => {
      res.json(await cicdService.getRunSteps(client, runId));
    });
  },

  dispatchGitHub: async (req: Request, res: Response, next: NextFunction) => {
    const pipelineId = parseId(req.params.pipelineId);
    if (!pipelineId) return res.status(400).json({ error: 'Invalid pipelineId' });
    await withTransaction(next, async client => {
      const run = await githubActionsService.dispatch(client, pipelineId, req.body || {});
      if (!run) return res.status(404).json({ error: 'Pipeline not found' });
      res.status(202).json(run);
    });
  },

  githubWebhook: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const rawBody = (req as Request & { rawBody?: Buffer }).rawBody;
      const signature = req.header('x-hub-signature-256');
      if (!githubActionsService.verifyWebhookSignature(rawBody, signature)) {
        return res.status(401).json({ error: 'Invalid GitHub webhook signature' });
      }
      await withTransaction(next, async client => {
        const result = await githubActionsService.handleWebhook(
          client,
          req.header('x-github-event') || 'unknown',
          req.header('x-github-delivery') || undefined,
          req.body || {}
        );
        res.json(result);
      });
    } catch (error) {
      next(error);
    }
  },

  receiveGitHubResult: async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!githubActionsService.verifyPipelineToken(req.header('authorization') || undefined)) {
        return res.status(401).json({ error: 'Invalid pipeline token' });
      }
      await withTransaction(next, async client => {
        res.status(201).json(await githubActionsService.receiveResult(client, req.body || {}));
      });
    } catch (error) {
      next(error);
    }
  },

  monitoring: async (req: Request, res: Response, next: NextFunction) => {
    const rawProjectId = Array.isArray(req.query.projectId) ? req.query.projectId[0] : req.query.projectId;
    const projectId = rawProjectId ? Number(rawProjectId) : null;
    if (rawProjectId && (!Number.isInteger(projectId) || Number(projectId) <= 0)) {
      return res.status(400).json({ error: 'Invalid projectId' });
    }
    await withClient(next, async client => {
      res.json(await githubActionsService.monitoring(client, projectId));
    });
  },
};
