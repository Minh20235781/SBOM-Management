"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.cicdController = void 0;
const db_1 = require("../config/db");
const cicdService_1 = require("../services/cicdService");
const githubActionsService_1 = require("../services/githubActionsService");
const parseId = (value) => {
    const raw = Array.isArray(value) ? value[0] : value;
    const id = Number(raw);
    return Number.isInteger(id) && id > 0 ? id : null;
};
const withClient = async (next, handler) => {
    const client = await db_1.pool.connect();
    try {
        await handler(client);
    }
    catch (error) {
        next(error);
    }
    finally {
        client.release();
    }
};
const withTransaction = async (next, handler) => {
    const client = await db_1.pool.connect();
    try {
        await client.query('BEGIN');
        await handler(client);
        await client.query('COMMIT');
    }
    catch (error) {
        await client.query('ROLLBACK');
        next(error);
    }
    finally {
        client.release();
    }
};
exports.cicdController = {
    listTasks: async (req, res, next) => {
        const projectId = parseId(req.params.projectId);
        if (!projectId)
            return res.status(400).json({ error: 'Invalid projectId' });
        await withClient(next, async (client) => {
            res.json(await cicdService_1.cicdService.listTasks(client, projectId));
        });
    },
    createTask: async (req, res, next) => {
        const projectId = parseId(req.params.projectId);
        if (!projectId)
            return res.status(400).json({ error: 'Invalid projectId' });
        await withTransaction(next, async (client) => {
            res.status(201).json(await cicdService_1.cicdService.createTask(client, projectId, req.body || {}));
        });
    },
    updateTask: async (req, res, next) => {
        const taskId = parseId(req.params.taskId);
        if (!taskId)
            return res.status(400).json({ error: 'Invalid taskId' });
        await withTransaction(next, async (client) => {
            const task = await cicdService_1.cicdService.updateTask(client, taskId, req.body || {});
            if (!task)
                return res.status(404).json({ error: 'Task not found' });
            res.json(task);
        });
    },
    deleteTask: async (req, res, next) => {
        const taskId = parseId(req.params.taskId);
        if (!taskId)
            return res.status(400).json({ error: 'Invalid taskId' });
        await withTransaction(next, async (client) => {
            const task = await cicdService_1.cicdService.deleteTask(client, taskId);
            if (!task)
                return res.status(404).json({ error: 'Task not found' });
            res.json({ deleted: true, task });
        });
    },
    listPipelines: async (req, res, next) => {
        const projectId = parseId(req.params.projectId);
        if (!projectId)
            return res.status(400).json({ error: 'Invalid projectId' });
        await withClient(next, async (client) => {
            res.json(await cicdService_1.cicdService.listPipelines(client, projectId));
        });
    },
    createPipeline: async (req, res, next) => {
        const projectId = parseId(req.params.projectId);
        if (!projectId)
            return res.status(400).json({ error: 'Invalid projectId' });
        await withTransaction(next, async (client) => {
            res.status(201).json(await cicdService_1.cicdService.createPipeline(client, projectId, req.body || {}));
        });
    },
    listRuns: async (req, res, next) => {
        const pipelineId = parseId(req.params.pipelineId);
        if (!pipelineId)
            return res.status(400).json({ error: 'Invalid pipelineId' });
        await withClient(next, async (client) => {
            res.json(await cicdService_1.cicdService.listRuns(client, pipelineId));
        });
    },
    runPipeline: async (req, res, next) => {
        const pipelineId = parseId(req.params.pipelineId);
        if (!pipelineId)
            return res.status(400).json({ error: 'Invalid pipelineId' });
        await withTransaction(next, async (client) => {
            const pipelineResult = await client.query('SELECT provider FROM cicd_pipelines WHERE pipeline_id = $1', [pipelineId]);
            const run = pipelineResult.rows[0]?.provider === 'GITHUB_ACTIONS'
                ? await githubActionsService_1.githubActionsService.dispatch(client, pipelineId, req.body || {})
                : await cicdService_1.cicdService.runPipeline(client, pipelineId, req.body || {});
            if (!run)
                return res.status(404).json({ error: 'Pipeline not found' });
            res.status(pipelineResult.rows[0]?.provider === 'GITHUB_ACTIONS' ? 202 : 201).json(run);
        });
    },
    getRunDetail: async (req, res, next) => {
        const runId = parseId(req.params.runId);
        if (!runId)
            return res.status(400).json({ error: 'Invalid runId' });
        await withClient(next, async (client) => {
            const run = await cicdService_1.cicdService.getRunDetail(client, runId);
            if (!run)
                return res.status(404).json({ error: 'Pipeline run not found' });
            res.json(run);
        });
    },
    getRunSteps: async (req, res, next) => {
        const runId = parseId(req.params.runId);
        if (!runId)
            return res.status(400).json({ error: 'Invalid runId' });
        await withClient(next, async (client) => {
            res.json(await cicdService_1.cicdService.getRunSteps(client, runId));
        });
    },
    dispatchGitHub: async (req, res, next) => {
        const pipelineId = parseId(req.params.pipelineId);
        if (!pipelineId)
            return res.status(400).json({ error: 'Invalid pipelineId' });
        await withTransaction(next, async (client) => {
            const run = await githubActionsService_1.githubActionsService.dispatch(client, pipelineId, req.body || {});
            if (!run)
                return res.status(404).json({ error: 'Pipeline not found' });
            res.status(202).json(run);
        });
    },
    githubWebhook: async (req, res, next) => {
        try {
            const rawBody = req.rawBody;
            const signature = req.header('x-hub-signature-256');
            if (!githubActionsService_1.githubActionsService.verifyWebhookSignature(rawBody, signature)) {
                return res.status(401).json({ error: 'Invalid GitHub webhook signature' });
            }
            await withTransaction(next, async (client) => {
                const result = await githubActionsService_1.githubActionsService.handleWebhook(client, req.header('x-github-event') || 'unknown', req.header('x-github-delivery') || undefined, req.body || {});
                res.json(result);
            });
        }
        catch (error) {
            next(error);
        }
    },
    receiveGitHubResult: async (req, res, next) => {
        try {
            if (!githubActionsService_1.githubActionsService.verifyPipelineToken(req.header('authorization') || undefined)) {
                return res.status(401).json({ error: 'Invalid pipeline token' });
            }
            await withTransaction(next, async (client) => {
                res.status(201).json(await githubActionsService_1.githubActionsService.receiveResult(client, req.body || {}));
            });
        }
        catch (error) {
            next(error);
        }
    },
    monitoring: async (req, res, next) => {
        const rawProjectId = Array.isArray(req.query.projectId) ? req.query.projectId[0] : req.query.projectId;
        const projectId = rawProjectId ? Number(rawProjectId) : null;
        if (rawProjectId && (!Number.isInteger(projectId) || Number(projectId) <= 0)) {
            return res.status(400).json({ error: 'Invalid projectId' });
        }
        await withClient(next, async (client) => {
            res.json(await githubActionsService_1.githubActionsService.monitoring(client, projectId));
        });
    },
};
