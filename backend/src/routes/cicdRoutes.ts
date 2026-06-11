import express from 'express';
import { cicdController } from '../controllers/cicdController';

const router = express.Router();

router.get('/projects/:projectId/tasks', cicdController.listTasks);
router.post('/projects/:projectId/tasks', cicdController.createTask);
router.patch('/tasks/:taskId', cicdController.updateTask);
router.delete('/tasks/:taskId', cicdController.deleteTask);

router.get('/projects/:projectId/pipelines', cicdController.listPipelines);
router.post('/projects/:projectId/pipelines', cicdController.createPipeline);
router.get('/pipelines/:pipelineId/runs', cicdController.listRuns);
router.post('/pipelines/:pipelineId/run', cicdController.runPipeline);

router.get('/pipeline-runs/:runId', cicdController.getRunDetail);
router.get('/pipeline-runs/:runId/steps', cicdController.getRunSteps);

export default router;
