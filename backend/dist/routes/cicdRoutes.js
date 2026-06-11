"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cicdController_1 = require("../controllers/cicdController");
const router = express_1.default.Router();
router.get('/projects/:projectId/tasks', cicdController_1.cicdController.listTasks);
router.post('/projects/:projectId/tasks', cicdController_1.cicdController.createTask);
router.patch('/tasks/:taskId', cicdController_1.cicdController.updateTask);
router.delete('/tasks/:taskId', cicdController_1.cicdController.deleteTask);
router.get('/projects/:projectId/pipelines', cicdController_1.cicdController.listPipelines);
router.post('/projects/:projectId/pipelines', cicdController_1.cicdController.createPipeline);
router.get('/pipelines/:pipelineId/runs', cicdController_1.cicdController.listRuns);
router.post('/pipelines/:pipelineId/run', cicdController_1.cicdController.runPipeline);
router.get('/pipeline-runs/:runId', cicdController_1.cicdController.getRunDetail);
router.get('/pipeline-runs/:runId/steps', cicdController_1.cicdController.getRunSteps);
exports.default = router;
