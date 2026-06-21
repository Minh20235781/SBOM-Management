"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cicdController_1 = require("../controllers/cicdController");
const router = express_1.default.Router();
/**
 * @swagger
 * tags:
 *   - name: CI/CD Pipeline
 *     description: Developer task and CI/CD pipeline APIs
 */
/**
 * @swagger
 * /api/projects/{projectId}/tasks:
 *   get:
 *     summary: List developer tasks for a project
 *     tags: [CI/CD Pipeline]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: projectId
 *         required: true
 *         schema:
 *           type: integer
 *         description: Project ID
 *     responses:
 *       200:
 *         description: Developer task list
 *       400:
 *         description: Invalid project ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Project not found
 *       500:
 *         description: Server error
 */
router.get('/projects/:projectId/tasks', cicdController_1.cicdController.listTasks);
/**
 * @swagger
 * /api/projects/{projectId}/tasks:
 *   post:
 *     summary: Create a developer task and optionally link it to a pipeline
 *     tags: [CI/CD Pipeline]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: projectId
 *         required: true
 *         schema:
 *           type: integer
 *         description: Project ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               title:
 *                 type: string
 *               description:
 *                 type: string
 *               status:
 *                 type: string
 *                 enum: [TODO, IN_PROGRESS, DONE, BLOCKED]
 *               priority:
 *                 type: string
 *                 enum: [LOW, MEDIUM, HIGH]
 *               assignedTo:
 *                 type: string
 *               relatedPipelineId:
 *                 type: integer
 *                 nullable: true
 *     responses:
 *       201:
 *         description: Task created
 *       400:
 *         description: Invalid project ID or request body
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Project not found
 *       500:
 *         description: Server error
 */
router.post('/projects/:projectId/tasks', cicdController_1.cicdController.createTask);
/**
 * @swagger
 * /api/tasks/{taskId}:
 *   patch:
 *     summary: Update a developer task
 *     tags: [CI/CD Pipeline]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: taskId
 *         required: true
 *         schema:
 *           type: integer
 *         description: Task ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: Task updated
 *       400:
 *         description: Invalid task ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Task not found
 *       500:
 *         description: Server error
 */
router.patch('/tasks/:taskId', cicdController_1.cicdController.updateTask);
/**
 * @swagger
 * /api/tasks/{taskId}:
 *   delete:
 *     summary: Delete a developer task
 *     tags: [CI/CD Pipeline]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: taskId
 *         required: true
 *         schema:
 *           type: integer
 *         description: Task ID
 *     responses:
 *       200:
 *         description: Task deleted
 *       400:
 *         description: Invalid task ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Task not found
 *       500:
 *         description: Server error
 */
router.delete('/tasks/:taskId', cicdController_1.cicdController.deleteTask);
/**
 * @swagger
 * /api/projects/{projectId}/pipelines:
 *   get:
 *     summary: List CI/CD pipelines for a project
 *     tags: [CI/CD Pipeline]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: projectId
 *         required: true
 *         schema:
 *           type: integer
 *         description: Project ID
 *     responses:
 *       200:
 *         description: Pipeline list
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Pipeline'
 *       400:
 *         description: Invalid project ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Project not found
 *       500:
 *         description: Server error
 */
router.get('/projects/:projectId/pipelines', cicdController_1.cicdController.listPipelines);
/**
 * @swagger
 * /api/projects/{projectId}/pipelines:
 *   post:
 *     summary: Create a CI/CD pipeline for SBOM generation
 *     tags: [CI/CD Pipeline]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: projectId
 *         required: true
 *         schema:
 *           type: integer
 *         description: Project ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Pipeline'
 *     responses:
 *       201:
 *         description: Pipeline created
 *       400:
 *         description: Invalid project ID or request body
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Project not found
 *       500:
 *         description: Server error
 */
router.post('/projects/:projectId/pipelines', cicdController_1.cicdController.createPipeline);
/**
 * @swagger
 * /api/pipelines/{pipelineId}/runs:
 *   get:
 *     summary: List pipeline runs
 *     tags: [CI/CD Pipeline]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: pipelineId
 *         required: true
 *         schema:
 *           type: integer
 *         description: Pipeline ID
 *     responses:
 *       200:
 *         description: Pipeline run list
 *       400:
 *         description: Invalid pipeline ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Pipeline not found
 *       500:
 *         description: Server error
 */
router.get('/pipelines/:pipelineId/runs', cicdController_1.cicdController.listRuns);
/**
 * @swagger
 * /api/pipelines/{pipelineId}/run:
 *   post:
 *     summary: Run a CI/CD pipeline and generate/update an SBOM snapshot
 *     tags: [CI/CD Pipeline, Generate SBOM]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: pipelineId
 *         required: true
 *         schema:
 *           type: integer
 *         description: Pipeline ID
 *     requestBody:
 *       required: false
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               commitHash:
 *                 type: string
 *               branch:
 *                 type: string
 *               triggeredBy:
 *                 type: string
 *     responses:
 *       201:
 *         description: Pipeline run created and completed
 *       400:
 *         description: Invalid pipeline ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Pipeline not found
 *       500:
 *         description: Server error
 */
router.post('/pipelines/:pipelineId/run', cicdController_1.cicdController.runPipeline);
// GitHub Actions integration. The webhook uses GitHub's HMAC signature; the
// result endpoint uses SBOM_PIPELINE_TOKEN configured in repository secrets.
router.post('/pipelines/:pipelineId/github-dispatch', cicdController_1.cicdController.dispatchGitHub);
router.post('/github-actions/webhook', cicdController_1.cicdController.githubWebhook);
router.post('/github-actions/results', cicdController_1.cicdController.receiveGitHubResult);
router.get('/cicd/monitoring', cicdController_1.cicdController.monitoring);
/**
 * @swagger
 * /api/pipeline-runs/{runId}:
 *   get:
 *     summary: Get pipeline run detail with steps and generated SBOM snapshot
 *     tags: [CI/CD Pipeline]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: runId
 *         required: true
 *         schema:
 *           type: integer
 *         description: Pipeline run ID
 *     responses:
 *       200:
 *         description: Pipeline run detail
 *       400:
 *         description: Invalid run ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Pipeline run not found
 *       500:
 *         description: Server error
 */
router.get('/pipeline-runs/:runId', cicdController_1.cicdController.getRunDetail);
/**
 * @swagger
 * /api/pipeline-runs/{runId}/steps:
 *   get:
 *     summary: List execution steps for a pipeline run
 *     tags: [CI/CD Pipeline]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: runId
 *         required: true
 *         schema:
 *           type: integer
 *         description: Pipeline run ID
 *     responses:
 *       200:
 *         description: Pipeline run steps
 *       400:
 *         description: Invalid run ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Pipeline run not found
 *       500:
 *         description: Server error
 */
router.get('/pipeline-runs/:runId/steps', cicdController_1.cicdController.getRunSteps);
exports.default = router;
