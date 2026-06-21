"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const sbomSnapshotController_1 = require("../controllers/sbomSnapshotController");
const router = express_1.default.Router();
/**
 * @swagger
 * tags:
 *   - name: Analyze/Compare SBOM
 *     description: Snapshot generation, comparison and project artifact APIs
 */
/**
 * @swagger
 * /api/projects/{projectId}/sbom/incremental-generate:
 *   post:
 *     summary: Generate an incremental SBOM snapshot for a project
 *     tags: [Analyze/Compare SBOM]
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
 *       required: false
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               sbom:
 *                 type: object
 *               dependencyFiles:
 *                 type: array
 *                 items:
 *                   type: object
 *                   properties:
 *                     artifactPath:
 *                       type: string
 *                     artifactName:
 *                       type: string
 *                     artifactType:
 *                       type: string
 *                     content:
 *                       type: string
 *     responses:
 *       201:
 *         description: Snapshot generated or existing snapshot reused
 *       400:
 *         description: Invalid project ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Project not found
 *       500:
 *         description: Server error
 */
router.post('/:projectId/sbom/incremental-generate', sbomSnapshotController_1.sbomSnapshotController.incrementalGenerate);
/**
 * @swagger
 * /api/projects/{projectId}/sbom/auto-generate:
 *   post:
 *     summary: Automatically generate or update an SBOM from stored project artifacts
 *     tags: [Generate SBOM, Analyze/Compare SBOM]
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
 *       required: false
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               dependencyFiles:
 *                 type: array
 *                 items:
 *                   type: object
 *     responses:
 *       201:
 *         description: SBOM snapshot generated from project artifacts
 *       400:
 *         description: Invalid project ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Project not found
 *       500:
 *         description: Server error
 */
router.post('/:projectId/sbom/auto-generate', sbomSnapshotController_1.sbomSnapshotController.incrementalGenerate);
/**
 * @swagger
 * /api/projects/{projectId}/sbom/snapshots:
 *   get:
 *     summary: List SBOM snapshots for a project
 *     tags: [Analyze/Compare SBOM]
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
 *         description: Snapshot list
 *       400:
 *         description: Invalid project ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Project not found
 *       500:
 *         description: Server error
 */
router.get('/:projectId/sbom/snapshots', sbomSnapshotController_1.sbomSnapshotController.listSnapshots);
/**
 * @swagger
 * /api/projects/{projectId}/artifacts:
 *   post:
 *     summary: Save dependency files or build artifacts for later SBOM generation
 *     tags: [Project, Generate SBOM]
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
 *               dependencyFiles:
 *                 type: array
 *                 items:
 *                   type: object
 *                   required: [artifactPath, content]
 *                   properties:
 *                     artifactPath:
 *                       type: string
 *                     artifactName:
 *                       type: string
 *                     artifactType:
 *                       type: string
 *                     content:
 *                       type: string
 *     responses:
 *       201:
 *         description: Artifacts saved
 *       400:
 *         description: Missing dependency files or invalid project ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Project not found
 *       500:
 *         description: Server error
 */
router.post('/:projectId/artifacts', sbomSnapshotController_1.sbomSnapshotController.saveArtifacts);
/**
 * @swagger
 * /api/projects/{projectId}/artifacts:
 *   get:
 *     summary: List stored dependency files or artifacts for a project
 *     tags: [Project, Generate SBOM]
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
 *         description: Stored artifact metadata
 *       400:
 *         description: Invalid project ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Project not found
 *       500:
 *         description: Server error
 */
router.get('/:projectId/artifacts', sbomSnapshotController_1.sbomSnapshotController.listArtifacts);
exports.default = router;
