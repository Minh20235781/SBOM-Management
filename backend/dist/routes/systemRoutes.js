"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const systemController_1 = require("../controllers/systemController");
const router = express_1.default.Router();
/**
 * @swagger
 * tags:
 *   - name: Project
 *     description: Project/System management APIs
 */
/**
 * @swagger
 * /api/systems:
 *   get:
 *     summary: List projects with SBOM counters
 *     tags: [Project]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Project list
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Project'
 *       401:
 *         description: JWT token is missing or invalid
 *       500:
 *         description: Server error
 */
router.get('/', systemController_1.systemController.list);
/**
 * @swagger
 * /api/systems:
 *   post:
 *     summary: Create a project or update an existing project with the same name
 *     tags: [Project]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [name]
 *             properties:
 *               name:
 *                 type: string
 *                 example: SBOM Management
 *               description:
 *                 type: string
 *                 nullable: true
 *     responses:
 *       200:
 *         description: Existing project updated
 *       201:
 *         description: Project created
 *       400:
 *         description: Missing project name
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiError'
 *       401:
 *         description: JWT token is missing or invalid
 *       500:
 *         description: Server error
 */
router.post('/', systemController_1.systemController.create);
/**
 * @swagger
 * /api/systems/{id}/detail:
 *   get:
 *     summary: Get project detail with linked SBOMs, snapshots and unlinked SBOMs
 *     tags: [Project, SBOM]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: Project ID
 *     responses:
 *       200:
 *         description: Project detail
 *       400:
 *         description: Invalid project ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Project not found
 *       500:
 *         description: Server error
 */
router.get('/:id/detail', systemController_1.systemController.getDetail);
/**
 * @swagger
 * /api/systems/{id}/link-sbom:
 *   post:
 *     summary: Link an existing SBOM metadata record to a project
 *     tags: [Project, SBOM]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
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
 *             required: [sbomId]
 *             properties:
 *               sbomId:
 *                 type: string
 *     responses:
 *       200:
 *         description: SBOM linked to project
 *       400:
 *         description: Invalid project ID or missing SBOM ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Project or SBOM not found
 *       500:
 *         description: Server error
 */
router.post('/:id/link-sbom', systemController_1.systemController.linkSbom);
/**
 * @swagger
 * /api/systems/{id}:
 *   delete:
 *     summary: Delete a project and its linked SBOM metadata records
 *     tags: [Project]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: Project ID
 *     responses:
 *       200:
 *         description: Project deleted
 *       400:
 *         description: Invalid project ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Project not found
 *       500:
 *         description: Server error
 */
router.delete('/:id', systemController_1.systemController.delete);
exports.default = router;
