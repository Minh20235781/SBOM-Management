import express from 'express';
import { sbomController } from '../controllers/sbomController';

const router = express.Router();

/**
 * @swagger
 * tags:
 *   - name: SBOM
 *     description: SBOM metadata, import, generation and analysis APIs
 *   - name: Component
 *     description: SBOM component APIs
 *   - name: Dependency
 *     description: SBOM dependency APIs
 *   - name: Vulnerability
 *     description: SBOM vulnerability APIs
 *   - name: License
 *     description: License information embedded in SBOM components
 */

/**
 * @swagger
 * /api/sboms/upload:
 *   post:
 *     summary: Import an existing SBOM document
 *     tags: [SBOM]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               system_id:
 *                 type: integer
 *                 nullable: true
 *               systemName:
 *                 type: string
 *               repoUrl:
 *                 type: string
 *               sbom:
 *                 type: object
 *                 description: CycloneDX or SPDX SBOM payload
 *     responses:
 *       201:
 *         description: SBOM imported successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 sbomId:
 *                   type: string
 *                 systemId:
 *                   type: integer
 *                   nullable: true
 *       400:
 *         description: Invalid or empty request body
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiError'
 *       401:
 *         description: JWT token is missing or invalid
 *       500:
 *         description: Server error
 */
router.post('/upload', sbomController.upload);

/**
 * @swagger
 * /api/sboms/analyze-repo:
 *   post:
 *     summary: Analyze a GitHub repository and return a generated SBOM preview
 *     tags: [SBOM]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [repoUrl]
 *             properties:
 *               repoUrl:
 *                 type: string
 *                 example: https://github.com/owner/repo
 *     responses:
 *       200:
 *         description: Repository analyzed successfully
 *       400:
 *         description: Invalid repository URL
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiError'
 *       401:
 *         description: JWT token is missing or invalid
 *       500:
 *         description: Server error
 */
router.post('/analyze-repo', sbomController.analyzeGitHub);

/**
 * @swagger
 * /api/sboms/generate:
 *   post:
 *     summary: Generate and persist an SBOM from a GitHub repository
 *     tags: [SBOM]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [repoUrl]
 *             properties:
 *               repoUrl:
 *                 type: string
 *               systemName:
 *                 type: string
 *                 description: Optional project name. Defaults to repository name.
 *     responses:
 *       201:
 *         description: SBOM generated and saved successfully
 *       400:
 *         description: Invalid request
 *       401:
 *         description: JWT token is missing or invalid
 *       500:
 *         description: Server error
 */
router.post('/generate', sbomController.generateFromGitHub);

/**
 * @swagger
 * /api/sboms:
 *   get:
 *     summary: List all SBOM metadata records
 *     tags: [SBOM]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of SBOM metadata records
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/SbomMetadata'
 *       401:
 *         description: JWT token is missing or invalid
 *       500:
 *         description: Server error
 */
router.get('/', sbomController.list);

router.get('/:id/export', sbomController.exportCycloneDx);

/**
 * @swagger
 * /api/sboms/{id}:
 *   get:
 *     summary: Get SBOM metadata by ID
 *     tags: [SBOM]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: SBOM identifier
 *     responses:
 *       200:
 *         description: SBOM metadata
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SbomMetadata'
 *       400:
 *         description: Invalid SBOM ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: SBOM not found
 *       500:
 *         description: Server error
 */
router.get('/:id', sbomController.getById);

/**
 * @swagger
 * /api/sboms/{id}/components:
 *   get:
 *     summary: List components in an SBOM
 *     tags: [Component, License]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: SBOM identifier
 *     responses:
 *       200:
 *         description: Components found in the SBOM
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Component'
 *       400:
 *         description: Invalid SBOM ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: SBOM not found
 *       500:
 *         description: Server error
 */
router.get('/:id/components', sbomController.getComponents);

/**
 * @swagger
 * /api/sboms/{id}/dependencies:
 *   get:
 *     summary: List dependency relationships in an SBOM
 *     tags: [Dependency]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: SBOM identifier
 *     responses:
 *       200:
 *         description: Dependency relationships
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Dependency'
 *       400:
 *         description: Invalid SBOM ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: SBOM not found
 *       500:
 *         description: Server error
 */
router.get('/:id/dependencies', sbomController.getDependencies);

/**
 * @swagger
 * /api/sboms/{id}/vulnerabilities:
 *   get:
 *     summary: List vulnerabilities associated with an SBOM
 *     tags: [Vulnerability]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: SBOM identifier
 *     responses:
 *       200:
 *         description: Vulnerabilities found in the SBOM
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Vulnerability'
 *       400:
 *         description: Invalid SBOM ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: SBOM not found
 *       500:
 *         description: Server error
 */
router.get('/:id/vulnerabilities', sbomController.getVulnerabilities);

export default router;
