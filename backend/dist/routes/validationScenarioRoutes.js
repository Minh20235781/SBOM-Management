"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const validationScenarioController_1 = require("../controllers/validationScenarioController");
const router = express_1.default.Router();
/**
 * @swagger
 * tags:
 *   - name: Policy/Compliance
 *     description: SBOM validation and verification scenario APIs
 */
/**
 * @swagger
 * /api/validation-scenarios:
 *   get:
 *     summary: List validation-ready repositories and scenario metadata
 *     tags: [Policy/Compliance, Repository]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Validation catalog
 *         # TODO: verify response schema
 *       401:
 *         description: JWT token is missing or invalid
 *       500:
 *         description: Server error
 */
router.get('/', validationScenarioController_1.validationScenarioController.list);
/**
 * @swagger
 * /api/validation-scenarios/{scenarioId}/analyze:
 *   post:
 *     summary: Analyze a validation scenario repository
 *     tags: [Policy/Compliance, Repository]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: scenarioId
 *         required: true
 *         schema:
 *           type: string
 *         description: Scenario ID
 *     responses:
 *       201:
 *         description: Scenario analysis run created
 *         # TODO: verify response schema
 *       400:
 *         description: Invalid scenario ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Scenario not found
 *       500:
 *         description: Server error
 */
router.post('/:scenarioId/analyze', validationScenarioController_1.validationScenarioController.analyze);
router.post('/:scenarioId/verify-current', validationScenarioController_1.validationScenarioController.verifyCurrent);
/**
 * @swagger
 * /api/validation-scenarios/runs/{runId}:
 *   get:
 *     summary: Get validation run detail
 *     tags: [Policy/Compliance]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: runId
 *         required: true
 *         schema:
 *           type: string
 *         description: Validation run ID
 *     responses:
 *       200:
 *         description: Validation run detail
 *         # TODO: verify response schema
 *       400:
 *         description: Invalid run ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Run not found
 *       500:
 *         description: Server error
 */
router.get('/runs/:runId', validationScenarioController_1.validationScenarioController.getRun);
/**
 * @swagger
 * /api/validation-scenarios/runs/{runId}/confirm:
 *   post:
 *     summary: Confirm a validation run before SBOM generation
 *     tags: [Policy/Compliance]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: runId
 *         required: true
 *         schema:
 *           type: string
 *         description: Validation run ID
 *     responses:
 *       200:
 *         description: Validation run confirmed
 *         # TODO: verify response schema
 *       400:
 *         description: Invalid run ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Run not found
 *       500:
 *         description: Server error
 */
router.post('/runs/:runId/confirm', validationScenarioController_1.validationScenarioController.confirm);
/**
 * @swagger
 * /api/validation-scenarios/runs/{runId}/generate:
 *   post:
 *     summary: Generate an SBOM for a validation run
 *     tags: [Generate SBOM, Policy/Compliance]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: runId
 *         required: true
 *         schema:
 *           type: string
 *         description: Validation run ID
 *     responses:
 *       200:
 *         description: SBOM generated for the validation run
 *         # TODO: verify response schema
 *       400:
 *         description: Invalid run ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Run not found
 *       500:
 *         description: Server error
 */
router.post('/runs/:runId/generate', validationScenarioController_1.validationScenarioController.generate);
/**
 * @swagger
 * /api/validation-scenarios/runs/{runId}/faulty:
 *   post:
 *     summary: Create a faulty SBOM variant for validation testing
 *     tags: [Policy/Compliance, Analyze/Compare SBOM]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: runId
 *         required: true
 *         schema:
 *           type: string
 *         description: Validation run ID
 *     responses:
 *       201:
 *         description: Faulty SBOM generated
 *         # TODO: verify response schema
 *       400:
 *         description: Invalid run ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Run not found
 *       500:
 *         description: Server error
 */
router.post('/runs/:runId/faulty', validationScenarioController_1.validationScenarioController.createFaulty);
/**
 * @swagger
 * /api/validation-scenarios/runs/{runId}/verify:
 *   post:
 *     summary: Verify generated SBOM compatibility against source evidence
 *     tags: [Policy/Compliance, Analyze/Compare SBOM]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: runId
 *         required: true
 *         schema:
 *           type: string
 *         description: Validation run ID
 *     requestBody:
 *       required: false
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               useFaulty:
 *                 type: boolean
 *     responses:
 *       200:
 *         description: Verification result
 *         # TODO: verify response schema
 *       400:
 *         description: Invalid run ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Run not found
 *       500:
 *         description: Server error
 */
router.post('/runs/:runId/verify', validationScenarioController_1.validationScenarioController.verify);
/**
 * @swagger
 * /api/validation-scenarios/runs/{runId}/verify-uploaded:
 *   post:
 *     summary: Verify an uploaded SBOM against validation run source evidence
 *     tags: [Policy/Compliance, Import SBOM]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: runId
 *         required: true
 *         schema:
 *           type: string
 *         description: Validation run ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               sbom:
 *                 type: object
 *               fileName:
 *                 type: string
 *     responses:
 *       200:
 *         description: Uploaded SBOM verification result
 *         # TODO: verify response schema
 *       400:
 *         description: Invalid request body or run ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Run not found
 *       500:
 *         description: Server error
 */
router.post('/runs/:runId/verify-uploaded', validationScenarioController_1.validationScenarioController.verifyUploaded);
/**
 * @swagger
 * /api/validation-scenarios/runs/{runId}/report:
 *   get:
 *     summary: Get validation test report for a run
 *     tags: [Policy/Compliance]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: runId
 *         required: true
 *         schema:
 *           type: string
 *         description: Validation run ID
 *     responses:
 *       200:
 *         description: Validation report
 *         # TODO: verify response schema
 *       400:
 *         description: Invalid run ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Report or run not found
 *       500:
 *         description: Server error
 */
router.get('/runs/:runId/report', validationScenarioController_1.validationScenarioController.report);
exports.default = router;
