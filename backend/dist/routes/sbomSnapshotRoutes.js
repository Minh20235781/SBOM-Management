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
 * /api/sbom/snapshots/{snapshotId}/changes:
 *   get:
 *     summary: Get change log for an SBOM snapshot
 *     tags: [Analyze/Compare SBOM]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: snapshotId
 *         required: true
 *         schema:
 *           type: string
 *         description: Snapshot ID
 *     responses:
 *       200:
 *         description: Snapshot change log
 *       400:
 *         description: Invalid snapshot ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Snapshot not found
 *       500:
 *         description: Server error
 */
router.get('/snapshots/:snapshotId/changes', sbomSnapshotController_1.sbomSnapshotController.getChanges);
/**
 * @swagger
 * /api/sbom/snapshots/{snapshotId}/export:
 *   get:
 *     summary: Export an internal SBOM snapshot as CycloneDX JSON
 *     tags: [SBOM]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: snapshotId
 *         required: true
 *         schema:
 *           type: string
 *         description: Snapshot ID
 *     responses:
 *       200:
 *         description: CycloneDX SBOM document
 *       400:
 *         description: Invalid snapshot ID
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Snapshot not found
 *       500:
 *         description: Server error
 */
router.get('/snapshots/:snapshotId/export', sbomSnapshotController_1.sbomSnapshotController.exportSnapshot);
/**
 * @swagger
 * /api/sbom/snapshots/{snapshotId}/graph:
 *   get:
 *     summary: Build a dependency graph for an SBOM snapshot
 *     tags: [Dependency, Analyze/Compare SBOM]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: snapshotId
 *         required: true
 *         schema:
 *           type: string
 *         description: Snapshot ID
 *       - in: query
 *         name: depth
 *         required: false
 *         schema:
 *           type: integer
 *         description: Maximum dependency depth
 *       - in: query
 *         name: onlyVulnerable
 *         required: false
 *         schema:
 *           type: boolean
 *         description: Return only vulnerable components
 *       - in: query
 *         name: search
 *         required: false
 *         schema:
 *           type: string
 *         description: Component search text
 *     responses:
 *       200:
 *         description: Dependency graph nodes, edges and summary
 *       400:
 *         description: Invalid snapshot ID or query value
 *       401:
 *         description: JWT token is missing or invalid
 *       404:
 *         description: Snapshot not found
 *       500:
 *         description: Server error
 */
router.get('/snapshots/:snapshotId/graph', sbomSnapshotController_1.sbomSnapshotController.getGraph);
exports.default = router;
