import express from 'express';
import { sbomSnapshotController } from '../controllers/sbomSnapshotController';

const router = express.Router();

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
router.get('/snapshots/:snapshotId/changes', sbomSnapshotController.getChanges);

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
router.get('/snapshots/:snapshotId/export', sbomSnapshotController.exportSnapshot);

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
router.get('/snapshots/:snapshotId/graph', sbomSnapshotController.getGraph);

export default router;
