import express from 'express';
import { sbomSnapshotController } from '../controllers/sbomSnapshotController';

const router = express.Router();

router.post('/:projectId/sbom/incremental-generate', sbomSnapshotController.incrementalGenerate);
router.post('/:projectId/sbom/auto-generate', sbomSnapshotController.incrementalGenerate);
router.get('/:projectId/sbom/snapshots', sbomSnapshotController.listSnapshots);
router.post('/:projectId/artifacts', sbomSnapshotController.saveArtifacts);
router.get('/:projectId/artifacts', sbomSnapshotController.listArtifacts);

export default router;
