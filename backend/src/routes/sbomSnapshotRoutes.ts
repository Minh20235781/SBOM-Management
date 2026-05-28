import express from 'express';
import { sbomSnapshotController } from '../controllers/sbomSnapshotController';

const router = express.Router();

router.get('/snapshots/:snapshotId/changes', sbomSnapshotController.getChanges);
router.get('/snapshots/:snapshotId/export', sbomSnapshotController.exportSnapshot);
router.get('/snapshots/:snapshotId/graph', sbomSnapshotController.getGraph);

export default router;
