"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const sbomSnapshotController_1 = require("../controllers/sbomSnapshotController");
const router = express_1.default.Router();
router.post('/:projectId/sbom/incremental-generate', sbomSnapshotController_1.sbomSnapshotController.incrementalGenerate);
router.post('/:projectId/sbom/auto-generate', sbomSnapshotController_1.sbomSnapshotController.incrementalGenerate);
router.get('/:projectId/sbom/snapshots', sbomSnapshotController_1.sbomSnapshotController.listSnapshots);
router.post('/:projectId/artifacts', sbomSnapshotController_1.sbomSnapshotController.saveArtifacts);
router.get('/:projectId/artifacts', sbomSnapshotController_1.sbomSnapshotController.listArtifacts);
exports.default = router;
