"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const sbomSnapshotController_1 = require("../controllers/sbomSnapshotController");
const router = express_1.default.Router();
router.get('/snapshots/:snapshotId/changes', sbomSnapshotController_1.sbomSnapshotController.getChanges);
router.get('/snapshots/:snapshotId/export', sbomSnapshotController_1.sbomSnapshotController.exportSnapshot);
router.get('/snapshots/:snapshotId/graph', sbomSnapshotController_1.sbomSnapshotController.getGraph);
exports.default = router;
