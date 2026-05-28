"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const systemController_1 = require("../controllers/systemController");
const router = express_1.default.Router();
router.get('/', systemController_1.systemController.list);
router.post('/', systemController_1.systemController.create);
router.get('/:id/detail', systemController_1.systemController.getDetail);
router.post('/:id/link-sbom', systemController_1.systemController.linkSbom);
router.delete('/:id', systemController_1.systemController.delete);
exports.default = router;
