"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const sbomController_1 = require("../controllers/sbomController");
const router = express_1.default.Router();
router.post('/upload', sbomController_1.sbomController.upload);
router.post('/generate', sbomController_1.sbomController.generateFromGitHub);
router.get('/', sbomController_1.sbomController.list);
router.get('/:id', sbomController_1.sbomController.getById);
router.get('/:id/components', sbomController_1.sbomController.getComponents);
router.get('/:id/dependencies', sbomController_1.sbomController.getDependencies);
router.get('/:id/vulnerabilities', sbomController_1.sbomController.getVulnerabilities);
exports.default = router;
