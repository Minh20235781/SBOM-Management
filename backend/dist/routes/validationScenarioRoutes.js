"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const validationScenarioController_1 = require("../controllers/validationScenarioController");
const router = express_1.default.Router();
router.get('/', validationScenarioController_1.validationScenarioController.list);
router.post('/:scenarioId/analyze', validationScenarioController_1.validationScenarioController.analyze);
router.get('/runs/:runId', validationScenarioController_1.validationScenarioController.getRun);
router.post('/runs/:runId/confirm', validationScenarioController_1.validationScenarioController.confirm);
router.post('/runs/:runId/generate', validationScenarioController_1.validationScenarioController.generate);
router.post('/runs/:runId/faulty', validationScenarioController_1.validationScenarioController.createFaulty);
router.post('/runs/:runId/verify', validationScenarioController_1.validationScenarioController.verify);
router.get('/runs/:runId/report', validationScenarioController_1.validationScenarioController.report);
exports.default = router;
