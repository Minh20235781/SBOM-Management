import express from 'express';
import { validationScenarioController } from '../controllers/validationScenarioController';

const router = express.Router();

router.get('/', validationScenarioController.list);
router.post('/:scenarioId/analyze', validationScenarioController.analyze);
router.get('/runs/:runId', validationScenarioController.getRun);
router.post('/runs/:runId/confirm', validationScenarioController.confirm);
router.post('/runs/:runId/generate', validationScenarioController.generate);
router.post('/runs/:runId/faulty', validationScenarioController.createFaulty);
router.post('/runs/:runId/verify', validationScenarioController.verify);
router.get('/runs/:runId/report', validationScenarioController.report);

export default router;
