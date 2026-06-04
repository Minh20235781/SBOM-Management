import express from 'express';
import { sbomController } from '../controllers/sbomController';

const router = express.Router();

router.post('/upload', sbomController.upload);
router.post('/generate', sbomController.generateFromGitHub);
router.get('/', sbomController.list);
router.get('/:id', sbomController.getById);
router.get('/:id/components', sbomController.getComponents);
router.get('/:id/dependencies', sbomController.getDependencies);
router.get('/:id/vulnerabilities', sbomController.getVulnerabilities);

export default router;
