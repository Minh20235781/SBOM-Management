import express from 'express';
import { systemController } from '../controllers/systemController';

const router = express.Router();

router.get('/', systemController.list);
router.post('/', systemController.create);
router.get('/:id/detail', systemController.getDetail);
router.post('/:id/link-sbom', systemController.linkSbom);
router.delete('/:id', systemController.delete);

export default router;
