import express from 'express';
import { systemController } from '../controllers/systemController';

const router = express.Router();

router.get('/', systemController.list);
router.post('/', systemController.create);

export default router;
