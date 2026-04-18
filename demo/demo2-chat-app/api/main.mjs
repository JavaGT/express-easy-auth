import { Router } from 'express';
import roomsRouter from './rooms.mjs';
import messagesRouter from './messages.mjs';
import botsRouter from './bots.mjs';

const router = Router();

router.use('/rooms', roomsRouter);
router.use('/messages', messagesRouter);
router.use('/bots', botsRouter);

export default router;
