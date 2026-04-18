import { Router } from 'express';
import { randomUUID } from 'node:crypto';

const router = Router();

// Send message
// Uses requireAuthOrApiKey to allow both humans (session) and bots (api_key)
router.post('/:roomId', (req, res, next) => req.authMiddleware.requireAuthOrApiKey(req, res, next, ['room:send']), async (req, res) => {
    try {
        const { roomId } = req.params;
        const { body } = req.body;
        if (!body) return res.status(400).json({ error: 'Body required' });

        // In a real app, we'd verify room membership here. 
        // For this demo, the API key scope 'room:send' is our primary check.

        const messageId = randomUUID();
        const now = Date.now();

        req.chatDb.prepare(`
            INSERT INTO messages (id, room_id, user_id, user_email, body, sent_at) 
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(
            messageId, roomId, req.user.id, req.user.email, body, now
        );

        res.status(201).json({ success: true, messageId });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// List messages
router.get('/:roomId', (req, res, next) => req.authMiddleware.requireAuthOrApiKey(req, res, next, ['room:read']), async (req, res) => {
    try {
        const { roomId } = req.params;
        const messages = req.chatDb.prepare('SELECT * FROM messages WHERE room_id = ? ORDER BY sent_at DESC LIMIT 50').all(roomId);
        res.json({ success: true, messages: messages.reverse() });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

export default router;
