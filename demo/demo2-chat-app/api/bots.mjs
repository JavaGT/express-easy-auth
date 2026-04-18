import { Router } from 'express';

const router = Router();

// Create bot (API Key) for a room
router.post('/:roomId', (req, res, next) => req.authMiddleware.requireFreshAuth(req, res, next), async (req, res) => {
    try {
        const { roomId } = req.params;
        const { name } = req.body;
        if (!name) return res.status(400).json({ error: 'Bot name required' });

        // Check if user is owner of the room
        const room = req.chatDb.prepare('SELECT owner_user_id FROM rooms WHERE id = ?').get(roomId);
        if (!room || room.owner_user_id !== req.user.id) {
            return res.status(403).json({ error: 'Only room owners can create bots' });
        }

        // Create API key with room scopes. 
        // We include both 'room:read' and 'room:send' scopes.
        const scopes = [`room:read`, `room:send` ];
        const expiresAt = Date.now() + (30 * 24 * 60 * 60 * 1000); // 30 days
        
        const apiKey = await req.authManager.createApiKey(req.user.id, scopes, expiresAt, `Bot: ${name} (Room: ${roomId})`);

        res.status(201).json({ 
            success: true, 
            apiKey, 
            message: 'Save this API key - it will not be shown again!' 
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// List bots (API keys)
router.get('/', (req, res, next) => req.authMiddleware.requireAuth(req, res, next), async (req, res) => {
    try {
        const keys = await req.authManager.getApiKeysByUser(req.user.id);
        // Filter for keys that belong to this demo's bots
        const bots = keys.filter(k => k.name && k.name.startsWith('Bot:'));
        res.json({ success: true, bots });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

export default router;
