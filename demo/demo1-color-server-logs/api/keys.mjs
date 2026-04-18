import { Router } from 'express';

const router = Router();

// Middleware helper using the new req.authMiddleware
const requireAuth = (req, res, next) => req.authMiddleware.requireAuth(req, res, next);

router.post('/', requireAuth, async (req, res) => {
    try {
        const { label } = req.body;
        const key = await req.authManager.createApiKey(req.user.id, label);
        res.status(201).json(key);
    } catch (err) {
        res.status(err.code || 400).json(err.toJSON ? err.toJSON() : { success: false, error: err.message });
    }
});

router.get('/', requireAuth, async (req, res) => {
    try {
        const keys = await req.authManager.getApiKeysByUser(req.user.id);
        res.json(keys);
    } catch (err) {
        res.status(err.code || 400).json(err.toJSON ? err.toJSON() : { success: false, error: err.message });
    }
});

router.delete('/:id', requireAuth, async (req, res) => {
    try {
        await req.authManager.revokeApiKey(req.params.id);
        res.json({ success: true });
    } catch (err) {
        res.status(err.code || 400).json(err.toJSON ? err.toJSON() : { success: false, error: err.message });
    }
});

export default router;

