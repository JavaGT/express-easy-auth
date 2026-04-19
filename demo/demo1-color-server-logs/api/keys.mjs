import { Router } from 'express';

const router = Router();

// Middleware helper using the new req.authMiddleware
const requireAuth = (req, res, next) => req.authMiddleware.requireAuth(req, res, next);

router.post('/', requireAuth, async (req, res) => {
    const { label, scopes, expiresAt } = req.body;
    const key = await req.authManager.createApiKey(req.user.id, scopes, expiresAt, label);
    res.status(201).json(key);
});

router.get('/', requireAuth, async (req, res) => {
    const keys = await req.authManager.getApiKeysByUser(req.user.id);
    res.json(keys);
});

router.delete('/:id', requireAuth, async (req, res) => {
    await req.authManager.revokeApiKey(req.params.id);
    res.json({ success: true });
});

export default router;

