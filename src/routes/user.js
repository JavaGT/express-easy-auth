import express from 'express';
import { authDb, userDb } from '../db/init.js';
import { requireAuth, requireFreshAuth } from '../middleware/auth.js';

const router = express.Router();

// ─── PROFILE ─────────────────────────────────────────────────────────────────

router.get('/me', requireAuth, (req, res) => {
    const user = authDb.prepare(
        'SELECT id, username, email, created_at FROM users WHERE id = ?'
    ).get(req.userId); // Fix: use req.userId

    if (!user) return res.status(404).json({ error: 'User not found' });

    const profile = userDb.prepare(
        'SELECT display_name, bio, avatar_url, location, website, updated_at FROM profiles WHERE user_id = ?'
    ).get(req.userId) || {};

    res.json({ ...user, profile });
});

router.patch('/me', requireAuth, (req, res) => {
    const { display_name, bio, location, website } = req.body;

    if (bio && bio.length > 500) {
        return res.status(400).json({ error: 'Bio must be under 500 characters' });
    }

    const now = Date.now();
    userDb.prepare(`
    INSERT INTO profiles (user_id, display_name, bio, location, website, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET
      display_name = COALESCE(excluded.display_name, display_name),
      bio = COALESCE(excluded.bio, bio),
      location = COALESCE(excluded.location, location),
      website = COALESCE(excluded.website, website),
      updated_at = excluded.updated_at
  `).run(req.userId, display_name || null, bio || null, location || null, website || null, now, now);

    res.json({ success: true });
});

// ─── SENSITIVE ACTION ─────────────────────────────────────────────────────────
// Requires fresh authentication (within last 5 minutes)

router.post('/sensitive-action', requireAuth, requireFreshAuth, (req, res) => {
    const { action, data } = req.body;

    // Example sensitive actions
    const allowedActions = ['export-data', 'delete-account-request', 'change-email', 'view-secret'];

    if (!action || !allowedActions.includes(action)) {
        return res.status(400).json({
            error: 'Invalid action',
            allowedActions
        });
    }

    const user = authDb.prepare(
        'SELECT id, username, email FROM users WHERE id = ?'
    ).get(req.userId);

    // Simulate performing the sensitive action
    let result;
    switch (action) {
        case 'export-data':
            const profile = userDb.prepare('SELECT * FROM profiles WHERE user_id = ?').get(req.userId);
            const passkeys = authDb.prepare('SELECT name, device_type, created_at FROM passkeys WHERE user_id = ?').all(req.userId);
            result = {
                user: { username: user.username, email: user.email },
                profile,
                passkeys,
                exportedAt: new Date().toISOString()
            };
            break;

        case 'view-secret':
            result = {
                secret: `TOP_SECRET_${user.id.substring(0, 8).toUpperCase()}`,
                message: 'This is your secret token — never share it!',
                generatedAt: new Date().toISOString()
            };
            break;

        case 'change-email':
            const { newEmail } = data || {};
            if (!newEmail) return res.status(400).json({ error: 'newEmail required' });
            // In production: send verification email, don't change directly
            result = { message: 'Verification email sent to ' + newEmail };
            break;

        case 'delete-account-request':
            result = {
                message: 'Account deletion requested. You have 30 days to cancel.',
                cancelToken: 'CANCEL_' + user.id.substring(0, 8).toUpperCase(),
                scheduledFor: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
            };
            break;
    }

    res.json({
        success: true,
        action,
        result,
        performedAt: new Date().toISOString(),
        performedBy: user.username
    });
});

// ─── SESSIONS (view & revoke) ─────────────────────────────────────────────────

router.get('/sessions', requireAuth, (req, res) => {
    const sessions = authDb.prepare(`
    SELECT id, created_at, expires_at, last_activity
    FROM sessions WHERE user_id = ? AND expires_at > ?
    ORDER BY last_activity DESC
  `).all(req.userId, Date.now());

    const annotated = sessions.map(s => ({
        ...s,
        isCurrent: s.id === req.sessionID
    }));

    res.json({ sessions: annotated });
});

router.delete('/sessions/:id', requireAuth, (req, res) => {
    const { id } = req.params;
    if (id === req.sessionID) {
        return res.status(400).json({ error: 'Cannot revoke current session; use logout instead' });
    }

    const session = authDb.prepare(
        'SELECT id FROM sessions WHERE id = ? AND user_id = ?'
    ).get(id, req.userId);

    if (!session) return res.status(404).json({ error: 'Session not found' });

    authDb.prepare('DELETE FROM sessions WHERE id = ?').run(id);
    res.json({ success: true });
});

export default router;