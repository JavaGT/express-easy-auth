import express from 'express';
import { randomUUID, randomBytes } from 'crypto';
import bcrypt from 'bcrypt';
import { authDb, userDb } from '../db/init.js';
import { requireAuth, requireFreshAuth } from '../middleware/auth.js';

const router = express.Router();

// ─── PROFILE ─────────────────────────────────────────────────────────────────

router.get('/me', requireAuth, (req, res) => {
    const user = authDb.prepare(
        'SELECT id, username, email, created_at FROM users WHERE id = ?'
    ).get(req.userId);

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

router.post('/sensitive-action', requireAuth, requireFreshAuth, (req, res) => {
    const { action, data } = req.body;
    const allowedActions = ['export-data', 'delete-account-request', 'change-email', 'view-secret'];

    if (!action || !allowedActions.includes(action)) {
        return res.status(400).json({ error: 'Invalid action', allowedActions });
    }

    const user = authDb.prepare('SELECT id, username, email FROM users WHERE id = ?').get(req.userId);

    let result;
    switch (action) {
        case 'export-data':
            const profile = userDb.prepare('SELECT * FROM profiles WHERE user_id = ?').get(req.userId);
            const passkeys = authDb.prepare('SELECT name, device_type, created_at FROM passkeys WHERE user_id = ?').all(req.userId);
            result = { user: { username: user.username, email: user.email }, profile, passkeys, exportedAt: new Date().toISOString() };
            break;
        case 'view-secret':
            result = { secret: `TOP_SECRET_${user.id.substring(0, 8).toUpperCase()}`, message: 'This is your secret token — never share it!', generatedAt: new Date().toISOString() };
            break;
        case 'change-email':
            const { newEmail } = data || {};
            if (!newEmail) return res.status(400).json({ error: 'newEmail required' });
            result = { message: 'Verification email sent to ' + newEmail };
            break;
        case 'delete-account-request':
            result = { message: 'Account deletion requested. You have 30 days to cancel.', cancelToken: 'CANCEL_' + user.id.substring(0, 8).toUpperCase(), scheduledFor: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString() };
            break;
    }

    res.json({ success: true, action, result, performedAt: new Date().toISOString(), performedBy: user.username });
});

// ─── SESSIONS ─────────────────────────────────────────────────────────────────

router.get('/sessions', requireAuth, (req, res) => {
    const sessions = authDb.prepare(`
    SELECT id, created_at, expires_at, last_activity
    FROM sessions WHERE user_id = ? AND expires_at > ?
    ORDER BY last_activity DESC
  `).all(req.userId, Math.floor(Date.now() / 1000));

    res.json({ sessions: sessions.map(s => ({ ...s, isCurrent: s.id === req.sessionID })) });
});

router.delete('/sessions/:id', requireAuth, (req, res) => {
    const { id } = req.params;
    if (id === req.sessionID) return res.status(400).json({ error: 'Cannot revoke current session' });
    const session = authDb.prepare('SELECT id FROM sessions WHERE id = ? AND user_id = ?').get(id, req.userId);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    authDb.prepare('DELETE FROM sessions WHERE id = ?').run(id);
    res.json({ success: true });
});

// ─── API KEYS ────────────────────────────────────────────────────────────────

router.get('/keys', requireAuth, (req, res) => {
    const keys = authDb.prepare(`
    SELECT id, name, permissions, created_at, last_used
    FROM api_keys WHERE user_id = ?
    ORDER BY created_at DESC
  `).all(req.userId);

    res.json({ keys: keys.map(k => ({ ...k, permissions: JSON.parse(k.permissions || '[]') })) });
});

router.post('/keys', requireAuth, async (req, res) => {
    const { name, permissions } = req.body;
    if (!name) return res.status(400).json({ error: 'Name is required' });
    
    const allowed = ['action:read', 'action:write'];
    const validPermissions = (permissions || []).filter(p => allowed.includes(p));

    const keyId = randomUUID().replace(/-/g, '').substring(0, 16);
    const secret = randomBytes(24).toString('base64').replace(/[^a-zA-Z0-9]/g, '');
    const rawKey = `sk_live_${keyId}_${secret}`;
    const hash = await bcrypt.hash(secret, 10);

    const now = Date.now();
    authDb.prepare('INSERT INTO api_keys (id, user_id, key_hash, name, permissions, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(keyId, req.userId, hash, name, JSON.stringify(validPermissions), now);

    res.status(201).json({ success: true, key: rawKey, metadata: { id: keyId, name, permissions: validPermissions, createdAt: now } });
});

router.delete('/keys/:id', requireAuth, (req, res) => {
    const { id } = req.params;
    const key = authDb.prepare('SELECT id FROM api_keys WHERE id = ? AND user_id = ?').get(id, req.userId);
    if (!key) return res.status(404).json({ error: 'API Key not found' });
    authDb.prepare('DELETE FROM api_keys WHERE id = ?').run(id);
    res.json({ success: true });
});

export default router;
