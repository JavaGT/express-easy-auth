import { randomUUID, randomBytes } from 'crypto';
import { authDb } from '../db/init.js';
import bcrypt from 'bcrypt';

const FRESH_AUTH_WINDOW_MS = 5 * 60 * 1000; // 5 minutes

export function requireAuth(req, res, next) {
    if (!req.session?.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    req.userId = req.session.userId; // Convenience attachment
    next();
}

export function requireFreshAuth(req, res, next) {
    if (!req.session?.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    req.userId = req.session.userId; // Ensure it's there too
    const lastAuthed = req.session.lastAuthedAt;

    // Pull dynamic duration from settings
    const rows = authDb.prepare("SELECT value FROM settings WHERE key='session_fresh_auth_mins'").get();
    const durationMins = parseInt(rows?.value || '5', 10);
    const windowMs = durationMins * 60 * 1000;

    if (!lastAuthed || Date.now() - lastAuthed > windowMs) {
        return res.status(403).json({
            error: 'Fresh authentication required',
            code: 'FRESH_AUTH_REQUIRED',
            freshAuthWindowMs: windowMs
        });
    }
    next();
}

/**
 * Middleware to authenticate requests via API Key.
 * Supports X-API-Key header or Authorization: Bearer <key>.
 */
export async function requireApiKey(req, res, next) {
    let key = req.get('X-API-Key');
    if (!key) {
        const authHeader = req.get('Authorization');
        if (authHeader && authHeader.startsWith('Bearer ')) {
            key = authHeader.substring(7);
        }
    }

    if (!key) {
        return res.status(401).json({ error: 'API Key required' });
    }

    const parts = key.split('_');
    if (parts.length < 4) {
        return res.status(401).json({ error: 'Invalid API Key format' });
    }

    const keyId = parts[2];
    const secret = parts[3];

    const apiKey = authDb.prepare('SELECT * FROM api_keys WHERE id = ?').get(keyId);
    if (!apiKey) {
        return res.status(401).json({ error: 'Invalid API Key' });
    }

    const valid = await bcrypt.compare(secret, apiKey.key_hash);
    if (!valid) {
        return res.status(401).json({ error: 'Invalid API Key' });
    }

    // Update last used
    authDb.prepare('UPDATE api_keys SET last_used = ? WHERE id = ?').run(Date.now(), keyId);

    req.userId = apiKey.user_id;
    req.permissions = JSON.parse(apiKey.permissions || '[]');
    next();
}

/**
 * Global error handler that logs to the authentication database
 */
export function authErrorLogger(err, req, res, next) {
    console.error('[error]', err);

    const isProd = process.env.NODE_ENV === 'production';

    // LOG TO DATABASE
    try {
        if (authDb) {
            authDb.prepare(`
                INSERT INTO system_logs (id, level, source, message, stack, context, user_id, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `).run(
                randomUUID(),
                'error',
                'server',
                err.message || String(err),
                err.stack || null,
                JSON.stringify({
                    url: req.url,
                    method: req.method,
                    ip: req.ip,
                    userAgent: req.get('user-agent')
                }),
                req.session?.userId || null,
                Date.now()
            );
        }
    } catch (logErr) {
        console.error('[critical] Failed to write to system_logs:', logErr);
    }

    if (res.headersSent) return next(err);
    res.status(500).json({ error: isProd ? 'Internal server error' : err.message });
}