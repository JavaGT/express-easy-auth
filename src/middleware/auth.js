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
    if (!lastAuthed || Date.now() - lastAuthed > FRESH_AUTH_WINDOW_MS) {
        return res.status(403).json({
            error: 'Fresh authentication required',
            code: 'FRESH_AUTH_REQUIRED',
            freshAuthWindowMs: FRESH_AUTH_WINDOW_MS
        });
    }
    next();
}