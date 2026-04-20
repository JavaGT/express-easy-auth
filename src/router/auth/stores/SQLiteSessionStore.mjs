import expressSession from 'express-session';

const Store = expressSession.Store;

// Default session TTL: 7 days in milliseconds.
const DEFAULT_SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export class SQLiteSessionStore extends Store {
    /**
     * @param {import('../database-adaptors/DatabaseAdaptor.mjs').default} databaseAdapter
     * @param {object} [options]
     * @param {number} [options.sessionTtlMs=604800000] - Default session TTL in milliseconds (default 7 days).
     */
    constructor(databaseAdapter, options = {}) {
        super();
        this.db = databaseAdapter.getDatabaseSync();
        this.sessionTtlMs = options.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS;
        this._initTable();
        setInterval(() => this._cleanup(), 15 * 60 * 1000).unref();
    }

    _initTable() {
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS express_sessions (
                sid TEXT PRIMARY KEY,
                user_id INTEGER,
                data TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                last_activity INTEGER NOT NULL
            )
        `);
    }

    get(sid, callback) {
        try {
            const row = this.db.prepare('SELECT data FROM express_sessions WHERE sid=? AND expires_at > ?').get(sid, Date.now());
            if (!row) return callback(null, null);
            callback(null, JSON.parse(row.data));
        } catch (e) {
            callback(e);
        }
    }

    set(sid, session, callback) {
        try {
            const now     = Date.now();
            const expires = session.cookie?.expires
                ? new Date(session.cookie.expires).getTime()
                : now + this.sessionTtlMs;
            const data    = JSON.stringify(session);
            const userId  = session.userId || null;

            this.db.prepare(`
                INSERT INTO express_sessions (sid, user_id, data, created_at, expires_at, last_activity)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(sid) DO UPDATE SET
                    data=excluded.data,
                    user_id=excluded.user_id,
                    expires_at=excluded.expires_at,
                    last_activity=excluded.last_activity
            `).run(sid, userId, data, now, expires, now);
            callback(null);
        } catch (e) {
            callback(e);
        }
    }

    destroy(sid, callback) {
        try {
            this.db.prepare('DELETE FROM express_sessions WHERE sid=?').run(sid);
            callback(null);
        } catch (e) {
            callback(e);
        }
    }

    touch(sid, session, callback) {
        this.set(sid, session, callback);
    }

    getAllByUserId(userId, callback) {
        try {
            const rows = this.db.prepare(
                'SELECT sid, created_at, expires_at, last_activity FROM express_sessions WHERE user_id=? AND expires_at > ? ORDER BY last_activity DESC'
            ).all(userId, Date.now());
            callback(null, rows);
        } catch (e) {
            callback(e);
        }
    }

    destroyByUserId(userId, callback) {
        try {
            this.db.prepare('DELETE FROM express_sessions WHERE user_id=?').run(userId);
            callback(null);
        } catch (e) {
            callback(e);
        }
    }

    _cleanup() {
        try {
            this.db.prepare('DELETE FROM express_sessions WHERE expires_at <= ?').run(Date.now());
        } catch (_) {}
    }
}
