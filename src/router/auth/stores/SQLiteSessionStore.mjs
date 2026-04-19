import expressSession from 'express-session';

const Store = expressSession.Store;

export class SQLiteSessionStore extends Store {
    /**
     * @param {Object} databaseAdapter - An instance of DatabaseAdaptor, like SQLiteAdaptor
     */
    constructor(databaseAdapter) {
        super();
        this.db = databaseAdapter.db;
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
            const row = this.db.prepare('SELECT data FROM express_sessions WHERE sid=? AND expires_at > unixepoch()').get(sid);
            if (!row) {
                return callback(null, null);
            }
            callback(null, JSON.parse(row.data));
        } catch (e) {
            callback(e);
        }
    }

    set(sid, session, callback) {
        try {
            const now = Math.floor(Date.now() / 1000);
            const expires = session.cookie && session.cookie.expires
                ? Math.floor(new Date(session.cookie.expires).getTime() / 1000)
                : Math.floor((Date.now() + 7 * 24 * 60 * 60 * 1000) / 1000);
            const data = JSON.stringify(session);
            const userId = session.userId || null;

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
                'SELECT sid, created_at, expires_at, last_activity FROM express_sessions WHERE user_id=? AND expires_at > unixepoch() ORDER BY last_activity DESC'
            ).all(userId);
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
            this.db.prepare('DELETE FROM express_sessions WHERE expires_at <= unixepoch()').run();
        } catch (_) {}
    }
}
