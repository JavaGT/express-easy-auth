import session from 'express-session';
import { authDb } from './init.js';

const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

export default class SQLiteSessionStore extends session.Store {
  constructor() {
    super();
    setInterval(() => this._cleanup(), 15 * 60 * 1000).unref();
  }

  get db() { return authDb; }

  get(sid, callback) {
    try {
      const row = this.db
        .prepare('SELECT data FROM sessions WHERE id=? AND expires_at > unixepoch()')
        .get(sid);
      if (!row) {
        console.log(`[session] GET ${sid} -> NOT FOUND`);
        return callback(null, null);
      }
      console.log(`[session] GET ${sid} -> FOUND`);
      callback(null, JSON.parse(row.data));
    } catch (e) {
      console.error(`[session] GET ${sid} -> ERROR`, e);
      callback(e);
    }
  }

  set(sid, session, callback) {
    try {
      const now = Math.floor(Date.now() / 1000);
      const expires = Math.floor((Date.now() + SESSION_TTL_MS) / 1000);
      const data = JSON.stringify(session);
      const userId = session.userId || null;

      this.db.prepare(`
        INSERT INTO sessions (id, user_id, data, created_at, expires_at, last_activity)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          data=excluded.data, 
          user_id=excluded.user_id,
          expires_at=excluded.expires_at, 
          last_activity=excluded.last_activity
      `).run(sid, userId, data, now, expires, now);
      console.log(`[session] SET ${sid} (user: ${userId})`);
      callback(null);
    } catch (e) {
      console.error(`[session] SET ${sid} -> ERROR`, e);
      callback(e);
    }
  }

  destroy(sid, callback) {
    try {
      this.db.prepare('DELETE FROM sessions WHERE id=?').run(sid);
      callback(null);
    } catch (e) { callback(e); }
  }

  touch(sid, session, callback) { this.set(sid, session, callback); }

  _cleanup() {
    try { this.db.prepare('DELETE FROM sessions WHERE expires_at <= unixepoch()').run(); } catch (_) { }
  }
}