import { DatabaseSync } from 'node:sqlite';
import fs from 'fs';
import path from 'path';

let authDb;
let userDb;

export function initAuthDb(dataDir) {
  if (!authDb) {
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
    authDb = new DatabaseSync(path.join(dataDir, 'auth.db'));
  }

  authDb.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      totp_enabled INTEGER NOT NULL DEFAULT 0,
      totp_secret TEXT,
      mfa_required INTEGER NOT NULL DEFAULT 0,
      failed_attempts INTEGER NOT NULL DEFAULT 0,
      locked_until INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT, -- Nullable for anonymous/pending sessions
      data TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      last_activity INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS totp_secrets (
      user_id TEXT PRIMARY KEY,
      secret TEXT NOT NULL,
      verified INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS passkeys (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      credential_id TEXT UNIQUE NOT NULL,
      public_key TEXT NOT NULL,
      counter INTEGER NOT NULL DEFAULT 0,
      device_type TEXT,
      backed_up INTEGER NOT NULL DEFAULT 0,
      transports TEXT,
      friendly_name TEXT,
      created_at INTEGER NOT NULL,
      last_used INTEGER,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS webauthn_challenges (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      challenge TEXT NOT NULL,
      type TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS fresh_auth_tokens (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      verified_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    
    CREATE TABLE IF NOT EXISTS recovery_codes (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      code_hash TEXT NOT NULL,
      used INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS system_logs (
      id TEXT PRIMARY KEY,
      level TEXT NOT NULL,
      source TEXT NOT NULL,
      message TEXT NOT NULL,
      stack TEXT,
      context TEXT,
      user_id TEXT,
      timestamp INTEGER NOT NULL
    );
    
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      used INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS api_keys (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      key_hash TEXT UNIQUE NOT NULL,
      name TEXT,
      permissions TEXT, -- JSON string
      created_at INTEGER NOT NULL,
      last_used INTEGER,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT
    );

    -- Seed settings with new grouped keys
    INSERT OR IGNORE INTO settings (key, value) VALUES ('auth_mfa_force_all', 'false');
    INSERT OR IGNORE INTO settings (key, value) VALUES ('auth_mfa_force_new_users', 'false');
    INSERT OR IGNORE INTO settings (key, value) VALUES ('auth_registration_enabled', 'true');
    INSERT OR IGNORE INTO settings (key, value) VALUES ('lockout_duration_mins', '15');
    INSERT OR IGNORE INTO settings (key, value) VALUES ('lockout_max_attempts', '5');
    INSERT OR IGNORE INTO settings (key, value) VALUES ('password_min_length', '8');
    INSERT OR IGNORE INTO settings (key, value) VALUES ('password_reset_expiry_mins', '30');
    INSERT OR IGNORE INTO settings (key, value) VALUES ('session_duration_days', '7');
    INSERT OR IGNORE INTO settings (key, value) VALUES ('session_fresh_auth_mins', '5');
    INSERT OR IGNORE INTO settings (key, value) VALUES ('site_admin_emails', 'admin@example.com');
    INSERT OR IGNORE INTO settings (key, value) VALUES ('site_name', 'Authentication Server');

    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
    CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys(user_id);
    CREATE INDEX IF NOT EXISTS idx_challenges_expires ON webauthn_challenges(expires_at);
    CREATE INDEX IF NOT EXISTS idx_fresh_auth_expires ON fresh_auth_tokens(expires_at);
    CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON system_logs(timestamp);
    CREATE INDEX IF NOT EXISTS idx_logs_level ON system_logs(level);
  `);

  // Migration: Rename old keys if they exist
  const migrateMap = {
    'force_2fa': 'auth_mfa_force_all',
    'enforce_mfa_new_users': 'auth_mfa_force_new_users',
    'registration_enabled': 'auth_registration_enabled',
    'max_login_attempts': 'lockout_max_attempts',
    'min_password_length': 'password_min_length',
    'reset_token_expiry_mins': 'password_reset_expiry_mins',
    'fresh_auth_duration': 'session_fresh_auth_mins',
    'admin_email': 'site_admin_emails'
  };

    for (const [oldKey, newKey] of Object.entries(migrateMap)) {
      try {
        authDb.prepare(`
          UPDATE settings SET key = ? 
          WHERE key = ? AND NOT EXISTS (SELECT 1 FROM settings WHERE key = ?)
        `).run(newKey, oldKey, newKey);
      } catch (e) {
        // Ignore migration errors (e.g. key already migrated)
      }
    }
  
    // Migration: Rename 'name' to 'friendly_name' in passkeys table if it exists
    try {
        const columns = authDb.prepare("PRAGMA table_info(passkeys)").all();
        const hasName = columns.some(c => c.name === 'name');
        const hasFriendlyName = columns.some(c => c.name === 'friendly_name');
        
        if (hasName && !hasFriendlyName) {
            authDb.exec("ALTER TABLE passkeys RENAME COLUMN name TO friendly_name");
        }
    } catch (e) {
        // Ignore table_info errors or if table doesn't exist yet
    }
  }

export function initUserDb(dataDir) {
  if (!userDb) {
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
    userDb = new DatabaseSync(path.join(dataDir, 'users.db'));
  }

  // Profile table removed from core library. Implement in demo if needed.
}

export { authDb, userDb };
export function getAppSettings() {
  const rows = authDb.prepare('SELECT key, value FROM settings').all();
  return rows.reduce((acc, row) => {
    acc[row.key] = row.value;
    return acc;
  }, {});
}
