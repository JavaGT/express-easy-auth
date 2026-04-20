export const init_statements = {
    // --- Core identity tables ---
    // NOTE: users.email is the canonical primary email and must stay in sync
    // with the 'email' row in user_identifiers (type='email', is_primary=1).
    // createUser() inserts both atomically. addUserIdentifier() manages extras.
    createUsersTable: `
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            display_name TEXT,
            password TEXT NOT NULL,
            totp_secret TEXT,
            requires_totp INTEGER DEFAULT 0,
            requires_login_code INTEGER DEFAULT 0,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )
    `,
    createPasswordHashesTable: `
        CREATE TABLE IF NOT EXISTS password_hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            hash TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `,
    createAuthenticatorsTable: `
        CREATE TABLE IF NOT EXISTS authenticators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            credential_id TEXT NOT NULL UNIQUE,
            public_key BLOB NOT NULL,
            counter INTEGER DEFAULT 0,
            transports TEXT,
            name TEXT,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `,
    createAuthenticatorsUserIndex: `
        CREATE INDEX IF NOT EXISTS idx_authenticators_user ON authenticators(user_id)
    `,
    createUserIdentifiersTable: `
        CREATE TABLE IF NOT EXISTS user_identifiers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL CHECK(type IN ('email', 'phone', 'username')),
            value TEXT NOT NULL,
            is_primary INTEGER NOT NULL DEFAULT 0,
            verified_at INTEGER,
            created_at INTEGER NOT NULL,
            UNIQUE(type, value),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `,
    createUserIdentifiersUserIndex: `
        CREATE INDEX IF NOT EXISTS idx_user_identifiers_user ON user_identifiers(user_id)
    `,
    createUserIdentifiersValueIndex: `
        CREATE INDEX IF NOT EXISTS idx_user_identifiers_value ON user_identifiers(value)
    `,
    createPasswordResetTokensTable: `
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at INTEGER NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `,
    createEmailVerificationTokensTable: `
        CREATE TABLE IF NOT EXISTS email_verification_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at INTEGER NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `,
    createInvitationsTable: `
        CREATE TABLE IF NOT EXISTS invitations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            invitation_token TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )
    `,

    // --- v4: Projects ---
    // Stores only what the auth library needs: existence and ownership.
    // All other project data lives in the app's own database.
    createProjectsTable: `
        CREATE TABLE IF NOT EXISTS projects (
            id         TEXT PRIMARY KEY,
            owner_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )
    `,
    createProjectsOwnerIndex: `
        CREATE INDEX IF NOT EXISTS idx_projects_owner ON projects(owner_id)
    `,

    // --- v4: Server Scopes ---
    createUserServerScopesTable: `
        CREATE TABLE IF NOT EXISTS user_server_scopes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            scope      TEXT NOT NULL,
            granted_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            created_at INTEGER NOT NULL,
            UNIQUE(user_id, scope)
        )
    `,
    createUserServerScopesIndex: `
        CREATE INDEX IF NOT EXISTS idx_uss_user ON user_server_scopes(user_id)
    `,

    // --- v4: API Keys ---
    // Raw key is never stored. Only SHA-256 hash + display prefix.
    createApiKeysTable: `
        CREATE TABLE IF NOT EXISTS api_keys (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            key_hash     TEXT UNIQUE NOT NULL,
            key_prefix   TEXT NOT NULL,
            name         TEXT NOT NULL,
            expires_at   INTEGER,
            created_at   INTEGER NOT NULL,
            last_used_at INTEGER
        )
    `,
    createApiKeysUserIndex: `
        CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id)
    `,

    // --- v4: API Key Grants ---
    // Three separate tables to avoid the NULL-in-UNIQUE footgun.
    // At most one server grant and one personal grant per key.
    createApiKeyServerGrantTable: `
        CREATE TABLE IF NOT EXISTS api_key_server_grant (
            api_key_id INTEGER PRIMARY KEY REFERENCES api_keys(id) ON DELETE CASCADE,
            scopes     TEXT NOT NULL
        )
    `,
    createApiKeyPersonalGrantTable: `
        CREATE TABLE IF NOT EXISTS api_key_personal_grant (
            api_key_id INTEGER PRIMARY KEY REFERENCES api_keys(id) ON DELETE CASCADE,
            scopes     TEXT NOT NULL
        )
    `,
    createApiKeyProjectGrantsTable: `
        CREATE TABLE IF NOT EXISTS api_key_project_grants (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            api_key_id INTEGER NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            scopes     TEXT NOT NULL,
            UNIQUE(api_key_id, project_id)
        )
    `,
    createApiKeyProjectGrantsKeyIndex: `
        CREATE INDEX IF NOT EXISTS idx_akpg_key     ON api_key_project_grants(api_key_id)
    `,
    createApiKeyProjectGrantsProjectIndex: `
        CREATE INDEX IF NOT EXISTS idx_akpg_project ON api_key_project_grants(project_id)
    `,
};

export const statements = {
    // --- Password hashes ---
    getPasswordHashByUserIdentifier: `
        SELECT ph.hash, ph.created_at
        FROM password_hashes ph
        JOIN users u ON ph.user_id = u.id
        WHERE u.email = ?
        ORDER BY ph.created_at DESC
        LIMIT 1
    `,

    // --- User lookup ---
    getUserAuthenticationDataByUserIdentifier: `
        SELECT id, email, display_name, password, totp_secret, requires_totp, requires_login_code
        FROM users
        WHERE email = ?
        LIMIT 1
    `,
    getUserById: `
        SELECT id, email, display_name, totp_secret, requires_totp, requires_login_code
        FROM users
        WHERE id = ?
        LIMIT 1
    `,
    updateUserTotpSecret: `
        UPDATE users SET totp_secret = ? WHERE id = ?
    `,
    createUser: `
        INSERT INTO users (email, password, display_name, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        RETURNING id
    `,

    // --- WebAuthn ---
    getAuthenticatorsByUserId: `
        SELECT id, user_id, credential_id, public_key, counter, transports, name
        FROM authenticators
        WHERE user_id = ?
    `,
    getAuthenticatorById: `
        SELECT id, user_id, credential_id, public_key, counter, transports, name
        FROM authenticators
        WHERE credential_id = ?
    `,
    createAuthenticator: `
        INSERT INTO authenticators (user_id, credential_id, public_key, counter, transports, name, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        RETURNING id
    `,
    updateAuthenticatorCounter: `
        UPDATE authenticators SET counter = ? WHERE credential_id = ?
    `,
    updateAuthenticatorName: `
        UPDATE authenticators SET name = ? WHERE credential_id = ? AND user_id = ?
    `,
    deleteAuthenticator: `
        DELETE FROM authenticators WHERE credential_id = ? AND user_id = ?
    `,

    // --- v4: Projects ---
    registerProject: `
        INSERT INTO projects (id, owner_id, created_at, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(id) DO NOTHING
    `,
    unregisterProject: `
        DELETE FROM projects WHERE id = ?
    `,
    getProject: `
        SELECT id, owner_id, created_at, updated_at FROM projects WHERE id = ?
    `,
    getOwnedProjects: `
        SELECT id FROM projects WHERE owner_id = ?
    `,
    setProjectOwner: `
        UPDATE projects SET owner_id = ?, updated_at = ? WHERE id = ?
    `,
    nullProjectOwnerByUser: `
        UPDATE projects SET owner_id = NULL, updated_at = ? WHERE owner_id = ?
    `,

    // --- v4: Server Scopes ---
    grantServerScope: `
        INSERT OR IGNORE INTO user_server_scopes (user_id, scope, granted_by, created_at)
        VALUES (?, ?, ?, ?)
    `,
    revokeServerScope: `
        DELETE FROM user_server_scopes WHERE user_id = ? AND scope = ?
    `,
    getUserServerScopes: `
        SELECT scope FROM user_server_scopes WHERE user_id = ?
    `,

    // --- v4: API Keys ---
    createApiKey: `
        INSERT INTO api_keys (user_id, key_hash, key_prefix, name, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        RETURNING id
    `,
    getApiKeyByHash: `
        SELECT ak.id, ak.user_id, ak.key_prefix, ak.name, ak.expires_at, ak.created_at, ak.last_used_at
        FROM api_keys ak
        WHERE ak.key_hash = ?
        LIMIT 1
    `,
    getApiKeyById: `
        SELECT id, user_id, key_prefix, name, expires_at, created_at, last_used_at
        FROM api_keys WHERE id = ?
    `,
    deleteApiKeyById: `
        DELETE FROM api_keys WHERE id = ? AND user_id = ?
    `,
    deleteApiKeyByIdAdmin: `
        DELETE FROM api_keys WHERE id = ?
    `,
    listApiKeysByUserId: `
        SELECT id, key_prefix, name, expires_at, created_at, last_used_at
        FROM api_keys WHERE user_id = ?
        ORDER BY created_at DESC
    `,
    updateApiKey: `
        UPDATE api_keys
        SET name       = COALESCE(?, name),
            expires_at = CASE WHEN ? = 1 THEN NULL ELSE COALESCE(?, expires_at) END
        WHERE id = ? AND user_id = ?
    `,
    touchApiKeyLastUsed: `
        UPDATE api_keys SET last_used_at = ? WHERE id = ?
    `,

    // --- v4: API Key Grants ---
    upsertServerGrant: `
        INSERT INTO api_key_server_grant (api_key_id, scopes) VALUES (?, ?)
        ON CONFLICT(api_key_id) DO UPDATE SET scopes = excluded.scopes
    `,
    upsertPersonalGrant: `
        INSERT INTO api_key_personal_grant (api_key_id, scopes) VALUES (?, ?)
        ON CONFLICT(api_key_id) DO UPDATE SET scopes = excluded.scopes
    `,
    upsertProjectGrant: `
        INSERT INTO api_key_project_grants (api_key_id, project_id, scopes) VALUES (?, ?, ?)
        ON CONFLICT(api_key_id, project_id) DO UPDATE SET scopes = excluded.scopes
    `,
    getServerGrant: `
        SELECT scopes FROM api_key_server_grant WHERE api_key_id = ?
    `,
    getPersonalGrant: `
        SELECT scopes FROM api_key_personal_grant WHERE api_key_id = ?
    `,
    getAllProjectGrants: `
        SELECT project_id, scopes FROM api_key_project_grants WHERE api_key_id = ?
    `,

    listUsers: `
        SELECT id, email, display_name, created_at, updated_at FROM users ORDER BY created_at DESC
    `,

    // --- User identifiers ---
    findUserByIdentifier: `
        SELECT u.id, u.email, u.display_name, u.password, u.totp_secret, u.requires_totp, u.requires_login_code,
               ui.value as primary_contact, ui.type as primary_contact_type
        FROM users u
        JOIN user_identifiers ui ON u.id = ui.user_id
        WHERE ui.value = ?
        LIMIT 1
    `,
    addUserIdentifier: `
        INSERT INTO user_identifiers (user_id, type, value, is_primary, created_at)
        VALUES (?, ?, ?, ?, ?)
        RETURNING id
    `,
    removeUserIdentifier: `
        DELETE FROM user_identifiers WHERE user_id = ? AND type = ? AND value = ?
    `,
    getUserIdentifiers: `
        SELECT id, type, value, is_primary, verified_at, created_at
        FROM user_identifiers
        WHERE user_id = ?
        ORDER BY is_primary DESC, created_at ASC
    `,
    clearPrimaryForType: `
        UPDATE user_identifiers SET is_primary = 0 WHERE user_id = ? AND type = ?
    `,
    setPrimaryIdentifier: `
        UPDATE user_identifiers SET is_primary = 1 WHERE user_id = ? AND type = ? AND value = ?
    `,

    // --- Password Reset Tokens ---
    createPasswordResetToken: `
        INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, created_at)
        VALUES (?, ?, ?, ?)
        RETURNING id
    `,
    getActivePasswordResetToken: `
        SELECT id, user_id, expires_at
        FROM password_reset_tokens
        WHERE token_hash = ? AND used = 0 AND expires_at > ?
        LIMIT 1
    `,
    getActivePasswordResetTokens: `
        SELECT id, user_id, token_hash, expires_at
        FROM password_reset_tokens
        WHERE user_id = ? AND used = 0 AND expires_at > ?
    `,
    getAllActivePasswordResetTokens: `
        SELECT id, user_id, token_hash, expires_at
        FROM password_reset_tokens
        WHERE used = 0 AND expires_at > ?
    `,
    invalidatePasswordResetToken: `
        UPDATE password_reset_tokens SET used = 1 WHERE token_hash = ?
    `,
    invalidateAllPasswordResetTokensByUser: `
        UPDATE password_reset_tokens SET used = 1 WHERE user_id = ? AND used = 0
    `,

    // --- Password management ---
    updateUserPassword: `
        UPDATE users SET password = ?, updated_at = ? WHERE id = ?
    `,
    updateUserRequiresTOTP: `
        UPDATE users SET requires_totp = ? WHERE id = ?
    `,
    updateUserRequiresLoginCode: `
        UPDATE users SET requires_login_code = ? WHERE id = ?
    `,

    // --- Email Verification Tokens ---
    createEmailVerificationToken: `
        INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, created_at)
        VALUES (?, ?, ?, ?)
        RETURNING id
    `,
    getEmailVerificationToken: `
        SELECT id, user_id, token_hash, expires_at, used
        FROM email_verification_tokens
        WHERE token_hash = ? AND used = 0 AND expires_at > ?
        LIMIT 1
    `,
    invalidateEmailVerificationToken: `
        UPDATE email_verification_tokens SET used = 1 WHERE token_hash = ?
    `,
    setUserEmailVerified: `
        UPDATE user_identifiers
        SET verified_at = ?
        WHERE user_id = ? AND type = 'email' AND verified_at IS NULL
    `,

    // --- Invitations ---
    createInvitation: `
        INSERT INTO invitations (email, invitation_token, created_at, expires_at)
        VALUES (?, ?, ?, ?)
        RETURNING id
    `,
    getInvitationByToken: `
        SELECT id, email, invitation_token, created_at, expires_at
        FROM invitations
        WHERE invitation_token = ?
        LIMIT 1
    `,
};
