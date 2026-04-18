export const init_statements = {
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
    createSessionsTable: `
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token TEXT NOT NULL UNIQUE,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            last_authenticated_at INTEGER,
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
    createApiKeysTable: `
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            api_key TEXT NOT NULL UNIQUE,
            name TEXT,
            scopes TEXT,
            created_at INTEGER NOT NULL,
            expires_at INTEGER,
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
    createRolesTable: `
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT
        )
    `,
    createPermissionsTable: `
        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT
        )
    `,
    createUserRolesTable: `
        CREATE TABLE IF NOT EXISTS user_roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            role_id INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
        )
    `,
    createRolePermissionsTable: `
        CREATE TABLE IF NOT EXISTS role_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            role_id INTEGER NOT NULL,
            permission_id INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (role_id) REFERENCES roles(id),
            FOREIGN KEY (permission_id) REFERENCES permissions(id)
        )
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
    createPasswordResetTokensTable: `
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL,
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
    `
}

export const statements = {
    // Password hashes
    getPasswordHashByUserIdentifier: `
        SELECT ph.hash, ph.created_at 
        FROM password_hashes ph
        JOIN users u ON ph.user_id = u.id
        WHERE u.email = ? OR u.id = ?
        ORDER BY ph.created_at DESC
        LIMIT 1
    `,
    
    // User lookup
    getUserAuthenticationDataByUserIdentifier: `
        SELECT id, email, display_name, password, totp_secret, requires_totp, requires_login_code
        FROM users 
        WHERE email = ? OR id = ?
        LIMIT 1
    `,
    
    getUserById: `
        SELECT id, email, display_name, totp_secret, requires_totp, requires_login_code
        FROM users 
        WHERE id = ?
        LIMIT 1
    `,

    // User updates
    updateUserTotpSecret: `
        UPDATE users SET totp_secret = ? WHERE id = ?
    `,

    // User creation
    createUser: `
        INSERT INTO users (email, password, display_name, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        RETURNING id
    `,

    // Sessions
    createSession: `
        INSERT INTO sessions (user_id, session_token, expires_at, created_at, last_authenticated_at)
        VALUES (?, ?, ?, ?, ?)
        RETURNING id
    `,
    
    getSession: `
        SELECT s.id, s.user_id, s.session_token, s.expires_at, s.last_authenticated_at, u.email, u.display_name
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.session_token = ?
        LIMIT 1
    `,
    
    deleteSession: `
        DELETE FROM sessions WHERE session_token = ?
    `,

    updateSessionLastAuthenticatedAt: `
        UPDATE sessions SET last_authenticated_at = ? WHERE session_token = ?
    `,

    // WebAuthn
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

    // API keys
    createApiKey: `
        INSERT INTO api_keys (user_id, api_key, name, scopes, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        RETURNING id
    `,
    
    getApiKey: `
        SELECT ak.id, ak.user_id, ak.api_key, ak.name, ak.scopes, ak.expires_at, u.email, u.display_name
        FROM api_keys ak
        JOIN users u ON ak.user_id = u.id
        WHERE ak.api_key = ?
        LIMIT 1
    `,
    
    deleteApiKey: `
        DELETE FROM api_keys WHERE api_key = ?
    `,

    getApiKeysByUserId: `
        SELECT ak.id, ak.api_key, ak.name, ak.scopes, ak.created_at, ak.expires_at
        FROM api_keys ak
        WHERE ak.user_id = ?
    `,

    updateApiKeyScopes: `
        UPDATE api_keys SET scopes = ? WHERE api_key = ?
    `,

    // User updates
    updateUserRequiresTOTP: `
        UPDATE users SET requires_totp = ? WHERE id = ?
    `,
    
    updateUserRequiresLoginCode: `
        UPDATE users SET requires_login_code = ? WHERE id = ?
    `,

    deleteUser: `
        DELETE FROM users WHERE id = ?
    `,
    deleteUserPasswordHashes: `
        DELETE FROM password_hashes WHERE user_id = ?
    `,
    deleteUserSessions: `
        DELETE FROM sessions WHERE user_id = ?
    `,
    deleteUserAuthenticators: `
        DELETE FROM authenticators WHERE user_id = ?
    `,
    deleteUserApiKeys: `
        DELETE FROM api_keys WHERE user_id = ?
    `,
    deleteUserRoles: `
        DELETE FROM user_roles WHERE user_id = ?
    `,

    // Invitations
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

    // Roles
    getUserRoles: `
        SELECT r.name, r.description
        FROM roles r
        JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = ?
    `,
    
    getRolePermissions: `
        SELECT p.name, p.description
        FROM permissions p
        JOIN role_permissions rp ON p.id = rp.permission_id
        JOIN roles r ON rp.role_id = r.id
        WHERE r.id = ?
    `,

    // User Identifiers
    findUserByIdentifier: `
        SELECT u.id, u.email, u.display_name, u.password, u.totp_secret, u.requires_totp, u.requires_login_code,
               ui.value as primary_contact, ui.type as primary_contact_type
        FROM users u
        JOIN user_identifiers ui ON u.id = ui.user_id
        WHERE ui.value = ?
        LIMIT 1
    `,
    addUserIdentifier: `
        INSERT OR IGNORE INTO user_identifiers (user_id, type, value, is_primary, created_at)
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

    // Password Reset Tokens
    createPasswordResetToken: `
        INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, created_at)
        VALUES (?, ?, ?, ?)
        RETURNING id
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

    // Password management
    updateUserPassword: `
        UPDATE users SET password = ?, updated_at = ? WHERE id = ?
    `,

    // Session listing & revocation
    getSessionsByUserId: `
        SELECT id, session_token, expires_at, created_at, last_authenticated_at
        FROM sessions
        WHERE user_id = ? AND expires_at > ?
        ORDER BY last_authenticated_at DESC
    `,
    deleteSessionById: `
        DELETE FROM sessions WHERE id = ? AND user_id = ?
    `,

    // Email Verification Tokens
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
    `
};
