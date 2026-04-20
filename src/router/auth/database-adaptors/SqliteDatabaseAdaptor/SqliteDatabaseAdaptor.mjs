import DatabaseAdaptor from '../DatabaseAdaptor.mjs';
import { DatabaseSync } from 'node:sqlite'
import { init_statements, statements } from './SqliteDatabaseAdaptor-statements.mjs';
import { ResourceConflictError } from '../../util/errors.mjs';

import fs from 'node:fs';
import path from 'node:path';

export default class SQLiteAdaptor extends DatabaseAdaptor {
    constructor(config) {
        super(config);
        if (config.mkdirp) {
            fs.mkdirSync(path.dirname(config.databasePath), { recursive: true });
        }
        this.db = new DatabaseSync(config.databasePath);
        this.init();
    }

    init() {
        for (const statement of Object.values(init_statements)) {
            this.db.exec(statement);
        }

        // Migrations
        const migrations = [
            'ALTER TABLE authenticators ADD COLUMN name TEXT',
            'ALTER TABLE api_keys ADD COLUMN name TEXT',
            // Seed user_identifiers from existing users.email column
            `INSERT OR IGNORE INTO user_identifiers (user_id, type, value, is_primary, created_at)
             SELECT id, 'email', email, 1, created_at FROM users WHERE email IS NOT NULL`
        ];
        for (const sql of migrations) {
            try { this.db.exec(sql); } catch (err) {}
        }
    }

    async retrieveUserAuthData(user_identifier) {
        const user = this.db.prepare(statements.getUserAuthenticationDataByUserIdentifier).get(user_identifier, user_identifier);
        return user || null;
    }

    async retrieveUserPasswordHash(user_identifier) {
        const user = this.db.prepare(statements.getPasswordHashByUserIdentifier).get(user_identifier, user_identifier);
        return user ? { hash: user.hash, createdAt: user.created_at } : null;
    }

    async getUserById(userId) {
        const user = this.db.prepare(statements.getUserById).get(userId);
        return user || null;
    }

    async createUser(email, passwordHash, displayName) {
        const now = Date.now();
        const stmt = this.db.prepare(statements.createUser);
        let result;
        try {
            result = stmt.get(email, passwordHash, displayName || null, now, now);
        } catch (err) {
            if (err.code === 'ERR_SQLITE_ERROR' && err.message?.includes('UNIQUE constraint failed')) {
                throw new ResourceConflictError(`User already exists with email: ${email}`);
            }
            throw err;
        }
        
        if (result && result.id) {
            // Insert into password_hashes for the library's lookup logic
            this.db.prepare(
                'INSERT INTO password_hashes (user_id, hash, created_at) VALUES (?, ?, ?)'
            ).run(result.id, passwordHash, now);

            // Seed user_identifiers with the email as primary
            this.db.prepare(statements.addUserIdentifier).get(result.id, 'email', email, 1, now);

            return result.id;
        }
        return null;
    }

    async createSession(userId, sessionToken, expiresAt, lastAuthenticatedAt) {
        const now = Date.now();
        const stmt = this.db.prepare(statements.createSession);
        const result = stmt.get(userId, sessionToken, expiresAt, now, lastAuthenticatedAt || now);
        return result ? result.id : null;
    }

    async getSession(sessionToken) {
        const session = this.db.prepare(statements.getSession).get(sessionToken);
        return session || null;
    }

    async deleteSession(sessionToken) {
        this.db.prepare(statements.deleteSession).run(sessionToken);
    }

    async updateSessionLastAuthenticatedAt(sessionToken, timestamp) {
        this.db.prepare(statements.updateSessionLastAuthenticatedAt).run(timestamp, sessionToken);
    }

    async createApiKey(userId, apiKey, name, scopes, expiresAt) {
        const now = Date.now();
        const stmt = this.db.prepare(statements.createApiKey);
        const result = stmt.get(userId, apiKey, name || null, scopes || null, now, expiresAt || null);
        return result ? result.id : null;
    }

    async getApiKey(apiKey) {
        const key = this.db.prepare(statements.getApiKey).get(apiKey);
        return key || null;
    }

    async deleteApiKey(apiKey) {
        this.db.prepare(statements.deleteApiKey).run(apiKey);
    }

    async updateApiKeyScopes(apiKey, scopes) {
        this.db.prepare(statements.updateApiKeyScopes).run(scopes, apiKey);
    }

    async getApiKeysByUserId(userId) {
        return this.db.prepare(statements.getApiKeysByUserId).all(userId);
    }

    async updateUserRequiresTOTP(userId, requires) {
        this.db.prepare(statements.updateUserRequiresTOTP).run(requires ? 1 : 0, userId);
    }

    async updateUserRequiresLoginCode(userId, requires) {
        this.db.prepare(statements.updateUserRequiresLoginCode).run(requires ? 1 : 0, userId);
    }

    async updateUserTotpSecret(userId, secret) {
        this.db.prepare(statements.updateUserTotpSecret).run(secret, userId);
    }

    async deleteUser(userId) {
        // Manually cascade deletes to support existing databases without ON DELETE CASCADE
        this.db.prepare(statements.deleteUserPasswordHashes).run(userId);
        this.db.prepare(statements.deleteUserSessions).run(userId);
        this.db.prepare(statements.deleteUserAuthenticators).run(userId);
        this.db.prepare(statements.deleteUserApiKeys).run(userId);
        this.db.prepare(statements.deleteUserRoles).run(userId);
        this.db.prepare(statements.deleteUser).run(userId);
    }

    // WebAuthn methods
    async getAuthenticatorsByUserId(userId) {
        return this.db.prepare(statements.getAuthenticatorsByUserId).all(userId);
    }

    async getAuthenticatorById(credentialId) {
        return this.db.prepare(statements.getAuthenticatorById).get(credentialId);
    }

    async createAuthenticator(userId, credentialId, publicKey, counter, transports, name) {
        const now = Date.now();
        const stmt = this.db.prepare(statements.createAuthenticator);
        const result = stmt.get(userId, credentialId, publicKey, counter, transports, name || null, now);
        return result ? result.id : null;
    }

    async updateAuthenticatorCounter(credentialId, counter) {
        this.db.prepare(statements.updateAuthenticatorCounter).run(counter, credentialId);
    }

    async updateAuthenticatorName(credentialId, userId, name) {
        this.db.prepare(statements.updateAuthenticatorName).run(name, credentialId, userId);
    }

    async deleteAuthenticator(credentialId, userId) {
        this.db.prepare(statements.deleteAuthenticator).run(credentialId, userId);
    }

    async createInvitation(email, invitationToken, expiresAt) {
        const now = Date.now();
        const stmt = this.db.prepare(statements.createInvitation);
        const result = stmt.get(email, invitationToken, now, expiresAt);
        return result ? result.id : null;
    }

    async getInvitationByToken(invitationToken) {
        const invitation = this.db.prepare(statements.getInvitationByToken).get(invitationToken);
        return invitation || null;
    }

    async getUserRoles(userId) {
        return this.db.prepare(statements.getUserRoles).all(userId);
    }

    async getRolePermissions(roleId) {
        return this.db.prepare(statements.getRolePermissions).all(roleId);
    }

    /**
     * Assign a named role to a user.
     * Creates the role in the `roles` table if it does not already exist,
     * then inserts the `user_roles` record. Both operations are idempotent.
     */
    async assignRole(userId, roleName) {
        const now = Date.now();
        this.db.prepare('INSERT OR IGNORE INTO roles (name) VALUES (?)').run(roleName);
        const role = this.db.prepare('SELECT id FROM roles WHERE name = ?').get(roleName);
        this.db.prepare(
            'INSERT OR IGNORE INTO user_roles (user_id, role_id, created_at) VALUES (?, ?, ?)'
        ).run(userId, role.id, now);
    }

    /**
     * Remove a named role from a user. No-ops silently if the user does not have the role.
     */
    async removeRole(userId, roleName) {
        const role = this.db.prepare('SELECT id FROM roles WHERE name = ?').get(roleName);
        if (!role) return;
        this.db.prepare('DELETE FROM user_roles WHERE user_id = ? AND role_id = ?').run(userId, role.id);
    }

    // Multi-channel Identifiers
    async findUserByIdentifier(value) {
        const user = this.db.prepare(statements.findUserByIdentifier).get(value);
        return user || null;
    }

    async addUserIdentifier(userId, type, value, isPrimary = false) {
        const now = Date.now();
        try {
            const result = this.db.prepare(statements.addUserIdentifier).get(userId, type, value, isPrimary ? 1 : 0, now);
            return result ? result.id : null;
        } catch (err) {
            if (err.code === 'ERR_SQLITE_ERROR' && err.message?.includes('UNIQUE constraint failed')) {
                throw new ResourceConflictError(`Identifier '${value}' is already in use`);
            }
            throw err;
        }
    }

    async removeUserIdentifier(userId, type, value) {
        this.db.prepare(statements.removeUserIdentifier).run(userId, type, value);
    }

    async getUserIdentifiers(userId) {
        return this.db.prepare(statements.getUserIdentifiers).all(userId);
    }

    async setPrimaryIdentifier(userId, type, value) {
        // Clear existing primary for this type, then set the new one
        this.db.prepare(statements.clearPrimaryForType).run(userId, type);
        this.db.prepare(statements.setPrimaryIdentifier).run(userId, type, value);
    }

    // Password Reset Tokens
    async createPasswordResetToken(userId, tokenHash, expiresAt) {
        const now = Date.now();
        const result = this.db.prepare(statements.createPasswordResetToken).get(userId, tokenHash, expiresAt, now);
        return result ? result.id : null;
    }

    async getActivePasswordResetTokens(userId) {
        return this.db.prepare(statements.getActivePasswordResetTokens).all(userId, Date.now());
    }

    async getAllActivePasswordResetTokens() {
        return this.db.prepare(statements.getAllActivePasswordResetTokens).all(Date.now());
    }

    async invalidatePasswordResetToken(tokenHash) {
        this.db.prepare(statements.invalidatePasswordResetToken).run(tokenHash);
    }

    // Password management
    async updateUserPassword(userId, passwordHash) {
        const now = Date.now();
        // Update canonical column
        this.db.prepare(statements.updateUserPassword).run(passwordHash, now, userId);
        // Update password_hashes so AuthenticationValidator (which reads this table) picks up the new password
        this.db.prepare(
            'INSERT INTO password_hashes (user_id, hash, created_at) VALUES (?, ?, ?)'
        ).run(userId, passwordHash, now);
    }

    // Session listing & revocation
    async getSessionsByUserId(userId) {
        return this.db.prepare(statements.getSessionsByUserId).all(userId, Date.now());
    }

    async deleteSessionById(sessionId, userId) {
        this.db.prepare(statements.deleteSessionById).run(sessionId, userId);
    }


    // Email Verification
    async createVerificationToken(userId, tokenHash, expiresAt) {
        const now = Date.now();
        const result = this.db.prepare(statements.createEmailVerificationToken).get(userId, tokenHash, expiresAt, now);
        return result ? result.id : null;
    }

    async getVerificationToken(tokenHash) {
        return this.db.prepare(statements.getEmailVerificationToken).get(tokenHash, Date.now()) || null;
    }

    async invalidateVerificationToken(tokenHash) {
        this.db.prepare(statements.invalidateEmailVerificationToken).run(tokenHash);
    }

    async setUserVerified(userId) {
        this.db.prepare(statements.setUserEmailVerified).run(Date.now(), userId);
    }

    async destroy() {
        this.db.close();
    }
}
