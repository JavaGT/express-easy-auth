import DatabaseAdaptor from '../DatabaseAdaptor.mjs';
import { DatabaseSync } from 'node:sqlite';
import { init_statements, statements } from './SqliteDatabaseAdaptor-statements.mjs';
import { ResourceConflictError } from '../../util/errors.mjs';

import fs from 'node:fs';
import path from 'node:path';

export default class SQLiteAdaptor extends DatabaseAdaptor {
    constructor(config = {}) {
        super(config);
        const databasePath = config.databasePath || './data/auth.db';
        const mkdirp = config.mkdirp ?? true;

        if (mkdirp) {
            fs.mkdirSync(path.dirname(databasePath), { recursive: true });
        }
        this.db = new DatabaseSync(databasePath);
        // Do not call init() here — AuthManager.init() calls it once via the DatabaseAdaptor interface.
    }

    init() {
        this.db.exec('PRAGMA journal_mode = WAL');
        this.db.exec('PRAGMA synchronous = NORMAL');
        this.db.exec('PRAGMA foreign_keys = ON');
        for (const statement of Object.values(init_statements)) {
            this.db.exec(statement);
        }
    }

    // --- User ---

    async retrieveUserAuthData(user_identifier) {
        return this.db.prepare(statements.getUserAuthenticationDataByUserIdentifier).get(user_identifier) || null;
    }

    async retrieveUserPasswordHash(user_identifier) {
        const row = this.db.prepare(statements.getPasswordHashByUserIdentifier).get(user_identifier);
        return row ? { hash: row.hash, createdAt: row.created_at } : null;
    }

    async getUserById(userId) {
        return this.db.prepare(statements.getUserById).get(userId) || null;
    }

    async listUsers() {
        return this.db.prepare(statements.listUsers).all();
    }

    async createUser(email, passwordHash, displayName) {
        const now = Date.now();
        let result;
        try {
            result = this.db.prepare(statements.createUser).get(email, passwordHash, displayName || null, now, now);
        } catch (err) {
            if (err.code === 'ERR_SQLITE_ERROR' && err.message?.includes('UNIQUE constraint failed')) {
                throw new ResourceConflictError(`User already exists with email: ${email}`);
            }
            throw err;
        }
        if (result?.id) {
            this.db.prepare(
                'INSERT INTO password_hashes (user_id, hash, created_at) VALUES (?, ?, ?)'
            ).run(result.id, passwordHash, now);
            this.db.prepare(statements.addUserIdentifier).get(result.id, 'email', email, 1, now);
            return result.id;
        }
        return null;
    }

    async deleteUser(userId) {
        const ownedRows = this.db.prepare(statements.getOwnedProjects).all(userId);
        const warnings = [];
        if (ownedRows.length > 0) {
            const projectIds = ownedRows.map(r => r.id);
            warnings.push({
                code: 'USER_OWNS_PROJECTS',
                projectIds,
                message: `User owns ${projectIds.length} project(s) that are now ownerless: ${projectIds.join(', ')}`,
            });
            this.db.prepare(statements.nullProjectOwnerByUser).run(Date.now(), userId);
        }
        // FK ON DELETE CASCADE handles all child rows; delete the root record.
        this.db.prepare('DELETE FROM users WHERE id = ?').run(userId);
        return { deleted: true, warnings };
    }

    // --- WebAuthn ---

    async getAuthenticatorsByUserId(userId) {
        return this.db.prepare(statements.getAuthenticatorsByUserId).all(userId);
    }

    async getAuthenticatorById(credentialId) {
        return this.db.prepare(statements.getAuthenticatorById).get(credentialId);
    }

    async createAuthenticator(userId, credentialId, publicKey, counter, transports, name) {
        const now = Date.now();
        const result = this.db.prepare(statements.createAuthenticator).get(userId, credentialId, publicKey, counter, transports, name || null, now);
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

    // --- v4: Projects ---

    async registerProject(projectId, ownerId) {
        const now = Date.now();
        this.db.prepare(statements.registerProject).run(projectId, ownerId, now, now);
    }

    async unregisterProject(projectId) {
        this.db.prepare(statements.unregisterProject).run(projectId);
    }

    async getProject(projectId) {
        return this.db.prepare(statements.getProject).get(projectId) || null;
    }

    async getOwnedProjects(userId) {
        return this.db.prepare(statements.getOwnedProjects).all(userId).map(r => r.id);
    }

    async isProjectOwner(projectId, userId) {
        const project = this.db.prepare(statements.getProject).get(projectId);
        return project ? project.owner_id === userId : false;
    }

    async setProjectOwner(projectId, newOwnerId) {
        this.db.prepare(statements.setProjectOwner).run(newOwnerId, Date.now(), projectId);
    }

    // --- v4: Server Scopes ---

    async grantServerScope(userId, scope, grantedBy) {
        const now = Date.now();
        this.db.prepare(statements.grantServerScope).run(userId, scope, grantedBy ?? null, now);
    }

    async revokeServerScope(userId, scope) {
        this.db.prepare(statements.revokeServerScope).run(userId, scope);
    }

    async getUserServerScopes(userId) {
        return this.db.prepare(statements.getUserServerScopes).all(userId).map(r => r.scope);
    }

    // --- v4: API Keys ---

    async createApiKey(userId, keyHash, keyPrefix, name, expiresAt) {
        const now = Date.now();
        const result = this.db.prepare(statements.createApiKey).get(userId, keyHash, keyPrefix, name, expiresAt ?? null, now);
        return result ? result.id : null;
    }

    async getApiKeyByHash(keyHash) {
        return this.db.prepare(statements.getApiKeyByHash).get(keyHash) || null;
    }

    async getApiKeyById(keyId) {
        return this.db.prepare(statements.getApiKeyById).get(keyId) || null;
    }

    async deleteApiKeyById(keyId, userId) {
        this.db.prepare(statements.deleteApiKeyById).run(keyId, userId);
    }

    async deleteApiKeyByIdAdmin(keyId) {
        this.db.prepare(statements.deleteApiKeyByIdAdmin).run(keyId);
    }

    async listApiKeysByUserId(userId) {
        return this.db.prepare(statements.listApiKeysByUserId).all(userId);
    }

    async updateApiKey(keyId, userId, name, expiresAt, clearExpiry = false) {
        this.db.prepare(statements.updateApiKey).run(name ?? null, clearExpiry ? 1 : 0, expiresAt ?? null, keyId, userId);
    }

    touchApiKeyLastUsed(keyId) {
        try {
            this.db.prepare(statements.touchApiKeyLastUsed).run(Date.now(), keyId);
        } catch (_) {}
    }

    // --- v4: API Key Grants ---

    async upsertServerGrant(keyId, scopes) {
        this.db.prepare(statements.upsertServerGrant).run(keyId, JSON.stringify(scopes));
    }

    async upsertPersonalGrant(keyId, scopes) {
        this.db.prepare(statements.upsertPersonalGrant).run(keyId, JSON.stringify(scopes));
    }

    async upsertProjectGrant(keyId, projectId, scopes) {
        this.db.prepare(statements.upsertProjectGrant).run(keyId, projectId, JSON.stringify(scopes));
    }

    async getServerGrant(keyId) {
        const row = this.db.prepare(statements.getServerGrant).get(keyId);
        return row ? JSON.parse(row.scopes) : [];
    }

    async getPersonalGrant(keyId) {
        const row = this.db.prepare(statements.getPersonalGrant).get(keyId);
        return row ? JSON.parse(row.scopes) : [];
    }

    async getAllProjectGrants(keyId) {
        const rows = this.db.prepare(statements.getAllProjectGrants).all(keyId);
        const map = {};
        for (const row of rows) {
            map[row.project_id] = JSON.parse(row.scopes);
        }
        return map;
    }

    getServerGrantsBatch(keyIds) {
        if (!keyIds.length) return {};
        const ph   = keyIds.map(() => '?').join(',');
        const rows = this.db.prepare(`SELECT api_key_id, scopes FROM api_key_server_grant WHERE api_key_id IN (${ph})`).all(...keyIds);
        const map  = {};
        for (const row of rows) map[row.api_key_id] = JSON.parse(row.scopes);
        return map;
    }

    getPersonalGrantsBatch(keyIds) {
        if (!keyIds.length) return {};
        const ph   = keyIds.map(() => '?').join(',');
        const rows = this.db.prepare(`SELECT api_key_id, scopes FROM api_key_personal_grant WHERE api_key_id IN (${ph})`).all(...keyIds);
        const map  = {};
        for (const row of rows) map[row.api_key_id] = JSON.parse(row.scopes);
        return map;
    }

    getAllProjectGrantsBatch(keyIds) {
        if (!keyIds.length) return {};
        const ph   = keyIds.map(() => '?').join(',');
        const rows = this.db.prepare(`SELECT api_key_id, project_id, scopes FROM api_key_project_grants WHERE api_key_id IN (${ph})`).all(...keyIds);
        const map  = {};
        for (const row of rows) {
            if (!map[row.api_key_id]) map[row.api_key_id] = [];
            map[row.api_key_id].push({ projectId: row.project_id, scopes: JSON.parse(row.scopes) });
        }
        return map;
    }

    // --- User identifiers ---

    async findUserByIdentifier(value) {
        return this.db.prepare(statements.findUserByIdentifier).get(value) || null;
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
        this.db.prepare(statements.clearPrimaryForType).run(userId, type);
        this.db.prepare(statements.setPrimaryIdentifier).run(userId, type, value);
    }

    // --- Password Reset Tokens ---

    async createPasswordResetToken(userId, tokenHash, expiresAt) {
        const now = Date.now();
        const result = this.db.prepare(statements.createPasswordResetToken).get(userId, tokenHash, expiresAt, now);
        return result ? result.id : null;
    }

    async getActivePasswordResetToken(tokenHash) {
        return this.db.prepare(statements.getActivePasswordResetToken).get(tokenHash, Date.now()) || null;
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

    async invalidateAllPasswordResetTokensByUser(userId) {
        this.db.prepare(statements.invalidateAllPasswordResetTokensByUser).run(userId);
    }

    // --- Password management ---

    async updateUserPassword(userId, passwordHash) {
        const now = Date.now();
        this.db.prepare(statements.updateUserPassword).run(passwordHash, now, userId);
        this.db.prepare(
            'INSERT INTO password_hashes (user_id, hash, created_at) VALUES (?, ?, ?)'
        ).run(userId, passwordHash, now);
        // Keep only the 5 most recent hashes; prune older ones.
        this.db.prepare(`
            DELETE FROM password_hashes WHERE user_id = ? AND id NOT IN (
                SELECT id FROM password_hashes WHERE user_id = ? ORDER BY created_at DESC LIMIT 5
            )
        `).run(userId, userId);
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

    // --- Email Verification ---

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

    // --- Invitations ---

    async createInvitation(email, invitationToken, expiresAt) {
        const now = Date.now();
        const result = this.db.prepare(statements.createInvitation).get(email, invitationToken, now, expiresAt);
        return result ? result.id : null;
    }

    async getInvitationByToken(invitationToken) {
        return this.db.prepare(statements.getInvitationByToken).get(invitationToken) || null;
    }

    getDatabaseSync() {
        return this.db;
    }

    async destroy() {
        this.db.close();
    }
}
