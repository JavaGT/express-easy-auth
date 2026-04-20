export default class DatabaseAdaptor {
    constructor(config) {
        this.config = config;
    }

    async init() { throw new Error('init not implemented'); }
    async destroy() { throw new Error('destroy not implemented'); }

    /**
     * Return the underlying synchronous database connection.
     * Required by SQLiteSessionStore to manage express_sessions directly.
     * Custom adaptors that want to use SQLiteSessionStore must implement this.
     */
    getDatabaseSync() { throw new Error('getDatabaseSync not implemented'); }

    // --- User ---
    async retrieveUserAuthData(user_identifier) { throw new Error('retrieveUserAuthData not implemented'); }
    async retrieveUserPasswordHash(user_identifier) { throw new Error('retrieveUserPasswordHash not implemented'); }
    async getUserById(userId) { throw new Error('getUserById not implemented'); }
    async listUsers() { throw new Error('listUsers not implemented'); }
    async createUser(email, passwordHash, displayName) { throw new Error('createUser not implemented'); }
    /** @returns {{ deleted: true, warnings: Array<{ code: string, projectIds: string[], message: string }> }} */
    async deleteUser(userId) { throw new Error('deleteUser not implemented'); }

    // --- WebAuthn ---
    async getAuthenticatorsByUserId(userId) { throw new Error('getAuthenticatorsByUserId not implemented'); }
    async getAuthenticatorById(credentialId) { throw new Error('getAuthenticatorById not implemented'); }
    async createAuthenticator(userId, credentialId, publicKey, counter, transports, name) { throw new Error('createAuthenticator not implemented'); }
    async updateAuthenticatorCounter(credentialId, counter) { throw new Error('updateAuthenticatorCounter not implemented'); }
    async updateAuthenticatorName(credentialId, userId, name) { throw new Error('updateAuthenticatorName not implemented'); }
    async deleteAuthenticator(credentialId, userId) { throw new Error('deleteAuthenticator not implemented'); }

    // --- MFA ---
    async updateUserRequiresTOTP(userId, requires) { throw new Error('updateUserRequiresTOTP not implemented'); }
    async updateUserRequiresLoginCode(userId, requires) { throw new Error('updateUserRequiresLoginCode not implemented'); }
    async updateUserTotpSecret(userId, secret) { throw new Error('updateUserTotpSecret not implemented'); }

    // --- v4: Projects ---
    async registerProject(projectId, ownerId) { throw new Error('registerProject not implemented'); }
    async unregisterProject(projectId) { throw new Error('unregisterProject not implemented'); }
    async getProject(projectId) { throw new Error('getProject not implemented'); }
    async getOwnedProjects(userId) { throw new Error('getOwnedProjects not implemented'); }
    async isProjectOwner(projectId, userId) { throw new Error('isProjectOwner not implemented'); }
    async setProjectOwner(projectId, newOwnerId) { throw new Error('setProjectOwner not implemented'); }

    // --- v4: Server Scopes ---
    async grantServerScope(userId, scope, grantedBy) { throw new Error('grantServerScope not implemented'); }
    async revokeServerScope(userId, scope) { throw new Error('revokeServerScope not implemented'); }
    async getUserServerScopes(userId) { throw new Error('getUserServerScopes not implemented'); }

    // --- v4: API Keys ---
    async createApiKey(userId, keyHash, keyPrefix, name, expiresAt) { throw new Error('createApiKey not implemented'); }
    async getApiKeyByHash(keyHash) { throw new Error('getApiKeyByHash not implemented'); }
    async getApiKeyById(keyId) { throw new Error('getApiKeyById not implemented'); }
    async deleteApiKeyById(keyId, userId) { throw new Error('deleteApiKeyById not implemented'); }
    async deleteApiKeyByIdAdmin(keyId) { throw new Error('deleteApiKeyByIdAdmin not implemented'); }
    async listApiKeysByUserId(userId) { throw new Error('listApiKeysByUserId not implemented'); }
    async updateApiKey(keyId, userId, name, expiresAt, clearExpiry) { throw new Error('updateApiKey not implemented'); }
    touchApiKeyLastUsed(keyId) {}  // best-effort, non-throwing

    // --- v4: API Key Grants ---
    async upsertServerGrant(keyId, scopes) { throw new Error('upsertServerGrant not implemented'); }
    async upsertPersonalGrant(keyId, scopes) { throw new Error('upsertPersonalGrant not implemented'); }
    async upsertProjectGrant(keyId, projectId, scopes) { throw new Error('upsertProjectGrant not implemented'); }
    async getServerGrant(keyId) { throw new Error('getServerGrant not implemented'); }
    async getPersonalGrant(keyId) { throw new Error('getPersonalGrant not implemented'); }
    async getAllProjectGrants(keyId) { throw new Error('getAllProjectGrants not implemented'); }
    async getServerGrantsBatch(keyIds) {
        const entries = await Promise.all(keyIds.map(async id => [id, await this.getServerGrant(id)]));
        return Object.fromEntries(entries);
    }
    async getPersonalGrantsBatch(keyIds) {
        const entries = await Promise.all(keyIds.map(async id => [id, await this.getPersonalGrant(id)]));
        return Object.fromEntries(entries);
    }
    async getAllProjectGrantsBatch(keyIds) {
        const entries = await Promise.all(keyIds.map(async id => {
            const map = await this.getAllProjectGrants(id);
            return [id, Object.entries(map).map(([projectId, scopes]) => ({ projectId, scopes }))];
        }));
        return Object.fromEntries(entries);
    }

    // --- User Identifiers ---
    async findUserByIdentifier(value) { throw new Error('findUserByIdentifier not implemented'); }
    async addUserIdentifier(userId, type, value, isPrimary) { throw new Error('addUserIdentifier not implemented'); }
    async removeUserIdentifier(userId, type, value) { throw new Error('removeUserIdentifier not implemented'); }
    async getUserIdentifiers(userId) { throw new Error('getUserIdentifiers not implemented'); }
    async setPrimaryIdentifier(userId, type, value) { throw new Error('setPrimaryIdentifier not implemented'); }

    // --- Password Reset ---
    async createPasswordResetToken(userId, tokenHash, expiresAt) { throw new Error('createPasswordResetToken not implemented'); }
    async getActivePasswordResetToken(tokenHash) { throw new Error('getActivePasswordResetToken not implemented'); }
    async getActivePasswordResetTokens(userId) { throw new Error('getActivePasswordResetTokens not implemented'); }
    async getAllActivePasswordResetTokens() { throw new Error('getAllActivePasswordResetTokens not implemented'); }
    async invalidatePasswordResetToken(tokenHash) { throw new Error('invalidatePasswordResetToken not implemented'); }
    async invalidateAllPasswordResetTokensByUser(userId) { throw new Error('invalidateAllPasswordResetTokensByUser not implemented'); }
    async updateUserPassword(userId, passwordHash) { throw new Error('updateUserPassword not implemented'); }

    // --- Email Verification ---
    async createVerificationToken(userId, tokenHash, expiresAt) { throw new Error('createVerificationToken not implemented'); }
    async getVerificationToken(tokenHash) { throw new Error('getVerificationToken not implemented'); }
    async invalidateVerificationToken(tokenHash) { throw new Error('invalidateVerificationToken not implemented'); }
    async setUserVerified(userId) { throw new Error('setUserVerified not implemented'); }

    // --- Invitations ---
    async createInvitation(email, invitationToken, expiresAt) { throw new Error('createInvitation not implemented'); }
    async getInvitationByToken(invitationToken) { throw new Error('getInvitationByToken not implemented'); }
}
