export default class DatabaseAdaptor {
    constructor(config) {
        this.config = config;
    }

    /**
     * Initialize the database connection/setup.
     */
    async init() {
        throw new Error('init not implemented');
    }

    /**
     * Retrieve all auth-related data for a user by email or identifier.
     */
    async retrieveUserAuthData(user_identifier) {
        throw new Error('retrieveUserAuthData not implemented');
    }

    /**
     * Retrieve only the password hash for a user.
     */
    async retrieveUserPasswordHash(user_identifier) {
        throw new Error('retrieveUserPasswordHash not implemented');
    }

    /**
     * Get basic user info by ID.
     */
    async getUserById(userId) {
        throw new Error('getUserById not implemented');
    }

    /**
     * Create a new user record.
     */
    async createUser(email, passwordHash, displayName) {
        throw new Error('createUser not implemented');
    }

    /**
     * Delete a user and associated data.
     */
    async deleteUser(userId) {
        throw new Error('deleteUser not implemented');
    }

    /**
     * Session management.
     */
    async createSession(userId, sessionToken, expiresAt, lastAuthenticatedAt) {
        throw new Error('createSession not implemented');
    }

    async getSession(sessionToken) {
        throw new Error('getSession not implemented');
    }

    async deleteSession(sessionToken) {
        throw new Error('deleteSession not implemented');
    }

    async updateSessionLastAuthenticatedAt(sessionToken, timestamp) {
        throw new Error('updateSessionLastAuthenticatedAt not implemented');
    }

    /**
     * API Key management.
     */
    async createApiKey(userId, apiKey, scopes, expiresAt) {
        throw new Error('createApiKey not implemented');
    }

    async getApiKey(apiKey) {
        throw new Error('getApiKey not implemented');
    }

    async deleteApiKey(apiKey) {
        throw new Error('deleteApiKey not implemented');
    }

    async updateApiKeyScopes(apiKey, scopes) {
        throw new Error('updateApiKeyScopes not implemented');
    }

    async getApiKeysByUserId(userId) {
        throw new Error('getApiKeysByUserId not implemented');
    }

    /**
     * MFA Requirements.
     */
    async updateUserRequiresTOTP(userId, requires) {
        throw new Error('updateUserRequiresTOTP not implemented');
    }

    async updateUserRequiresLoginCode(userId, requires) {
        throw new Error('updateUserRequiresLoginCode not implemented');
    }

    async updateUserTotpSecret(userId, secret) {
        throw new Error('updateUserTotpSecret not implemented');
    }

    /**
     * WebAuthn / Passkeys.
     */
    async getAuthenticatorsByUserId(userId) {
        throw new Error('getAuthenticatorsByUserId not implemented');
    }

    async getAuthenticatorById(credentialId) {
        throw new Error('getAuthenticatorById not implemented');
    }

    async createAuthenticator(userId, credentialId, publicKey, counter, transports, name) {
        throw new Error('createAuthenticator not implemented');
    }

    async updateAuthenticatorCounter(credentialId, counter) {
        throw new Error('updateAuthenticatorCounter not implemented');
    }

    async updateAuthenticatorName(credentialId, userId, name) {
        throw new Error('updateAuthenticatorName not implemented');
    }

    async deleteAuthenticator(credentialId, userId) {
        throw new Error('deleteAuthenticator not implemented');
    }

    /**
     * Invitations & RBAC.
     */
    async createInvitation(email, invitationToken, expiresAt) {
        throw new Error('createInvitation not implemented');
    }

    async getInvitationByToken(invitationToken) {
        throw new Error('getInvitationByToken not implemented');
    }

    async getUserRoles(userId) {
        throw new Error('getUserRoles not implemented');
    }

    async getRolePermissions(roleId) {
        throw new Error('getRolePermissions not implemented');
    }

    /**
     * Assign a named role to a user, creating the role record if it does not exist.
     * This operation must be idempotent (calling it twice must not error).
     */
    async assignRole(userId, roleName) {
        throw new Error('assignRole not implemented');
    }

    /**
     * Remove a named role from a user. No-ops silently if the user does not have the role.
     */
    async removeRole(userId, roleName) {
        throw new Error('removeRole not implemented');
    }

    /**
     * Multi-channel Identifiers (email, phone, username).
     * Each identifier belongs to exactly one user and has a type.
     */
    async findUserByIdentifier(value) {
        throw new Error('findUserByIdentifier not implemented');
    }

    async addUserIdentifier(userId, type, value, isPrimary) {
        throw new Error('addUserIdentifier not implemented');
    }

    async removeUserIdentifier(userId, type, value) {
        throw new Error('removeUserIdentifier not implemented');
    }

    async getUserIdentifiers(userId) {
        throw new Error('getUserIdentifiers not implemented');
    }

    async setPrimaryIdentifier(userId, type, value) {
        throw new Error('setPrimaryIdentifier not implemented');
    }

    /**
     * Password Reset Tokens.
     */
    async createPasswordResetToken(userId, tokenHash, expiresAt) {
        throw new Error('createPasswordResetToken not implemented');
    }

    async getActivePasswordResetTokens(userId) {
        throw new Error('getActivePasswordResetTokens not implemented');
    }

    async invalidatePasswordResetToken(tokenHash) {
        throw new Error('invalidatePasswordResetToken not implemented');
    }

    /**
     * Password management.
     */
    async updateUserPassword(userId, passwordHash) {
        throw new Error('updateUserPassword not implemented');
    }

    /**
     * Session listing & revocation.
     */
    async getSessionsByUserId(userId) {
        throw new Error('getSessionsByUserId not implemented');
    }

    async deleteSessionById(sessionId, userId) {
        throw new Error('deleteSessionById not implemented');
    }

    /**
     * Email Verification Tokens.
     * Required when AuthManager is configured with requireEmailVerification: true.
     */
    async createVerificationToken(userId, tokenHash, expiresAt) {
        throw new Error('createVerificationToken not implemented');
    }

    async getVerificationToken(tokenHash) {
        throw new Error('getVerificationToken not implemented');
    }

    async invalidateVerificationToken(tokenHash) {
        throw new Error('invalidateVerificationToken not implemented');
    }

    async setUserVerified(userId) {
        throw new Error('setUserVerified not implemented');
    }

    /**
     * Cleanup.
     */
    async destroy() {
        throw new Error('destroy not implemented');
    }
}