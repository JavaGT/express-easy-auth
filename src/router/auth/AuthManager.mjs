import { createHash, randomBytes } from 'node:crypto';
import SQLiteAdaptor from './database-adaptors/SqliteDatabaseAdaptor/SqliteDatabaseAdaptor.mjs';
import { ContactAdaptor, ConsoleContactAdaptor, SmsContactAdaptor } from './contact-adaptors/index.mjs';
import { MultiError, ERROR, AuthError } from './util/index.mjs';
import {
    ContactRequirementChecker,
    AuthenticationValidator,
    WebAuthnService,
    TotpService,
    PasswordService,
} from './services/index.mjs';
import { ValidationError } from './util/errors.mjs';
import { InMemoryChallengeStore } from './stores/InMemoryChallengeStore.mjs';
import { PERSONAL_SCOPES, SESSION_ONLY_SCOPES } from './util/PersonalScopes.mjs';

export { SQLiteAdaptor, ContactAdaptor, ConsoleContactAdaptor, SmsContactAdaptor };
export { PERSONAL_SCOPES, SESSION_ONLY_SCOPES };

export class AuthManager {
    #config;
    #db;
    #contactAdaptors;
    #requirementChecker;
    #authValidator;
    #webAuthnService;
    #totpService;
    #challengeStore;

    constructor(config = {}) {
        this.#config = config;

        this.#db = config.databaseAdapter?.init
            ? config.databaseAdapter
            : new (config.databaseAdapter || SQLiteAdaptor)(config);

        this.#contactAdaptors = config.contactAdaptors || [new ConsoleContactAdaptor(this)];

        const { services = {} } = config;
        this.#requirementChecker = services.requirementChecker || new ContactRequirementChecker(this.#db);
        this.#authValidator     = services.authValidator     || new AuthenticationValidator(this.#db);
        this.#webAuthnService   = services.webAuthnService   || new WebAuthnService(this.#db, config.webAuthn);
        this.#totpService       = services.totpService       || new TotpService(config.totp?.issuer || 'Easy Auth');
        this.#challengeStore    = config.challengeStore      || new InMemoryChallengeStore();

        this.#bindMethods();
    }

    #bindMethods() {
        const proto = Object.getPrototypeOf(this);
        for (const name of Object.getOwnPropertyNames(proto)) {
            if (name === 'constructor') continue;
            const desc = Object.getOwnPropertyDescriptor(proto, name);
            if (desc && typeof desc.value === 'function') {
                this[name] = desc.value.bind(this);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Init / Destroy
    // -------------------------------------------------------------------------

    async init() {
        await this.#db.init?.();
        await Promise.all(this.#contactAdaptors.map(a => a.init?.()));
    }

    async destroy() {
        await this.#db.destroy();
    }

    // -------------------------------------------------------------------------
    // Authentication
    // -------------------------------------------------------------------------

    async authenticateLogin(userIdentifier, userPassword, totpCode, loginCode) {
        const { LoginValidationService } = await import('./services/LoginValidationService.mjs');
        const svc = new LoginValidationService();
        const validation = svc.validateLoginInput(userIdentifier, userPassword, totpCode, loginCode);

        const authConfig = await this.#requirementChecker.checkUserLoginRequirements(userIdentifier);
        if (!authConfig) {
            await PasswordService.dummyCompare(userPassword);
            throw new AuthError(ERROR.invalid_credentials);
        }

        const reqErrors = svc.validateLoginRequirements(authConfig, validation.totpCode, validation.loginCode);
        if (reqErrors.count > 0) throw reqErrors;

        const errors = new MultiError();
        await Promise.all([
            this.#authValidator.verifyPassword(authConfig.email, userPassword, errors),
            this.#authValidator.verifyTotp(authConfig, validation.totpCode, errors),
            this.#authValidator.verifyLoginCode(authConfig, validation.loginCode, errors),
        ]);
        if (errors.count > 0) throw errors;

        return { user: { id: authConfig.userId, email: authConfig.email, display_name: authConfig.display_name ?? null } };
    }

    async authenticateApiKey(rawKey) {
        const keyHash = createHash('sha256').update(rawKey).digest('hex');
        const keyRecord = await this.#db.getApiKeyByHash(keyHash);
        if (!keyRecord) throw new AuthError(ERROR.invalid_api_key);
        if (keyRecord.expires_at && Date.now() > keyRecord.expires_at) throw new AuthError(ERROR.api_key_expired);

        const [serverScopes, personalScopes, projectGrants] = await Promise.all([
            this.#db.getServerGrant(keyRecord.id),
            this.#db.getPersonalGrant(keyRecord.id),
            this.#db.getAllProjectGrants(keyRecord.id),
        ]);

        const user = await this.#db.getUserById(keyRecord.user_id);

        // Non-blocking — does not affect the response
        this.#db.touchApiKeyLastUsed(keyRecord.id);

        return {
            user: { id: user.id, email: user.email, display_name: user.display_name },
            keyId: keyRecord.id,
            keyPrefix: keyRecord.key_prefix,
            keyName: keyRecord.name,
            grants: {
                server: serverScopes,
                personal: personalScopes,
                projects: projectGrants,
            },
        };
    }

    // -------------------------------------------------------------------------
    // User management
    // -------------------------------------------------------------------------

    async registerUser(email, password, displayName) {
        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            throw new ValidationError(ERROR.invalid_input, 'A valid email address is required');
        }
        PasswordService.validateStrength(password);
        const passwordHash = await PasswordService.hash(password);
        const userId = await this.#db.createUser(email, passwordHash, displayName);

        if (this.#config.requireEmailVerification) {
            await this.#dispatchEmailVerification(userId, email);
        }

        return userId;
    }

    async #dispatchEmailVerification(userId, email) {
        const token = randomBytes(32).toString('hex');
        const tokenHash = createHash('sha256').update(token).digest('hex');
        await this.#db.createVerificationToken(userId, tokenHash, Date.now() + 24 * 3600 * 1000);
        await this.#contactAdaptors[0].sendUserSignupCode({ id: userId, email }, token);
    }

    async verifyEmail(token) {
        const tokenHash = createHash('sha256').update(token).digest('hex');
        const record = await this.#db.getVerificationToken(tokenHash);
        if (!record) throw new AuthError(ERROR.invalid_session, 'Invalid or expired verification token');

        await this.#db.setUserVerified(record.user_id);
        await this.#db.invalidateVerificationToken(tokenHash);
        return { success: true, userId: record.user_id };
    }

    /**
     * Delete a user. Returns warnings for any projects that became ownerless.
     * Projects are NOT deleted — their owner_id is set to NULL.
     * The caller must handle warnings and reassign or archive orphaned projects.
     *
     * @returns {{ deleted: true, warnings: Array<{ code: string, projectIds: string[], message: string }> }}
     */
    async deleteUser(userId) {
        return await this.#db.deleteUser(userId);
    }

    async getUserById(userId) {
        return await this.#db.getUserById(userId);
    }

    async listUsers() {
        return await this.#db.listUsers();
    }

    // -------------------------------------------------------------------------
    // Projects
    // -------------------------------------------------------------------------

    /**
     * Register a project in the auth system. Call this when the app creates a project.
     * Idempotent — safe to call multiple times with the same projectId.
     */
    async registerProject(projectId, ownerId) {
        await this.#db.registerProject(projectId, ownerId);
    }

    /**
     * Remove the auth record for a project. Call this when the app deletes a project.
     * Cascades to api_key_project_grants.
     */
    async unregisterProject(projectId) {
        await this.#db.unregisterProject(projectId);
    }

    /** Returns true if userId is the current owner of projectId. */
    async isProjectOwner(projectId, userId) {
        return await this.#db.isProjectOwner(projectId, userId);
    }

    /** Returns all project IDs owned by a user. */
    async getOwnedProjects(userId) {
        return await this.#db.getOwnedProjects(userId);
    }

    /**
     * Transfer project ownership to another user.
     * The route calling this should be guarded with requireFreshAuth.
     */
    async transferProjectOwnership(projectId, newOwnerId) {
        const project = await this.#db.getProject(projectId);
        if (!project) throw new AuthError(ERROR.project_not_found);
        const user = await this.#db.getUserById(newOwnerId);
        if (!user) throw new AuthError(ERROR.user_not_found, 'New owner user not found');
        await this.#db.setProjectOwner(projectId, newOwnerId);
    }

    // -------------------------------------------------------------------------
    // Server Scopes
    // -------------------------------------------------------------------------

    /**
     * Assign a server scope to a user.
     * grantorId must already hold the scope, unless null (bootstrap / server-side only).
     */
    async grantServerScope(userId, scope, grantorId = null) {
        if (this.#config.serverScopes && !this.#config.serverScopes.includes(scope)) {
            throw new ValidationError(ERROR.invalid_scope, `Unknown server scope: ${scope}`);
        }
        if (grantorId !== null) {
            const grantorScopes = await this.#db.getUserServerScopes(grantorId);
            if (!grantorScopes.includes(scope)) {
                throw new ValidationError(ERROR.scope_exceeds_user_authority, `Grantor does not hold scope: ${scope}`);
            }
        }
        await this.#db.grantServerScope(userId, scope, grantorId);
    }

    async revokeServerScope(userId, scope) {
        await this.#db.revokeServerScope(userId, scope);
    }

    async getUserServerScopes(userId) {
        return await this.#db.getUserServerScopes(userId);
    }

    // -------------------------------------------------------------------------
    // API Keys
    // -------------------------------------------------------------------------

    /**
     * Create a new API key for a user.
     *
     * @param {number} userId
     * @param {{ name: string, grants: { server?: string[], personal?: string[], projects?: Array<{ projectId: string, scopes: string[] }> }, expiresAt?: number }} options
     * @returns {{ key: string, id: number, prefix: string, name: string, grants: object, createdAt: number }}
     */
    async createApiKey(userId, options) {
        const { name, grants = {}, expiresAt } = options;
        if (!name?.trim()) throw new ValidationError(ERROR.invalid_input, 'API key name is required');

        const serverScopes  = grants.server   ?? [];
        const personalScopes = grants.personal ?? [];
        const projectGrants  = grants.projects ?? [];

        // Validate server scopes against taxonomy and user's authority
        if (serverScopes.length > 0) {
            if (this.#config.serverScopes) {
                const unknown = serverScopes.filter(s => !this.#config.serverScopes.includes(s));
                if (unknown.length > 0) throw new ValidationError(ERROR.invalid_scope, `Unknown server scopes: ${unknown.join(', ')}`);
            }
            const userServerScopes = await this.#db.getUserServerScopes(userId);
            const unauthorized = serverScopes.filter(s => !userServerScopes.includes(s));
            if (unauthorized.length > 0) {
                throw new ValidationError(ERROR.scope_exceeds_user_authority, `Cannot grant server scopes you do not hold: ${unauthorized.join(', ')}`);
            }
        }

        // Validate personal scopes against fixed taxonomy; reject unknown scopes, strip session-only
        const unknownPersonal = personalScopes.filter(s => !PERSONAL_SCOPES.includes(s));
        if (unknownPersonal.length > 0) throw new ValidationError(ERROR.invalid_scope, `Unknown personal scopes: ${unknownPersonal.join(', ')}`);
        const cleanPersonal = personalScopes.filter(s => !SESSION_ONLY_SCOPES.includes(s));
        if (this.#config.projectScopes && projectGrants.length > 0) {
            for (const g of projectGrants) {
                const unknown = g.scopes.filter(s => !this.#config.projectScopes.includes(s));
                if (unknown.length > 0) throw new ValidationError(ERROR.invalid_scope, `Unknown project scopes: ${unknown.join(', ')}`);
            }
        }

        const rawKey = 'sk_' + randomBytes(24).toString('hex');
        const keyHash = createHash('sha256').update(rawKey).digest('hex');
        const keyPrefix = rawKey.slice(0, 16);
        const createdAt = Date.now();

        const keyId = await this.#db.createApiKey(userId, keyHash, keyPrefix, name.trim(), expiresAt ?? null);

        if (serverScopes.length > 0)  await this.#db.upsertServerGrant(keyId, serverScopes);
        if (cleanPersonal.length > 0) await this.#db.upsertPersonalGrant(keyId, cleanPersonal);
        for (const g of projectGrants) {
            await this.#db.upsertProjectGrant(keyId, g.projectId, g.scopes);
        }

        return {
            key: rawKey,
            id: keyId,
            prefix: keyPrefix,
            name: name.trim(),
            grants: {
                server:   serverScopes,
                personal: cleanPersonal,
                projects: projectGrants,
            },
            createdAt,
        };
    }

    /** Revoke a key by ID. User may only revoke their own keys. */
    async revokeApiKey(userId, keyId) {
        await this.#db.deleteApiKeyById(keyId, userId);
    }

    /** Server-side revocation with no user context check. */
    async revokeApiKeyAsAdmin(keyId) {
        await this.#db.deleteApiKeyByIdAdmin(keyId);
    }

    /** List all API keys for a user (metadata only — raw keys are never returned). */
    async listApiKeys(userId) {
        const rows = await this.#db.listApiKeysByUserId(userId);
        if (!rows.length) return [];

        const keyIds = rows.map(r => r.id);
        const [serverMap, personalMap, projectMap] = await Promise.all([
            this.#db.getServerGrantsBatch(keyIds),
            this.#db.getPersonalGrantsBatch(keyIds),
            this.#db.getAllProjectGrantsBatch(keyIds),
        ]);

        return rows.map(row => ({
            id:         row.id,
            prefix:     row.key_prefix,
            name:       row.name,
            grants: {
                server:   serverMap[row.id]  ?? [],
                personal: personalMap[row.id] ?? [],
                projects: (projectMap[row.id] ?? []),
            },
            expiresAt:  row.expires_at,
            createdAt:  row.created_at,
            lastUsedAt: row.last_used_at,
        }));
    }

    /**
     * Update a key's name or expiry. Grants cannot be changed — revoke and reissue instead.
     * Pass `clearExpiry: true` to remove an expiry date (make the key non-expiring).
     */
    async updateApiKey(userId, keyId, { name, expiresAt, clearExpiry } = {}) {
        await this.#db.updateApiKey(keyId, userId, name ?? null, expiresAt ?? null, !!clearExpiry);
    }

    // -------------------------------------------------------------------------
    // WebAuthn / Passkeys
    // -------------------------------------------------------------------------

    async generateRegistrationOptions(user, webAuthnReqConfig = {}) {
        return await this.#webAuthnService.generateRegistrationOptions(user, webAuthnReqConfig);
    }

    async verifyRegistration(user, registrationResponse, expectedChallenge, authenticatorName, webAuthnReqConfig = {}) {
        return await this.#webAuthnService.verifyRegistration(user, registrationResponse, expectedChallenge, authenticatorName, webAuthnReqConfig);
    }

    async generateAuthenticationOptions(webAuthnReqConfig = {}) {
        return await this.#webAuthnService.generateAuthenticationOptions(webAuthnReqConfig);
    }

    async verifyAuthentication(authenticationResponse, expectedChallenge, webAuthnReqConfig = {}) {
        const result = await this.#webAuthnService.verifyAuthentication(authenticationResponse, expectedChallenge, webAuthnReqConfig);
        if (result.verified) {
            const user = await this.#db.getUserById(result.userId);
            return { success: true, user: { id: user.id, email: user.email, display_name: user.display_name } };
        }
        throw new AuthError(ERROR.invalid_credentials);
    }

    /** @deprecated Use verifyAuthentication — identical behaviour. */
    async verifyAuthenticationForStepUp(authenticationResponse, expectedChallenge, webAuthnReqConfig = {}) {
        return this.verifyAuthentication(authenticationResponse, expectedChallenge, webAuthnReqConfig);
    }

    async getPasskeys(userId) {
        return await this.#db.getAuthenticatorsByUserId(userId);
    }

    async updatePasskeyName(userId, credentialId, name) {
        return await this.#db.updateAuthenticatorName(credentialId, userId, name);
    }

    async deletePasskey(userId, credentialId) {
        return await this.#db.deleteAuthenticator(credentialId, userId);
    }

    // -------------------------------------------------------------------------
    // TOTP
    // -------------------------------------------------------------------------

    async generateTotpSetup(userId) {
        const user = await this.#db.getUserById(userId);
        if (!user) throw new AuthError(ERROR.user_not_found);
        const secret = await this.#totpService.generateSecret();
        const url    = await this.#totpService.generateOtpauthUrl(user.email, secret);
        const qrCode = await this.#totpService.generateQrCode(url);
        return { secret, qrCode };
    }

    async verifyAndEnableTotp(userId, code, secret) {
        const user = await this.#db.getUserById(userId);
        if (!user) throw new AuthError(ERROR.user_not_found);
        if (user.requires_totp) throw new ValidationError(ERROR.resource_conflict, 'TOTP is already enabled');
        const isValid = await this.#totpService.verifyToken(secret, code);
        if (!isValid) throw new AuthError(ERROR.invalid_totp);
        await this.#db.updateUserTotpSecret(userId, secret);
        await this.#db.updateUserRequiresTOTP(userId, true);
        return { success: true };
    }

    async disableTotp(userId) {
        await this.#db.updateUserRequiresTOTP(userId, false);
        await this.#db.updateUserTotpSecret(userId, null);
        return { success: true };
    }

    async getTotpStatus(userId) {
        const user = await this.#db.getUserById(userId);
        return { enabled: !!user?.requires_totp, hasSecret: !!user?.totp_secret };
    }

    // -------------------------------------------------------------------------
    // Challenges
    // -------------------------------------------------------------------------

    async setChallenge(key, challenge, ttlMs = 60000) {
        await this.#challengeStore.set(key, challenge, ttlMs);
    }

    async getChallenge(key) {
        return await this.#challengeStore.consumeChallenge(key);
    }

    // -------------------------------------------------------------------------
    // Password management
    // -------------------------------------------------------------------------

    async requestPasswordReset(identifier) {
        const user = await this.#db.findUserByIdentifier(identifier)
            ?? await this.#db.retrieveUserAuthData(identifier);
        if (!user) return;

        await this.#db.invalidateAllPasswordResetTokensByUser(user.id);
        const token     = randomBytes(32).toString('hex');
        const tokenHash = createHash('sha256').update(token).digest('hex');
        await this.#db.createPasswordResetToken(user.id, tokenHash, Date.now() + 30 * 60 * 1000);

        const identifiers = await this.#db.getUserIdentifiers(user.id);
        const primaryEmail = identifiers.find(i => i.type === 'email' && i.is_primary)?.value
            ?? identifiers.find(i => i.type === 'email')?.value;
        const primaryPhone = identifiers.find(i => i.type === 'phone' && i.is_primary)?.value
            ?? identifiers.find(i => i.type === 'phone')?.value;

        await this.#contactAdaptors[0].sendUserRecoveryCode({
            ...user,
            primaryContact:     primaryPhone ?? primaryEmail ?? user.email,
            primaryContactType: primaryPhone ? 'phone' : 'email',
            phone:              primaryPhone,
        }, token);
    }

    async resetPassword(token, newPassword) {
        const tokenHash = createHash('sha256').update(token).digest('hex');
        const record    = await this.#db.getActivePasswordResetToken(tokenHash);
        if (!record) throw new AuthError(ERROR.invalid_session, 'Invalid or expired reset token');

        PasswordService.validateStrength(newPassword);
        const passwordHash = await PasswordService.hash(newPassword);
        await this.#db.updateUserPassword(record.user_id, passwordHash);
        await this.#db.invalidatePasswordResetToken(tokenHash);
        return { userId: record.user_id };
    }

    async changePassword(userId, newPassword) {
        PasswordService.validateStrength(newPassword);
        const passwordHash = await PasswordService.hash(newPassword);
        await this.#db.updateUserPassword(userId, passwordHash);
    }

    // -------------------------------------------------------------------------
    // User identifiers
    // -------------------------------------------------------------------------

    async addUserIdentifier(userId, type, value) {
        const validTypes = this.#config.identifierTypes || ['email', 'phone', 'username'];
        if (!validTypes.includes(type)) {
            throw new ValidationError(ERROR.invalid_input, `Identifier type '${type}' is not permitted`);
        }
        return await this.#db.addUserIdentifier(userId, type, value, false);
    }

    async removeUserIdentifier(userId, type, value) {
        const all = await this.#db.getUserIdentifiers(userId);
        if (all.length <= 1) {
            throw new ValidationError(ERROR.invalid_input, 'Cannot remove the last identifier on an account');
        }
        await this.#db.removeUserIdentifier(userId, type, value);
    }

    async getIdentifiers(userId) {
        return await this.#db.getUserIdentifiers(userId);
    }

    // -------------------------------------------------------------------------
    // Exposed config helpers
    // -------------------------------------------------------------------------

    /** Returns the full scope taxonomy exposed to API consumers. */
    getScopeTaxonomy() {
        return {
            server:   this.#config.serverScopes  ?? [],
            personal: PERSONAL_SCOPES,
            project:  this.#config.projectScopes ?? [],
        };
    }

    get databaseAdapter() {
        return this.#db;
    }
}
