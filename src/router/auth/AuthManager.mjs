import SQLiteAdaptor from './database-adaptors/SqliteDatabaseAdaptor/SqliteDatabaseAdaptor.mjs';
import { ContactAdaptor, ConsoleContactAdaptor, SmsContactAdaptor } from './contact-adaptors/index.mjs';
import { MultiError, ERROR, AuthError } from './util/index.mjs';
import {
    ContactRequirementChecker,
    AuthenticationValidator,
    ApiKeyService,
    WebAuthnService,
    TotpService,
    PasswordService
} from './services/index.mjs';
import { ScopeValidator } from './util/ScopeValidator.mjs';
import { ValidationError } from './util/errors.mjs';
import { InMemoryChallengeStore } from './stores/InMemoryChallengeStore.mjs';

export { SQLiteAdaptor, ContactAdaptor, ConsoleContactAdaptor, SmsContactAdaptor };

export class AuthManager {
    #config;
    #databaseAdapter;
    #contactAdaptors;
    #requirementChecker;
    #authValidator;
    #apiKeyService;
    #webAuthnService;
    #totpService;
    #challengeStore;

    constructor(config = {}) {
        this.#config = config;

        this.#databaseAdapter = config.databaseAdapter?.init
            ? config.databaseAdapter
            : new (config.databaseAdapter || SQLiteAdaptor)(config);

        this.#contactAdaptors = config.contactAdaptors || [new ConsoleContactAdaptor(this)];

        const { services = {} } = config;
        this.#requirementChecker = services.requirementChecker || new ContactRequirementChecker(this.#databaseAdapter);
        this.#authValidator = services.authValidator || new AuthenticationValidator(this.#databaseAdapter);
        this.#apiKeyService = services.apiKeyService || new ApiKeyService(this.#databaseAdapter);
        this.#webAuthnService = services.webAuthnService || new WebAuthnService(this.#databaseAdapter, config.webAuthn);
        this.#totpService = services.totpService || new TotpService(config.totp?.issuer || 'Easy Auth Demo');
        this.#challengeStore = config.challengeStore || new InMemoryChallengeStore();

        this.#bindMethods();
    }

    #bindMethods() {
        const methods = [
            'registerUser', 'deleteUser', 'getUserById',
            'generateRegistrationOptions', 'verifyRegistration',
            'generateAuthenticationOptions', 'verifyAuthentication', 'verifyAuthenticationForStepUp',
            'getPasskeys', 'updatePasskeyName', 'deletePasskey', 'createApiKey',
            'getApiKeysByUser', 'revokeApiKey', 'updateApiKeyScopes', 'setChallenge', 'getChallenge',
            'generateTotpSetup', 'verifyAndEnableTotp', 'disableTotp', 'getTotpStatus',
            'authenticateLogin', 'authenticateApiKey', 'init', 'destroy',
            'getScopeTaxonomy',
            'requestPasswordReset', 'resetPassword', 'changePassword',
            'addUserIdentifier', 'removeUserIdentifier', 'getIdentifiers',
            'verifyEmail'
        ];

        for (const method of methods) {
            if (typeof this[method] === 'function') {
                this[method] = this[method].bind(this);
            }
        }
    }

    async init() {
        await this.#databaseAdapter.init();
        await Promise.all(this.#contactAdaptors.map(adaptor => adaptor.init()));
    }

    async authenticateLogin(userIdentifier, userPassword, totpCode, loginCode) {
        const validation = await this.#validateLoginInputs(userIdentifier, userPassword, totpCode, loginCode);
        const authConfig = await this.#getAuthConfig(userIdentifier);

        await this.#validateLoginRequirements(authConfig, validation.totpCode, validation.loginCode);
        await this.#verifyAuthCredentials(authConfig, userPassword, validation.totpCode, validation.loginCode);

        return this.#buildLoginResponse(authConfig);
    }

    async #validateLoginInputs(userIdentifier, userPassword, totpCode, loginCode) {
        const { LoginValidationService } = await import('./services/LoginValidationService.mjs');
        const validationService = new LoginValidationService();
        return validationService.validateLoginInput(userIdentifier, userPassword, totpCode, loginCode);
    }

    async #getAuthConfig(userIdentifier) {
        const authConfig = await this.#requirementChecker.checkUserLoginRequirements(userIdentifier);
        if (!authConfig) {
            throw new AuthError(ERROR.user_not_found);
        }
        return authConfig;
    }

    async #validateLoginRequirements(authConfig, totpCode, loginCode) {
        const { LoginValidationService } = await import('./services/LoginValidationService.mjs');
        const validationService = new LoginValidationService();
        const errors = validationService.validateLoginRequirements(authConfig, totpCode, loginCode);

        if (errors.count > 0) throw errors;
    }

    async #verifyAuthCredentials(authConfig, password, totpCode, loginCode) {
        const errors = new MultiError();

        await Promise.all([
            this.#authValidator.verifyPassword(authConfig.email, password, errors),
            this.#authValidator.verifyTotp(authConfig, totpCode, errors),
            this.#authValidator.verifyLoginCode(authConfig, loginCode, errors)
        ]);

        if (errors.count > 0) throw errors;
    }

    #buildLoginResponse(authConfig) {
        return {
            user: { id: authConfig.userId, email: authConfig.email },
            scopes: [],
            roles: []
        };
    }

    async authenticateApiKey(apiKey) {
        return await this.#apiKeyService.validateApiKey(apiKey);
    }

    async destroy() {
        await this.#databaseAdapter.destroy();
    }

    async getUserById(userId) {
        return await this.#databaseAdapter.getUserById(userId);
    }

    async registerUser(email, password, displayName) {
        PasswordService.validateStrength(password);
        const passwordHash = await PasswordService.hash(password);
        const userId = await this.#databaseAdapter.createUser(email, passwordHash, displayName);

        if (this.#config.requireEmailVerification) {
            await this.#dispatchEmailVerification(userId, email);
        }

        return userId;
    }

    async #dispatchEmailVerification(userId, email) {
        const { randomBytes, createHash } = await import('node:crypto');
        const token = randomBytes(32).toString('hex');
        const tokenHash = createHash('sha256').update(token).digest('hex');
        const expiresAt = Date.now() + 24 * 60 * 60 * 1000;

        await this.#databaseAdapter.createVerificationToken(userId, tokenHash, expiresAt);

        const adaptor = this.#contactAdaptors[0];
        await adaptor.sendUserSignupCode({ id: userId, email }, token);
    }

    async verifyEmail(token) {
        const { createHash } = await import('node:crypto');
        const tokenHash = createHash('sha256').update(token).digest('hex');

        const record = await this.#databaseAdapter.getVerificationToken(tokenHash);
        if (!record) throw new AuthError(ERROR.invalid_session, 'Invalid or expired verification token');

        await this.#databaseAdapter.setUserVerified(record.user_id);
        await this.#databaseAdapter.invalidateVerificationToken(tokenHash);

        return { success: true, userId: record.user_id };
    }

    async deleteUser(userId) {
        return await this.#databaseAdapter.deleteUser(userId);
    }

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
            const user = await this.#databaseAdapter.getUserById(result.userId);
            return {
                user: { id: user.id, email: user.email, display_name: user.display_name },
                scopes: [],
                roles: []
            };
        }
        throw new AuthError(ERROR.invalid_credentials);
    }

    async verifyAuthenticationForStepUp(authenticationResponse, expectedChallenge, webAuthnReqConfig = {}) {
        const result = await this.#webAuthnService.verifyAuthentication(authenticationResponse, expectedChallenge, webAuthnReqConfig);
        if (result.verified) {
            const user = await this.#databaseAdapter.getUserById(result.userId);
            return {
                success: true,
                user: { id: user.id, email: user.email, display_name: user.display_name }
            };
        }
        throw new AuthError(ERROR.invalid_credentials);
    }

    async getPasskeys(userId) {
        return await this.#databaseAdapter.getAuthenticatorsByUserId(userId);
    }

    async updatePasskeyName(userId, credentialId, name) {
        return await this.#databaseAdapter.updateAuthenticatorName(credentialId, userId, name);
    }

    async deletePasskey(userId, credentialId) {
        return await this.#databaseAdapter.deleteAuthenticator(credentialId, userId);
    }

    async createApiKey(userId, scopes, expiresAt, name) {
        if (this.#config.scopes && !ScopeValidator.isValidTaxonomy(scopes, this.#config.scopes)) {
            const unknown = scopes.filter(s => !this.#config.scopes.includes(s) && s !== '*');
            throw new ValidationError(ERROR.invalid_scope, `Unknown scopes: ${unknown.join(', ')}`);
        }

        const userScopes = await this.#getUserScopes(userId);

        if (!ScopeValidator.isSubset(scopes, userScopes)) {
            const unauthorized = scopes.filter(s => !userScopes.includes(s) && !userScopes.includes('*'));
            throw new ValidationError(ERROR.scope_exceeds_user_authority, `Cannot grant scopes you do not possess: ${unauthorized.join(', ')}`);
        }

        const apiKey = this.#generateApiKey();
        await this.#databaseAdapter.createApiKey(userId, apiKey, name || null, JSON.stringify(scopes), expiresAt);
        return apiKey;
    }

    async #getUserScopes(userId) {
        const userRoles = await this.#databaseAdapter.getUserRoles(userId);
        const roleNames = userRoles.map(r => r.name);

        if (roleNames.length === 0 && this.#config.defaultRole) {
            roleNames.push(this.#config.defaultRole);
        }

        let flatScopes = [];
        for (const roleName of roleNames) {
            const roleScopes = this.#config.roles?.[roleName] || [];
            flatScopes.push(...roleScopes);
        }

        if (this.#config.scopes) {
            return ScopeValidator.expand(flatScopes, this.#config.scopes);
        }

        return [...new Set(flatScopes)];
    }

    async getApiKeysByUser(userId) {
        return await this.#databaseAdapter.getApiKeysByUserId(userId);
    }

    async revokeApiKey(apiKey) {
        return await this.#databaseAdapter.deleteApiKey(apiKey);
    }

    async updateApiKeyScopes(apiKey, scopes) {
        return await this.#databaseAdapter.updateApiKeyScopes(apiKey, JSON.stringify(scopes));
    }

    #generateApiKey() {
        return 'sk_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    }

    getScopeTaxonomy() {
        return this.#config.scopes || [];
    }

    async setChallenge(key, challenge, ttlMs = 60000) {
        await this.#challengeStore.set(key, challenge, ttlMs);
    }

    async getChallenge(key) {
        return await this.#challengeStore.consumeChallenge(key);
    }

    async generateTotpSetup(userId) {
        const user = await this.#databaseAdapter.getUserById(userId);
        if (!user) throw new AuthError(ERROR.user_not_found);

        const secret = await this.#totpService.generateSecret();
        const url = await this.#totpService.generateOtpauthUrl(user.email, secret);
        const qrCode = await this.#totpService.generateQrCode(url);

        return { secret, qrCode };
    }

    async verifyAndEnableTotp(userId, code, secret) {
        const isValid = await this.#totpService.verifyToken(secret, code);
        if (!isValid) throw new AuthError(ERROR.invalid_totp);

        await this.#databaseAdapter.updateUserTotpSecret(userId, secret);
        await this.#databaseAdapter.updateUserRequiresTOTP(userId, true);
        return { success: true };
    }

    async disableTotp(userId) {
        await this.#databaseAdapter.updateUserRequiresTOTP(userId, false);
        await this.#databaseAdapter.updateUserTotpSecret(userId, null);
        return { success: true };
    }

    async getTotpStatus(userId) {
        const user = await this.#databaseAdapter.getUserById(userId);
        return {
            enabled: !!user?.requires_totp,
            hasSecret: !!user?.totp_secret
        };
    }

    async requestPasswordReset(identifier) {
        const user = await this.#databaseAdapter.findUserByIdentifier(identifier)
            ?? await this.#databaseAdapter.retrieveUserAuthData(identifier);

        if (!user) return;

        const { randomBytes, createHash } = await import('node:crypto');

        const token = randomBytes(32).toString('hex');
        const tokenHash = createHash('sha256').update(token).digest('hex');
        const expiresAt = Date.now() + 30 * 60 * 1000;

        await this.#databaseAdapter.createPasswordResetToken(user.id, tokenHash, expiresAt);

        const identifiers = await this.#databaseAdapter.getUserIdentifiers(user.id);
        const primaryEmail = identifiers.find(i => i.type === 'email' && i.is_primary)?.value
            ?? identifiers.find(i => i.type === 'email')?.value;
        const primaryPhone = identifiers.find(i => i.type === 'phone' && i.is_primary)?.value
            ?? identifiers.find(i => i.type === 'phone')?.value;

        const contactData = {
            ...user,
            primaryContact: primaryPhone ?? primaryEmail ?? user.email,
            primaryContactType: primaryPhone ? 'phone' : 'email',
            phone: primaryPhone,
        };

        const adaptor = this.#contactAdaptors[0];
        await adaptor.sendUserRecoveryCode(contactData, token);
    }

    async resetPassword(token, newPassword) {
        const { createHash } = await import('node:crypto');
        const tokenHash = createHash('sha256').update(token).digest('hex');

        const allTokens = await this.#databaseAdapter.getAllActivePasswordResetTokens();
        const matched = allTokens.find(t => t.token_hash === tokenHash);

        if (!matched) throw new AuthError(ERROR.invalid_session, 'Invalid or expired reset token');

        PasswordService.validateStrength(newPassword);
        const passwordHash = await PasswordService.hash(newPassword);
        await this.#databaseAdapter.updateUserPassword(matched.user_id, passwordHash);
        await this.#databaseAdapter.invalidatePasswordResetToken(matched.token_hash);
    }

    async changePassword(userId, newPassword) {
        PasswordService.validateStrength(newPassword);
        const passwordHash = await PasswordService.hash(newPassword);
        await this.#databaseAdapter.updateUserPassword(userId, passwordHash);
    }

    async addUserIdentifier(userId, type, value) {
        const validTypes = this.#config.identifierTypes || ['email', 'phone', 'username'];
        if (!validTypes.includes(type)) {
            throw new ValidationError(ERROR.server_error, `Identifier type '${type}' is not permitted`);
        }
        return await this.#databaseAdapter.addUserIdentifier(userId, type, value, false);
    }

    async removeUserIdentifier(userId, type, value) {
        const all = await this.#databaseAdapter.getUserIdentifiers(userId);
        if (all.length <= 1) {
            throw new ValidationError(ERROR.server_error, 'Cannot remove the last identifier on an account');
        }
        await this.#databaseAdapter.removeUserIdentifier(userId, type, value);
    }

    async getIdentifiers(userId) {
        return await this.#databaseAdapter.getUserIdentifiers(userId);
    }

    get databaseAdapter() {
        return this.#databaseAdapter;
    }
}
