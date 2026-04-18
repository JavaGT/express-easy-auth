import { Router } from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { AuthMiddleware } from './AuthMiddleware.mjs';
import { ERROR, AuthError } from './util/errors.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Helper to wrap async route handlers and catch errors.
 */
const wrap = (fn) => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};

function extractWebAuthnConfig(req) {
    const host = req.get('host') || req.hostname || '';
    const origin = req.get('origin') || `${req.protocol}://${host}`;
    let rpID = req.hostname;
    if (origin) {
        try {
            rpID = new URL(origin).hostname;
        } catch {}
    }
    return { origin, rpID };
}

export default function authRoutes(authManager) {
    const router = Router();
    const middleware = new AuthMiddleware(authManager);

    // Health check / Info
    router.get('/', (req, res) => {
        res.json({ name: 'Express Easy Auth API', version: '1.0.0' });
    });

    // Serve Client Library
    router.get('/client.js', (req, res) => {
        res.sendFile(path.join(__dirname, '../../client/EasyAuthClient.mjs'));
    });

    // --- Authentication & Registration ---

    router.post('/register', wrap(async (req, res) => {
        const { email, password, displayName } = req.body;
        const userId = await authManager.registerUser(email, password, displayName);
        res.status(201).json({ success: true, userId });
    }));

    router.post('/verify-email', wrap(async (req, res) => {
        const { token } = req.body;
        const result = await authManager.verifyEmail(token);
        res.json(result);
    }));

    router.post('/login', wrap(async (req, res) => {
        const { email, password, totp, code, userIdentifier } = req.body;
        const identifier = email || userIdentifier;
        const totpCode = totp || code;

        const authResult = await authManager.authenticateLogin(identifier, password, totpCode);
        res.json({ success: true, ...authResult });
    }));

    router.post('/logout', middleware.requireAuth, wrap(async (req, res) => {
        await authManager.logout(req.sessionToken);
        res.json({ success: true });
    }));

    // --- Identity Info ---

    router.get('/me', middleware.requireAuthOrApiKey, (req, res) => {
        res.json({
            success: true,
            user: req.user,
            authType: req.authType,
            scopes: req.scopes,
            roles: req.roles,
            keyName: req.keyName,
            lastAuthenticatedAt: req.lastAuthenticatedAt
        });
    });

    router.delete('/account', middleware.requireFreshAuth, wrap(async (req, res) => {
        await authManager.deleteUser(req.user.id);
        res.json({ success: true });
    }));

    // --- TOTP Endpoints ---

    router.get('/totp/status', middleware.requireAuth, wrap(async (req, res) => {
        const status = await authManager.getTotpStatus(req.user.id);
        res.json({ success: true, ...status });
    }));

    router.post('/totp/setup', middleware.requireAuth, wrap(async (req, res) => {
        const setup = await authManager.generateTotpSetup(req.user.id);
        res.json({ success: true, ...setup });
    }));

    router.post('/totp/verify', middleware.requireAuth, wrap(async (req, res) => {
        const { code, secret } = req.body;
        const result = await authManager.verifyAndEnableTotp(req.user.id, code, secret);
        res.json(result);
    }));

    router.post('/totp/disable', middleware.requireAuth, wrap(async (req, res) => {
        const result = await authManager.disableTotp(req.user.id);
        res.json(result);
    }));

    // --- WebAuthn Passkey Endpoints ---

    router.post('/passkeys/register/options', middleware.requireAuth, wrap(async (req, res) => {
        const reqConfig = extractWebAuthnConfig(req);
        const options = await authManager.generateRegistrationOptions(req.user, reqConfig);
        await authManager.setChallenge('reg_' + req.user.id, options.challenge);
        res.json(options);
    }));

    router.post('/passkeys/register/verify', middleware.requireAuth, wrap(async (req, res) => {
        const reqConfig = extractWebAuthnConfig(req);
        const { name, ...registrationResponse } = req.body;
        const expectedChallenge = await authManager.getChallenge('reg_' + req.user.id);
        const verification = await authManager.verifyRegistration(req.user, registrationResponse, expectedChallenge, name, reqConfig);
        res.json(verification);
    }));

    router.patch('/passkeys/:id/name', middleware.requireAuth, wrap(async (req, res) => {
        const { name } = req.body;
        await authManager.updatePasskeyName(req.user.id, req.params.id, name);
        res.json({ success: true });
    }));

    router.post('/passkeys/login/options', wrap(async (req, res) => {
        const reqConfig = extractWebAuthnConfig(req);
        const options = await authManager.generateAuthenticationOptions(reqConfig);
        const tempId = Math.random().toString(36).substring(7);
        await authManager.setChallenge('login_' + tempId, options.challenge);
        res.json({ ...options, tempId });
    }));

    router.post('/passkeys/login/verify', wrap(async (req, res) => {
        const reqConfig = extractWebAuthnConfig(req);
        const { response, tempId } = req.body;
        const expectedChallenge = await authManager.getChallenge('login_' + tempId);
        const authResult = await authManager.verifyAuthentication(response, expectedChallenge, reqConfig);
        res.json({ success: true, ...authResult, lastAuthenticatedAt: Date.now() });
    }));

    router.post('/passkeys/verify/options', middleware.requireAuth, wrap(async (req, res) => {
        const reqConfig = extractWebAuthnConfig(req);
        const options = await authManager.generateAuthenticationOptions(reqConfig);
        await authManager.setChallenge('verify_' + req.user.id, options.challenge);
        res.json(options);
    }));

    router.post('/passkeys/verify/verify', middleware.requireAuth, wrap(async (req, res) => {
        const reqConfig = extractWebAuthnConfig(req);
        const response = req.body;
        const expectedChallenge = await authManager.getChallenge('verify_' + req.user.id);
        const authResult = await authManager.verifyAuthenticationForStepUp(response, expectedChallenge, req.sessionToken, reqConfig);
        res.json(authResult);
    }));

    router.get('/passkeys', middleware.requireAuth, wrap(async (req, res) => {
        const passkeys = await authManager.getPasskeys(req.user.id);
        res.json(passkeys);
    }));

    router.delete('/passkeys/:id', middleware.requireAuth, wrap(async (req, res) => {
        await authManager.deletePasskey(req.user.id, req.params.id);
        res.json({ success: true });
    }));

    // --- API Key Endpoints ---

    router.get('/keys', middleware.requireAuth, wrap(async (req, res) => {
        const keys = await authManager.getApiKeysByUser(req.user.id);
        res.json(keys);
    }));

    router.post('/keys', middleware.requireAuth, wrap(async (req, res) => {
        const { scopes, expiresAt, name } = req.body;
        const apiKey = await authManager.createApiKey(req.user.id, scopes || ['all'], expiresAt, name);
        res.status(201).json({ success: true, apiKey });
    }));

    router.delete('/keys/:key', middleware.requireAuth, wrap(async (req, res) => {
        await authManager.revokeApiKey(req.params.key);
        res.json({ success: true });
    }));

    router.patch('/keys/:key/scopes', middleware.requireAuth, wrap(async (req, res) => {
        const { scopes } = req.body;
        await authManager.updateApiKeyScopes(req.params.key, scopes);
        res.json({ success: true });
    }));

    // --- Scope Taxonomy ---

    router.get('/scopes', (req, res) => {
        res.json({
            success: true,
            scopes: authManager.getScopeTaxonomy()
        });
    });

    // --- Password Reset ---

    router.post('/password-reset/request', wrap(async (req, res) => {
        const { identifier, email } = req.body;
        // Always return success to prevent user enumeration
        try {
            await authManager.requestPasswordReset(identifier || email);
        } catch (err) {}
        res.json({ success: true });
    }));

    router.post('/password-reset/reset', wrap(async (req, res) => {
        const { token, newPassword } = req.body;
        await authManager.resetPassword(token, newPassword);
        res.json({ success: true });
    }));

    // --- Account Management ---

    router.post('/password/change', middleware.requireFreshAuth, wrap(async (req, res) => {
        const { newPassword } = req.body;
        await authManager.changePassword(req.user.id, newPassword);
        res.json({ success: true });
    }));

    router.get('/identifiers', middleware.requireAuth, wrap(async (req, res) => {
        const identifiers = await authManager.getIdentifiers(req.user.id);
        res.json({ success: true, identifiers });
    }));

    router.post('/identifiers', middleware.requireAuth, wrap(async (req, res) => {
        const { type, value } = req.body;
        await authManager.addUserIdentifier(req.user.id, type, value);
        res.status(201).json({ success: true });
    }));

    router.delete('/identifiers/:type/:value', middleware.requireFreshAuth, wrap(async (req, res) => {
        await authManager.removeUserIdentifier(req.user.id, req.params.type, req.params.value);
        res.json({ success: true });
    }));

    // --- Session Management ---

    router.get('/sessions', middleware.requireAuth, wrap(async (req, res) => {
        const sessions = await authManager.getUserSessions(req.user.id);
        const annotated = sessions.map(s => ({
            ...s,
            isCurrent: s.session_token === req.sessionToken
        }));
        res.json({ success: true, sessions: annotated });
    }));

    router.delete('/sessions/:sessionId', middleware.requireAuth, wrap(async (req, res) => {
        const { sessionId } = req.params;
        const sessions = await authManager.getUserSessions(req.user.id);
        const target = sessions.find(s => String(s.id) === sessionId);
        
        if (!target) {
            const err = new AuthError(ERROR.invalid_session, 'Session not found');
            err.code = 404;
            throw err;
        }
        
        if (target.session_token === req.sessionToken) {
            const err = new AuthError(ERROR.invalid_session, 'Cannot revoke your current session. Use /logout instead.');
            err.code = 400;
            throw err;
        }
        
        await authManager.revokeSession(req.user.id, target.id);
        res.json({ success: true });
    }));

    router.use(AuthMiddleware.errorHandler);

    return router;
}

