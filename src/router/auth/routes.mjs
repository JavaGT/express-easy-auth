import { Router } from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { AuthMiddleware } from './AuthMiddleware.mjs';
import { ERROR, AuthError } from './util/errors.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const wrap = (fn) => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};

function extractWebAuthnConfig(req) {
    const host   = req.get('host') || req.hostname || '';
    const origin = req.get('origin') || `${req.protocol}://${host}`;
    let rpID     = req.hostname;
    if (origin) {
        try { rpID = new URL(origin).hostname; } catch {}
    }
    return { origin, rpID };
}

function populateSession(req, user) {
    req.session.userId              = user.id;
    req.session.lastAuthenticatedAt = Date.now();
    return new Promise((resolve, reject) =>
        req.session.save((err) => err ? reject(err) : resolve())
    );
}

export default function authRoutes(authManager, rateLimitOptions = {}) {
    const router = Router();
    const mw     = new AuthMiddleware(authManager);

    const rl = rateLimitOptions !== false
        ? mw.rateLimit({ windowMs: 15 * 60 * 1000, max: 20, ...rateLimitOptions })
        : (req, res, next) => next();

    router.get('/', (req, res) => {
        res.json({ name: 'Express Easy Auth API', version: '4.1.0' });
    });

    router.get('/client.js', (req, res) => {
        res.setHeader('Content-Type', 'application/javascript');
        res.sendFile(path.join(__dirname, '../../client/EasyAuthClient.mjs'));
    });

    // -------------------------------------------------------------------------
    // Authentication & Registration
    // -------------------------------------------------------------------------

    router.post('/register', rl, wrap(async (req, res) => {
        const { email, password, displayName } = req.body;
        await authManager.registerUser(email, password, displayName);
        res.status(201).json({ success: true });
    }));

    router.post('/verify-email', wrap(async (req, res) => {
        const { token } = req.body;
        res.json(await authManager.verifyEmail(token));
    }));

    router.post('/login', rl, wrap(async (req, res) => {
        const { email, password, totp, code, userIdentifier, loginCode } = req.body;
        const { user } = await authManager.authenticateLogin(email || userIdentifier, password, totp || code, loginCode);
        await populateSession(req, user);
        res.json({ success: true, user });
    }));

    router.post('/logout', mw.requireAuth, wrap(async (req, res) => {
        req.session.destroy(() => res.json({ success: true }));
    }));

    // -------------------------------------------------------------------------
    // Identity info
    // -------------------------------------------------------------------------

    router.get('/me', mw.requireAuthOrApiKey, (req, res) => {
        res.json({
            success:            true,
            user:               req.user,
            authType:           req.authType,
            lastAuthenticatedAt: req.lastAuthenticatedAt,
            apiKey:             req.apiKey ? { id: req.apiKey.id, name: req.apiKey.name, prefix: req.apiKey.prefix } : undefined,
        });
    });

    router.delete('/account', mw.requireFreshAuth, wrap(async (req, res) => {
        const userId = req.user.id;
        const result = await authManager.deleteUser(userId);
        await new Promise((resolve) => req.session.destroy(resolve));
        res.json(result);
    }));

    // -------------------------------------------------------------------------
    // TOTP
    // -------------------------------------------------------------------------

    router.get('/totp/status', mw.requireAuth, wrap(async (req, res) => {
        res.json({ success: true, ...await authManager.getTotpStatus(req.user.id) });
    }));

    router.post('/totp/setup', mw.requireFreshAuth, wrap(async (req, res) => {
        const setup = await authManager.generateTotpSetup(req.user.id);
        // Store the pending secret server-side; do not trust the client to echo it back.
        req.session.pendingTotpSecret = setup.secret;
        res.json({ success: true, secret: setup.secret, qrCode: setup.qrCode });
    }));

    router.post('/totp/verify', mw.requireFreshAuth, wrap(async (req, res) => {
        const secret = req.session.pendingTotpSecret;
        if (!secret) throw new AuthError(ERROR.invalid_session, 'No pending TOTP setup. Call /totp/setup first.');
        const { code } = req.body;
        const result = await authManager.verifyAndEnableTotp(req.user.id, code, secret);
        delete req.session.pendingTotpSecret;
        res.json(result);
    }));

    router.post('/totp/disable', mw.requireFreshAuth, wrap(async (req, res) => {
        res.json(await authManager.disableTotp(req.user.id));
    }));

    // -------------------------------------------------------------------------
    // WebAuthn Passkeys
    // -------------------------------------------------------------------------

    router.post('/passkeys/register/options', mw.requireAuth, wrap(async (req, res) => {
        const cfg     = extractWebAuthnConfig(req);
        const options = await authManager.generateRegistrationOptions(req.user, cfg);
        const nonce   = randomBytes(8).toString('hex');
        req.session.regNonce = nonce;
        await authManager.setChallenge('reg_' + req.user.id + '_' + nonce, options.challenge);
        res.json(options);
    }));

    router.post('/passkeys/register/verify', mw.requireAuth, wrap(async (req, res) => {
        const cfg             = extractWebAuthnConfig(req);
        const { name, ...body } = req.body;
        const nonce           = req.session.regNonce;
        const challenge       = await authManager.getChallenge('reg_' + req.user.id + '_' + (nonce || ''));
        if (!challenge) throw new AuthError(ERROR.invalid_session, 'Registration challenge expired or not found. Request new options.');
        delete req.session.regNonce;
        res.json(await authManager.verifyRegistration(req.user, body, challenge, name, cfg));
    }));

    router.patch('/passkeys/:id/name', mw.requireAuth, wrap(async (req, res) => {
        await authManager.updatePasskeyName(req.user.id, req.params.id, req.body.name);
        res.json({ success: true });
    }));

    router.post('/passkeys/login/options', rl, wrap(async (req, res) => {
        const cfg     = extractWebAuthnConfig(req);
        const options = await authManager.generateAuthenticationOptions(cfg);
        const tempId  = randomBytes(8).toString('hex');
        await authManager.setChallenge('login_' + tempId, options.challenge);
        res.json({ ...options, tempId });
    }));

    router.post('/passkeys/login/verify', wrap(async (req, res) => {
        const cfg            = extractWebAuthnConfig(req);
        const { response, tempId } = req.body;
        const challenge      = await authManager.getChallenge('login_' + tempId);
        if (!challenge) throw new AuthError(ERROR.invalid_session, 'Passkey challenge expired or not found. Request new options.');
        const { user }       = await authManager.verifyAuthentication(response, challenge, cfg);
        await populateSession(req, user);
        res.json({ success: true, user });
    }));

    router.post('/passkeys/verify/options', mw.requireAuth, wrap(async (req, res) => {
        const cfg     = extractWebAuthnConfig(req);
        const options = await authManager.generateAuthenticationOptions(cfg);
        const nonce   = randomBytes(8).toString('hex');
        req.session.verifyNonce = nonce;
        await authManager.setChallenge('verify_' + req.user.id + '_' + nonce, options.challenge);
        res.json(options);
    }));

    router.post('/passkeys/verify/verify', mw.requireAuth, wrap(async (req, res) => {
        const cfg       = extractWebAuthnConfig(req);
        const nonce     = req.session.verifyNonce;
        const challenge = await authManager.getChallenge('verify_' + req.user.id + '_' + (nonce || ''));
        if (!challenge) throw new AuthError(ERROR.invalid_session, 'Step-up challenge expired or not found. Request new options.');
        delete req.session.verifyNonce;
        const result    = await authManager.verifyAuthentication(req.body, challenge, cfg);
        req.session.lastAuthenticatedAt = Date.now();
        await new Promise((resolve, reject) => req.session.save((err) => err ? reject(err) : resolve()));
        res.json(result);
    }));

    router.get('/passkeys', mw.requireAuth, wrap(async (req, res) => {
        res.json(await authManager.getPasskeys(req.user.id));
    }));

    router.delete('/passkeys/:id', mw.requireAuth, wrap(async (req, res) => {
        await authManager.deletePasskey(req.user.id, req.params.id);
        res.json({ success: true });
    }));

    // -------------------------------------------------------------------------
    // API Keys
    //
    // Create and revoke require requireAuth (session only) because
    // personal:apikeys.write is a session-only scope — a key cannot create
    // or revoke other keys.
    //
    // Listing requires personal:apikeys.read and can be done via API key.
    // -------------------------------------------------------------------------

    router.get('/keys', mw.requireAuthOrApiKey, mw.requirePersonalScope('personal:apikeys.read'), wrap(async (req, res) => {
        res.json(await authManager.listApiKeys(req.user.id));
    }));

    router.post('/keys', mw.requireAuth, wrap(async (req, res) => {
        const { name, grants, expiresAt } = req.body;
        const result = await authManager.createApiKey(req.user.id, { name, grants: grants || {}, expiresAt });
        res.status(201).json({ success: true, ...result });
    }));

    router.patch('/keys/:id', mw.requireAuth, wrap(async (req, res) => {
        const { name, expiresAt, clearExpiry } = req.body;
        if (name !== undefined && !name?.trim()) {
            throw new AuthError(ERROR.invalid_input, 'API key name cannot be blank');
        }
        await authManager.updateApiKey(req.user.id, Number(req.params.id), { name, expiresAt, clearExpiry });
        res.json({ success: true });
    }));

    router.delete('/keys/:id', mw.requireAuth, wrap(async (req, res) => {
        await authManager.revokeApiKey(req.user.id, Number(req.params.id));
        res.json({ success: true });
    }));

    // -------------------------------------------------------------------------
    // Scope taxonomy
    // -------------------------------------------------------------------------

    router.get('/scopes', (req, res) => {
        res.json({ success: true, ...authManager.getScopeTaxonomy() });
    });

    // -------------------------------------------------------------------------
    // Password Reset
    // -------------------------------------------------------------------------

    router.post('/password-reset/request', rl, wrap(async (req, res) => {
        const { identifier, email } = req.body;
        try { await authManager.requestPasswordReset(identifier || email); } catch (_) {}
        res.json({ success: true });
    }));

    router.post('/password-reset/reset', wrap(async (req, res) => {
        const { token, newPassword } = req.body;
        const { userId } = await authManager.resetPassword(token, newPassword);
        // Invalidate all sessions for the user after a password reset.
        await new Promise((resolve) => req.sessionStore.destroyByUserId(userId, resolve));
        res.json({ success: true });
    }));

    // -------------------------------------------------------------------------
    // Account management
    // -------------------------------------------------------------------------

    router.post('/password/change', mw.requireFreshAuth, wrap(async (req, res) => {
        const userId = req.user.id;
        await authManager.changePassword(userId, req.body.newPassword);
        // Invalidate all sessions except the current one, then re-populate it.
        await new Promise((resolve) => req.sessionStore.destroyByUserId(userId, resolve));
        await populateSession(req, req.user);
        res.json({ success: true });
    }));

    router.get('/identifiers', mw.requireAuth, wrap(async (req, res) => {
        res.json({ success: true, identifiers: await authManager.getIdentifiers(req.user.id) });
    }));

    router.post('/identifiers', mw.requireAuth, wrap(async (req, res) => {
        const { type, value } = req.body;
        await authManager.addUserIdentifier(req.user.id, type, value);
        res.status(201).json({ success: true });
    }));

    router.delete('/identifiers/:type/:value', mw.requireFreshAuth, wrap(async (req, res) => {
        await authManager.removeUserIdentifier(req.user.id, req.params.type, req.params.value);
        res.json({ success: true });
    }));

    // -------------------------------------------------------------------------
    // Session management
    // -------------------------------------------------------------------------

    router.get('/sessions', mw.requireAuth, wrap(async (req, res) => {
        const sessions = await new Promise((resolve, reject) =>
            req.sessionStore.getAllByUserId(req.user.id, (err, rows) => err ? reject(err) : resolve(rows))
        );
        res.json({ success: true, sessions: sessions.map(s => ({ ...s, isCurrent: s.sid === req.sessionID })) });
    }));

    router.delete('/sessions/:sessionId', mw.requireAuth, wrap(async (req, res) => {
        const { sessionId } = req.params;
        if (sessionId === req.sessionID) {
            const err = new AuthError(ERROR.invalid_session, 'Cannot revoke your current session. Use /logout instead.');
            err.code = 400;
            throw err;
        }
        const sessions = await new Promise((resolve, reject) =>
            req.sessionStore.getAllByUserId(req.user.id, (err, rows) => err ? reject(err) : resolve(rows))
        );
        if (!sessions.find(s => s.sid === sessionId)) {
            const err = new AuthError(ERROR.invalid_session, 'Session not found');
            err.code = 404;
            throw err;
        }
        await new Promise((resolve, reject) =>
            req.sessionStore.destroy(sessionId, (err) => err ? reject(err) : resolve())
        );
        res.json({ success: true });
    }));

    router.use(AuthMiddleware.errorHandler);
    return router;
}
