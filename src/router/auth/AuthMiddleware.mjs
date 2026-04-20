import { ERROR, AuthError } from './util/errors.mjs';
import MultiError from './util/MultiError.mjs';

/**
 * AuthMiddleware - Handles Express middleware for authentication.
 * Separates routing/HTTP concerns from core auth business logic.
 */
export class AuthMiddleware {
    #authManager;

    constructor(authManager) {
        this.#authManager = authManager;

        // Bind methods for Express context
        this.useApiKey = this.useApiKey.bind(this);
        this.requireApiKey = this.requireApiKey.bind(this);
        this.requireAuth = this.requireAuth.bind(this);
        this.requireAuthOrApiKey = this.requireAuthOrApiKey.bind(this);
        this.requireFreshAuth = this.requireFreshAuth.bind(this);
        this.rateLimit = this.rateLimit.bind(this);

        this.#rateLimitStore = new Map();
    }

    #rateLimitStore;

    /**
     * Extract an API key from the request using multiple transports:
     *   1. `X-API-Key` header (canonical)
     *   2. `Authorization: Bearer sk_...` (when token starts with the `sk_` prefix)
     *   3. `req.query.apiKey` / `req.body.apiKey` (legacy query/body forms)
     *
     * Note: `Authorization: Bearer` tokens that do NOT start with `sk_` are
     * intentionally ignored here so that session bearer tokens are unaffected.
     *
     * @param {import('express').Request} req
     * @returns {string|null}
     */
    #extractApiKey(req) {
        if (req.headers['x-api-key']) return req.headers['x-api-key'];

        const authHeader = req.headers['authorization'];
        if (authHeader?.startsWith('Bearer sk_')) {
            return authHeader.slice('Bearer '.length);
        }

        return req.query?.apiKey || req.body?.apiKey || null;
    }

    /**
     * Middleware to authenticate via API Key only.
     * Errors immediately if no valid key is present.
     *
     * Accepted transports:
     *   - `X-API-Key: <key>` header
     *   - `Authorization: Bearer sk_<key>` header
     *   - `?apiKey=<key>` query param or `req.body.apiKey`
     *
     * Sets `req.user`, `req.scopes`, `req.authType = 'api_key'`.
     */
    async useApiKey(req, res, next) {
        const apiKey = this.#extractApiKey(req);

        if (!apiKey) {
            return next(new AuthError(ERROR.api_key_required));
        }

        try {
            const authData = await this.#authManager.authenticateApiKey(apiKey);
            req.user = authData.user;
            req.scopes = authData.scopes;
            req.authType = 'api_key';
            next();
        } catch (err) {
            next(err);
        }
    }

    /**
     * Alias for `useApiKey`. Provided to complete the naming trilogy:
     * `requireAuth` / `requireApiKey` / `requireAuthOrApiKey`.
     *
     * Use this when a route must be accessed by API key only (no session).
     */
    requireApiKey(req, res, next) {
        return this.useApiKey(req, res, next);
    }

    /**
     * Middleware to require a valid session (cookie-based via express-session).
     */
    async requireAuth(req, res, next) {
        if (!req.session?.userId) {
            return next(new AuthError(ERROR.invalid_session));
        }

        try {
            const user = await this.#authManager.getUserById(req.session.userId);
            if (!user) return next(new AuthError(ERROR.invalid_session));

            req.user = { id: user.id, email: user.email, display_name: user.display_name };
            req.lastAuthenticatedAt = req.session.lastAuthenticatedAt ?? 0;
            req.scopes = req.session.scopes ?? [];
            req.roles = req.session.roles ?? [];
            req.authType = 'session';
            next();
        } catch (err) {
            next(err);
        }
    }

    /**
     * Middleware to allow either session or API key.
     */
    async requireAuthOrApiKey(req, res, next) {
        if (req.session?.userId) {
            try {
                const user = await this.#authManager.getUserById(req.session.userId);
                if (user) {
                    req.user = { id: user.id, email: user.email, display_name: user.display_name };
                    req.lastAuthenticatedAt = req.session.lastAuthenticatedAt ?? 0;
                    req.scopes = req.session.scopes ?? [];
                    req.roles = req.session.roles ?? [];
                    req.authType = 'session';
                    return next();
                }
            } catch (_) {}
        }

        const apiKey = this.#extractApiKey(req);

        if (apiKey) {
            try {
                const authData = await this.#authManager.authenticateApiKey(apiKey);
                req.user = authData.user;
                req.scopes = authData.scopes || [];
                req.keyName = authData.name;
                req.authType = 'api_key';
                return next();
            } catch (_) {}
        }

        next(new AuthError(ERROR.invalid_session));
    }

    /**
     * Middleware to require "fresh" authentication (session re-verified within the last 5 minutes).
     *
     * Internally calls `requireAuth` first, so you do NOT need to chain `requireAuth` before this.
     * API key authentication is explicitly rejected — this guard is for human session flows only.
     *
     * Can be used in two ways:
     *
     * @example Plain middleware (no scope check)
     * app.delete('/account', auth.requireFreshAuth, handler);
     *
     * @example Factory with scope enforcement
     * app.post('/members', auth.requireFreshAuth(['project:manage']), handler);
     *
     * @param {string[]|import('express').Request} scopesOrReq
     *   When called as a factory, pass the required scopes array.
     *   When used directly as middleware, Express passes `req` here.
     */
    requireFreshAuth(scopesOrReq, res, next) {
        // Factory mode: requireFreshAuth(['scope:a', 'scope:b'])
        if (Array.isArray(scopesOrReq)) {
            const requiredScopes = scopesOrReq;
            return (req, res, next) => this.#runFreshAuth(req, res, next, requiredScopes);
        }
        // Plain middleware mode: requireFreshAuth used directly on a route
        return this.#runFreshAuth(scopesOrReq, res, next, []);
    }

    async #runFreshAuth(req, res, next, requiredScopes = []) {
        if (req.authType === 'api_key') {
            return next(new AuthError(ERROR.session_expired));
        }

        await this.requireAuth(req, res, (err) => {
            if (err) return next(err);

            const FRESHNESS_WINDOW = 5 * 60 * 1000; // 5 minutes
            const timeSinceAuth = Date.now() - req.lastAuthenticatedAt;

            if (timeSinceAuth > FRESHNESS_WINDOW) {
                return next(new AuthError(ERROR.session_step_up_required));
            }

            if (requiredScopes.length > 0) {
                const userScopes = req.scopes || [];
                const hasAll = requiredScopes.every(
                    s => userScopes.includes(s) || userScopes.includes('*')
                );
                if (!hasAll) {
                    return next(new AuthError(ERROR.insufficient_scope));
                }
            }

            next();
        });
    }

    /**
     * Generic rate limiting middleware.
     * @param {Object} options
     * @param {number} options.windowMs - Time window in milliseconds (default: 15 mins)
     * @param {number} options.max - Max requests per window (default: 100)
     */
    rateLimit(options = {}) {
        const windowMs = options.windowMs || 15 * 60 * 1000;
        const max = options.max || 100;
        const message = options.message || 'Too many requests, please try again later.';

        return (req, res, next) => {
            const ip = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
            const now = Date.now();

            if (!this.#rateLimitStore.has(ip)) {
                this.#rateLimitStore.set(ip, { count: 1, resetTime: now + windowMs });
                return next();
            }

            const record = this.#rateLimitStore.get(ip);

            if (now > record.resetTime) {
                record.count = 1;
                record.resetTime = now + windowMs;
                return next();
            }

            record.count++;

            if (record.count > max) {
                return res.status(429).json({
                    success: false,
                    error: 'TOO_MANY_REQUESTS',
                    message
                });
            }

            next();
        };
    }

    /**
     * Unified error handling middleware for Express.
     */
    static errorHandler(err, req, res, next) {
        const { status, body } = AuthMiddleware.processError(err);
        res.status(status).json(body);
    }

    static processError(err) {
        if (err instanceof MultiError) {
            return {
                status: 400,
                body: {
                    success: false,
                    error: 'VALIDATION_FAILED',
                    errors: err.errors
                }
            };
        }

        if (err.toJSON) {
            const json = err.toJSON();
            return {
                status: typeof err.code === 'number' ? err.code : 400,
                body: json
            };
        }

        const status = typeof err.code === 'number' ? err.code : 500;
        return {
            status,
            body: {
                success: false,
                error: 'INTERNAL_ERROR',
                message: err.message || 'An unexpected error occurred'
            }
        };
    }
}
