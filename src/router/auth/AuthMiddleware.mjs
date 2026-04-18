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
        this.requireAuth = this.requireAuth.bind(this);
        this.requireAuthOrApiKey = this.requireAuthOrApiKey.bind(this);
        this.requireFreshAuth = this.requireFreshAuth.bind(this);
        this.rateLimit = this.rateLimit.bind(this);
        
        this.#rateLimitStore = new Map();
    }

    #rateLimitStore;

    /**
     * Middleware to authenticate via API Key.
     */
    async useApiKey(req, res, next) {
        const apiKey = req.headers['x-api-key'] || req.query?.apiKey || req.body?.apiKey;
        
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
     * Middleware to require a valid session (Bearer token).
     */
    async requireAuth(req, res, next) {
        const authHeader = req.headers.authorization;
        const sessionToken = authHeader?.startsWith('Bearer ') 
            ? authHeader.substring(7) 
            : req.query?.session || req.body?.session;

        if (!sessionToken) {
            return next(new AuthError(ERROR.invalid_session));
        }

        try {
            const sessionData = await this.#authManager.validateSession(sessionToken);
            
            req.user = sessionData.user;
            req.sessionToken = sessionData.sessionToken;
            req.lastAuthenticatedAt = sessionData.lastAuthenticatedAt;
            req.scopes = sessionData.scopes || [];
            req.roles = sessionData.roles || [];
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
        const authHeader = req.headers.authorization;
        const sessionToken = authHeader?.startsWith('Bearer ') 
            ? authHeader.substring(7) 
            : req.query?.session || req.body?.session;

        if (sessionToken) {
            try {
                // Try session auth first
                const sessionData = await this.#authManager.validateSession(sessionToken);
                req.user = sessionData.user;
                req.sessionToken = sessionData.sessionToken;
                req.lastAuthenticatedAt = sessionData.lastAuthenticatedAt;
                req.authType = 'session';
                return next();
            } catch (err) {
                // Continue to check API key if session fails
            }
        }

        const apiKey = req.headers['x-api-key'] || req.query?.apiKey || req.body?.apiKey;
        
        if (apiKey) {
            try {
                const authData = await this.#authManager.authenticateApiKey(apiKey);
                req.user = authData.user;
                req.scopes = authData.scopes || [];
                req.keyName = authData.name;
                req.authType = 'api_key';
                return next();
            } catch (err) {
                // Return error if API key also fails
            }
        }

        next(new AuthError(ERROR.invalid_session));
    }

    /**
     * Middleware to require "fresh" authentication (recent session, no API keys).
     */
    async requireFreshAuth(req, res, next) {
        if (req.authType === 'api_key') {
            return next(new AuthError(ERROR.session_expired));
        }
        
        // Use requireAuth to establish baseline authentication
        await this.requireAuth(req, res, (err) => {
            if (err) return next(err);
            
            const FRESHNESS_WINDOW = 5 * 60 * 1000; // 5 minutes
            const timeSinceAuth = Date.now() - req.lastAuthenticatedAt;
            
            if (timeSinceAuth > FRESHNESS_WINDOW) {
                return next(new AuthError(ERROR.session_step_up_required));
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
     * Processes AuthErrors, MultiErrors, and standard JS Errors into a
     * consistent JSON response format.
     */
    static errorHandler(err, req, res, next) {
        const { status, body } = AuthMiddleware.processError(err);
        res.status(status).json(body);
    }

    /**
     * Helper to convert various error types into an HTTP status and JSON body.
     */
    static processError(err) {
        // MultiError (Collection of validation/auth errors)
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

        // AuthError/ValidationError (Single domain error with code/message)
        if (err.toJSON) {
            const json = err.toJSON();
            return {
                status: typeof err.code === 'number' ? err.code : 400,
                body: json
            };
        }

        // Generic Error
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

