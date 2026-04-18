import { AuthError, ERROR } from './util/errors.mjs';

/**
 * AuthGuard - A DX-focused wrapper for AuthMiddleware.
 * Provides a fluent, declarative interface for route protection.
 */
export class AuthGuard {
    #middleware;

    constructor(authMiddleware) {
        this.#middleware = authMiddleware;
    }

    /**
     * Require either session or API key with a specific scope.
     * @param {string} scope - The required scope.
     */
    allow(scope) {
        return (req, res, next) => {
            this.#middleware.requireAuthOrApiKey(req, res, (err) => {
                if (err) return next(err);
                
                // Unified check: req.scopes is populated by middleware for both auth types
                if (!req.scopes || (!req.scopes.includes(scope) && !req.scopes.includes('*'))) {
                    return next(new AuthError(ERROR.insufficient_scope));
                }
                next();
            });
        };
    }

    /**
     * Require a valid UI session only (no API keys).
     */
    session() {
        return this.#middleware.requireAuth;
    }

    /**
     * Require a "fresh" session (recent authentication).
     * @param {object} options - Options for freshness check.
     */
    fresh(options = {}) {
        return (req, res, next) => {
            this.#middleware.requireFreshAuth(req, res, next);
        };
    }

    /**
     * Require both a fresh session AND a specific scope.
     * @param {string} scope - The required scope.
     */
    freshAndAllow(scope) {
        return (req, res, next) => {
            this.#middleware.requireFreshAuth(req, res, (err) => {
                if (err) return next(err);
                
                if (!req.scopes || (!req.scopes.includes(scope) && !req.scopes.includes('*'))) {
                    return next(new AuthError(ERROR.insufficient_scope));
                }
                next();
            });
        };
    }

    /**
     * Optional authentication: populates req.user if possible, but never blocks.
     */
    optional() {
        return (req, res, next) => {
            // We can try to authenticate but ignore any errors
            this.#middleware.requireAuthOrApiKey(req, res, () => next());
        };
    }
}
