import session from 'express-session';
import authRoutes from './routes.mjs';
import { AuthMiddleware } from './AuthMiddleware.mjs';
import { OpenAPIService } from './services/OpenAPIService.mjs';
import { SQLiteSessionStore } from './stores/SQLiteSessionStore.mjs';

/**
 * High-level convenience façade for wiring Easy Auth into an Express app
 * in a single call, without needing to manually configure the router and
 * middleware. The low-level API (`authRoutes`, `AuthMiddleware`) is still
 * fully available for advanced use cases.
 *
 * @example
 * import { EasyAuth } from 'express-easy-auth';
 *
 * const auth = EasyAuth.attach(app, authManager, {
 *   basePath: '/auth',
 *   session: { secret: process.env.SESSION_SECRET }
 * });
 *
 * // `auth` is an AuthMiddleware instance, ready to use on your own routes:
 * app.get('/profile', auth.requireAuth, (req, res) => res.json(req.user));
 */
export class EasyAuth {
    /**
     * Mount express-session and the Easy Auth router on an Express app,
     * then return a ready AuthMiddleware instance.
     *
     * @param {import('express').Application} app - Your Express application.
     * @param {import('./AuthManager.mjs').AuthManager} authManager - Configured AuthManager instance.
     * @param {object} [options]
     * @param {string} [options.basePath='/auth'] - The URL prefix to mount the auth router on.
     * @param {boolean} [options.exposeOpenApi=true] - Whether to serve the OpenAPI spec at `${basePath}/openapi.json`.
     * @param {object} [options.session] - Options forwarded to express-session (must include `secret`).
     * @param {object|false} [options.rateLimit] - Rate-limit options for sensitive auth routes, or false to disable.
     * @returns {AuthMiddleware} A bound middleware helper for protecting your own routes.
     */
    static attach(app, authManager, { basePath = '/auth', exposeOpenApi = true, session: sessionOptions = {}, rateLimit: rateLimitOptions = {} } = {}) {
        if (!sessionOptions.secret) {
            if (process.env.NODE_ENV === 'production') {
                throw new Error('[EasyAuth] options.session.secret is required in production.');
            }
            console.warn('[EasyAuth] No session secret provided — using an insecure default. Set options.session.secret in production.');
            sessionOptions.secret = 'easy-auth-default-secret-change-me';
        }

        const isProduction = process.env.NODE_ENV === 'production';
        const cookieDefaults = { httpOnly: true, sameSite: 'lax', secure: isProduction };
        const userCookie = sessionOptions.cookie || {};

        const store = new SQLiteSessionStore(authManager.databaseAdapter);

        app.use(session({
            resave: false,
            saveUninitialized: false,
            ...sessionOptions,
            cookie: { ...cookieDefaults, ...userCookie },
            store,
        }));

        const router = authRoutes(authManager, rateLimitOptions);
        app.use(basePath, router);

        if (exposeOpenApi) {
            const openApiService = new OpenAPIService(basePath);
            router.get('/openapi.json', (req, res) => {
                res.json(openApiService.getSpec());
            });
        }

        return new AuthMiddleware(authManager);
    }
}
