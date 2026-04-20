import session from 'express-session';
import authRoutes from './routes.mjs';
import { AuthMiddleware } from './AuthMiddleware.mjs';
import { OpenAPIService } from './services/OpenAPIService.mjs';
import { SQLiteSessionStore } from './stores/SQLiteSessionStore.mjs';
import { AuthManager } from './AuthManager.mjs';

/**
 * Main facade for Express Easy Auth.
 */
export class EasyAuth {
    /**
     * Recommended way to get started. Instantiates AuthManager, initializes it,
     * attaches routes to the app, and returns both the auth middleware and manager.
     *
     * @param {import('express').Application} app The Express application instance.
     * @param {object} config Configuration for AuthManager.
     * @returns {Promise<{ auth: AuthMiddleware, authManager: AuthManager }>}
     */
    static async create(app, config = {}) {
        const authManager = new AuthManager(config);
        await authManager.init();
        const auth = EasyAuth.attach(app, authManager, config);
        return { auth, authManager };
    }

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
