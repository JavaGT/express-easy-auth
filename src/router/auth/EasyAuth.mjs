import authRoutes from './routes.mjs';
import { AuthMiddleware } from './AuthMiddleware.mjs';
import { OpenAPIService } from './services/OpenAPIService.mjs';

/**
 * High-level convenience façade for wiring Easy Auth into an Express app
 * in a single call, without needing to manually configure the router and
 * middleware. The low-level API (`authRoutes`, `AuthMiddleware`) is still
 * fully available for advanced use cases.
 *
 * @example
 * import { EasyAuth } from 'express-easy-auth';
 *
 * const auth = EasyAuth.attach(app, authManager, { basePath: '/auth' });
 *
 * // `auth` is an AuthMiddleware instance, ready to use on your own routes:
 * app.get('/profile', auth.requireAuth, (req, res) => res.json(req.user));
 */
export class EasyAuth {
    /**
     * Mount the Easy Auth router on an Express app and return a ready
     * AuthMiddleware instance.
     *
     * @param {import('express').Application} app - Your Express application.
     * @param {import('./AuthManager.mjs').AuthManager} authManager - Configured AuthManager instance.
     * @param {object} [options]
     * @param {string} [options.basePath='/auth'] - The URL prefix to mount the auth router on.
     * @param {boolean} [options.exposeOpenApi=true] - Whether to serve the OpenAPI spec at `${basePath}/openapi.json`.
     * @returns {AuthMiddleware} A bound middleware helper for protecting your own routes.
     */
    static attach(app, authManager, { basePath = '/auth', exposeOpenApi = true } = {}) {
        const router = authRoutes(authManager);
        app.use(basePath, router);

        if (exposeOpenApi) {
            const openApiService = new OpenAPIService(basePath);
            router.get('/openapi.json', (req, res) => {
                res.json(openApiService.getSpec());
            });
        }
        
        // Attach error handler to the end of the auth router chain
        router.use(AuthMiddleware.errorHandler);

        return new AuthMiddleware(authManager);
    }
}
