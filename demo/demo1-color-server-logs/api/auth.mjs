import authRoutes from '../../../src/router/auth/routes.mjs';

export default function(req, res, next) {
    // We wrap the standardized router so we can pass the authManager from the request
    return authRoutes(req.authManager)(req, res, next);
}
