import { initAuthDb, authDb } from './db/init.js';
import SQLiteSessionStore from './db/sessionStore.js';
import authRouter from './routes/auth.js';
import { requireAuth, requireFreshAuth, requireApiKey, authErrorLogger } from './middleware/auth.js';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

import { DefaultLogger } from './utils/logger.js';
import { AuthClient, AuthError } from './client.js';
import { formatAuthError, resolveWebAuthnOptions } from './utils/authHelpers.js';

/**
 * Initializes the authentication databases and configuration.
 * @param {import('express').Application} app - The Express application.
 * @param {Object} options - Configuration options.
 * @param {string} [options.dataDir] - Directory to store SQLite databases. Defaults to './data'.
 * @param {Object} [options.config] - Authentication configuration (domain, rpID, origin, etc.). Stored by reference (not copied).
 * @param {string|boolean} [options.sdkRoute='/auth-sdk.js'] - Route to serve the frontend SDK. Set to false to disable.
 * @param {boolean} [options.exposeErrors=false] - If true, detailed error messages are sent to the client.
 * @param {Object} [options.logger] - Custom logger object. Should implement error, warn, info, debug.
 * @param {function(import('express').Request): { rpID: string, origin: string, rpName?: string }} [options.getWebAuthnOptions] - Per-request WebAuthn rpID/origin (e.g. behind reverse proxies). Requires trust proxy for correct Host/proto.
 * @param {boolean} [options.enableApiKeys=true] - If false, user-facing /api-keys CRUD routes return 404. requireApiKey middleware still works.
 */
export function setupAuth(app, options = {}) {
  const dataDir = options.dataDir || path.join(process.cwd(), 'data');
  const config = options.config || {};
  const sdkRoute = options.sdkRoute !== undefined ? options.sdkRoute : '/auth-sdk.js';
  const exposeErrors = options.exposeErrors !== undefined ? options.exposeErrors : false;
  const logger = options.logger || new DefaultLogger();

  initAuthDb(dataDir);

  app.set('config', config);
  app.set('exposeErrors', exposeErrors);
  app.set('getWebAuthnOptions', options.getWebAuthnOptions ?? null);
  app.set('enableApiKeys', options.enableApiKeys !== false);
  app.set('logger', logger);

  // Serve the frontend SDK if enabled
  if (sdkRoute) {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = dirname(__filename);
    const sdkPath = path.join(__dirname, 'client.js');

    app.get(sdkRoute, (req, res) => {
      res.setHeader('Content-Type', 'application/javascript');
      res.sendFile(sdkPath);
    });
  }
}

export {
  authDb,
  SQLiteSessionStore,
  authRouter,
  authRouter as auth,
  requireAuth,
  requireFreshAuth,
  requireApiKey,
  authErrorLogger,
  DefaultLogger,
  AuthClient,
  AuthError,
  formatAuthError,
  resolveWebAuthnOptions
};
