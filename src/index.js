import { initAuthDb, authDb } from './db/init.js';
import SQLiteSessionStore from './db/sessionStore.js';
import authRouter from './routes/auth.js';
import { requireAuth, requireFreshAuth, requireApiKey, authErrorLogger } from './middleware/auth.js';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

import { DefaultLogger } from './utils/logger.js';
import { AuthClient, AuthError } from './client.js';

/**
 * Initializes the authentication databases and configuration.
 * @param {import('express').Application} app - The Express application.
 * @param {Object} options - Configuration options.
 * @param {string} [options.dataDir] - Directory to store SQLite databases. Defaults to './data'.
 * @param {Object} [options.config] - Authentication configuration (domain, rpID, etc.).
 * @param {string|boolean} [options.sdkRoute='/auth-sdk.js'] - Route to serve the frontend SDK. Set to false to disable.
 * @param {boolean} [options.exposeErrors=false] - If true, detailed error messages are sent to the client.
 * @param {Object} [options.logger] - Custom logger object. Should implement error, warn, info, debug.
 */
export function setupAuth(app, options = {}) {
  const dataDir = options.dataDir || path.join(process.cwd(), 'data');
  const config = options.config || {};
  const sdkRoute = options.sdkRoute !== undefined ? options.sdkRoute : '/auth-sdk.js';
  const exposeErrors = options.exposeErrors !== undefined ? options.exposeErrors : false;
  const logger = options.logger || new DefaultLogger();

  initAuthDb(dataDir);

  // Store for middleware access
  app.set('config', { ...config, exposeErrors });
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
  AuthError
};
