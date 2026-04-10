import { initAuthDb, initUserDb, authDb, userDb } from './db/init.js';
import SQLiteSessionStore from './db/sessionStore.js';
import authRouter from './routes/auth.js';
import passkeysRouter from './routes/passkeys.js';
import userRouter from './routes/user.js';
import { requireAuth, requireFreshAuth, requireApiKey, authErrorLogger } from './middleware/auth.js';
import path from 'path';

/**
 * Initializes the authentication databases and configuration.
 * @param {import('express').Application} app - The Express application.
 * @param {Object} options - Configuration options.
 * @param {string} [options.dataDir] - Directory to store SQLite databases. Defaults to './data'.
 * @param {Object} [options.config] - Authentication configuration (domain, rpID, etc.).
 */
export function setupAuth(app, options = {}) {
  const dataDir = options.dataDir || path.join(process.cwd(), 'data');
  const config = options.config || {};

  initAuthDb(dataDir);
  initUserDb(dataDir);

  app.set('config', config);
}

export {
  authDb,
  userDb,
  SQLiteSessionStore,
  authRouter,
  passkeysRouter,
  userRouter,
  requireAuth,
  requireFreshAuth,
  requireApiKey,
  authErrorLogger
};
