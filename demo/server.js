import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

// 1. Import the library's main integration tools
// - setupAuth: Initializes the databases and configures the RP (Relying Party)
// - Routers: Standard Express routers for various auth features
// - SQLiteSessionStore: A custom session store optimized for this library
// - authErrorLogger: A global error handler that logs issues to the auth database
import { 
  setupAuth, 
  authRouter, 
  passkeysRouter, 
  userRouter, 
  SQLiteSessionStore,
  authErrorLogger,
  requireApiKey
} from '../src/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ─── CONFIG ──────────────────────────────────────────────────────────────────

const DOMAIN = process.env.DOMAIN || 'auth-test.javagrant.ac.nz';
const PORT = parseInt(process.env.PORT || '3000', 10);
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-in-production-please';
const IS_PROD = process.env.NODE_ENV === 'production';

// Robust hostname extraction
let HOSTNAME = DOMAIN.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
const IS_LOCALHOST = HOSTNAME.includes('localhost') || HOSTNAME.includes('127.0.0.1');
const PROTOCOL = (IS_PROD || !IS_LOCALHOST) ? 'https' : 'http';
const ORIGIN = `${PROTOCOL}://${HOSTNAME}${(!IS_PROD && IS_LOCALHOST && PORT !== 80 && PORT !== 443) ? `:${PORT}` : ''}`;

// 2. Global Configuration
// These settings are crucial for Passkeys/WebAuthn to function correctly.
// RP (Relying Party) Info must match the domain where the app is hosted.
const config = {
  domain: HOSTNAME,               // The domain name (e.g., app.com)
  port: PORT,                     // The port the server is listening on
  protocol: PROTOCOL,             // http/https
  origin: ORIGIN,                 // Full URL of the frontend (e.g., https://app.com)
  rpName: 'Auth Server Demo',     // Human-readable name shown in Passkey prompts
  rpID: HOSTNAME,                 // Must be the domain name
};

const app = express();

// 3. Initialize Authentication Services
// This creates the SQLite databases (auth.db, user.db) if they don't exist
// and attaches the config to the 'app' object for the routers to use.
setupAuth(app, {
  dataDir: path.join(__dirname, '../data'),
  config
});

// ─── MIDDLEWARE ──────────────────────────────────────────────────────────────

app.set('trust proxy', 1);

app.use(helmet({
  hsts: IS_PROD,
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
    },
  },
}));

app.use(cors({
  origin: ORIGIN,
  credentials: true,
}));

// 4. Core Express Middlewares
app.use(express.json());             // Required to parse JSON bodies from AJAX/SPA
app.use(express.urlencoded({ extended: true })); // Required to parse standard HTML form submissions
app.use(cookieParser(SESSION_SECRET));

// ─── SESSION ─────────────────────────────────────────────────────────────────

// 5. Session Management
// We use SQLiteSessionStore to keep session metadata (like last_activity)
// in our own database, enabling easy session viewing/revocation.
const sessionStore = new SQLiteSessionStore();

app.use(session({
  secret: SESSION_SECRET,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  name: 'auth.sid',
  cookie: {
    secure: PROTOCOL === 'https',
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 1 week
  },
}));

// ─── ROUTES ──────────────────────────────────────────────────────────────────

// Mount the authentication library routers
// 6. Library Routes
// It's recommended to mount these under /api/ to separate them from public assets.
app.use('/api/auth', authRouter);         // Register, Login, Logout, Status, 2FA
app.use('/api/passkeys', passkeysRouter); // WebAuthn Registration & Authentication
app.use('/api/user', userRouter);         // Profile & Session Management

// Sample Public API protected by API Keys
app.get('/api/public/data', requireApiKey, (req, res) => {
  if (!req.permissions.includes('action:read')) {
    return res.status(403).json({ error: 'Missing permission: action:read' });
  }
  res.json({
    message: 'Success! You accessed this data with an API key.',
    user: req.userId,
    permissions: req.permissions,
    timestamp: new Date().toISOString()
  });
});

app.post('/api/public/data', requireApiKey, (req, res) => {
  if (!req.permissions.includes('action:write')) {
    return res.status(403).json({ error: 'Missing permission: action:write' });
  }
  res.json({
    message: 'Success! You published data with an API key.',
    publishedAt: new Date().toISOString()
  });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', domain: DOMAIN, timestamp: new Date().toISOString() });
});

// Serve frontend from demo directory
app.use(express.static(path.join(__dirname, './public')));

// SPA fallback — serve index.html for all non-API routes
app.get(/^(?!\/api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, './public/index.html'));
});

// ─── ERROR HANDLER ───────────────────────────────────────────────────────────

app.use(authErrorLogger);

// ─── START ───────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n🔐 Auth Demo Server running`);
  console.log(`   URL:     ${ORIGIN}`);
  console.log(`   RPID:    ${config.rpID}`);
  console.log(`   Env:     ${IS_PROD ? 'production' : 'development'}\n`);
});
