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
import {
  setupAuth,
  authRouter,
  SQLiteSessionStore,
  authErrorLogger,
  requireApiKey
} from '../src/index.js';
import { DatabaseSync } from 'node:sqlite';
import profileRouter from './profileRouter.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ─── CONFIG ──────────────────────────────────────────────────────────────────
const DOMAIN = process.env.DOMAIN || 'localhost';
const PORT = parseInt(process.env.PORT || '3000', 10);
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-in-production-please';
const IS_PROD = process.env.NODE_ENV === 'production';

// Robust hostname extraction
let HOSTNAME = DOMAIN.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
const IS_LOCALHOST = HOSTNAME.includes('localhost') || HOSTNAME.includes('127.0.0.1');
const PROTOCOL = (IS_PROD || !IS_LOCALHOST) ? 'https' : 'http';
const ORIGIN = `${PROTOCOL}://${HOSTNAME}${(!IS_PROD && IS_LOCALHOST && PORT !== 80 && PORT !== 443) ? `:${PORT}` : ''}`;

const config = {
  domain: HOSTNAME,
  port: PORT,
  protocol: PROTOCOL,
  origin: ORIGIN,
  rpName: 'Auth Server Demo',
  rpID: HOSTNAME,
};

const app = express();

// 2. Initialize Authentication Services
const dataDir = path.join(__dirname, '../data');
setupAuth(app, {
  dataDir,
  exposeErrors: !IS_PROD,
  config
});

// 2b. Initialize Application Database (External to Auth Server)
const appDataDb = new DatabaseSync(path.join(dataDir, 'app_data.db'));
appDataDb.exec(`
  CREATE TABLE IF NOT EXISTS profiles (
    user_id TEXT PRIMARY KEY,
    display_name TEXT,
    bio TEXT,
    avatar_url TEXT,
    location TEXT,
    website TEXT,
    preferences TEXT, -- JSON string for app settings
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
`);

// Attach appDataDb to app for use in routers
app.set('appDataDb', appDataDb);


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

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(SESSION_SECRET));

// ─── SESSION ─────────────────────────────────────────────────────────────────

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

// 3. Mount Library & Application Routes
app.use('/api/v1/auth', authRouter);
app.use('/api/v1/profile', profileRouter);

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

// ─── DEMO MAILBOX (TEST ENDPOINTS) ──────────────────────────────────────────
const mailboxMessages = [];

app.get('/api/v1/test/mailbox', (req, res) => {
  res.json({ messages: mailboxMessages });
});

app.post('/api/v1/test/mailbox', (req, res) => {
  const { type, subject, body } = req.body;
  const msg = {
    id: Math.random().toString(36).substring(2, 9),
    type: type || 'System',
    subject: subject || 'No Subject',
    body: body || '',
    timestamp: Date.now()
  };
  mailboxMessages.unshift(msg);
  if (mailboxMessages.length > 50) mailboxMessages.pop();
  res.status(201).json(msg);
});

app.delete('/api/v1/test/mailbox', (req, res) => {
  mailboxMessages.length = 0;
  res.status(204).send();
});

// Serve frontend from demo directory
app.use(express.static(path.join(__dirname, './public')));

// ─── ERROR HANDLER ───────────────────────────────────────────────────────────

app.use(authErrorLogger);

// ─── START ───────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n🔐 Auth Demo Server running`);
  console.log(`   URL:     ${ORIGIN}`);
  console.log(`   RPID:    ${config.rpID}`);
  console.log(`   Env:     ${IS_PROD ? 'production' : 'development'}\n`);
});
