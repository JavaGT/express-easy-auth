import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

import { randomUUID } from 'crypto';
import { initAuthDb, initUserDb, authDb } from './db/init.js';
import SQLiteStore from './db/sessionStore.js';
import authRoutes from './routes/auth.js';
import passkeyRoutes from './routes/passkeys.js';
import userRoutes from './routes/user.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ─── CONFIG ──────────────────────────────────────────────────────────────────

const DOMAIN = process.env.DOMAIN || 'auth-test.javagrant.ac.nz';
const PORT = parseInt(process.env.PORT || '3000', 10);
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-in-production-please';
const IS_PROD = process.env.NODE_ENV === 'production';

// ─── DYNAMIC CONFIG ──────────────────────────────────────────────────────────

// Robust hostname extraction: strip protocol, port, and any path/trailing characters
let HOSTNAME = DOMAIN.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
const IS_LOCALHOST = HOSTNAME.includes('localhost') || HOSTNAME.includes('127.0.0.1');
const PROTOCOL = (IS_PROD || !IS_LOCALHOST) ? 'https' : 'http';

// Standardize origin: include port if not production default and it's localhost
const ORIGIN = `${PROTOCOL}://${HOSTNAME}${(!IS_PROD && IS_LOCALHOST && PORT !== 80 && PORT !== 443) ? `:${PORT}` : ''}`;

const config = {
  domain: HOSTNAME,
  port: PORT,
  protocol: PROTOCOL,
  origin: ORIGIN,
  rpName: 'Auth Server',
  rpID: HOSTNAME,
};

console.log(`🔐 Auth Server running
   Domain:  ${HOSTNAME}
   Port:    ${PORT}
   Origin:  ${ORIGIN}
   RPID:    ${config.rpID}
   Env:     ${process.env.NODE_ENV || 'development'}
`);

initAuthDb();
initUserDb();

// ─── APP ─────────────────────────────────────────────────────────────────────

const app = express();

app.set('trust proxy', 1); // Trust reverse proxy (nginx etc.)
app.set('config', config);

// Security headers
app.use(helmet({
  hsts: IS_PROD, // Disable HSTS in development to avoid TLS errors on localhost
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

// CORS — local or production domain
app.use(cors({
  origin: ORIGIN,
  credentials: true,
}));

app.use(express.json());
app.use(cookieParser(SESSION_SECRET));

// ─── SESSION ─────────────────────────────────────────────────────────────────

const sessionStore = new SQLiteStore(); // ttl is handled inside now

app.use(session({
  secret: SESSION_SECRET,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  name: 'auth.sid',
  cookie: {
    secure: PROTOCOL === 'https', // Secure if using HTTPS
    httpOnly: true,       // No JS access
    sameSite: 'lax',      // CSRF protection
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  },
}));

// ─── ROUTES ──────────────────────────────────────────────────────────────────

app.use('/api/auth', authRoutes);
app.use('/api/passkeys', passkeyRoutes);
app.use('/api/user', userRoutes);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', domain: DOMAIN, timestamp: new Date().toISOString() });
});

// Serve frontend
app.use(express.static(path.join(__dirname, '../public')));

// SPA fallback — serve index.html for all non-API routes
app.get(/^(?!\/api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// ─── ERROR HANDLER ───────────────────────────────────────────────────────────

app.use((err, req, res, next) => {
  console.error('[error]', err);

  // LOG TO DATABASE
  try {
    authDb.prepare(`
      INSERT INTO system_logs (id, level, source, message, stack, context, user_id, timestamp)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      randomUUID(),
      'error',
      'server',
      err.message || String(err),
      err.stack || null,
      JSON.stringify({
        url: req.url,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('user-agent')
      }),
      req.session?.userId || null,
      Date.now()
    );
  } catch (logErr) {
    console.error('[critical] Failed to write to system_logs:', logErr);
  }

  if (res.headersSent) return next(err); // Don't attempt to send another response
  res.status(500).json({ error: IS_PROD ? 'Internal server error' : err.message });
});

// ─── START ───────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n🔐 Auth Server running`);
  console.log(`   Domain:  ${DOMAIN}`);
  console.log(`   Port:    ${PORT}`);
  console.log(`   Origin:  ${config.origin}`);
  console.log(`   Env:     ${IS_PROD ? 'production' : 'development'}\n`);
});

export default app;