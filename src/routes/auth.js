import { Router } from 'express';
import bcrypt from 'bcrypt';
import { randomUUID } from 'crypto';
import { generateSync, verifySync, generateSecret } from 'otplib';
import QRCode from 'qrcode';
import { authDb } from '../db/init.js';
import { requireAuth, requireFreshAuth } from '../middleware/auth.js';

const router = Router();
const SALT_ROUNDS = 12;

// ─── Register ────────────────────────────────────────────────────────────────

router.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'username, email, and password are required' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  const db = authDb;
  const existing = db.prepare('SELECT id FROM users WHERE username=? OR email=?').get(username, email);
  if (existing) {
    return res.status(409).json({ error: 'Username or email already taken' });
  }

  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
  const userId = randomUUID();
  const now = Date.now();

  db.prepare('INSERT INTO users (id, username, email, password_hash, created_at, updated_at) VALUES (?,?,?,?,?,?)')
    .run(userId, username, email, passwordHash, now, now);

  req.session.userId = userId;
  req.session.username = username;
  req.session.lastAuthedAt = now;

  res.status(201).json({ 
    userId, 
    username, 
    message: 'Registered successfully',
    user: { id: userId, username, email } // Frontend expects .user object
  });
});

// ─── Login Step 1: password ───────────────────────────────────────────────────

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }

  const db = authDb;
  const user = db.prepare('SELECT * FROM users WHERE username=? OR email=?').get(username, username);
  if (!user) {
    await bcrypt.hash('dummy', SALT_ROUNDS); // timing attack mitigation
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  if (user.totp_enabled) {
    // Partial session: awaiting 2FA
    req.session.pendingUserId = user.id;
    req.session.pendingUsername = user.username;
    return res.json({ requires2FA: true });
  }

  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.lastAuthedAt = Date.now();
  res.json({ 
    userId: user.id, 
    username: user.username,
    user: { id: user.id, username: user.username, email: user.email } // Frontend expects .user
  });
});

// ─── Login Step 2: 2FA (TOTP) ─────────────────────────────────────────────────

router.post(['/login/2fa', '/login/totp'], (req, res) => {
  const { code, token } = req.body; // app.js sends 'token', README says 'code'
  const submittedToken = token || code;
  const pendingId = req.session.pendingUserId;
  if (!pendingId) return res.status(400).json({ error: 'No pending login' });

  const db = authDb;
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(pendingId);
  if (!user?.totp_secret) return res.status(400).json({ error: 'No TOTP configured' });

  const valid = verifySync({ token: submittedToken, secret: user.totp_secret, type: 'totp' });
  if (!valid?.valid) return res.status(401).json({ error: 'Invalid code' });

  delete req.session.pendingUserId;
  delete req.session.pendingUsername;
  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.lastAuthedAt = Date.now();

  res.json({ 
    userId: user.id, 
    username: user.username,
    user: { id: user.id, username: user.username, email: user.email }
  });
});

// ─── Logout ───────────────────────────────────────────────────────────────────

router.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ message: 'Logged out' }));
});

// ─── Session status ───────────────────────────────────────────────────────────

router.get('/status', (req, res) => {
  const userId = req.session.userId;
  if (!userId) {
    return res.json({ authenticated: false });
  }

  const db = authDb;
  const user = db.prepare('SELECT id, username, email, totp_enabled FROM users WHERE id=?')
    .get(userId);

  if (!user) {
    req.session.destroy();
    return res.json({ authenticated: false });
  }

  const passkeyCount = db.prepare('SELECT COUNT(*) as count FROM passkeys WHERE user_id=?')
    .get(userId).count;

  res.json({
    authenticated: true,
    user: { id: user.id, username: user.username, email: user.email },
    security: {
      has2FA: !!user.totp_enabled,
      passkeyCount,
      loginMethod: req.session.loginMethod || 'password'
    },
    freshAuth: {
      active: !!(req.session.lastAuthedAt && (Date.now() - req.session.lastAuthedAt < 5 * 60 * 1000)),
      expiresAt: (req.session.lastAuthedAt || 0) + 5 * 60 * 1000
    }
  });
});

router.get('/me', requireAuth, (req, res) => {
  const db = authDb;
  const user = db.prepare('SELECT id, username, email, totp_enabled FROM users WHERE id=?')
    .get(req.session.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const passkeys = db.prepare('SELECT id, friendly_name, device_type, created_at FROM passkeys WHERE user_id=?')
    .all(req.session.userId);

  res.json({
    userId: user.id,
    username: user.username,
    email: user.email,
    totpEnabled: !!user.totp_enabled,
    passkeys,
    lastAuthedAt: req.session.lastAuthedAt
  });
});

// ─── Fresh Auth (re-authenticate within session) ──────────────────────────────

router.post(['/fresh-auth', '/reauth'], requireAuth, async (req, res) => {
  const { password, totpCode, token } = req.body;
  const submittedToken = token || totpCode;
  const db = authDb;
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId);

  if (password) {
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid password' });

    if (user.totp_enabled && !totpCode) {
      return res.json({ requires2FA: true });
    }
    if (user.totp_enabled && submittedToken) {
      const ok = verifySync({ token: submittedToken, secret: user.totp_secret, type: 'totp' });
      if (!ok?.valid) return res.status(401).json({ error: 'Invalid TOTP code' });
    }
  } else {
    return res.status(400).json({ error: 'password required for reauth' });
  }

  req.session.lastAuthedAt = Date.now();
  res.json({ 
    message: 'Reauthenticated', 
    lastAuthedAt: req.session.lastAuthedAt,
    expiresAt: req.session.lastAuthedAt + 5 * 60 * 1000
  });
});

// ─── TOTP Setup ───────────────────────────────────────────────────────────────

router.post(['/2fa/setup', '/totp/setup'], requireAuth, async (req, res) => {
  const db = authDb;
  const user = db.prepare('SELECT username, email FROM users WHERE id=?').get(req.session.userId);
  const secret = generateSecret();

  // Store pending (not yet confirmed)
  req.session.pendingTotpSecret = secret;

  const otpauthUrl = `otpauth://totp/${encodeURIComponent('AuthServer')}:${encodeURIComponent(user.email)}?secret=${secret}&issuer=AuthServer`;
  const qrCode = await QRCode.toDataURL(otpauthUrl);

  res.json({ secret, qrCode, otpauthUrl });
});

router.post(['/2fa/verify-setup', '/totp/confirm'], requireAuth, (req, res) => {
  const { code, token } = req.body;
  const submittedToken = token || code;
  const secret = req.session.pendingTotpSecret;
  if (!secret) return res.status(400).json({ error: 'No pending TOTP setup' });

  const valid = verifySync({ token: submittedToken, secret, type: 'totp' });
  if (!valid?.valid) return res.status(401).json({ error: 'Invalid code' });

  const db = authDb;
  db.prepare('UPDATE users SET totp_secret=?, totp_enabled=1 WHERE id=?')
    .run(secret, req.session.userId);

  delete req.session.pendingTotpSecret;
  res.json({ message: '2FA enabled' });
});

router.post('/2fa/disable', requireFreshAuth, (req, res) => {
  const db = authDb;
  db.prepare('UPDATE users SET totp_secret=NULL, totp_enabled=0 WHERE id=?')
    .run(req.session.userId);
  res.json({ message: '2FA disabled' });
});

router.delete('/totp', requireFreshAuth, (req, res) => {
  const db = authDb;
  db.prepare('UPDATE users SET totp_secret=NULL, totp_enabled=0 WHERE id=?')
    .run(req.session.userId);
  res.json({ message: '2FA disabled' });
});

export default router;