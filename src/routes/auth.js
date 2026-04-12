import { Router } from 'express';
import bcrypt from 'bcrypt';
import { randomUUID, randomBytes } from 'node:crypto';
import { verifySync, generateSecret } from 'otplib';
import QRCode from 'qrcode';
import { 
  generateRegistrationOptions, 
  verifyRegistrationResponse, 
  generateAuthenticationOptions, 
  verifyAuthenticationResponse 
} from '@simplewebauthn/server';
import { authDb, getAppSettings } from '../db/init.js';
import { requireAuth, requireFreshAuth } from '../middleware/auth.js';
import { generateRecoveryCodes, generateResetToken, getAuthResponse } from '../utils/authHelpers.js';

import { requestId } from '../middleware/requestId.js';

const router = Router();
router.use(requestId);

const SALT_ROUNDS = 12;

// ─── HELPER ──────────────────────────────────────────────────────────────────

function getRpConfig(req) {
  const config = req.app.get('config');
  if (!config) throw new Error('Server configuration missing');
  return {
    rpName: config.rpName || 'Auth Server',
    rpID: config.rpID,
    origin: config.origin,
  };
}

// ─── AUTH CORE ───────────────────────────────────────────────────────────────

router.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return getAuthResponse(req, res, {
      status: 400,
      data: { error: 'username, email, and password are required', code: 'MISSING_CREDENTIALS' }
    });
  }
  const settings = getAppSettings();
  if (settings.auth_registration_enabled !== 'true') {
    return res.status(403).json({ error: 'Registration is currently disabled', code: 'REGISTRATION_DISABLED' });
  }

  const minLen = parseInt(settings.password_min_length || '8', 10);
  if (password.length < minLen) {
    return res.status(400).json({ error: `Password must be at least ${minLen} characters`, code: 'PASSWORD_TOO_SHORT' });
  }

  const db = authDb;
  const existing = db.prepare('SELECT id FROM users WHERE username=? OR email=?').get(username || null, email || null);
  if (existing) {
    return getAuthResponse(req, res, {
      status: 409,
      data: { error: 'Username or email already taken', code: 'USER_EXISTS' }
    });
  }

  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
  const userId = randomUUID();
  const now = Date.now();
  const mfaRequired = settings.auth_force_mfa_new_users === 'true' ? 1 : 0;

  db.prepare('INSERT INTO users (id, username, email, password_hash, mfa_required, created_at, updated_at) VALUES (?,?,?,?,?,?,?)')
    .run(userId, username || null, email || null, passwordHash, mfaRequired, now, now);

  const autologin = settings.register_autologin === 'true';
  if (autologin) {
    req.session.userId = userId;
    req.session.username = username;
    req.session.lastAuthedAt = now;
    const days = parseInt(settings.session_duration_days || '7', 10);
    req.session.cookie.maxAge = days * 24 * 60 * 60 * 1000;
  }

  return getAuthResponse(req, res, {
    status: 201,
    data: { userId, username, message: 'Registered successfully', user: { id: userId, username, email } },
    redirect: '/'
  });
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return getAuthResponse(req, res, {
      status: 400,
      data: { error: 'username and password are required', code: 'MISSING_CREDENTIALS' }
    });
  }

  const db = authDb;
  const settings = getAppSettings();
  const user = db.prepare('SELECT * FROM users WHERE username=? OR email=?').get(username || null, username || null);

  if (!user) {
    await bcrypt.hash('dummy', SALT_ROUNDS);
    return getAuthResponse(req, res, {
      status: 401,
      data: { error: 'Invalid credentials', code: 'INVALID_CREDENTIALS' }
    });
  }

  const now = Date.now();
  if (user.locked_until > now) {
    const minsLeft = Math.ceil((user.locked_until - now) / 60000);
    return getAuthResponse(req, res, {
      status: 403,
      data: { error: `Account locked. Please try again in ${minsLeft} minutes.`, code: 'ACCOUNT_LOCKED' }
    });
  }

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) {
    const failed = user.failed_attempts + 1;
    let lockedUntil = 0;
    const maxAttempts = parseInt(settings.lockout_max_attempts || '5', 10);
    const lockoutMins = parseInt(settings.lockout_duration_mins || '15', 10);

    if (failed >= maxAttempts) {
      lockedUntil = now + (lockoutMins * 60 * 1000);
    }

    db.prepare('UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?')
      .run(failed, lockedUntil, user.id);

    return getAuthResponse(req, res, {
      status: 401,
      data: { 
        error: failed >= maxAttempts ? `Account locked for ${lockoutMins} minutes` : 'Invalid credentials',
        code: failed >= maxAttempts ? 'ACCOUNT_LOCKED' : 'INVALID_CREDENTIALS'
      }
    });
  }

  db.prepare('UPDATE users SET failed_attempts=0, locked_until=0 WHERE id=?').run(user.id);

  const days = parseInt(settings.session_duration_days || '7', 10);
  req.session.cookie.maxAge = days * 24 * 60 * 60 * 1000;

  if (user.totp_enabled) {
    const { totp } = req.body;
    if (!totp) {
      req.session.pendingUserId = user.id;
      req.session.pendingUsername = user.username;
      return getAuthResponse(req, res, {
        status: 401,
        data: { requires2FA: true, error: 'Two-factor authentication required', code: '2FA_REQUIRED' },
        redirect: '/?requires2FA=true'
      });
    }

    const valid2FA = verifySync({ token: totp, secret: user.totp_secret, type: 'totp' });
    if (!valid2FA?.valid) {
      return getAuthResponse(req, res, {
        status: 401,
        data: { error: 'Invalid 2FA code', code: 'INVALID_2FA_CODE' }
      });
    }
  }

  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.lastAuthedAt = Date.now();

  return getAuthResponse(req, res, {
    status: 200,
    data: { userId: user.id, username: user.username, user: { id: user.id, username: user.username, email: user.email } },
    redirect: '/'
  });
});

router.post('/login/recovery', async (req, res) => {
  let { username, code } = req.body;
  if (!username) username = req.session.pendingUsername;

  if (!username || !code) {
    return getAuthResponse(req, res, { status: 400, data: { error: 'Username and recovery code are required', code: 'MISSING_CREDENTIALS' } });
  }

  const db = authDb;
  const user = db.prepare('SELECT * FROM users WHERE username=? OR email=?').get(username || null, username || null);
  if (!user) {
    return getAuthResponse(req, res, { status: 401, data: { error: 'Invalid recovery attempt', code: 'INVALID_CREDENTIALS' } });
  }

  const codes = db.prepare('SELECT * FROM recovery_codes WHERE user_id=? AND used=0').all(user.id);
  let matchedCodeId = null;
  for (const rc of codes) {
    if (await bcrypt.compare(code, rc.code_hash)) {
      matchedCodeId = rc.id;
      break;
    }
  }

  if (!matchedCodeId) {
    return getAuthResponse(req, res, { status: 401, data: { error: 'Invalid recovery code', code: 'INVALID_RECOVERY_CODE' } });
  }

  db.prepare('UPDATE recovery_codes SET used=1 WHERE id=?').run(matchedCodeId);
  delete req.session.pendingUserId;
  delete req.session.pendingUsername;
  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.lastAuthedAt = Date.now();
  req.session.isRecovered = true;

  return getAuthResponse(req, res, { status: 200, data: { success: true }, redirect: '/' });
});

router.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ message: 'Logged out' }));
});

// GET /logout for manual logouts (redirects to login)
router.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/?logged_out=1'));
});

router.get('/status', (req, res) => {
  const userId = req.session.userId;
  if (!userId) return res.json({ authenticated: false });

  const db = authDb;
  const user = db.prepare('SELECT id, username, email, totp_enabled, mfa_required FROM users WHERE id=?').get(userId);
  if (!user) {
    req.session.destroy();
    return res.json({ authenticated: false });
  }

  const passkeyCount = db.prepare('SELECT COUNT(*) as count FROM passkeys WHERE user_id=?').get(userId).count;
  const settings = getAppSettings();

  res.json({
    authenticated: true,
    user: { id: user.id, username: user.username, email: user.email, mfaRequired: !!user.mfa_required },
    isRecovered: !!req.session.isRecovered,
    settings,
    security: { has2FA: !!user.totp_enabled, passkeyCount, loginMethod: req.session.loginMethod || 'password' },
    freshAuth: {
      active: !!(req.session.lastAuthedAt && (Date.now() - req.session.lastAuthedAt < 5 * 60 * 1000)),
      expiresAt: (req.session.lastAuthedAt || 0) + 5 * 60 * 1000
    }
  });
});

router.get('/me', requireAuth, (req, res) => {
  const user = authDb.prepare('SELECT id, username, email, totp_enabled FROM users WHERE id=?').get(req.session.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const passkeys = authDb.prepare('SELECT id, friendly_name, device_type, created_at FROM passkeys WHERE user_id=?').all(req.session.userId);

  res.json({
    userId: user.id,
    username: user.username,
    email: user.email,
    totpEnabled: !!user.totp_enabled,
    passkeys,
    lastAuthedAt: req.session.lastAuthedAt
  });
});

// ─── FRESH AUTH ──────────────────────────────────────────────────────────────

router.post(['/fresh-auth', '/reauth'], requireAuth, async (req, res) => {
  const { password, totpCode, token } = req.body;
  const submittedToken = token || totpCode;
  const user = authDb.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId);

  if (password) {
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid password', code: 'INVALID_PASSWORD' });

    if (user.totp_enabled) {
      if (!submittedToken) return res.json({ requires2FA: true });
      const ok = verifySync({ token: submittedToken, secret: user.totp_secret, type: 'totp' });
      if (!ok?.valid) return res.status(401).json({ error: 'Invalid TOTP code', code: 'INVALID_2FA_CODE' });
    }
  } else {
    return res.status(400).json({ error: 'password required for reauth', code: 'MISSING_PASSWORD' });
  }

  req.session.lastAuthedAt = Date.now();
  res.json({ message: 'Reauthenticated', lastAuthedAt: req.session.lastAuthedAt, expiresAt: req.session.lastAuthedAt + 5 * 60 * 1000 });
});

// ─── 2FA (TOTP) ──────────────────────────────────────────────────────────────

router.post('/2fa/setup', requireAuth, async (req, res) => {
  const user = authDb.prepare('SELECT username, email FROM users WHERE id=?').get(req.session.userId);
  const secret = generateSecret();
  req.session.pendingTotpSecret = secret;

  const { rpName } = getRpConfig(req);
  const issuer = encodeURIComponent(rpName);
  const otpauthUrl = `otpauth://totp/${issuer}:${encodeURIComponent(user.email)}?secret=${secret}&issuer=${issuer}`;
  const qrCode = await QRCode.toDataURL(otpauthUrl);

  res.json({ secret, qrCode, otpauthUrl });
});

router.post('/2fa/verify-setup', requireAuth, (req, res) => {
  const { code, token } = req.body;
  const submittedToken = token || code;
  const secret = req.session.pendingTotpSecret;
  if (!secret) return res.status(400).json({ error: 'No pending TOTP setup', code: 'NO_PENDING_2FA' });

  const valid = verifySync({ token: submittedToken, secret, type: 'totp' });
  if (!valid?.valid) return res.status(401).json({ error: 'Invalid code', code: 'INVALID_2FA_CODE' });

  authDb.prepare('UPDATE users SET totp_secret=?, totp_enabled=1 WHERE id=?').run(secret, req.session.userId);

  generateRecoveryCodes(10).then(({ plain: codes, hashed: hashes }) => {
    const now = Date.now();
    const stmt = authDb.prepare('INSERT INTO recovery_codes (id, user_id, code_hash, created_at) VALUES (?, ?, ?, ?)');
    for (const hash of hashes) {
      stmt.run(randomUUID(), req.session.userId, hash, now);
    }
    delete req.session.pendingTotpSecret;
    res.json({ message: '2FA enabled', recoveryCodes: codes });
  }).catch(err => {
    console.error('[auth] Failed to generate recovery codes:', err);
    res.json({ message: '2FA enabled (but recovery codes failed)', recoveryCodes: [] });
  });
});

router.post('/2fa/disable', requireFreshAuth, (req, res) => {
  authDb.prepare('UPDATE users SET totp_secret=NULL, totp_enabled=0 WHERE id=?').run(req.session.userId);
  res.json({ message: '2FA disabled' });
});

// ─── PASSKEYS ────────────────────────────────────────────────────────────────

router.post('/passkeys/register/options', requireAuth, async (req, res) => {
  const { rpName, rpID } = getRpConfig(req);
  const user = authDb.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const existingCredentials = authDb.prepare('SELECT credential_id, transports FROM passkeys WHERE user_id = ?').all(req.userId);
  const excludeCredentials = existingCredentials.map(c => ({ id: c.credential_id, transports: c.transports ? JSON.parse(c.transports) : [] }));

  const options = await generateRegistrationOptions({
    rpName, rpID, userID: Buffer.from(user.id, 'utf-8'), userName: user.username, userDisplayName: user.username,
    attestationType: 'none', excludeCredentials,
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
  });

  const now = Date.now();
  authDb.prepare('INSERT INTO webauthn_challenges (id, user_id, challenge, type, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(randomUUID(), req.userId, options.challenge, 'registration', now, now + 5 * 60 * 1000);

  res.json(options);
});

router.post('/passkeys/register/verify', requireAuth, async (req, res) => {
  const { rpID, origin } = getRpConfig(req);
  const { response, name } = req.body;
  const challengeRow = authDb.prepare('SELECT * FROM webauthn_challenges WHERE user_id = ? AND type = \'registration\' AND expires_at > ? ORDER BY created_at DESC LIMIT 1')
    .get(req.userId, Date.now());

  if (!challengeRow) return res.status(400).json({ error: 'No valid challenge found', code: 'WEBAUTHN_CHALLENGE_NOT_FOUND' });

  try {
    const verification = await verifyRegistrationResponse({ response, expectedChallenge: challengeRow.challenge, expectedOrigin: origin, expectedRPID: rpID });
    if (!verification.verified || !verification.registrationInfo) return res.status(400).json({ error: 'Passkey registration failed', code: 'PASSKEY_REGISTRATION_FAILED' });

    const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
    const now = Date.now();
    authDb.prepare(`
      INSERT INTO passkeys (id, user_id, credential_id, public_key, counter, device_type, backed_up, transports, friendly_name, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(randomUUID(), req.userId, credential.id, Buffer.from(credential.publicKey).toString('base64'), credential.counter,
      credentialDeviceType, credentialBackedUp ? 1 : 0, JSON.stringify(response.response?.transports || []),
      name || `Passkey ${new Date().toLocaleDateString()}`, now);

    authDb.prepare('DELETE FROM webauthn_challenges WHERE id = ?').run(challengeRow.id);
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/passkeys/authenticate/options', async (req, res) => {
  const { rpID } = getRpConfig(req);
  const { username } = req.body;
  let allowCredentials = [];
  let userId = null;

  if (username) {
    const user = authDb.prepare('SELECT * FROM users WHERE username = ? OR email = ?').get(username.toLowerCase(), username.toLowerCase());
    if (user) {
      userId = user.id;
      const creds = authDb.prepare('SELECT credential_id, transports FROM passkeys WHERE user_id = ?').all(user.id);
      allowCredentials = creds.map(c => ({ id: c.credential_id, transports: c.transports ? JSON.parse(c.transports) : [] }));
    }
  }

  const options = await generateAuthenticationOptions({ rpID, userVerification: 'preferred', allowCredentials });
  const now = Date.now();
  authDb.prepare('INSERT INTO webauthn_challenges (id, user_id, challenge, type, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(randomUUID(), userId, options.challenge, 'authentication', now, now + 5 * 60 * 1000);

  req.session.passkeyChallenge = options.challenge;
  res.json(options);
});

router.post('/passkeys/authenticate/verify', async (req, res) => {
  const { rpID, origin } = getRpConfig(req);
  const { response } = req.body;
  const challenge = req.session.passkeyChallenge;
  if (!challenge) return res.status(400).json({ error: 'No active passkey challenge', code: 'WEBAUTHN_CHALLENGE_NOT_FOUND' });

  const challengeRow = authDb.prepare('SELECT * FROM webauthn_challenges WHERE challenge = ? AND type = \'authentication\' AND expires_at > ? ORDER BY created_at DESC LIMIT 1')
    .get(challenge, Date.now());
  if (!challengeRow) return res.status(400).json({ error: 'Challenge expired or not found', code: 'WEBAUTHN_CHALLENGE_EXPIRED' });

  const passkey = authDb.prepare('SELECT * FROM passkeys WHERE credential_id = ?').get(response.id);
  if (!passkey) return res.status(400).json({ error: 'Passkey not registered', code: 'PASSKEY_NOT_FOUND' });

  try {
    const verification = await verifyAuthenticationResponse({
      response, expectedChallenge: challengeRow.challenge, expectedOrigin: origin, expectedRPID: rpID,
      credential: { id: passkey.credential_id, publicKey: Buffer.from(passkey.public_key, 'base64'), counter: passkey.counter,
      transports: passkey.transports ? JSON.parse(passkey.transports) : [] }
    });

    if (!verification.verified) return res.status(401).json({ error: 'Passkey verification failed', code: 'PASSKEY_VERIFICATION_FAILED' });

    authDb.prepare('UPDATE passkeys SET counter = ?, last_used = ? WHERE id = ?').run(verification.authenticationInfo.newCounter, Date.now(), passkey.id);
    authDb.prepare('DELETE FROM webauthn_challenges WHERE id = ?').run(challengeRow.id);
    delete req.session.passkeyChallenge;

    req.session.userId = passkey.user_id;
    req.session.lastAuthedAt = Date.now();
    req.session.loginMethod = 'passkey';
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/passkeys', requireAuth, (req, res) => {
  const passkeys = authDb.prepare('SELECT id, friendly_name as name, device_type, created_at, last_used FROM passkeys WHERE user_id = ? ORDER BY created_at DESC').all(req.userId);
  res.json({ passkeys });
});

router.delete('/passkeys/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  const passkey = authDb.prepare('SELECT id FROM passkeys WHERE id = ? AND user_id = ?').get(id, req.userId);
  if (!passkey) return res.status(404).json({ error: 'Passkey not found' });
  authDb.prepare('DELETE FROM passkeys WHERE id = ?').run(id);
  res.json({ success: true });
});

// ─── ACCOUNT MANAGEMENT ──────────────────────────────────────────────────────

router.post('/password/change', requireFreshAuth, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword) return res.status(400).json({ error: 'newPassword is required' });

  const settings = getAppSettings();
  const minLen = parseInt(settings.password_min_length || '8', 10);
  if (newPassword.length < minLen) {
    return res.status(400).json({ error: `Password must be at least ${minLen} characters` });
  }

  const hash = await bcrypt.hash(newPassword, SALT_ROUNDS);
  authDb.prepare('UPDATE users SET password_hash=?, updated_at=? WHERE id=?').run(hash, Date.now(), req.userId);

  res.json({ success: true, message: 'Password changed successfully' });
});

router.post('/email/change', requireFreshAuth, async (req, res) => {
  const { newEmail } = req.body;
  if (!newEmail) return res.status(400).json({ error: 'newEmail is required' });

  authDb.prepare('UPDATE users SET email=?, updated_at=? WHERE id=?').run(newEmail, Date.now(), req.userId);

  res.json({ success: true, message: 'Email updated successfully', email: newEmail });
});

// ─── SESSIONS ────────────────────────────────────────────────────────────────

router.get('/sessions', requireAuth, (req, res) => {
  const sessions = authDb.prepare('SELECT id, created_at, expires_at, last_activity FROM sessions WHERE user_id = ? AND expires_at > ? ORDER BY last_activity DESC')
    .all(req.userId, Math.floor(Date.now() / 1000));
  res.json({ sessions: sessions.map(s => ({ ...s, isCurrent: s.id === req.sessionID })) });
});

router.delete('/sessions/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  if (id === req.sessionID) return res.status(400).json({ error: 'Cannot revoke current session' });
  const session = authDb.prepare('SELECT id FROM sessions WHERE id = ? AND user_id = ?').get(id, req.userId);
  if (!session) return res.status(404).json({ error: 'Session not found' });
  authDb.prepare('DELETE FROM sessions WHERE id = ?').run(id);
  res.json({ success: true });
});

// ─── API KEYS ────────────────────────────────────────────────────────────────

router.get('/api-keys', requireAuth, (req, res) => {
  const keys = authDb.prepare('SELECT id, name, permissions, created_at, last_used FROM api_keys WHERE user_id = ? ORDER BY created_at DESC').all(req.userId);
  res.json({ keys: keys.map(k => ({ ...k, permissions: JSON.parse(k.permissions || '[]') })) });
});

router.post('/api-keys', requireAuth, async (req, res) => {
  const { name, permissions } = req.body;
  if (!name) return res.status(400).json({ error: 'Name is required' });

  const allowed = ['action:read', 'action:write'];
  const validPermissions = (permissions || []).filter(p => allowed.includes(p));

  const keyId = randomUUID().replace(/-/g, '').substring(0, 16);
  const secret = randomBytes(24).toString('base64').replace(/[^a-zA-Z0-9]/g, '');
  const rawKey = `sk_live_${keyId}_${secret}`;
  const hash = await bcrypt.hash(secret, 10);

  const now = Date.now();
  authDb.prepare('INSERT INTO api_keys (id, user_id, key_hash, name, permissions, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(keyId, req.userId, hash, name || null, JSON.stringify(validPermissions), now);

  res.status(201).json({ success: true, key: rawKey, metadata: { id: keyId, name, permissions: validPermissions, createdAt: now } });
});

router.delete('/api-keys/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  const key = authDb.prepare('SELECT id FROM api_keys WHERE id = ? AND user_id = ?').get(id, req.userId);
  if (!key) return res.status(404).json({ error: 'API Key not found' });
  authDb.prepare('DELETE FROM api_keys WHERE id = ?').run(id);
  res.json({ success: true });
});

// ─── PASSWORD RESET ──────────────────────────────────────────────────────────

router.post('/password-reset/request', async (req, res) => {
  const { username, email } = req.body;
  const user = authDb.prepare('SELECT * FROM users WHERE username=? OR email=?').get(username || null, email || null);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const token = generateResetToken();
  const hash = await bcrypt.hash(token, 10);
  const settings = getAppSettings();
  const expiryMins = parseInt(settings.password_reset_expiry_mins || '30', 10);
  const expiresAt = Date.now() + (expiryMins * 60 * 1000);

  authDb.prepare('INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)').run(hash, user.id, expiresAt);

  const config = req.app.get('config');
  if (config?.origin) {
    fetch(`${config.origin}/api/v1/test/mailbox`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'Email', subject: 'Password Reset', body: `Token: ${token}` })
    }).catch(() => {});
  }

  res.json({ success: true, token, expiresAt });
});

router.post('/password-reset/reset', async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.status(400).json({ error: 'Missing data' });

  const tokens = authDb.prepare('SELECT * FROM password_reset_tokens WHERE used=0 AND expires_at > ?').all(Date.now());
  let matchedToken = null;
  for (const t of tokens) {
    if (await bcrypt.compare(token, t.token_hash)) { matchedToken = t; break; }
  }

  if (!matchedToken) return res.status(401).json({ error: 'Invalid or expired token' });

  const hash = await bcrypt.hash(newPassword, 12);
  authDb.prepare('UPDATE users SET password_hash=?, updated_at=? WHERE id=?').run(hash, Date.now(), matchedToken.user_id);
  authDb.prepare('UPDATE password_reset_tokens SET used=1 WHERE token_hash=?').run(matchedToken.token_hash);

  res.json({ success: true });
});

// ─── SETTINGS ────────────────────────────────────────────────────────────────

router.patch('/settings', requireAuth, (req, res) => {
  const updates = req.body;
  const stmt = authDb.prepare("UPDATE settings SET value=? WHERE key=?");
  try {
    for (const [key, value] of Object.entries(updates)) { stmt.run(String(value), key); }
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/report-error', (req, res) => {
  const { level, message, stack, context } = req.body;
  authDb.prepare('INSERT INTO system_logs (id, level, source, message, stack, context, user_id, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run(randomUUID(), level || 'error', 'client', message || 'No message', stack || null, context ? JSON.stringify(context) : null, req.session?.userId || null, Date.now());
  res.json({ success: true });
});

export default router;