import { Router } from 'express';
import bcrypt from 'bcrypt';
import { randomUUID, randomBytes } from 'crypto';
import { generateSync, verifySync, generateSecret } from 'otplib';
import QRCode from 'qrcode';
import { authDb, getAppSettings } from '../db/init.js';
import { requireAuth, requireFreshAuth } from '../middleware/auth.js';

const router = Router();
const SALT_ROUNDS = 12;

console.log('[auth] Initializing Auth Router v2 (Redirect Support)');

// Middleware to ensure req.body is always an object
router.use((req, res, next) => {
  // Only check for req.body on methods that typically have a body
  const methodsWithBody = ['POST', 'PUT', 'PATCH', 'DELETE'];
  if (methodsWithBody.includes(req.method) && !req.body) {
    console.debug(`[auth] req.body was undefined for ${req.method} ${req.url}`);
    req.body = {};
  }
  next();
});

function getAuthResponse(req, res, { status, data, redirect }) {
  const isHtml = req.headers.accept?.includes('text/html');
  if (isHtml) {
    if (status >= 400) {
      const origin = `${req.protocol}://${req.get('host')}`;
      const url = new URL(req.headers.referer || '/', origin);
      url.searchParams.set('error', data.error || 'Authentication failed');
      return res.redirect(url.toString());
    }
    return res.redirect(redirect || '/');
  }
  return res.status(status).json(data);
}

/**
 * Generate a set of secure, readable recovery codes.
 * Returns { plain: string[], hashed: string[] }
 */
async function generateRecoveryCodes(count = 10) {
  const codes = [];
  const hashes = [];
  
  for (let i = 0; i < count; i++) {
    // Generate 8 random bytes -> 16 hex chars -> XXXX-XXXX-XXXX format
    const code = randomBytes(6).toString('hex').toUpperCase().match(/.{4}/g).join('-');
    codes.push(code);
    hashes.push(await bcrypt.hash(code, 10)); // Use lower rounds for recovery codes to speed up batch setup
  }
  
  return { plain: codes, hashed: hashes };
}

/**
 * Generate a secure alphanumeric reset token.
 */
function generateResetToken(length = 12) {
  const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Readable alphanumeric
  let token = '';
  const bytes = randomBytes(length);
  for (let i = 0; i < length; i++) {
    token += charset[bytes[i] % charset.length];
  }
  return token;
}


// ─── Register ────────────────────────────────────────────────────────────────

router.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return getAuthResponse(req, res, { 
      status: 400, 
      data: { error: 'username, email, and password are required' } 
    });
  }
  const settings = getAppSettings();
  if (settings.auth_registration_enabled !== 'true') {
    return res.status(403).json({ error: 'Registration is currently disabled' });
  }

  const minLen = parseInt(settings.password_min_length || '8', 10);
  if (password.length < minLen) {
    return res.status(400).json({ error: `Password must be at least ${minLen} characters` });
  }

  const db = authDb;
  const existing = db.prepare('SELECT id FROM users WHERE username=? OR email=?').get(username, email);
  if (existing) {
    return getAuthResponse(req, res, { 
      status: 409, 
      data: { error: 'Username or email already taken' } 
    });
  }

  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
  const userId = randomUUID();
  const now = Date.now();
  const mfaRequired = settings.auth_force_mfa_new_users === 'true' ? 1 : 0;

  db.prepare('INSERT INTO users (id, username, email, password_hash, mfa_required, created_at, updated_at) VALUES (?,?,?,?,?,?,?)')
    .run(userId, username, email, passwordHash, mfaRequired, now, now);

  req.session.userId = userId;
  req.session.username = username;
  req.session.lastAuthedAt = now;

  // Set session duration
  const days = parseInt(settings.session_duration_days || '7', 10);
  req.session.cookie.maxAge = days * 24 * 60 * 60 * 1000;

  return getAuthResponse(req, res, {
    status: 201,
    data: { 
      userId, 
      username, 
      message: 'Registered successfully',
      user: { id: userId, username, email }
    },
    redirect: '/'
  });
});

// ─── Login Step 1: password ───────────────────────────────────────────────────

router.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return getAuthResponse(req, res, {
      status: 400,
      data: { error: 'username and password are required' }
    });
  }

  const db = authDb;
  const settings = getAppSettings();
  const user = db.prepare('SELECT * FROM users WHERE username=? OR email=?').get(username, username);
  
  if (!user) {
    await bcrypt.hash('dummy', SALT_ROUNDS); // timing attack mitigation
    return getAuthResponse(req, res, {
      status: 401,
      data: { error: 'Invalid credentials' }
    });
  }

  // Check lockout
  const now = Date.now();
  if (user.locked_until > now) {
    const minsLeft = Math.ceil((user.locked_until - now) / 60000);
    return getAuthResponse(req, res, {
      status: 403,
      data: { error: `Account locked. Please try again in ${minsLeft} minutes.` }
    });
  }

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) {
    const failed = user.failed_attempts + 1;
    let lockedUntil = 0;
    // Check lockout policy
    const maxAttempts = parseInt(settings.lockout_max_attempts || '5', 10);
    const lockoutMins = parseInt(settings.lockout_duration_mins || '15', 10);

    if (failed >= maxAttempts) {
      lockedUntil = now + (lockoutMins * 60 * 1000);
    }

    db.prepare('UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?')
      .run(failed, lockedUntil, user.id);

    return getAuthResponse(req, res, {
      status: 401,
      data: { error: failed >= maxAttempts ? `Account locked for ${lockoutMins} minutes` : 'Invalid credentials' }
    });
  }

  // Success: Reset failures
  db.prepare('UPDATE users SET failed_attempts=0, locked_until=0 WHERE id=?').run(user.id);

  // Set session duration
  const days = parseInt(settings.session_duration_days || '7', 10);
  req.session.cookie.maxAge = days * 24 * 60 * 60 * 1000;

  if (user.totp_enabled) {
    // Partial session: awaiting 2FA
    req.session.pendingUserId = user.id;
    req.session.pendingUsername = user.username;
    
    // For HTML requests, we should redirect to a 2FA entry view
    // But since the SPA handles views via state, we return JSON if we can
    // Or redirect to root where the SPA will see the pending session.
    // In this specific demo, the SPA handles the requires2FA: true.
    return getAuthResponse(req, res, {
      status: 200,
      data: { requires2FA: true },
      redirect: '/?requires2FA=true'
    });
  }

  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.lastAuthedAt = Date.now();

  return getAuthResponse(req, res, {
    status: 200,
    data: { 
      userId: user.id, 
      username: user.username,
      user: { id: user.id, username: user.username, email: user.email }
    },
    redirect: '/'
  });
});

// ─── Login Step 3: Recovery Code ──────────────────────────────────────────────

router.post('/login/recovery', async (req, res) => {
  let { username, code } = req.body;
  
  // Support recovery during pending 2FA login
  if (!username) username = req.session.pendingUsername;
  
  if (!username || !code) {
    return getAuthResponse(req, res, { 
      status: 400, 
      data: { error: 'Username and recovery code are required' } 
    });
  }

  const db = authDb;
  const user = db.prepare('SELECT * FROM users WHERE username=? OR email=?').get(username, username);
  if (!user) {
    return getAuthResponse(req, res, { 
      status: 401, 
      data: { error: 'Invalid recovery attempt' } 
    });
  }

  // Find all unused recovery codes for this user
  const codes = db.prepare('SELECT * FROM recovery_codes WHERE user_id=? AND used=0').all(user.id);
  
  let matchedCodeId = null;
  for (const rc of codes) {
    if (await bcrypt.compare(code, rc.code_hash)) {
      matchedCodeId = rc.id;
      break;
    }
  }

  if (!matchedCodeId) {
    return getAuthResponse(req, res, { 
      status: 401, 
      data: { error: 'Invalid recovery code' } 
    });
  }

  // Mark code as used
  db.prepare('UPDATE recovery_codes SET used=1 WHERE id=?').run(matchedCodeId);

  // Complete login
  delete req.session.pendingUserId;
  delete req.session.pendingUsername;
  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.lastAuthedAt = Date.now();
  req.session.isRecovered = true; // Mark session for mandatory password reset

  return getAuthResponse(req, res, {
    status: 200,
    data: { success: true, message: 'Account recovered' },
    redirect: '/'
  });
});

// ─── Password Reset (Developer Flow) ──────────────────────────────────────────

/**
 * Developer-facing endpoint to request a reset token.
 * Typically called from the consumer app's backend.
 */
router.post('/password-reset/request', async (req, res) => {
  const { username, email } = req.body;
  if (!username && !email) {
    return res.status(400).json({ error: 'Username or email required' });
  }

  const db = authDb;
  const user = db.prepare('SELECT * FROM users WHERE username=? OR email=?').get(username, email);
  
  if (!user) {
    // For security, don't reveal if user exists in a public-facing way, 
    // but since this is a dev-facing API, we can be more explicit or follow generic 200.
    // We'll return 404 here as it's a developer tool.
    return res.status(404).json({ error: 'User not found' });
  }

  const token = generateResetToken();
  const hash = await bcrypt.hash(token, 10);
  const settings = getAppSettings();
  const expiryMins = parseInt(settings.password_reset_expiry_mins || '30', 10);
  const expiresAt = Date.now() + (expiryMins * 60 * 1000);

  db.prepare('INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
    .run(hash, user.id, expiresAt);

  res.json({
    success: true,
    token, // Plain token returned to developer
    expiresAt,
    user: { id: user.id, username: user.username, email: user.email }
  });
});

/**
 * Public-facing endpoint for the user to reset their password using the token.
 */
router.post('/password-reset/reset', async (req, res) => {
  const { token, newPassword } = req.body;
  
  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token and new password required' });
  }

  const db = authDb;
  const settings = getAppSettings();
  const minLen = parseInt(settings.min_password_length || '8', 10);
  
  if (newPassword.length < minLen) {
    return res.status(400).json({ error: `Password must be at least ${minLen} characters` });
  }

  // Find valid tokens
  const now = Date.now();
  const tokens = db.prepare('SELECT * FROM password_reset_tokens WHERE used=0 AND expires_at > ?')
    .all(now);

  let matchedToken = null;
  for (const t of tokens) {
    if (await bcrypt.compare(token, t.token_hash)) {
      matchedToken = t;
      break;
    }
  }

  if (!matchedToken) {
    return res.status(401).json({ error: 'Invalid or expired reset token' });
  }

  // Duplicate declaration removed. Password length check already performed above.

  // Update password
  const newHash = await bcrypt.hash(newPassword, 12);
  db.prepare('UPDATE users SET password_hash=?, updated_at=? WHERE id=?')
    .run(newHash, Date.now(), matchedToken.user_id);

  // Mark token as used
  db.prepare('UPDATE password_reset_tokens SET used=1 WHERE token_hash=?')
    .run(matchedToken.token_hash);

  res.json({ success: true, message: 'Password reset successfully' });
});

// ─── Login Step 2: 2FA (TOTP) ─────────────────────────────────────────────────

router.post(['/login/2fa', '/login/totp'], (req, res) => {
  const { code, token } = req.body; // app.js sends 'token', README says 'code'
  const submittedToken = token || code;
  const pendingId = req.session.pendingUserId;
  if (!pendingId) {
    return getAuthResponse(req, res, {
      status: 400,
      data: { error: 'No pending login' }
    });
  }

  const db = authDb;
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(pendingId);
  if (!user?.totp_secret) {
    return getAuthResponse(req, res, {
      status: 400,
      data: { error: 'No TOTP configured' }
    });
  }

  const valid = verifySync({ token: submittedToken, secret: user.totp_secret, type: 'totp' });
  if (!valid?.valid) {
    return getAuthResponse(req, res, {
      status: 401,
      data: { error: 'Invalid 2FA code' }
    });
  }

  delete req.session.pendingUserId;
  delete req.session.pendingUsername;
  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.lastAuthedAt = Date.now();

  return getAuthResponse(req, res, {
    status: 200,
    data: { 
      userId: user.id, 
      username: user.username,
      user: { id: user.id, username: user.username, email: user.email }
    },
    redirect: '/'
  });
});

// ─── Logout ───────────────────────────────────────────────────────────────────

router.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ message: 'Logged out' }));
});

// GET /logout for manual logouts (redirects to login)
router.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/?logged_out=1'));
});

// ─── Session status ───────────────────────────────────────────────────────────

router.get('/status', (req, res) => {
  const userId = req.session.userId;
  if (!userId) {
    return res.json({ authenticated: false });
  }

  const db = authDb;
  const user = db.prepare('SELECT id, username, email, totp_enabled, mfa_required FROM users WHERE id=?')
    .get(userId);

  if (!user) {
    req.session.destroy();
    return res.json({ authenticated: false });
  }

  const passkeyCount = db.prepare('SELECT COUNT(*) as count FROM passkeys WHERE user_id=?')
    .get(userId).count;

  const settings = getAppSettings();

  res.json({
    authenticated: true,
    user: { 
      id: user.id, 
      username: user.username, 
      email: user.email,
      mfaRequired: !!user.mfa_required
    },
    isRecovered: !!req.session.isRecovered,
    settings,
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

  // Generate recovery codes
  generateRecoveryCodes(10).then(({ codes, hashes }) => {
    const now = Date.now();
    const stmt = db.prepare(`
      INSERT INTO recovery_codes (id, user_id, code_hash, created_at)
      VALUES (?, ?, ?, ?)
    `);
    
    for (const hash of hashes) {
      stmt.run(randomUUID(), req.session.userId, hash, now);
    }
    
    delete req.session.pendingTotpSecret;
    res.json({ 
      message: '2FA enabled',
      recoveryCodes: codes
    });
  }).catch(err => {
    console.error('[auth] Failed to generate recovery codes:', err);
    res.json({ message: '2FA enabled (but recovery codes failed)', recoveryCodes: [] });
  });
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

router.post('/change-password', requireAuth, async (req, res) => {
  const { newPassword } = req.body;
  const settings = getAppSettings();
  const minLen = parseInt(settings.password_min_length || '8', 10);
  if (!newPassword || newPassword.length < minLen) {
    return res.status(400).json({ error: `Password must be at least ${minLen} characters` });
  }

  // If not a recovered session, require fresh auth for security
  if (!req.session.isRecovered) {
    const freshToken = req.headers['x-fresh-auth-token'];
    const now = Date.now();
    const fresh = authDb.prepare('SELECT id FROM fresh_auth_tokens WHERE id=? AND user_id=? AND expires_at > ?')
      .get(freshToken, req.session.userId, now);
    
    if (!fresh) {
      return res.status(401).json({ 
        error: 'Fresh authentication required to change password',
        code: 'FRESH_AUTH_REQUIRED'
      });
    }
  }

  // Duplicate declaration removed. Password length check already performed above.

  const hash = await bcrypt.hash(newPassword, 12);
  authDb.prepare('UPDATE users SET password_hash=?, updated_at=? WHERE id=?')
    .run(hash, Date.now(), req.session.userId);

  // Clear recovery flag after successful reset
  delete req.session.isRecovered;
  
  res.json({ success: true, message: 'Password updated successfully' });
});

router.patch('/settings', requireAuth, (req, res) => {
  const updates = req.body;
  const db = authDb;
  
  const stmt = db.prepare("UPDATE settings SET value=? WHERE key=?");
  
  try {
    for (const [key, value] of Object.entries(updates)) {
      stmt.run(String(value), key);
    }
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/report-error', (req, res) => {
  const { level, message, stack, context } = req.body;
  const now = Date.now();
  
  authDb.prepare(`
    INSERT INTO system_logs (id, level, source, message, stack, context, user_id, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    randomUUID(),
    level || 'error',
    'client',
    message || 'No message provided',
    stack || null,
    context ? JSON.stringify(context) : null,
    req.session?.userId || null,
    now
  );

  res.json({ success: true });
});

export default router;