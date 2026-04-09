import express from 'express';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { v4 as uuidv4 } from 'uuid';
import { authDb } from '../db/init.js';
import { requireAuth } from '../middleware/auth.js';

const router = express.Router();

// These come from config
function getRpConfig(req) {
  const config = req.app.get('config');
  if (!config) throw new Error('Server configuration missing');
  
  // LOG FOR DIAGNOSTICS
  console.log(`[passkey] Using RPID: ${config.rpID}, Origin: ${config.origin}`);
  
  return {
    rpName: config.rpName || 'Auth Server',
    rpID: config.rpID,
    origin: config.origin,
  };
}

// ─── REGISTER PASSKEY ────────────────────────────────────────────────────────

router.post('/register/options', requireAuth, async (req, res) => {
  const { rpName, rpID } = getRpConfig(req);

  const user = authDb.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  // Get existing passkey credential IDs to exclude
  const existingCredentials = authDb.prepare(
    'SELECT credential_id, transports FROM passkeys WHERE user_id = ?'
  ).all(req.userId);

  const excludeCredentials = existingCredentials.map(c => ({
    id: c.credential_id,
    transports: c.transports ? JSON.parse(c.transports) : [],
  }));

  const userIdBuffer = Buffer.from(user.id, 'utf-8');

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userName: user.username,
    userID: userIdBuffer,
    userDisplayName: user.username,
    attestationType: 'none',
    excludeCredentials,
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  });

  // Store challenge
  const now = Date.now();
  authDb.prepare(`
    INSERT INTO webauthn_challenges (id, user_id, challenge, type, created_at, expires_at)
    VALUES (?, ?, ?, 'registration', ?, ?)
  `).run(uuidv4(), req.userId, options.challenge, now, now + 5 * 60 * 1000);

  res.json(options);
});

router.post('/register/verify', requireAuth, async (req, res) => {
  const { rpID, origin } = getRpConfig(req);
  const { response, name } = req.body;

  const challengeRow = authDb.prepare(`
    SELECT * FROM webauthn_challenges 
    WHERE user_id = ? AND type = 'registration' AND expires_at > ?
    ORDER BY created_at DESC LIMIT 1
  `).get(req.userId, Date.now());

  if (!challengeRow) {
    return res.status(400).json({ error: 'No valid challenge found' });
  }

  try {
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: challengeRow.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ error: 'Passkey registration failed' });
    }

    const { 
      credential, 
      credentialDeviceType, 
      credentialBackedUp 
    } = verification.registrationInfo;

    const now = Date.now();
    const passkeyId = uuidv4();

    authDb.prepare(`
      INSERT INTO passkeys (id, user_id, credential_id, public_key, counter, device_type, backed_up, transports, name, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      passkeyId,
      req.userId,
      credential.id, // ID is already a base64url string in v13
      Buffer.from(credential.publicKey).toString('base64'),
      credential.counter,
      credentialDeviceType,
      credentialBackedUp ? 1 : 0,
      JSON.stringify(response.response?.transports || []),
      name || `Passkey ${new Date().toLocaleDateString()}`,
      now
    );

    // Clean up challenge
    authDb.prepare('DELETE FROM webauthn_challenges WHERE id = ?').run(challengeRow.id);

    res.json({ success: true, passkeyId, name: name || `Passkey ${new Date().toLocaleDateString()}` });
  } catch (err) {
    console.error('Passkey registration verify error:', err);
    res.status(400).json({ error: err.message || 'Passkey registration failed' });
  }
});

// ─── AUTHENTICATE WITH PASSKEY ────────────────────────────────────────────────

router.post('/authenticate/options', async (req, res) => {
  const { rpID } = getRpConfig(req);
  const { username } = req.body;

  let allowCredentials = [];
  let userId = null;

  if (username) {
    const user = authDb.prepare(
      'SELECT * FROM users WHERE username = ? OR email = ?'
    ).get(username.toLowerCase(), username.toLowerCase());

    if (user) {
      userId = user.id;
      const creds = authDb.prepare(
        'SELECT credential_id, transports FROM passkeys WHERE user_id = ?'
      ).all(user.id);

      allowCredentials = creds.map(c => ({
        id: c.credential_id,
        transports: c.transports ? JSON.parse(c.transports) : [],
      }));
    }
  }

  const options = await generateAuthenticationOptions({
    rpID,
    userVerification: 'preferred',
    allowCredentials,
  });

  const now = Date.now();
  authDb.prepare(`
    INSERT INTO webauthn_challenges (id, user_id, challenge, type, created_at, expires_at)
    VALUES (?, ?, ?, 'authentication', ?, ?)
  `).run(uuidv4(), userId, options.challenge, now, now + 5 * 60 * 1000);

  // Store challenge ID in session for lookup
  req.session.passkeyChallenge = options.challenge;

  res.json(options);
});

router.post('/authenticate/verify', async (req, res) => {
  const { rpID, origin } = getRpConfig(req);
  const { response } = req.body;

  const challenge = req.session.passkeyChallenge;
  if (!challenge) {
    return res.status(400).json({ error: 'No active passkey challenge' });
  }

  const challengeRow = authDb.prepare(`
    SELECT * FROM webauthn_challenges
    WHERE challenge = ? AND type = 'authentication' AND expires_at > ?
    ORDER BY created_at DESC LIMIT 1
  `).get(challenge, Date.now());

  if (!challengeRow) {
    return res.status(400).json({ error: 'Challenge expired or not found' });
  }

  // Find passkey by credential ID
  const credentialId = response.id;
  const passkey = authDb.prepare(
    'SELECT * FROM passkeys WHERE credential_id = ?'
  ).get(credentialId);

  if (!passkey) {
    return res.status(400).json({ error: 'Passkey not registered' });
  }

  try {
    const publicKeyBuffer = Buffer.from(passkey.public_key, 'base64');

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challengeRow.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: passkey.credential_id,
        publicKey: publicKeyBuffer,
        counter: passkey.counter,
        transports: passkey.transports ? JSON.parse(passkey.transports) : [],
      },
    });

    if (!verification.verified) {
      return res.status(401).json({ error: 'Passkey verification failed' });
    }

    // Update counter
    authDb.prepare(
      'UPDATE passkeys SET counter = ?, last_used = ? WHERE id = ?'
    ).run(verification.authenticationInfo.newCounter, Date.now(), passkey.id);

    // Clean up
    authDb.prepare('DELETE FROM webauthn_challenges WHERE id = ?').run(challengeRow.id);
    delete req.session.passkeyChallenge;

    // Full login
    const now = Date.now();
    req.session.userId = passkey.user_id;
    req.session.lastAuthedAt = now; // Passkey = fresh auth
    req.session.loginMethod = 'passkey';
    req.session.loginAt = now;

    const user = authDb.prepare(
      'SELECT id, username, email FROM users WHERE id = ?'
    ).get(passkey.user_id);

    res.json({ success: true, user: { id: user.id, username: user.username } });
  } catch (err) {
    console.error('Passkey verify error:', err);
    res.status(400).json({ error: err.message || 'Passkey verification failed' });
  }
});

// ─── MANAGE PASSKEYS ─────────────────────────────────────────────────────────

router.get('/list', requireAuth, (req, res) => {
  const passkeys = authDb.prepare(`
    SELECT id, name, device_type, backed_up, created_at, last_used
    FROM passkeys WHERE user_id = ?
    ORDER BY created_at DESC
  `).all(req.userId);

  res.json({ passkeys });
});

router.patch('/:id', requireAuth, (req, res) => {
  const { name } = req.body;
  const { id } = req.params;

  const passkey = authDb.prepare(
    'SELECT id FROM passkeys WHERE id = ? AND user_id = ?'
  ).get(id, req.userId);

  if (!passkey) return res.status(404).json({ error: 'Passkey not found' });

  authDb.prepare('UPDATE passkeys SET name = ? WHERE id = ?').run(name, id);
  res.json({ success: true });
});

router.delete('/:id', requireAuth, (req, res) => {
  const { id } = req.params;

  const passkey = authDb.prepare(
    'SELECT id FROM passkeys WHERE id = ? AND user_id = ?'
  ).get(id, req.userId);

  if (!passkey) return res.status(404).json({ error: 'Passkey not found' });

  authDb.prepare('DELETE FROM passkeys WHERE id = ?').run(id);
  res.json({ success: true });
});

export default router;