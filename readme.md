# Express Easy Auth 🛡️

**Express Easy Auth** is a professional-grade, SOLID-compliant authentication and identity library for Node.js/Express. It provides a complete, modern security solution with a focus on Passkeys, TOTP, and per-user API keys.

- **🚀 Passkeys (WebAuthn)**: Biometric authentication (TouchID, FaceID) as a standard.
- **🛡️ TOTP 2FA**: Built-in support for Google Authenticator and hardware tokens.
- **🔑 API Key Management**: Per-user API keys with granular scope permissions.
- **💾 Session Store**: Secure, SQLite-backed session management that extends `express-session`.
- **📜 SOLID Architecture**: Service-oriented, decoupled, and easily extensible.

---

## 🚀 Quickstart (5 Minutes)

### 1. Install
```bash
npm install @javagt/express-easy-auth
```

### 2. Initialize
The library uses `AuthManager` to handle logic and `EasyAuth` to wire it into Express.

```javascript
import express from 'express';
import { AuthManager, EasyAuth } from '@javagt/express-easy-auth';

const app = express();
app.use(express.json());

// 1. Configure the core manager
const authManager = new AuthManager({
  databasePath: './data/auth.db', // SQLite database path
  mkdirp: true,                   // Auto-create directories
  totp: {
    issuer: 'My Awesome App'      // Appearance in Authenticator apps
  },
  webAuthn: {
    rpName: 'My Awesome App',
    rpID: 'localhost',
    origin: 'http://localhost:3000'
  }
});

await authManager.init();

// 2. Attach to Express
const auth = EasyAuth.attach(app, authManager, {
  basePath: '/auth',
  session: { secret: process.env.SESSION_SECRET }
});

// 3. Protect your routes
app.get('/api/profile', auth.requireAuth, (req, res) => {
  res.json({ user: req.user });
});

app.listen(3000);
```

---

## 🏗️ Core Architecture

### AuthManager
The `AuthManager` is the brain of the system. It orchestrates various services like `PasswordService`, `WebAuthnService`, and `ApiKeyService`. It is database-agnostic through the `DatabaseAdaptor` pattern.

### EasyAuth Facade
`EasyAuth.attach()` performs several high-level tasks:
1. Mounts `express-session` using the `SQLiteSessionStore`.
2. Registers the identity router at your specified `basePath`.
3. Automatically serves the frontend SDK at `${basePath}/client.js`.
4. Adds the `AuthMiddleware.errorHandler` to ensure standardized JSON error responses.
5. Returns a bound `AuthMiddleware` instance for protecting your own routes.

---

## 🛡️ AuthMiddleware Reference

`EasyAuth.attach()` returns an `AuthMiddleware` instance. All methods below are pre-bound and ready to use as Express middleware.

| Method | Returns | Description |
| :--- | :--- | :--- |
| `requireAuth` | middleware | Requires a valid session cookie. Sets `req.user`, `req.scopes`, `req.roles`, `req.authType = 'session'`. |
| `requireApiKey` | middleware | Requires a valid API key. Errors immediately if no key is present. Sets `req.user`, `req.scopes`, `req.authType = 'api_key'`. |
| `useApiKey` | middleware | Same as `requireApiKey` — alias provided for semantic clarity in some contexts. |
| `requireAuthOrApiKey` | middleware | Accepts either a valid session **or** a valid API key. Tries session first, then key. |
| `requireFreshAuth` | middleware **or** factory | Requires the session to have been re-authenticated within the last 5 minutes. Does **not** accept API keys. Imples `requireAuth` — no need to chain. |
| `rateLimit(options)` | factory | Returns an IP-based rate-limiting middleware. |

### API Key Transport

All API-key-aware middleware accept keys via:
- **`X-API-Key: <key>`** header *(canonical)*
- **`Authorization: Bearer sk_<key>`** header *(when the token starts with `sk_`)*
- **`?apiKey=<key>`** query param or `req.body.apiKey`

> **Note:** `Authorization: Bearer` tokens that do **not** start with `sk_` are left untouched and are never interpreted as API keys, so standard session bearer flows are unaffected.

### Naming Hierarchy

```
requireAuth          → session only
requireApiKey        → API key only
requireAuthOrApiKey  → either
requireFreshAuth     → session only, recently re-verified
```

### `requireFreshAuth` with scope enforcement

```javascript
// Plain middleware — checks freshness only
app.delete('/account', auth.requireFreshAuth, handler);

// Factory variant — checks freshness AND required scopes in one step
app.post('/members', auth.requireFreshAuth(['project:manage']), handler);
```

`requireFreshAuth` internally calls `requireAuth`, so you should **not** chain `requireAuth` before it.

---

## 🔑 API Key Workflow (End-to-End)

This section documents the complete workflow for creating and using API keys.

### 1. Assign a role (server-side, at registration or bootstrap)

Before a user can create API keys, they need a role whose configured scopes cover the key's requested scopes.

```javascript
// In your registration hook or bootstrap script:
await authManager.assignRole(userId, 'owner');
// assignRole creates the role in auth.db if it doesn't exist, then links it to the user.
// This replaces the old pattern of reaching into authManager.databaseAdapter.db directly.
```

Remove a role with:
```javascript
await authManager.removeRole(userId, 'owner');
```

### 2. Create a key (from a trusted server context)

When your own authorization model (e.g. project ownership in an external DB) grants authority, pass `callerScopes` to bypass the `user_roles` lookup:

```javascript
// Trusted server-side issuance — callerScopes replaces the role lookup
const { key, id, name, scopes, createdAt } = await authManager.createApiKey(
  userId,
  ['files:read', 'files:write'],
  null,        // expiresAt
  'worker-key',
  { callerScopes: ['files:read', 'files:write', 'files:delete'] }
);

// `id` can now be stored in your own DB to reference the key record
// without needing to call authManager.databaseAdapter.getApiKey(rawKey)
```

**`createApiKey` return shape:**

```json
{
  "key": "sk_abc123...",
  "id": 7,
  "name": "worker-key",
  "scopes": ["files:read", "files:write"],
  "createdAt": 1713571234567
}
```

> ⚠️ **Breaking change from v3.0.x:** `createApiKey` previously returned a bare string. It now returns an object. Update any callers that used the return value directly as a string.

### 3. Create a key (via the built-in API route)

```http
POST /auth/keys
Authorization: Cookie (session)

{ "scopes": ["files:read"], "name": "my-worker" }
```

Response:
```json
{
  "success": true,
  "key": "sk_abc123...",
  "id": 7,
  "name": "my-worker",
  "scopes": ["files:read"],
  "createdAt": 1713571234567
}
```

### 4. Use the key in a worker

```javascript
// Option A: X-API-Key header (canonical)
fetch('/api/jobs', { headers: { 'X-API-Key': process.env.WORKER_KEY } });

// Option B: Authorization Bearer (also accepted for sk_ prefixed tokens)
fetch('/api/jobs', { headers: { 'Authorization': `Bearer ${process.env.WORKER_KEY}` } });
```

### 5. Protect routes

```javascript
// Session only
app.get('/profile', auth.requireAuth, handler);

// API key only
app.post('/api/jobs/claim', auth.requireApiKey, handler);

// Either (e.g. dashboard + background workers)
app.get('/api/projects', auth.requireAuthOrApiKey, handler);

// Fresh session required (sensitive operations)
app.delete('/account', auth.requireFreshAuth, handler);
app.post('/members', auth.requireFreshAuth(['project:manage']), handler);
```

---

## 🌐 Frontend SDK

No installation required. `EasyAuth.attach()` serves a modern, lightweight client directly from your server.

```html
<script type="module">
  import { EasyAuthClient } from '/auth/client.js';
  const auth = new EasyAuthClient({ apiBase: '/auth' });

  // Login with Passkey
  const result = await auth.loginWithPasskey(SimpleWebAuthnBrowser);
  
  // Register for 2FA
  const { qrCode, secret } = await auth.setupTotp();
</script>
```

---

## 📜 API Reference

All routes are nested under the `basePath` provided to `EasyAuth.attach`.

| Category | Method | Path | Auth | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Auth** | POST | `/login` | — | Login with password/TOTP |
| | POST | `/register` | — | Create a new account |
| | POST | `/logout` | ✓ | End the session |
| | GET | `/me` | ✓ or 🔑 | Get current user profile |
| **TOTP** | GET | `/totp/status` | ✓ | Check if 2FA is enabled |
| | POST | `/totp/setup` | ✓ | Generate QR code/secret |
| | POST | `/totp/verify` | ✓ | Finalize 2FA setup |
| **Passkeys**| POST | `/passkeys/login/options` | — | WebAuthn challenge |
| | POST | `/passkeys/login/verify` | — | Finalize Passkey login |
| | POST | `/passkeys/register/options`| ✓ | Start Passkey enrollment |
| | GET | `/passkeys` | ✓ | List registered keys |
| **API Keys**| GET | `/keys` | ✓ | List user API keys |
| | POST | `/keys` | ✓ | Create a new API key (returns `{ key, id, name, scopes, createdAt }`) |
| | DELETE | `/keys/:key` | ✓ | Revoke a key |
| **Sessions**| GET | `/sessions` | ✓ | List all active sessions |
| | DELETE | `/sessions/:id`| ✓ | Revoke a specific session |

### Error Format
All failures return a consistent JSON structure:
```json
{
  "success": false,
  "error": "INVALID_CREDENTIALS",
  "message": "The password you entered is incorrect."
}
```

---

## 🛡️ Security Features

### Fresh Auth
Sensitive operations (like changing passwords or deleting accounts) can be protected by `requireFreshAuth`. This forces the user to provide a password or passkey if their session hasn't been re-verified recently.

```javascript
app.delete('/account', auth.requireFreshAuth, (req, res) => {
  // Only reachable if user just re-authenticated
});
```

### SQLite Session Store
Unlike the default memory store, our `SQLiteSessionStore` is persistent across restarts and supports revoking sessions for specific users programmatically.

---

## 🧪 Verification & Examples
Check the `demo/` directory for full reference implementations:
1. `demo/demo1-color-server-logs`: Basic setup with API keys.
2. `demo/demo2-chat-app`: Advanced multi-scoped identity and bots.

## License
ISC