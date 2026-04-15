# Express Auth Service (Library)

**Express Auth Service** is a modular, professional-grade authentication and session management library for Node.js/Express. It provides a complete identity solution with a focus on modern security (Passkeys) and developer experience.

- **🚀 Passkeys (WebAuthn)**: Passwordless biometric authentication (TouchID, FaceID).
- **🛡️ TOTP 2FA**: Google Authenticator, Authy, and hardware token support.
- **🔑 API Key Management**: Per-user API keys with granular permissions for programmatic access.
- **💾 Session Store**: Secure, ACID-compliant SQLite-backed session management.
- **🔒 Fresh Auth**: Middleware to require recent re-authentication for sensitive actions.
- **📜 System Logs**: Built-in diagnostics and activity logging.

---

## 🚀 5-Minute Quickstart

### 1. Install
```bash
npm install @javagt/express-easy-auth
```

### 2. Initialize
```javascript
import express from 'express';
import { setupAuth, authRouter } from '@javagt/express-easy-auth';

const app = express();
app.use(express.json());

setupAuth(app, {
  dataDir: './data',
  config: { 
    domain: 'localhost',
    rpName: 'My Auth App',
    rpID: 'localhost',
    origin: 'http://localhost:3000'
  }
});

// Standard mounting pattern
app.use('/api/v1/auth', authRouter);
app.listen(3000);
```

### JSON errors (v2+)

Failed API responses use a stable machine-readable shape:

```json
{
  "error": {
    "code": "MISSING_CREDENTIALS",
    "message": "Human-readable description"
  }
}
```

Branch UIs on `error.code`, not `error.message`. See [CHANGELOG.md](CHANGELOG.md) for migration notes from v1.

### 3. Protect
```javascript
import { requireAuth } from '@javagt/express-easy-auth';

app.get('/dashboard', requireAuth, (req, res) => {
  res.json({ message: `Hello User ${req.userId}` });
});
```

---

## Minimal integration profile

For a small **management plane** (sessions + passkeys + login/logout, optional 2FA), you typically mount the auth router and use session middleware. Core routes:

| Area | Prefix (example) | Notes |
| :--- | :--- | :--- |
| Login / logout / status | `POST /login`, `POST /logout`, `GET /status` | Session cookies |
| Passkeys | `/passkeys/*`, `/passkeys/authenticate/*` | WebAuthn |
| Sessions | `GET /sessions`, `DELETE /sessions/:id` | List / revoke |
| Optional 2FA | `/2fa/*` | TOTP |
| Optional extras | `/api-keys`, `/password-reset/*`, `/settings`, `/report-error` | Omit or disable as needed |

**Threat model / scope:** Turning off user API key CRUD does not remove server-side verification of API keys you issue elsewhere—use `setupAuth({ enableApiKeys: false })` only to hide the built-in key management UI; protect M2M routes with `requireApiKey` when you still use keys.

---

## Reverse proxy and WebAuthn (`rpID` / `origin`)

The same app may be reached as `http://127.0.0.1:…` and as `https://app.example.com` behind a proxy. WebAuthn requires `expectedOrigin` and `expectedRPID` to match the browser.

1. Set **`app.set('trust proxy', …)`** so Express sees `X-Forwarded-Proto` / `X-Forwarded-Host` (or your proxy’s equivalents).
2. Either omit static `config.origin` / `config.rpID` so the library **derives** them from each request, or supply a resolver:

```javascript
setupAuth(app, {
  dataDir: './data',
  config: { rpName: 'My App' },
  getWebAuthnOptions: (req) => {
    const host = req.get('host') || '';
    const origin = `${req.protocol}://${host}`;
    return {
      rpName: 'My App',
      origin,
      rpID: new URL(origin).hostname
    };
  }
});
```

`exposeErrors` is configured only via `setupAuth({ exposeErrors })`; it is stored separately and is **not** copied onto `config` (so Proxies/getters on `config` remain usable).

---

## 🌐 Frontend SDK

The library hosts its own lightweight SDK at `/auth-sdk.js` (can be customized). No installation required.

```html
<script type="module">
  import { AuthClient } from '/auth-sdk.js';
  const auth = new AuthClient();
  
  // High-level ceremonies
  await auth.loginWithPasskey();
  await auth.registerPasskey('My Mac');
  
  // Standard methods
  const status = await auth.getStatus();
</script>
```

---

## 📖 Features & Documentation

### 🛡️ Multi-Factor Auth (TOTP)
Users can enable TOTP 2FA for an extra layer of security.
- **Setup**: `POST /api/v1/auth/2fa/setup`
- **Verify**: `POST /api/v1/auth/2fa/verify-setup`
- [View Example: TOTP Setup](examples/04-totp-setup.js)

### 🏎️ Passkeys (WebAuthn)
Full WebAuthn support including discovery and residency.
- **Integration**: Use `AuthClient.loginWithPasskey()` and `AuthClient.registerPasskey()`.
- **Discoverable / username-less login**: Call `loginWithPasskey()` with no argument (or omit username). The server then sends an empty `allowCredentials` list so the authenticator can use discoverable credentials.
- [View Example: Passkey Ceremony](examples/02-passkeys.js)

### 🔑 Programmatic Access (API Keys)
Allow users to create and manage their own API keys for your service.
- **Middleware**: Use `requireApiKey` to protect machine-to-machine routes.
- **Permissions**: Supports `action:read` and `action:write`.
- **Hiding CRUD**: `setupAuth({ enableApiKeys: false })` returns 404 for `GET/POST/DELETE /api-keys` while `requireApiKey` still validates keys.
- [View Example: API Key Integration](examples/03-api-keys.js)

### 🔗 Linking to your Application Database
**Auth-server** is designed to be a standalone identity provider. It does not store application-specific data (like bios or preferences). Instead, you should link your application database to the `userId` provided by the library.

**Pattern:**
1. Use `requireAuth` to get `req.userId`.
2. Query your own database using that ID.

[View full example of linking databases](examples/08-external-db-linking.js)

### 📜 Logging & Debugging
The library provides a flexible logging system and explicit control over error exposure.
- **`exposeErrors`**: Boolean passed to `setupAuth`; stored on the app (not merged into `config`). Recommended to set to `process.env.NODE_ENV !== 'production'`.
- **Custom Logger**: Plug in your own logger (e.g., Winston, Pino) by passing it to `setupAuth`.
- [View Example: Custom Logger](examples/05-custom-logger.js)

### 🌐 SPA Fallback (Modern Alternative to Wildcard Routes)
When building Single Page Applications (SPAs), avoid using catch-all wildcard routes (e.g., `app.get('*', ...)`) as they can cause routing conflicts and `PathError` in newer versions of Express. 

Instead, use a middleware-based fallback that only triggers for HTML requests:
```javascript
app.use((req, res, next) => {
  if (req.method === 'GET' && req.accepts('html') && !req.path.startsWith('/api')) {
    res.sendFile(path.join(__dirname, 'public/index.html'));
  } else {
    next();
  }
});
```

---

## 📜 API Reference

### Backend API (V1)
All identity endpoints are nested under the router (recommended path: `/api/v1/auth`).

| Category | Method | Path | Auth | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Auth** | POST | `/login` | — | Login with password |
| | POST | `/register` | — | Create account |
| | POST | `/logout` | ✓ | Destroy session |
| | GET | `/status` | — | Check session status |
| **2FA** | POST | `/2fa/setup` | ✓ | Generate TOTP secret |
| | POST | `/2fa/verify-setup` | ✓ | Enable 2FA after verification |
| | POST | `/2fa/disable` | ✓ (Fresh) | Disable TOTP |
| **Passkeys** | POST | `/passkeys/register/options` | ✓ | Get registration options |
| | POST | `/passkeys/register/verify` | ✓ | Verify and save passkey |
| | POST | `/passkeys/authenticate/options` | — | Get login options |
| | POST | `/passkeys/authenticate/verify` | — | Verify passkey login |
| | GET | `/passkeys` | ✓ | List registered passkeys |
| | DELETE | `/passkeys/:id` | ✓ | Delete a passkey |
| **Account** | POST | `/password/change` | ✓ (Fresh) | Change current password |
| | POST | `/email/change` | ✓ (Fresh) | Update email address |
| **Password Reset** | POST | `/password-reset/request` | — | Generate reset token |
| | POST | `/password-reset/reset` | — | Complete reset |
| **API Keys** | GET | `/api-keys` | ✓ | List user API keys |
| | POST | `/api-keys` | ✓ | Create new API key |
| | DELETE | `/api-keys/:id` | ✓ | Revoke API key |

### Frontend SDK (AuthClient)
The SDK is available at `/auth-sdk.js`.

#### Methods
- `client.login(username, password)`: Manual login.
- `client.register(username, email, password)`: Manual registration.
- `client.logout()`: Logout.
- `client.getStatus()`: Get authentication and security status.
- `client.loginWithPasskey(username?)`: Biometric login; omit `username` for discoverable credentials.
- `client.registerPasskey(name)`: Register a biometric key.
- `client.createApiKey(name, permissions)`: Generate a new API key.
- `client.listApiKeys()`: List keys.
- `client.reportError(err, context)`: Report client-side errors to server.

## Examples
The `examples/` directory contains standalone, documented reference implementations. See [examples/README.md](examples/README.md) for how to run them and v2 notes.

1. `01-basic-setup.js`: Minimal Express integration.
2. `02-passkeys.js`: WebAuthn registration and login.
3. `03-api-keys.js`: Service-to-service authentication.
4. `04-totp-setup.js`: TOTP 2FA lifecycle.
5. `05-custom-logger.js`: Injecting a custom logger.
6. `06-password-reset.js`: Full password recovery flow.
7. `08-external-db-linking.js`: Linking to your own application database.

---

## License
MIT