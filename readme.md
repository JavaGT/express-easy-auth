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
  session: { secret: 'process.env.SESSION_SECRET' }
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
| | GET | `/me` | ✓ | Get current user profile |
| **TOTP** | GET | `/totp/status` | ✓ | Check if 2FA is enabled |
| | POST | `/totp/setup` | ✓ | Generate QR code/secret |
| | POST | `/totp/verify` | ✓ | Finalize 2FA setup |
| **Passkeys**| POST | `/passkeys/login/options` | — | WebAuthn challenge |
| | POST | `/passkeys/login/verify` | — | Finalize Passkey login |
| | POST | `/passkeys/register/options`| ✓ | Start Passkey enrollment |
| | GET | `/passkeys` | ✓ | List registered keys |
| **API Keys**| GET | `/keys` | ✓ | List user API keys |
| | POST | `/keys` | ✓ | Create a new API key |
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