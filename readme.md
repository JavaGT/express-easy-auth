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
npm install auth-server
```

### 2. Initialize
```javascript
import express from 'express';
import { setupAuth, authRouter } from 'auth-server';

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

### 3. Protect
```javascript
import { requireAuth } from 'auth-server';

app.get('/dashboard', requireAuth, (req, res) => {
  res.json({ message: `Hello User ${req.userId}` });
});
```

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
- [View Example: Passkey Ceremony](examples/02-passkeys.js)

### 🔑 Programmatic Access (API Keys)
Allow users to create and manage their own API keys for your service.
- **Middleware**: Use `requireApiKey` to protect machine-to-machine routes.
- **Permissions**: Supports `action:read` and `action:write`.
- [View Example: API Key Integration](examples/03-api-keys.js)

### 🔗 Linking to your Application Database
**Auth-server** is designed to be a standalone identity provider. It does not store application-specific data (like bios or preferences). Instead, you should link your application database to the `userId` provided by the library.

**Pattern:**
1. Use `requireAuth` to get `req.userId`.
2. Query your own database using that ID.

[View full example of linking databases](examples/08-external-db-linking.js)

### 📜 Logging & Debugging
The library provides a flexible logging system and explicit control over error exposure.
- **`exposeErrors`**: Boolean flag to toggle detailed error messages in the API responses. Recommended to set to `process.env.NODE_ENV !== 'production'`.
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
- `client.loginWithPasskey(username?)`: Biometric login.
- `client.registerPasskey(name)`: Register a biometric key.
- `client.createApiKey(name, permissions)`: Generate a new API key.
- `client.listApiKeys()`: List keys.
- `client.reportError(err, context)`: Report client-side errors to server.

## Examples
The `examples/` directory contains standalone, documented reference implementations.

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