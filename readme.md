# Express Easy Auth

**A powerful, secure, and developer-friendly authentication library for Express.js that "just works."**

Express Easy Auth provides a complete authentication solution including password-based login, TOTP 2FA, WebAuthn Passkeys, and user-managed API keys—all with sensible defaults and a focus on clean, SOLID architecture.

## 🚀 Quick Start

Get up and running in minutes with the `EasyAuth.create()` factory:

```javascript
import express from 'express';
import session from 'express-session';
import { EasyAuth } from '@javagt/express-easy-auth';

const app = express();

app.use(express.json());
app.use(session({
  secret: 'your-secret',
  resave: false,
  saveUninitialized: false
}));

// Initialize with sensible defaults (SQLite at ./data/auth.db)
const { auth, authManager } = await EasyAuth.create(app);

// Use middleware to protect your routes
app.get('/protected', auth.requireAuth, (req, res) => {
  res.json({ message: 'Welcome!', user: req.user });
});

app.listen(3000, () => console.log('Server started on port 3000'));
```

## ✨ Key Features

- **Sensible Defaults**: Comes with an SQLite adapter that auto-creates its data directory.
- **Modern Auth**: Built-in support for **WebAuthn Passkeys** and **TOTP (Google Authenticator)**.
- **Programmable Access**: Sophisticated **API Key** management with scope-based permissions.
- **Granular Permissions**: Built-in middleware for Server, Personal, and Project-level authorization.
- **SOLID Design**: Decoupled, service-oriented architecture designed for extensibility and testability.

## 🛡️ Middleware Patterns

Express Easy Auth provides a "trilogy" of guards to handle different authentication flows:

- `auth.requireAuth`: For interactive user sessions (human flows).
- `auth.requireApiKey`: For programmatic or worker flows.
- `auth.requireAuthOrApiKey`: For hybrid endpoints that support both.
- `auth.requireFreshAuth`: For sensitive operations requiring a recent (5-minute) re-authentication.

## 🏗️ Architecture

The library is built on four core pillars:

1. **AuthManager**: The central orchestrator that coordinates all authentication logic.
2. **AuthMiddleware**: Express-specific middleware for route protection and access control.
3. **DatabaseAdaptors**: Pluggable storage layer (SQLite provided out-of-the-box).
4. **ContactAdaptors**: Pluggable notification layer (Console logging provided by default).

## 🗄️ Database Defaults

By default, `EasyAuth.create()` uses the `SQLiteAdaptor` with these settings:
- **Path**: `./data/auth.db`
- **Auto-create directory**: Enabled (`mkdirp: true`)

To override, pass a configuration object:

```javascript
const { auth } = await EasyAuth.create(app, {
  databaseAdapter: new SQLiteAdaptor({
    databasePath: '/custom/path/auth.db',
    mkdirp: false
  })
});
```

## 📜 Documentation

For detailed guides and API references, see:
- [DESIGN.md](./DESIGN.md) - Deep dive into architecture and core concepts.
- [AGENTS.md](./AGENTS.md) - Guide for developers and AI agents working on the library.

---
*Stay Clean. Stay SOLID.*