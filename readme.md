# Express Auth Service

A modular Express middleware service for authentication, providing **Passkeys (WebAuthn)**, **TOTP 2FA**, and **Session Management** out of the box.

## features

- 🛡️ **Passkeys (WebAuthn)**: Passwordless biometric authentication.
- 🔐 **TOTP 2FA**: Google Authenticator / Authy support.
- 🚪 **Session Management**: Secure, SQLite-backed session store.
- 🔒 **Fresh Auth**: Middleware to protect sensitive actions with re-authentication.
- 📋 **System Logs**: Built-in error and activity logging.

## Quickstart

### 1. Install Dependencies

```bash
npm install auth-server
```

### 2. Configure Environment

Create a `.env` file in your root directory (see `.env.example`):

```bash
DOMAIN=your-domain.com
SESSION_SECRET=your-secure-session-secret
PORT=3000
```

### 3. Integration

```javascript
import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import path from 'path';
import { 
  setupAuth, 
  authRouter, 
  passkeysRouter, 
  userRouter, 
  SQLiteSessionStore,
  authErrorLogger 
} from 'auth-server';

const app = express();

const config = {
  domain: process.env.DOMAIN || 'localhost',
  rpName: 'My Application',
  rpID: process.env.DOMAIN || 'localhost',
  origin: `https://${process.env.DOMAIN || 'localhost'}`
};

// 1. Initialize Auth Service
setupAuth(app, {
  dataDir: './data',
  config
});

// 2. Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 3. Configure Session
app.use(session({
  secret: process.env.SESSION_SECRET,
  store: new SQLiteSessionStore(),
  resave: false,
  saveUninitialized: false,
  cookie: { secure: true, httpOnly: true }
}));

// 4. Mount Routes
app.use('/api/auth', authRouter);
app.use('/api/passkeys', passkeysRouter);
app.use('/api/user', userRouter);

// 5. Global Error Logger
app.use(authErrorLogger);

app.listen(process.env.PORT || 3000);
```

### 3. Protect Routes

```javascript
import { requireAuth, requireFreshAuth } from 'auth-server';

// Requires any valid session
app.get('/dashboard', requireAuth, (req, res) => {
  res.send(`Welcome, user ${req.userId}`);
});

// Requires re-authentication within the last 5 minutes
app.post('/change-password', requireAuth, requireFreshAuth, (req, res) => {
  res.send('Sensitive action authorized');
});
```

## Running the Demo

The project includes a full-featured demo in the `demo/` folder.

1. `npm install`
2. `cp .env.example .env` (Set your `DOMAIN` and `SESSION_SECRET`)
3. `npm start`
4. Access the UI at the configured `DOMAIN`.

## Exported API

### `setupAuth(app, options)`
Initializes the databases and attaches the configuration to the Express app.
- `options.dataDir`: Path to store SQLite databases.
- `options.config`: Auth configuration object.

### Routers
- `authRouter`: Register, Login (Password/TOTP), Logout, Status, 2FA Setup.
- `passkeysRouter`: WebAuthn registration, authentication, and management.
- `userRouter`: Profile management and session viewing/revocation.

### Middlewares
- `requireAuth`: Rejects unauthenticated requests (401).
- `requireFreshAuth`: Rejects requests if the user hasn't authed recently (403).
- `authErrorLogger`: Express error handler that logs to the `system_logs` table.

---

## API Reference (Current Endpoints)

### Auth (`/api/auth`)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/register` | — | Create account + auto-login |
| `POST` | `/login` | — | Password login |
| `POST` | `/login/2fa` | pending | Complete 2FA after password |
| `POST` | `/logout` | ✓ | Destroy session |
| `GET`  | `/status` | — | Current session info |

### Passkeys (`/api/passkeys`)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/register/options` | ✓ | Get WebAuthn registration options |
| `POST` | `/register/verify` | ✓ | Verify and save new passkey |
| `POST` | `/authenticate/options` | — | Get WebAuthn assertion options |
| `POST` | `/authenticate/verify` | — | Verify passkey login |

### User (`/api/user`)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET`  | `/me` | ✓ | Get profile |
| `PATCH`| `/me` | ✓ | Update profile |
| `POST` | `/sensitive-action` | ✓ + 🔒fresh | Perform sensitive action |