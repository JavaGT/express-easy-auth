# Auth Server

A full-stack authentication server with **passkeys (WebAuthn)**, **TOTP 2FA**, password auth, scoped sessions, and fresh-auth-gated sensitive actions.

## Stack

- **Backend**: Express.js (Node ≥22)
- **Auth DB**: `node:sqlite` — sessions, credentials, 2FA secrets, passkey challenges
- **User DB**: `node:sqlite` — profile data (bio, display name, location, website)
- **Session store**: Custom SQLite adapter for `express-session`
- **Passkeys**: `@simplewebauthn/server` v13
- **TOTP**: `otplib` + `qrcode`
- **Passwords**: `bcrypt` (12 rounds)

## Project Structure

```
auth-server/
├── src/
│   ├── server.js              # Entry point, Express config, session setup
│   ├── db/
│   │   ├── init.js            # SQLite table creation for both DBs
│   │   └── sessionStore.js    # Custom express-session store on SQLite
│   ├── middleware/
│   │   └── auth.js            # requireAuth, requireFreshAuth
│   └── routes/
│       ├── auth.js            # Register, login, logout, TOTP, fresh-auth
│       ├── passkeys.js        # WebAuthn registration & authentication
│       └── user.js            # Profile, sessions, sensitive-action endpoint
├── public/
│   ├── index.html             # SPA shell
│   ├── css/style.css          # Dark terminal-inspired UI
│   └── js/app.js              # Frontend (vanilla JS, no framework)
├── data/                      # Created at runtime
│   ├── auth.db                # Sessions, users, passkeys, TOTP
│   └── users.db               # Profile data
└── .env.example
```

## Setup

```bash
# 1. Install dependencies
npm install

# 2. Configure environment
cp .env.example .env
# Edit .env — set DOMAIN, SESSION_SECRET

# 3. Start
npm start          # production
npm run dev        # development (node --watch)
```

The `data/` directory and SQLite databases are created automatically on first run.

## Environment Variables

| Variable         | Default                        | Description |
|-----------------|--------------------------------|-------------|
| `NODE_ENV`       | `development`                  | Set to `production` for HTTPS cookies |
| `PORT`           | `3000`                         | HTTP port |
| `DOMAIN`         | `auth-test.javagrant.ac.nz`    | Subdomain — controls RP ID, cookie domain, CORS |
| `RP_NAME`        | `Auth Server`                  | Display name shown in passkey prompts |
| `SESSION_SECRET` | *(insecure default)*           | Long random string for signing session cookies |

## API Reference

### Auth

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/api/auth/register` | — | Create account + auto-login |
| `POST` | `/api/auth/login` | — | Password login (returns `requires2FA: true` if enabled) |
| `POST` | `/api/auth/login/2fa` | pending | Complete 2FA after password |
| `POST` | `/api/auth/logout` | ✓ | Destroy session |
| `GET`  | `/api/auth/status` | — | Current session info |
| `POST` | `/api/auth/2fa/setup` | ✓ | Begin TOTP setup → returns QR + secret |
| `POST` | `/api/auth/2fa/verify-setup` | ✓ | Confirm TOTP code to activate |
| `POST` | `/api/auth/2fa/disable` | ✓ | Disable TOTP (requires password + code) |
| `POST` | `/api/auth/fresh-auth` | ✓ | Re-verify identity (password or TOTP) |

### Passkeys

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/api/passkeys/register/options` | ✓ | Get WebAuthn registration options |
| `POST` | `/api/passkeys/register/verify` | ✓ | Verify and save new passkey |
| `POST` | `/api/passkeys/authenticate/options` | — | Get WebAuthn assertion options |
| `POST` | `/api/passkeys/authenticate/verify` | — | Verify passkey login |
| `GET`  | `/api/passkeys/list` | ✓ | List registered passkeys |
| `PATCH`| `/api/passkeys/:id` | ✓ | Rename passkey |
| `DELETE`| `/api/passkeys/:id` | ✓ | Remove passkey |

### User

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET`  | `/api/user/me` | ✓ | Get profile |
| `PATCH`| `/api/user/me` | ✓ | Update profile |
| `GET`  | `/api/user/sessions` | ✓ | List active sessions |
| `DELETE`| `/api/user/sessions/:id` | ✓ | Revoke session |
| `POST` | `/api/user/sensitive-action` | ✓ + 🔒fresh | Perform sensitive action |

#### Sensitive Actions

Send `{ "action": "<name>", "data": {} }` to `/api/user/sensitive-action`.

| Action | Description |
|--------|-------------|
| `view-secret` | Return account secret token |
| `export-data` | Full account data export |
| `change-email` | Initiate email change (pass `data.newEmail`) |
| `delete-account-request` | Schedule account deletion |

Returns `403 FRESH_AUTH_REQUIRED` if fresh auth has expired. Frontend re-prompts.

## Security Design

### Cookie scoping
Session cookies are set with `domain: DOMAIN` — they only transmit to `auth-test.javagrant.ac.nz` and its subpaths. They won't cross to `javagrant.ac.nz` or other subdomains.

### WebAuthn RP ID
`rpID` is set to the bare domain (no `https://`, no port). The browser will only allow passkeys registered here to be used on exactly this domain.

### Fresh auth
Sensitive endpoints use `requireFreshAuth` middleware. A fresh-auth token is stored in the DB with a 5-minute TTL. The token is tied to both `user_id` and `session_id` — it can't be reused across sessions.

### Sessions
Sessions live in `auth.db`. The SQLite store cleans expired sessions hourly. Session cookies are `httpOnly`, `sameSite: lax`, and `secure: true` in production.

## Nginx Example

```nginx
server {
    listen 443 ssl;
    server_name auth-test.javagrant.ac.nz;

    ssl_certificate     /etc/letsencrypt/live/auth-test.javagrant.ac.nz/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth-test.javagrant.ac.nz/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```