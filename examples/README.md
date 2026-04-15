# Express Easy Auth — Examples

This directory contains standalone reference implementations for major features. Examples assume the package is installed as `@javagt/express-easy-auth` (see [CHANGELOG.md](../CHANGELOG.md) for v2 breaking changes: nested JSON errors, `exposeErrors` storage, WebAuthn options).

## How to run

1. From the repo root: `npm install`
2. `node examples/01-basic-setup.js` (or any numbered example)

Examples use local SQLite under `./data-example` by default.

## Available examples

### 01. Basic setup

**File:** [01-basic-setup.js](01-basic-setup.js)

Minimal `setupAuth`, sessions, and a protected route.

### 02. Passkeys (WebAuthn)

**File:** [02-passkeys.js](02-passkeys.js)

Passkey registration and login with `AuthClient`. Uses the unified `authRouter` mounted at `/api/v1/auth` (not a separate passkeys router).

### 03. API keys

**File:** [03-api-keys.js](03-api-keys.js)

Machine-to-machine keys (`action:read`, `action:write`) and `requireApiKey` middleware.

### 04. TOTP 2FA

**File:** [04-totp-setup.js](04-totp-setup.js)

TOTP setup and verification, including `requireFreshAuth` for sensitive actions.

---

You can copy these files into your project as a starting point. For a smaller surface area (sessions + passkeys only), see the “Minimal integration profile” section in the main [readme.md](../readme.md).
