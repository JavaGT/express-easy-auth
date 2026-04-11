# Auth Server Library Examples

This directory contains standalone, well-documented reference implementations for each major feature of the library. These examples are designed to be read and run in isolation.

## 🚀 How to Run
Most examples require an Express environment. To run an example:

1. `npm install` (if you haven't already)
2. `node examples/01-basic-setup.js`

## 📖 Available Examples

### 01. Basic Setup
**File**: `01-basic-setup.js`
The "Hello World" of the library. Shows how to initialize `setupAuth`, configure standard Express sessions, and protect a basic route.

### 02. Passkeys (WebAuthn)
**File**: `02-passkeys.js`
Focuses on the passwordless experience. Shows how to mount the `passkeysRouter` and integrate the `AuthClient` ceremonies for registration and login.

### 03. API Keys
**File**: `03-api-keys.js`
Demonstrates programmatic access. Create machine-to-machine keys with granular permissions (`action:read`, `action:write`) and verify them using the `requireApiKey` middleware.

### 04. TOTP 2FA lifecycle
**File**: `04-totp-setup.js`
Covers the setup and verification of Google Authenticator-style 2FA. Includes an example of `requireFreshAuth` for sensitive actions.

---

> [!TIP]
> **Prototyping**: You can copy these files directly into your project as a starting point. All examples use local SQLite databases (`./data-example`) by default.
