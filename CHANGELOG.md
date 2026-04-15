# Changelog

## 2.0.0

### Breaking changes

- **JSON error shape**: Failure responses now use a nested envelope: `{ "error": { "code": string, "message": string, "details"?: unknown } }`. Previously many endpoints returned `{ "error": string, "code"?: string }` at the top level. Update clients to read `body.error.message` and `body.error.code`.
- **`setupAuth` config**: The `config` object is stored **by reference** (no shallow copy). `exposeErrors` is **not** merged onto `config`; use `req.app.get('exposeErrors')` or read it from `setupAuth` options in your own code.
- **`AuthClient`**: `request()` resolves `AuthError.message` and `AuthError.code` from the nested `error` object.

### Added

- **`setupAuth` options**: `getWebAuthnOptions(req)` for per-request `rpID`, `origin`, and `rpName` (e.g. reverse proxies and multiple hosts). When `config.rpID` / `config.origin` are omitted, defaults are derived from the request (`Host` / `X-Forwarded-*` when `trust proxy` is enabled).
- **`setupAuth` options**: `enableApiKeys: false` hides user-facing `/api-keys` CRUD (returns 404). `requireApiKey` middleware behavior is unchanged.
- **Exports**: `formatAuthError`, `resolveWebAuthnOptions` from the main package entry.

### Documentation

- README: reverse-proxy / WebAuthn notes, minimal integration profile, discoverable passkey login, `enableApiKeys`.
