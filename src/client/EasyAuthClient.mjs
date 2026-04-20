/**
 * EasyAuthClient - A modern JavaScript client for the Express Easy Auth API.
 * Sessions are managed via httpOnly cookies — no token storage required.
 * Handles TOTP and WebAuthn flows with a clean, throw-based error model.
 */
export class EasyAuthClient {
    constructor(options = {}) {
        if (typeof options === 'string') {
            throw new TypeError(
                `EasyAuthClient expects a configuration object, not a string. ` +
                `Use: new EasyAuthClient({ apiBase: '${options}' })`
            );
        }
        const { apiBase = '/auth' } = options;
        this.apiBase = apiBase;
        this.user = JSON.parse(localStorage.getItem('auth_user') || 'null');
    }

    async register(email, password, displayName) {
        return this._post('/register', { email, password, displayName });
    }

    async verifyEmail(token) {
        return this._post('/verify-email', { token });
    }

    async login(email, password, totpCode) {
        const result = await this._post('/login', { email, password, code: totpCode });
        this.user = result.user ?? null;
        this._saveLocal();
        return result;
    }

    async logout() {
        try {
            await this._post('/logout', {});
        } finally {
            this._clearSession();
        }
    }

    async me() {
        const result = await this._get('/me');
        this.user = result.user ?? null;
        this._saveLocal();
        return result;
    }

    async deleteAccount() {
        return this._request('/account', { method: 'DELETE' });
    }

    // --- TOTP Methods ---

    async getTotpStatus() {
        return this._get('/totp/status');
    }

    async setupTotp() {
        return this._post('/totp/setup', {});
    }

    async verifyTotp(code) {
        return this._post('/totp/verify', { code });
    }

    async disableTotp() {
        return this._post('/totp/disable', {});
    }

    // --- Passkey Methods ---

    async registerPasskey(SimpleWebAuthnBrowser, name) {
        const options = await this._post('/passkeys/register/options', {});
        const attestation = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON: options });
        return this._post('/passkeys/register/verify', { ...attestation, name });
    }

    async loginWithPasskey(SimpleWebAuthnBrowser) {
        const options = await this._post('/passkeys/login/options', {});
        const assertion = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON: options });
        const result = await this._post('/passkeys/login/verify', { response: assertion, tempId: options.tempId });
        this.user = result.user ?? null;
        this._saveLocal();
        return result;
    }

    async reauthWithPasskey(SimpleWebAuthnBrowser) {
        const options = await this._post('/passkeys/verify/options', {});
        const assertion = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON: options });
        return this._post('/passkeys/verify/verify', assertion);
    }

    async getPasskeys() {
        return this._get('/passkeys');
    }

    async updatePasskeyName(credentialId, name) {
        return this._request(`/passkeys/${credentialId}/name`, {
            method: 'PATCH',
            body: JSON.stringify({ name })
        });
    }

    async deletePasskey(credentialId) {
        return this._request(`/passkeys/${credentialId}`, { method: 'DELETE' });
    }

    // --- API Key Methods ---
    //
    // createApiKey and revokeApiKey require an active session.
    // A key can never create or revoke other keys.

    async listApiKeys() {
        return this._get('/keys');
    }

    /**
     * @param {{ name: string, grants?: { server?: string[], personal?: string[], projects?: Array<{ projectId: string, scopes: string[] }> }, expiresAt?: number }} options
     */
    async createApiKey(options) {
        return this._post('/keys', options);
    }

    async revokeApiKey(keyId) {
        return this._request(`/keys/${keyId}`, { method: 'DELETE' });
    }

    /**
     * Update a key's name or expiry. Pass `clearExpiry: true` to remove an expiry date.
     * @param {number} keyId
     * @param {{ name?: string, expiresAt?: number, clearExpiry?: boolean }} patch
     */
    async updateApiKey(keyId, patch) {
        return this._request(`/keys/${keyId}`, {
            method: 'PATCH',
            body: JSON.stringify(patch)
        });
    }

    async getScopeTaxonomy() {
        return this._get('/scopes');
    }

    // --- Password Management ---

    async changePassword(newPassword) {
        return this._post('/password/change', { newPassword });
    }

    async requestPasswordReset(identifier) {
        return this._post('/password-reset/request', { identifier });
    }

    async resetPassword(token, newPassword) {
        return this._post('/password-reset/reset', { token, newPassword });
    }

    // --- Identifier Management ---

    async getIdentifiers() {
        return this._get('/identifiers');
    }

    async addIdentifier(type, value) {
        return this._post('/identifiers', { type, value });
    }

    async removeIdentifier(type, value) {
        return this._request(`/identifiers/${encodeURIComponent(type)}/${encodeURIComponent(value)}`, { method: 'DELETE' });
    }

    // --- Session Management ---

    async listSessions() {
        return this._get('/sessions');
    }

    async revokeSession(sessionId) {
        return this._request(`/sessions/${encodeURIComponent(sessionId)}`, { method: 'DELETE' });
    }

    // --- Private Helpers ---

    _clearSession() {
        this.user = null;
        localStorage.removeItem('auth_user');
    }

    _saveLocal() {
        localStorage.setItem('auth_user', JSON.stringify(this.user));
    }

    async _get(path) {
        return this._request(path, { method: 'GET' });
    }

    async _post(path, body) {
        return this._request(path, {
            method: 'POST',
            body: JSON.stringify(body)
        });
    }

    async _request(path, options = {}) {
        const headers = {
            'Content-Type': 'application/json',
            ...(options.headers || {})
        };

        const response = await fetch(`${this.apiBase}${path}`, {
            credentials: 'same-origin',
            ...options,
            headers
        });

        const data = await response.json();

        if (!response.ok) {
            const error = new Error(data.message || data.error || `HTTP Error ${response.status}`);
            error.code = response.status;
            error.type = data.error || 'UNKNOWN_ERROR';
            error.errors = data.errors || [];
            throw error;
        }

        return data;
    }
}
