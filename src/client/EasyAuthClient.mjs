/**
 * EasyAuthClient - A modern JavaScript client for the Express Easy Auth API.
 * Handles sessions, TOTP, and WebAuthn flows with a clean, throw-based error model.
 */
export class EasyAuthClient {
    constructor(options = {}) {
        if (typeof options === 'string') {
            throw new TypeError(
                `EasyAuthClient expects a configuration object, not a string. ` +
                `Use: new EasyAuthClient({ apiBase: '${options}' })`
            );
        }
        const { apiBase = '/api/v1/auth', sessionToken = null } = options;
        this.apiBase = apiBase;
        this.sessionToken = sessionToken || localStorage.getItem('auth_session_token');
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
        this._setSession(result);
        return result;
    }

    async logout() {
        try {
            if (this.sessionToken) {
                await this._post('/logout', {});
            }
        } finally {
            this._clearSession();
        }
    }

    async me() {
        const result = await this._get('/me');
        this.user = result.user;
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

    async verifyTotp(code, secret) {
        return this._post('/totp/verify', { code, secret });
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
        
        const result = await this._post('/passkeys/login/verify', {
            response: assertion,
            tempId: options.tempId
        });

        this._setSession(result);
        return result;
    }

    async reauthWithPasskey(SimpleWebAuthnBrowser) {
        const options = await this._post('/passkeys/verify/options', {});
        const assertion = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON: options });
        
        const result = await this._post('/passkeys/verify/verify', assertion);
        this.lastAuthenticatedAt = result.lastAuthenticatedAt;
        this._saveLocal();
        return result;
    }

    async getPasskeys() {
        return this._get('/passkeys');
    }

    async renamePasskey(credentialId, name) {
        return this._request(`/passkeys/${credentialId}/name`, {
            method: 'PATCH',
            body: JSON.stringify({ name })
        });
    }

    async deletePasskey(credentialId) {
        return this._request(`/passkeys/${credentialId}`, { method: 'DELETE' });
    }

    // --- API Key Methods ---

    async getApiKeys() {
        return this._get('/keys');
    }

    async createApiKey(scopes, expiresAt) {
        return this._post('/keys', { scopes, expiresAt });
    }

    async revokeApiKey(key) {
        return this._request(`/keys/${key}`, { method: 'DELETE' });
    }

    async updateApiKeyScopes(key, scopes) {
        return this._request(`/keys/${key}/scopes`, {
            method: 'PATCH',
            body: JSON.stringify({ scopes })
        });
    }

    // --- Private Helpers ---

    _setSession(authData) {
        this.sessionToken = authData.sessionToken;
        this.user = authData.user;
        this.lastAuthenticatedAt = authData.lastAuthenticatedAt;
        this._saveLocal();
    }

    _clearSession() {
        this.sessionToken = null;
        this.user = null;
        localStorage.removeItem('auth_session_token');
        localStorage.removeItem('auth_user');
    }

    _saveLocal() {
        localStorage.setItem('auth_session_token', this.sessionToken || '');
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

        if (this.sessionToken) {
            headers['Authorization'] = `Bearer ${this.sessionToken}`;
        }

        const response = await fetch(`${this.apiBase}${path}`, {
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
