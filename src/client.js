/**
 * AuthClient - Frontend SDK for Auth Server
 * 
 * This library handles authentication ceremonies, including WebAuthn (Passkeys),
 * TOTP 2FA, and session management.
 */

export class AuthClient {
  /**
   * @param {Object} options
   * @param {string} [options.baseUrl] - The base URL for the API (default: '/api')
   * @param {string} [options.apiVersion] - The API version (default: 'v1')
   */
  constructor(options = {}) {
    this.baseUrl = options.baseUrl || '/api';
    this.apiVersion = options.apiVersion || 'v1';
    this.apiPrefix = `${this.baseUrl}/${this.apiVersion}/auth`;
  }

  // ─── PRIVATE HELPERS ────────────────────────────────────────────────────────

  /**
   * Standard fetch wrapper with error handling
   * @param {string} path - The API path (relative to /auth or /v1)
   * @param {Object} [options] - Fetch options
   */
  /**
   * Standard fetch wrapper with error handling
   * @param {string} path - The API path (relative to /auth or /v1)
   * @param {Object} [options] - Fetch options
   */
  async request(path, options = {}) {
    // Standardize path: remove redundant prefixes if they exist
    let cleanPath = path
      .replace(/^\/?api\/v1\/auth/, '')
      .replace(/^\/?api\/v1/, '')
      .replace(/^\/?auth/, '')
      .replace(/^\//, '');
    
    const url = `${this.apiPrefix}/${cleanPath}`;

    const res = await fetch(url, {
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
      },
      credentials: 'same-origin',
      ...options,
      body: options.body ? JSON.stringify(options.body) : undefined,
    });

    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw Object.assign(new Error(data.error || 'Request failed'), {
        code: data.code,
        status: res.status,
        data,
      });
    }
    return data;
  }

  _base64urlToBuffer(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const pad = base64.length % 4;
    const padded = pad ? base64 + '='.repeat(4 - pad) : base64;
    const binary = window.atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  _bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    const base64 = window.btoa(binary);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  // ─── AUTH METHODS ──────────────────────────────────────────────────────────

  async getStatus() {
    return this.request('/status');
  }

  async login(username, password, totp) {
    return this.request('/login', {
      method: 'POST',
      body: { username, password, totp: totp || undefined },
    });
  }

  async register(username, email, password) {
    return this.request('/register', {
      method: 'POST',
      body: { username, email, password },
    });
  }

  async logout() {
    return this.request('/logout', { method: 'POST' });
  }

  async changePassword(newPassword) {
    return this.request('/password/change', {
      method: 'POST',
      body: { newPassword }
    });
  }

  async changeEmail(newEmail) {
    return this.request('/email/change', {
      method: 'POST',
      body: { newEmail }
    });
  }

  // ─── PASSKEY METHODS ────────────────────────────────────────────────────────

  async registerPasskey(name = 'My Device') {
    if (!window.PublicKeyCredential) throw new Error('WebAuthn not supported');
    const opts = await this.request('/passkeys/register/options', { method: 'POST' });
    const creationOptions = {
      ...opts,
      challenge: this._base64urlToBuffer(opts.challenge),
      user: { ...opts.user, id: this._base64urlToBuffer(opts.user.id) },
      excludeCredentials: (opts.excludeCredentials || []).map(c => ({
        ...c, id: this._base64urlToBuffer(c.id)
      })),
    };
    const cred = await navigator.credentials.create({ publicKey: creationOptions });
    const response = {
      id: cred.id,
      rawId: this._bufferToBase64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: this._bufferToBase64url(cred.response.clientDataJSON),
        attestationObject: this._bufferToBase64url(cred.response.attestationObject),
        transports: cred.response.getTransports ? cred.response.getTransports() : [],
      },
    };
    return this.request('/passkeys/register/verify', {
      method: 'POST',
      body: { response, name },
    });
  }

  async loginWithPasskey(username) {
    if (!window.PublicKeyCredential) throw new Error('WebAuthn not supported');
    const opts = await this.request('/passkeys/authenticate/options', {
      method: 'POST',
      body: { username },
    });
    const requestOptions = {
      ...opts,
      challenge: this._base64urlToBuffer(opts.challenge),
      allowCredentials: (opts.allowCredentials || []).map(c => ({
        ...c, id: this._base64urlToBuffer(c.id)
      })),
    };
    const cred = await navigator.credentials.get({ publicKey: requestOptions });
    const response = {
      id: cred.id,
      rawId: this._bufferToBase64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: this._bufferToBase64url(cred.response.clientDataJSON),
        authenticatorData: this._bufferToBase64url(cred.response.authenticatorData),
        signature: this._bufferToBase64url(cred.response.signature),
        userHandle: cred.response.userHandle ? this._bufferToBase64url(cred.response.userHandle) : null,
      },
    };
    return this.request('/passkeys/authenticate/verify', {
      method: 'POST',
      body: { response },
    });
  }

  async listPasskeys() {
    return this.request('/passkeys');
  }

  async deletePasskey(id) {
    return this.request(`/passkeys/${id}`, { method: 'DELETE' });
  }

  // ─── SESSION METHODS ────────────────────────────────────────────────────────

  async listSessions() {
    return this.request('/sessions');
  }

  async revokeSession(id) {
    return this.request(`/sessions/${id}`, { method: 'DELETE' });
  }

  // ─── API KEY METHODS ────────────────────────────────────────────────────────

  async listApiKeys() {
    return this.request('/api-keys');
  }

  async createApiKey(name, permissions) {
    return this.request('/api-keys', {
      method: 'POST',
      body: { name, permissions }
    });
  }

  async deleteApiKey(id) {
    return this.request(`/api-keys/${id}`, { method: 'DELETE' });
  }

  // ─── 2FA METHODS ────────────────────────────────────────────────────────────

  /**
   * Start 2FA (TOTP) setup
   */
  async setup2FA() {
    return this.request('/2fa/setup', { method: 'POST' });
  }

  /**
   * Verify and enable 2FA
   */
  async verify2FASetup(token) {
    return this.request('/2fa/verify-setup', {
      method: 'POST',
      body: { token },
    });
  }

  /**
   * Disable 2FA
   * @param {string} password - Required for security
   * @param {string} [token] - Optional current code
   */
  async disable2FA(password, token) {
    return this.request('/2fa/disable', {
      method: 'POST',
      body: { password, token },
    });
  }

  // ─── UTIL METHODS ───────────────────────────────────────────────────────────

  /**
   * Report an error to the server's system logs
   */
  async reportError(error, context = {}) {
    const isString = typeof error === 'string';
    const message = isString ? error : (error.message || String(error));
    const stack = isString ? null : (error.stack || null);

    return this.request('/report-error', {
      method: 'POST',
      body: { level: 'error', message, stack, context },
    }).catch(e => console.warn('[Auth SDK] Failed to report error:', e));
  }

  // ─── PASSWORD RESET METHODS ──────────────────────────────────────────────────

  /**
   * Request a password reset token
   * @param {string} identity - Username or email
   */
  async forgotPassword(identity) {
    return this.request('/password-reset/request', {
      method: 'POST',
      body: { username: identity, email: identity }
    });
  }

  /**
   * Reset password using a token
   * @param {string} token - The reset token
   * @param {string} newPassword - The new password
   */
  async resetPassword(token, newPassword) {
    return this.request('/password-reset/reset', {
      method: 'POST',
      body: { token, newPassword }
    });
  }

  /**
   * Sync passkeys with device (conditional UI / Signal API)
   */
  async syncPasskeys(credentialIds) {
    if (!window.PublicKeyCredential || !PublicKeyCredential.signalAllAcceptedCredentials) {
      return { supported: false };
    }
    try {
      const ids = credentialIds.map(id => this._base64urlToBuffer(id));
      await PublicKeyCredential.signalAllAcceptedCredentials({ credentialIds: ids });
      return { supported: true, success: true };
    } catch (err) {
      return { supported: true, success: false, error: err };
    }
  }
}
