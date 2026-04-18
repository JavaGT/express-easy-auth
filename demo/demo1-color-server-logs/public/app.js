import { EasyAuthClient } from '/api/v1/auth/client.js';

// Constants
const API_BASE = '/api/v1';
const auth = new EasyAuthClient({ apiBase: '/api/v1/auth' });

let stepUpPendingAction = null;
let currentTotpSecret = null;

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
    if (auth.sessionToken) {
        await checkAuth();
    }
    setupForms();
    setupColorPickers();
});

// Expose functions to HTML onclick handlers (since this is now a module)
window.switchView = switchView;
window.switchAuthTab = switchAuthTab;
window.switchTab = switchTab;
window.loginWithPasskey = loginWithPasskey;
window.registerPasskey = registerPasskey;
window.sendLog = sendLog;
window.confirmStepUp = confirmStepUp;
window.reauthWithPasskey = reauthWithPasskey;
window.closeReauth = closeReauth;
window.logout = logout;
window.deleteAccount = deleteAccount;
window.createApiKey = createApiKey;
window.revokeApiKey = revokeApiKey;
window.sendSandboxLog = sendSandboxLog;
window.showTotpSetup = showTotpSetup;
window.closeTotpModal = closeTotpModal;
window.verifyTotpSetup = verifyTotpSetup;
window.disableTotp = disableTotp;
window.loadPasskeys = loadPasskeys;
window.removePasskey = removePasskey;
window.renamePasskey = renamePasskey;
window.changeApiKeyScopes = changeApiKeyScopes;

function setupForms() {
    document.getElementById('login-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('login-email').value;
        const password = document.getElementById('login-password').value;
        const totp = document.getElementById('login-totp').value;
        await login(email, password, totp);
    });

    document.getElementById('register-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('reg-email').value;
        const password = document.getElementById('reg-password').value;
        const displayName = document.getElementById('reg-name').value;
        await register(email, password, displayName);
    });
}

function setupColorPickers() {
    const picker = document.getElementById('scope-picker');
    if (!picker) return;

    picker.querySelectorAll('.color-option').forEach(opt => {
        opt.onclick = () => {
            const scope = opt.dataset.scope;
            if (scope === 'all') {
                picker.querySelectorAll('.color-option').forEach(o => o.classList.remove('selected'));
                opt.classList.add('selected');
            } else {
                picker.querySelector('[data-scope="all"]').classList.remove('selected');
                opt.classList.toggle('selected');
                
                // If nothing selected, select 'all'
                if (!picker.querySelector('.color-option.selected')) {
                    picker.querySelector('[data-scope="all"]').classList.add('selected');
                }
            }
        };
    });
}

// UI Controllers
function switchView(view) {
    document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
    document.getElementById(`view-${view}`).classList.remove('hidden');
    
    if (view === 'dashboard') {
        document.getElementById('user-display').classList.remove('hidden');
        updateSecuritySettings();
        loadPasskeys();
    } else {
        document.getElementById('user-display').classList.add('hidden');
    }
}

async function updateSecuritySettings() {
    const status = await auth.getTotpStatus();
    const setupBtn = document.getElementById('btn-totp-setup');
    const disableBtn = document.getElementById('btn-totp-disable');
    
    if (status.enabled) {
        setupBtn.classList.add('hidden');
        disableBtn.classList.remove('hidden');
    } else {
        setupBtn.classList.remove('hidden');
        disableBtn.classList.add('hidden');
    }
}

function switchAuthTab(tab) {
    document.querySelector('#view-auth .tabs .active').classList.remove('active');
    document.querySelector(`#view-auth .tabs .tab:nth-child(${tab === 'login' ? 1 : 2})`).classList.add('active');
    
    if (tab === 'login') {
        document.getElementById('login-form').classList.remove('hidden');
        document.getElementById('register-form').classList.add('hidden');
    } else {
        document.getElementById('login-form').classList.add('hidden');
        document.getElementById('register-form').classList.remove('hidden');
    }
}

function switchTab(tab) {
    document.querySelector('#view-dashboard > .tabs .active').classList.remove('active');
    event.target.classList.add('active');
    
    document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
    document.getElementById(`tab-${tab}`).classList.remove('hidden');

    if (tab === 'dev') loadApiKeys();
    if (tab === 'security') {
        updateSecuritySettings();
        loadPasskeys();
    }
}

function showStatus(msg, isError = false) {
    const status = document.getElementById('status');
    status.innerText = msg;
    status.classList.remove('hidden');
    status.className = isError ? 'error' : '';
    status.style.borderLeftColor = isError ? 'var(--red)' : 'var(--green)';
    setTimeout(() => status.classList.add('hidden'), 3000);
}

// Authentication Logic
async function login(email, password, totp) {
    try {
        const result = await auth.login(email, password, totp);
        onLoginSuccess(result);
        showStatus('Logged in successfully!');
    } catch (err) {
        const isTotpRequired = err.type === 'TOTP_CODE_REQUIRED' || 
                               (err.type === 'VALIDATION_FAILED' && err.errors?.some(e => e.type === 'TOTP_CODE_REQUIRED'));

        if (isTotpRequired) {
            document.getElementById('login-totp-group').classList.remove('hidden');
            document.getElementById('login-totp').focus();
            showStatus('TOTP code required', true);
            return;
        }

        showStatus(err.message || err.type, true);
    }
}

async function register(email, password, displayName) {
    try {
        const result = await auth.register(email, password, displayName);
        if (!result.success) throw new Error(result.message || result.error);
        
        showStatus('Registered! Now please log in.');
        switchAuthTab('login');
    } catch (err) {
        showStatus(err.message, true);
    }
}

function onLoginSuccess(data) {
    document.getElementById('display-name').innerText = auth.user.display_name || auth.user.email;
    updateFreshness(data.lastAuthenticatedAt || Date.now());
    switchView('dashboard');
}

function updateFreshness(timestamp) {
    const badge = document.getElementById('fresh-badge');
    const elapsed = Date.now() - timestamp;
    const isFresh = elapsed < (5 * 60 * 1000);
    
    badge.innerText = isFresh ? 'Fresh Session' : 'Stale Session';
    badge.className = `badge ${isFresh ? 'badge-fresh' : 'badge-stale'}`;
}

async function checkAuth() {
    try {
        const result = await auth.me();
        if (!result.success) throw new Error(result.error);
        
        onLoginSuccess(result);
    } catch (err) {
        logout();
    }
}

async function logout() {
    try {
        await auth.logout();
    } catch (err) {
        console.warn('Server-side logout failed (likely session already gone):', err);
    }
    switchView('auth');
}

// TOTP Logic
async function showTotpSetup() {
    const result = await auth.setupTotp();
    if (result.success) {
        currentTotpSecret = result.secret;
        const container = document.getElementById('totp-qr-container');
        container.innerHTML = `<img src="${result.qrCode}" alt="TOTP QR Code" style="width: 200px; height: 200px;">`;
        document.getElementById('totp-modal').classList.remove('hidden');
    } else {
        showStatus('Failed to start TOTP setup: ' + result.message, true);
    }
}

function closeTotpModal() {
    document.getElementById('totp-modal').classList.add('hidden');
    currentTotpSecret = null;
}

async function verifyTotpSetup() {
    const code = document.getElementById('totp-verify-code').value;
    if (!code) return;

    const result = await auth.verifyTotp(code, currentTotpSecret);
    if (result.success) {
        showStatus('TOTP enabled!');
        closeTotpModal();
        updateSecuritySettings();
    } else {
        showStatus('Verification failed: ' + result.message, true);
    }
}

async function disableTotp() {
    if (!confirm('Are you sure you want to disable TOTP security?')) return;
    const result = await auth.disableTotp();
    if (result.success) {
        showStatus('TOTP disabled');
        updateSecuritySettings();
    } else {
        showStatus('Failed to disable TOTP: ' + result.message, true);
    }
}

// Passkeys Logic
async function registerPasskey() {
    const name = prompt('Give this passkey a name (e.g. "Work Laptop", "Yubikey"):');
    if (name === null) return; // Cancelled

    try {
        const result = await auth.registerPasskey(SimpleWebAuthnBrowser, name);
        if (result.verified) {
            showStatus('Passkey registered!');
            loadPasskeys();
        } else {
            throw new Error(result.error || 'Verification failed');
        }
    } catch (err) {
        showStatus('Passkey registration failed: ' + err.message, true);
    }
}

async function loadPasskeys() {
    try {
        const passkeys = await auth.getPasskeys();
        const list = document.getElementById('passkeys-list');
        list.innerHTML = passkeys.map(p => `
            <div class="api-key-item" style="padding: 0.5rem; border: 1px solid var(--border); border-radius: 4px; margin-bottom: 0.5rem; display: flex; justify-content: space-between; align-items: center;">
                <div style="display: flex; flex-direction: column; overflow: hidden;">
                    <span style="font-weight: 600; font-size: 0.9rem;">${p.name || 'Unnamed Passkey'}</span>
                    <span style="font-family: monospace; font-size: 0.7rem; color: var(--text-dim); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 200px;">
                        ID: ${p.credential_id.substring(0, 16)}...
                    </span>
                </div>
                <div style="display: flex; gap: 0.5rem;">
                    <button class="secondary" style="width: auto; padding: 0.2rem 0.5rem; font-size: 0.7rem;" onclick="renamePasskey('${p.credential_id}')">Rename</button>
                    <button class="danger" style="width: auto; padding: 0.2rem 0.5rem; font-size: 0.7rem;" onclick="removePasskey('${p.credential_id}')">Remove</button>
                </div>
            </div>
        `).join('') || '<p style="color: var(--text-dim); font-size: 0.8rem;">No passkeys registered.</p>';
    } catch (err) {
        console.error('Failed to load passkeys:', err);
    }
}

async function renamePasskey(credentialId) {
    const newName = prompt('Enter a new name for this passkey:');
    if (!newName) return;

    try {
        const result = await auth.renamePasskey(credentialId, newName);
        if (result.success) {
            showStatus('Passkey renamed');
            loadPasskeys();
        } else {
            throw new Error(result.message || result.error);
        }
    } catch (err) {
        showStatus('Failed to rename passkey: ' + err.message, true);
    }
}

async function removePasskey(credentialId) {
    if (!confirm('Are you sure you want to remove this passkey?')) return;
    try {
        const result = await auth.deletePasskey(credentialId);
        if (result.success) {
            showStatus('Passkey removed');
            loadPasskeys();
        } else {
            throw new Error(result.message || result.error);
        }
    } catch (err) {
        showStatus('Failed to remove passkey: ' + err.message, true);
    }
}

async function loginWithPasskey() {
    try {
        const result = await auth.loginWithPasskey(SimpleWebAuthnBrowser);
        if (result.success) {
            onLoginSuccess(result);
            showStatus('Logged in with Passkey!');
        } else {
            throw new Error(result.message || result.error);
        }
    } catch (err) {
        showStatus('Passkey login failed: ' + err.message, true);
    }
}

// Logging Demo
async function sendLog(color) {
    const message = document.getElementById('log-message').value;
    if (!message) return;

    try {
        const response = await fetch(`${API_BASE}/logs/server`, {
            method: 'POST',
            headers: { 
                'Authorization': `Bearer ${auth.sessionToken}`,
                'Content-Type': 'application/json' 
            },
            body: JSON.stringify({ message, color })
        });
        const data = await response.json();
        
        if (data.error === 'STEP_UP_REQUIRED') {
            promptStepUp(() => sendLog(color));
            return;
        }

        if (data.error) throw new Error(data.message || data.error);
        showStatus(`Log sent (${color})`);
    } catch (err) {
        showStatus(err.message, true);
    }
}

// Step-Up Prompt
function promptStepUp(onSuccess) {
    stepUpPendingAction = onSuccess;
    document.getElementById('reauth-modal').classList.remove('hidden');
    
    // Check if TOTP is required for re-auth
    auth.getTotpStatus().then(status => {
        if (status.enabled) {
            document.getElementById('reauth-totp-group').classList.remove('hidden');
        } else {
            document.getElementById('reauth-totp-group').classList.add('hidden');
        }
    });
}

function closeReauth() {
    document.getElementById('reauth-modal').classList.add('hidden');
    stepUpPendingAction = null;
}

async function confirmStepUp() {
    const password = document.getElementById('reauth-password').value;
    const totp = document.getElementById('reauth-totp').value;
    if (!password) return;

    try {
        const result = await auth.login(auth.user.email, password, totp);
        if (!result.success) throw new Error(result.message || result.error);

        onLoginSuccess(result);
        closeReauth();
        if (stepUpPendingAction) stepUpPendingAction();
    } catch (err) {
        showStatus('Verification failed: ' + err.message, true);
    }
}

async function reauthWithPasskey() {
    try {
        const result = await auth.reauthWithPasskey(SimpleWebAuthnBrowser);
        if (!result.success) throw new Error(result.message || result.error);

        updateFreshness(result.lastAuthenticatedAt);
        showStatus('Session refreshed with Passkey!');
        closeReauth();
        if (stepUpPendingAction) stepUpPendingAction();
    } catch (err) {
        showStatus('Passkey verification failed: ' + err.message, true);
    }
}

// Developer (API Keys)
async function loadApiKeys() {
    const keys = await auth.getApiKeys();
    const list = document.getElementById('api-keys-list');
    
    list.innerHTML = keys.map(k => {
        const scopes = k.scopes ? JSON.parse(k.scopes) : [];
        const scopeBadges = scopes.map(s => {
            const color = s.split(':')[1] || 'all';
            return `<span class="scope-badge scope-${color}">${s}</span>`;
        }).join('');

        return `
            <div class="api-key-item" style="flex-direction: column; align-items: flex-start; gap: 0.75rem;">
                <div style="display: flex; justify-content: space-between; width: 100%; align-items: center;">
                    <span style="font-size: 0.8rem; font-weight: bold;">${k.api_key}</span>
                    <div style="display: flex; gap: 0.5rem;">
                        <button class="secondary" style="width: auto; padding: 0.2rem 0.5rem; font-size: 0.7rem;" onclick="changeApiKeyScopes('${k.api_key}')">Edit Scopes</button>
                        <button class="danger" style="width: auto; padding: 0.2rem 0.5rem; font-size: 0.7rem;" onclick="revokeApiKey('${k.api_key}')">Revoke</button>
                    </div>
                </div>
                <div style="display: flex; flex-wrap: wrap; gap: 0.2rem;">
                    ${scopeBadges}
                </div>
            </div>
        `;
    }).join('') || '<p style="color: var(--text-dim); font-size: 0.8rem;">No active keys.</p>';
}

async function createApiKey() {
    const picker = document.getElementById('scope-picker');
    const selectedScopes = Array.from(picker.querySelectorAll('.color-option.selected')).map(opt => opt.dataset.scope);
    
    const result = await auth.createApiKey(selectedScopes);
    if (result.success) {
        showStatus('New API Key generated!');
        loadApiKeys();
    } else {
        showStatus('Failed to create API key: ' + result.message, true);
    }
}

async function changeApiKeyScopes(key) {
    const scopesStr = prompt('Enter comma-separated scopes (e.g. "log:red,log:blue" or "all"):');
    if (scopesStr === null) return;
    
    const scopes = scopesStr.split(',').map(s => s.trim()).filter(s => s);
    const result = await auth.updateApiKeyScopes(key, scopes);
    
    if (result.success) {
        showStatus('Key scopes updated!');
        loadApiKeys();
    } else {
        showStatus('Update failed: ' + result.message, true);
    }
}

async function revokeApiKey(key) {
    const result = await auth.revokeApiKey(key);
    if (result.success) {
        loadApiKeys();
    } else {
        showStatus('Failed to revoke API key: ' + result.message, true);
    }
}

// Public Sandbox
async function sendSandboxLog(color = 'default') {
    const key = document.getElementById('sandbox-key').value;
    const message = document.getElementById('sandbox-message').value;
    if (!key || !message) {
        showStatus('Please enter an API key and message', true);
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/logs/server`, {
            method: 'POST',
            headers: { 
                'x-api-key': key,
                'Content-Type': 'application/json' 
            },
            body: JSON.stringify({ message, color })
        });
        const data = await response.json();
        if (data.error) throw new Error(data.message || data.error);
        showStatus('Sandbox log executed successfully!');
    } catch (err) {
        showStatus('Sandbox error: ' + err.message, true);
    }
}

// Account Deletion
async function deleteAccount() {
    if (!confirm('EXTREMELY DANGEROUS: Are you sure you want to delete your entire account?')) return;
    
    try {
        await auth.deleteAccount();
        showStatus('Account deleted. Goodbye.');
        await logout();
    } catch (err) {
        if (err.type === 'STEP_UP_REQUIRED') {
            promptStepUp(() => deleteAccount());
            return;
        }
        showStatus(err.message || err.type, true);
    }
}
