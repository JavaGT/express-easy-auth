import { AuthClient } from '/auth-sdk.js';

/* ─────────────────────────────────────────────────────────────────────
    Auth Server — Frontend App
    ───────────────────────────────────────────────────────────────────── */

const auth = new AuthClient();

// ─── UTILS ───────────────────────────────────────────────────────────────────

const $ = id => document.getElementById(id);

const toast = (msg, type = 'success') => {
    const el = document.createElement('div');
    el.className = `toast${type !== 'success' ? ` ${type}` : ''}`;
    el.textContent = msg;
    const container = $('toast-container');
    if (container) {
        container.appendChild(el);
        setTimeout(() => el.remove(), 3800);
    } else {
        console.warn('toast-container not found');
    }
};

// ─── THEME MANAGER ───────────────────────────────────────────────────────────

function initTheme() {
    const savedTheme = localStorage.getItem('theme');
    const systemDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    
    if (savedTheme) {
        document.documentElement.setAttribute('data-theme', savedTheme);
    } else if (systemDark) {
        // We don't set the attribute yet so it respects system updates
    }
}

function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme');
    const systemDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    
    let next;
    if (current === 'dark') next = 'light';
    else if (current === 'light') next = 'dark';
    else next = systemDark ? 'light' : 'dark';
    
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    toast(`Switched to ${next} mode`);
}

initTheme();

/**
 * Wrapper for the SDK's reportError to also show a toast
 */
async function reportError(error, context = {}) {
    console.error(`[error] ${error.message || error}`, { error, context });
    auth.reportError(error, context);
    toast(error.message || String(error), 'error');
}

// Global error handling
window.onerror = (message, source, lineno, colno, error) => {
    reportError(error || message, { source, lineno, colno, type: 'global' });
};

window.onunhandledrejection = (event) => {
    reportError(event.reason, { type: 'promise_rejection' });
};

function formatDate(ts) {
    if (!ts) return 'Never';
    return new Date(ts).toLocaleDateString('en-NZ', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// ─── STATE ────────────────────────────────────────────────────────────────────

const state = {
    user: null,
    security: null,
    has2FA: false,
};

// ─── NAVIGATION ──────────────────────────────────────────────────────────────

function showView(id) {
    const authViews = ['view-login', 'view-register', 'view-reset-request', 'view-reset-confirm'];
    const isAuthView = authViews.includes(id);

    $('view-auth').style.display = 'none';
    $('view-dashboard').style.display = 'none';
    $('view-profile').style.display = 'none';
    $('dash-header').style.display = 'none';

    if (isAuthView) {
        $('view-auth').style.display = 'grid';
        document.querySelectorAll('.auth-form').forEach(v => v.classList.remove('active'));
        const view = $(id);
        if (view) view.classList.add('active');
    } else {
        const view = $(id);
        if (view) view.style.display = 'block';
        if (id === 'view-dashboard' || id === 'view-profile') {
            $('dash-header').style.display = 'flex';
        }
    }
}

// ─── CORE LOGIC ───────────────────────────────────────────────────────────────

async function refreshStatus() {
    try {
        const status = await auth.getStatus();
        if (status.authenticated) {
            state.user = status.user;
            state.security = status.security;
            state.has2FA = status.security?.has2FA;
        } else {
            state.user = null;
            state.security = null;
            state.has2FA = false;
        }
    } catch (e) {
        state.user = null;
    }
}

async function loadDashboard() {
    if (!state.user) return showView('view-login');
    showView('view-dashboard');
    
    $('dashboard-user').innerHTML = `
        <div class="security-block wide">
            <div class="security-block-header">
                <div>
                    <h3>Welcome back, ${state.user.username}</h3>
                    <p>${state.user.email}</p>
                </div>
                <div class="security-badge ${state.has2FA ? 'on' : ''}">
                    MFA ${state.has2FA ? 'ENABLED' : 'DISABLED'}
                </div>
            </div>
        </div>
    `;

    await Promise.all([
        loadSessions(),
        loadPasskeys(),
        loadApiKeys(),
        loadSecurityTab()
    ]);
}

async function loadSessions() {
    const list = $('sessions-list');
    list.innerHTML = 'Loading...';
    try {
        const { sessions } = await auth.request('/sessions');
        list.innerHTML = sessions.map(s => `
            <div class="session-item ${s.isCurrent ? 'current' : ''}">
                <div class="sess-info">
                    <div class="sess-label">${s.isCurrent ? 'Current Session' : 'Active Session'}</div>
                    <div class="sess-meta">Started on ${formatDate(s.created_at)}</div>
                </div>
                ${!s.isCurrent ? `<button class="btn-xs btn-danger action-revoke-session" data-id="${s.id}">Revoke</button>` : ''}
            </div>
        `).join('');
    } catch (e) {
        list.innerHTML = 'Failed to load sessions';
    }
}

async function loadPasskeys() {
    const list = $('passkeys-list');
    list.innerHTML = 'Loading...';
    try {
        const { passkeys } = await auth.listPasskeys();
        if (!passkeys.length) {
            list.innerHTML = '<div class="empty-msg">No passkeys found</div>';
        } else {
            list.innerHTML = passkeys.map(pk => `
                <div class="passkey-item">
                    <div class="pk-info">
                        <div class="pk-name">${pk.name || 'Unnamed Device'}</div>
                        <div class="pk-meta">Registered ${formatDate(pk.created_at)}</div>
                    </div>
                    <button class="btn-xs btn-danger action-delete-passkey" data-id="${pk.id}">Remove</button>
                </div>
            `).join('');
        }
        auth.syncPasskeys(passkeys.map(pk => pk.credential_id));
    } catch (e) {
        list.innerHTML = 'Failed to load passkeys';
    }
}

async function loadApiKeys() {
    const list = $('key-list-container');
    list.innerHTML = 'Loading...';
    try {
        const res = await auth.request('/api-keys');
        if (!res.keys || !res.keys.length) {
            list.innerHTML = '<div class="empty-msg">No API keys found</div>';
        } else {
            list.innerHTML = res.keys.map(k => `
                <div class="api-key-item">
                    <div class="pk-info">
                        <div class="pk-name">${k.name}</div>
                        <div class="pk-meta">Permissions: ${k.permissions.join(', ')}</div>
                        <div class="pk-meta">Created: ${formatDate(k.created_at)}</div>
                    </div>
                    <button class="btn-xs btn-danger action-revoke-key" data-id="${k.id}">Revoke</button>
                </div>
            `).join('');
        }
    } catch (e) {
        list.innerHTML = 'Failed to load API keys';
    }
}

async function loadSecurityTab() {
    const has2FA = state.has2FA;
    $('btn-setup-2fa').style.display = has2FA ? 'none' : 'inline-block';
    $('btn-confirm-2fa').style.display = 'none';
    $('btn-confirm-disable-2fa').style.display = has2FA ? 'inline-block' : 'none';
    
    $('totp-code').style.display = 'none';
    $('totp-code').parentElement.style.display = 'none'; 
}

// ─── INITIALIZATION ──────────────────────────────────────────────────────────

async function init() {
    await refreshStatus();
    if (state.user) {
        loadDashboard();
    } else {
        showView('view-login');
    }
}

// Header Navigation
$('go-dashboard').addEventListener('click', () => loadDashboard());
$('go-profile').addEventListener('click', async () => {
    showView('view-profile');
    try {
        const res = await fetch('/api/v1/profile/me');
        const data = await res.json();
        const p = data.profile || {};
        $('prof-display-name').value = p.display_name || '';
        $('prof-bio').value = p.bio || '';
        $('prof-location').value = p.location || '';
        $('prof-website').value = p.website || '';
        
        const prefs = p.preferences || {};
        $('prof-pref-theme').value = prefs.theme || 'system';
        $('prof-pref-notifications').checked = !!prefs.notifications;
    } catch (e) {
        reportError(new Error('Failed to load profile'));
    }
});
$('go-logout').addEventListener('click', async () => {
    await auth.logout();
    state.user = null;
    showView('view-login');
    toast('Logged out');
});

$('theme-toggle').addEventListener('click', () => toggleTheme());
$('theme-toggle-public').addEventListener('click', () => toggleTheme());

// Forms
$('form-login').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = $('login-username').value.trim();
    const password = $('login-password').value;
    const totp = $('login-totp').value.trim();

    try {
        await auth.login(username, password, totp);
        await refreshStatus();
        loadDashboard();
        $('login-totp-field').style.display = 'none';
        $('login-totp').value = '';
    } catch (e) { 
        if (e.code === '2FA_REQUIRED') {
            $('login-totp-field').style.display = 'block';
            $('login-totp').focus();
        }
        reportError(e); 
    }
});

$('form-register').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = $('register-username').value.trim();
    const email = $('register-email').value.trim();
    const password = $('register-password').value;
    try {
        await auth.register(username, email, password);
        toast('Registered! Please login.');
        showView('view-login');
    } catch (e) { reportError(e); }
});

$('btn-passkey-login').addEventListener('click', async () => {
    try {
        const username = $('login-username').value.trim() || undefined;
        await auth.loginWithPasskey(username);
        await refreshStatus();
        loadDashboard();
        toast('Logged in with passkey');
    } catch (e) { if (e.name !== 'NotAllowedError') reportError(e); }
});

$('btn-add-passkey').addEventListener('click', async () => {
    const name = prompt('Name for this passkey:', 'My Device');
    if (!name) return;
    try {
        await auth.registerPasskey(name);
        toast('Passkey registered');
        loadPasskeys();
    } catch (e) { if (e.name !== 'NotAllowedError') reportError(e); }
});

$('btn-create-key').addEventListener('click', async () => {
    const name = $('api-key-name').value.trim();
    if (!name) return toast('Name required', 'error');

    const permsCheckboxes = document.querySelectorAll('input[name="api-perm"]:checked');
    const permissions = Array.from(permsCheckboxes).map(cb => cb.value);

    if (!permissions.length) return toast('At least one permission required', 'error');

    try {
        const res = await auth.request('/api-keys', { method: 'POST', body: { name, permissions } });
        $('test-api-key').value = res.key;
        alert('Your API Key (save it!): ' + res.key);
        $('api-key-name').value = '';
        loadApiKeys();
    } catch (e) { reportError(e); }
});

// API Key Testing
let selectedMethod = 'GET';
document.querySelectorAll('.method-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.method-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        selectedMethod = tab.dataset.method;
    });
});

$('btn-test-key').addEventListener('click', async () => {
    const key = $('test-api-key').value.trim();
    if (!key) return toast('API Key required', 'error');

    const log = $('test-result-log');
    const container = $('test-result-container');
    
    container.style.display = 'block';
    log.textContent = 'Testing...';
    log.className = '';

    try {
        const res = await fetch('/api/public/data', {
            method: selectedMethod,
            headers: { 'X-API-Key': key }
        });

        const data = await res.json();
        log.textContent = JSON.stringify(data, null, 2);
        
        if (res.ok) {
            log.classList.add('test-success');
            toast('API Key valid!');
        } else {
            log.classList.add('test-error');
            toast('Request failed: ' + (data.error?.message ?? data.error ?? 'Unknown error'), 'error');
        }
    } catch (e) {
        log.textContent = 'Connection Error: ' + e.message;
        log.classList.add('test-error');
        toast('Failed to reach API', 'error');
    }
});

$('btn-setup-2fa').addEventListener('click', async () => {
    try {
        const data = await auth.setup2FA();
        $('totp-setup-container').innerHTML = `
            <div class="qr-setup">
                <img src="${data.qrCode}" alt="QR Code">
                <p>Secret: <code>${data.secret}</code></p>
                <p class="form-hint" style="margin-top: 10px;">Scan this QR code and enter the verification code below.</p>
            </div>
        `;
        $('btn-setup-2fa').style.display = 'none';
        $('btn-confirm-2fa').style.display = 'inline-block';
        $('totp-code').style.display = 'block';
        $('totp-code').parentElement.style.display = 'block';
    } catch (e) { reportError(e); }
});

$('btn-confirm-2fa').addEventListener('click', async () => {
    const token = $('totp-code').value.trim();
    try {
        await auth.verify2FASetup(token);
        toast('2FA Enabled');
        $('totp-code').value = '';
        await refreshStatus();
        loadSecurityTab();
    } catch (e) { reportError(e); }
});

$('btn-confirm-disable-2fa').addEventListener('click', async () => {
    const password = prompt('Enter password to disable 2FA:');
    if (!password) return;
    try {
        await auth.disable2FA(password);
        toast('2FA Disabled');
        $('totp-code').value = '';
        await refreshStatus();
        loadSecurityTab();
    } catch (e) { reportError(e); }
});

$('btn-save-profile').addEventListener('click', async (e) => {
    e.preventDefault();
    const body = {
        display_name: $('prof-display-name').value,
        bio: $('prof-bio').value,
        location: $('prof-location').value,
        website: $('prof-website').value,
        preferences: {
            theme: $('prof-pref-theme').value,
            notifications: $('prof-pref-notifications').checked
        }
    };
    try {
        const res = await fetch('/api/v1/profile/me', {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        if (!res.ok) throw new Error('Failed to save profile');
        toast('Profile saved');
    } catch (e) { reportError(e); }
});

$('btn-submit-reset-request').addEventListener('click', async (e) => {
    e.preventDefault();
    const username = $('reset-request-identifier').value.trim();
    try {
        const res = await auth.request('/password-reset/request', { method: 'POST', body: { username } });
        toast('Code: ' + res.token);
        showView('view-reset-confirm');
    } catch (e) { reportError(e); }
});

$('btn-submit-reset-confirm').addEventListener('click', async (e) => {
    e.preventDefault();
    const token = $('reset-token-input').value.trim();
    const newPassword = $('reset-new-password').value;
    try {
        await auth.request('/password-reset/reset', { method: 'POST', body: { token, newPassword } });
        toast('Password reset success');
        showView('view-login');
    } catch (e) { reportError(e); }
});

// ─── EVENT DELEGATION ────────────────────────────────────────────────────────
document.body.addEventListener('click', async (e) => {
    const btn = e.target.closest('button');
    if (!btn) return;

    const id = btn.dataset.id;
    
    if (btn.classList.contains('action-revoke-session')) {
        if (!confirm('Revoke this session?')) return;
        try {
            await auth.request('/sessions/' + id, { method: 'DELETE' });
            toast('Session revoked');
            loadSessions();
        } catch (e) { reportError(e); }
    }

    if (btn.classList.contains('action-delete-passkey')) {
        if (!confirm('Delete this passkey?')) return;
        try {
            await auth.deletePasskey(id);
            toast('Passkey deleted');
            loadPasskeys();
        } catch (e) { reportError(e); }
    }

    if (btn.classList.contains('action-revoke-key')) {
        if (!confirm('Revoke this API key?')) return;
        try {
            await auth.request('/api-keys/' + id, { method: 'DELETE' });
            toast('API key revoked');
            loadApiKeys();
        } catch (e) { reportError(e); }
    }
});

init();

// ─── MAILBOX ───────────────────────────────────────────────────────────────
async function loadMailbox() {
    try {
        const res = await fetch('/api/v1/test/mailbox');
        const data = await res.json();
        const body = $('mailbox-body');
        if (!body) return;

        if (!data.messages || !data.messages.length) {
            body.innerHTML = '<div class="empty-msg">No messages yet...</div>';
            return;
        }

        body.innerHTML = data.messages.map(m => `
            <div class="mailbox-item">
                <div class="msg-header">
                    <span class="msg-type">${m.type}</span>
                    <span class="msg-time">${formatDate(m.timestamp)}</span>
                </div>
                <div class="msg-subject">${m.subject}</div>
                <div class="msg-body">${m.body}</div>
            </div>
        `).join('');
    } catch (e) {
        // Silently fail mailbox
    }
}

setInterval(loadMailbox, 3000);
loadMailbox();
