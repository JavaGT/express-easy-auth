/* ─────────────────────────────────────────────────────────────────────
   Auth Server — Frontend App
   ───────────────────────────────────────────────────────────────────── */

// --- DEBUGGING LOGS ---
// Print cookies and storage for debugging
console.debug('[debug] Document cookies:', document.cookie);
try {
  console.debug('[debug] sessionStorage:', JSON.stringify(sessionStorage));
  console.debug('[debug] localStorage:', JSON.stringify(localStorage));
} catch (e) {
  console.warn('[debug] Could not access storage:', e);
}
console.debug('[debug] User agent:', navigator.userAgent);
['view-auth', 'view-dashboard', 'loading-screen'].forEach(id => {
  const el = document.getElementById(id);
  console.debug(`[debug] Element #${id}:`, el ? 'present' : 'MISSING');
});
document.querySelectorAll('.view').forEach(v => {
  console.debug('[debug] .view:', v.id, v.classList.value);
});
// (Removed erroneous debug lines using 'id' outside of any function)
  // --- END DEBUGGING LOGS ---

// ─── UTILS ───────────────────────────────────────────────────────────────────

const $ = id => document.getElementById(id);

// 1. Toast Notification Helper
// Used throughout the app to give visual feedback for auth events.
const toast = (msg, type = 'success') => {
  const el = document.createElement('div');
  el.className = `toast${type !== 'success' ? ` ${type}` : ''}`;
  el.textContent = msg;
  $('toast-container').appendChild(el);
  setTimeout(() => el.remove(), 3800);
};

// 2. API Request Wrapper
// Centralizes request logic (headers, credentials) for talking to the library.
async function api(path, options = {}) {
  const res = await fetch('/api' + path, {
    // 'same-origin' is critical to ensure cookies (session) are sent automatically
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    credentials: 'same-origin', 
    ...options,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const data = await res.json();
  if (!res.ok) throw Object.assign(new Error(data.error || 'Request failed'), { code: data.code, status: res.status });
  return data;
}

/**
 * Report an error to the server and show a toast to the user.
 */
async function reportError(error, context = {}) {
  const isString = typeof error === 'string';
  const message = isString ? error : (error.message || String(error));
  const stack = isString ? null : (error.stack || null);
  
  console.error(`[error] ${message}`, { error, context });

  // Reporting to server (fire-and-forget)
  fetch('/api/auth/report-error', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ level: 'error', message, stack, context }),
  }).catch(e => console.warn('[critical] Failed to report error to server:', e));

  // Show user feedback
  toast(message, 'error');
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

// Base64url helpers for WebAuthn
function bufferToBase64url(buf) {
  const bytes = new Uint8Array(buf);
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function base64urlToBuffer(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

/**
 * Synchronize the browser's credential storage with the server's list of valid passkeys.
 * Uses the WebAuthn Signal API (if available) to remove stale/deleted credentials.
 */
async function syncPasskeysWithDevice(credentialIds) {
  if (!window.PublicKeyCredential || !PublicKeyCredential.signalAllAcceptedCredentials) {
    return { supported: false }; // Silently fail for older browsers
  }

  try {
    const ids = credentialIds.map(id => base64urlToBuffer(id));
    await PublicKeyCredential.signalAllAcceptedCredentials({
      credentialIds: ids
    });
    return { supported: true, success: true };
  } catch (err) {
    console.warn('[passkey] Signal API error:', err);
    return { supported: true, success: false };
  }
}

// Encode all credential fields to/from ArrayBuffer <-> base64url
function preparePublicKeyCredentialCreationOptions(options) {
  return {
    ...options,
    challenge: base64urlToBuffer(options.challenge),
    user: { ...options.user, id: base64urlToBuffer(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map(c => ({
      ...c, id: base64urlToBuffer(c.id)
    })),
  };
}

function preparePublicKeyCredentialRequestOptions(options) {
  return {
    ...options,
    challenge: base64urlToBuffer(options.challenge),
    allowCredentials: (options.allowCredentials || []).map(c => ({
      ...c, id: base64urlToBuffer(c.id)
    })),
  };
}

function serializeRegistrationCredential(cred) {
  return {
    id: cred.id,
    rawId: bufferToBase64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufferToBase64url(cred.response.clientDataJSON),
      attestationObject: bufferToBase64url(cred.response.attestationObject),
      transports: cred.response.getTransports ? cred.response.getTransports() : [],
    },
  };
}

function serializeAuthenticationCredential(cred) {
  return {
    id: cred.id,
    rawId: bufferToBase64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufferToBase64url(cred.response.clientDataJSON),
      authenticatorData: bufferToBase64url(cred.response.authenticatorData),
      signature: bufferToBase64url(cred.response.signature),
      userHandle: cred.response.userHandle ? bufferToBase64url(cred.response.userHandle) : null,
    },
  };
}

// ─── STATE ────────────────────────────────────────────────────────────────────

const state = {
  user: null,
  security: null,
  freshAuth: null,
  freshAuthTimer: null,
  has2FA: false,
  isRecovered: false,
  force2FA: false,
  settings: {},
  pendingUsername: null,
};

// ─── ROUTING / VIEWS ─────────────────────────────────────────────────────────

function showView(id) {
  document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
  const el = $(id);
  if (el) {
    el.classList.remove('hidden');
    console.debug(`[debug] Showing view: ${id}`);
  } else {
    console.warn(`[debug] View element not found: ${id}`);
  }
}

function showAuthForm(id) {
  console.debug('[debug] showAuthForm called with:', id);
  document.querySelectorAll('.auth-form').forEach(f => f.classList.remove('active'));
  const el = $(id);
  if (el) {
    el.classList.add('active');
    console.debug(`[debug] Showing auth form: ${id}`);
  } else {
    console.warn(`[debug] Auth form element not found: ${id}`);
  }
  // --- END DEBUGGING LOGS ---
}

function resetUI() {
  clearFreshAuthTimer();
  state.user = null;
  state.security = null;
  state.freshAuth = null;
  state.has2FA = false;

  // Clear sensitive DOM contents
  $('passkeys-list').innerHTML = '';
  $('sessions-list').innerHTML = '';
  $('prof-display-name').value = '';
  $('prof-bio').value = '';
  $('prof-location').value = '';
  $('prof-website').value = '';
  $('bio-len').textContent = '0';

  // Reset tabs
  showTab('overview');
}

function showTab(name) {
  console.debug('[debug] showTab called with:', name);
  // Enforcement: Only allow security tab if 2FA is forced but not yet setup
  if (state.force2FA && !state.has2FA && name !== 'security') {
    toast('Security setup required by administrator', 'error');
    return;
  }

  document.querySelectorAll('.dash-tab').forEach(t => t.classList.add('hidden'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  const tab = document.getElementById(`tab-${name}`);
  if (tab) {
    tab.classList.remove('hidden');
    console.debug(`[debug] Showing tab: tab-${name}`);
  } else {
    console.warn(`[debug] Tab element not found: tab-${name}`);
  }
  const navBtn = document.querySelector(`.nav-btn[data-tab="${name}"]`);
  if (navBtn) navBtn.classList.add('active');
}

// ─── INIT ─────────────────────────────────────────────────────────────────────

// 4. Initializing the App
// On every page load, we check the user's status via /api/auth/status.
// This determines if we show the login screen or the dashboard.
async function init() {
  // Check for URL parameters (from traditional form redirects)
  const params = new URLSearchParams(window.location.search);
  const error = params.get('error');
  const requires2FA = params.get('requires2FA');

  if (error) {
    toast(error, 'error');
    // Clean up URL
    window.history.replaceState({}, document.title, window.location.pathname);
  }

  try {
    console.debug('[debug] About to call api(/auth/status)');
    const status = await api('/auth/status');
    console.debug('[debug] /auth/status response:', status);
    if (status.authenticated) {
      console.debug('[debug] Authenticated user:', status.user);
      console.debug('[debug] State before dashboard:', JSON.parse(JSON.stringify(state)));
      state.user = status.user;
      state.security = status.security;
      state.freshAuth = status.freshAuth;
      state.has2FA = status.security?.has2FA;
      state.isRecovered = status.isRecovered;
      state.settings = status.settings || {};
      state.force2FA = state.settings.force_2fa === 'true';
      state.mfaRequired = status.user?.mfaRequired;

      updateBranding();
      console.debug('[debug] Showing dashboard...');
      showDashboard();
    } else {
      console.debug('[debug] Not authenticated, showing auth view.');
      console.debug('[debug] State before auth view:', JSON.parse(JSON.stringify(state)));
      showView('view-auth');
      if (requires2FA) {
        console.debug('[debug] Showing 2FA form.');
        showAuthForm('form-2fa');
      }
    }
  } catch (e) {
    console.error('[debug] Error fetching /auth/status:', e);
    showView('view-auth');
  } finally {
    console.debug('[debug] Hiding loading screen.');
    const ls = $('loading-screen');
    ls.classList.add('fade-out');
    setTimeout(() => ls.remove(), 400);
  }
}

function updateBranding() {
  const s = state.settings;
  const siteName = s.site_name || 'AuthServer';
  const adminEmail = s.site_admin_emails || 'admin@example.com';

  document.querySelectorAll('#display-site-name, #display-site-name-nav').forEach(el => {
    el.textContent = siteName;
  });
  
  const emailEl = $('display-admin-email-recovery'); // Check if ID matches
  const emailElRecovery = $('display-admin-email');
  if (emailElRecovery) {
    // Format list for recovery view
    const emails = adminEmail.split(',').map(e => e.trim()).filter(Boolean);
    if (emails.length > 1) {
      emailElRecovery.innerHTML = emails.join(', ');
    } else {
      emailElRecovery.textContent = emails[0] || 'admin@example.com';
    }
  }
  
  document.title = siteName;

  // Registration UI handling
  const regEnabled = s.auth_registration_enabled === 'true';
  const goReg = $('go-register');
  if (goReg) {
    if (!regEnabled) {
      goReg.style.pointerEvents = 'none';
      goReg.style.opacity = '0.5';
      goReg.textContent = 'Registration disabled';
    } else {
      goReg.style.pointerEvents = '';
      goReg.style.opacity = '';
      goReg.textContent = 'Create one';
    }
  }
}

// ─── DASHBOARD ────────────────────────────────────────────────────────────────

async function showDashboard() {
  console.debug('[debug] showDashboard() called');
  // Force show dashboard view
  const dashView = document.getElementById('view-dashboard');
  if (dashView) {
    dashView.classList.remove('hidden');
    console.debug('[debug] Removed .hidden from #view-dashboard');
  } else {
    console.warn('[debug] #view-dashboard not found');
  }
  $('dash-username').textContent = '@' + state.user.username;
  updateOverview();
  await loadProfile();
  setupFreshAuthBanner();

  // Handle Enforcement
  const mfaEnforced = state.force2FA || state.mfaRequired;
  if (mfaEnforced && !state.has2FA) {
    showTab('security');
    toast(state.mfaRequired ? 'Account security setup required' : 'MFA is mandatory for all accounts', 'warning');
  } else {
    showTab('overview');
  }

  // Handle Recovery Notice
  if (state.isRecovered) {
    $('recovered-notice').classList.remove('hidden');
  } else {
    $('recovered-notice').classList.add('hidden');
  }

  // Update Global Settings (Demo Admin)
  const s = state.settings;
  if ($('cfg-site_name')) {
    $('cfg-site_name').value = s.site_name || '';
    $('cfg-site_admin_emails').value = s.site_admin_emails || '';
    $('cfg-auth_registration_enabled').checked = s.auth_registration_enabled === 'true';
    $('cfg-auth_mfa_force_all').checked = s.auth_mfa_force_all === 'true';
    $('cfg-auth_mfa_force_new_users').checked = s.auth_mfa_force_new_users === 'true';
    $('cfg-password_min_length').value = s.password_min_length || 8;
    $('cfg-session_fresh_auth_mins').value = s.session_fresh_auth_mins || 5;
    $('cfg-session_duration_days').value = s.session_duration_days || 7;
    $('cfg-lockout_max_attempts').value = s.lockout_max_attempts || 5;
    $('cfg-lockout_duration_mins').value = s.lockout_duration_mins || 15;
  }
  console.debug('[debug] showDashboard() complete');
}

function updateOverview() {
  $('ov-username').textContent = state.user?.username || '—';
  $('ov-email').textContent = state.user?.email || '—';
  $('ov-method').textContent = state.security?.loginMethod || '—';
  $('ov-2fa').textContent = state.security?.has2FA ? '✓ Enabled' : '✗ Disabled';
  $('ov-passkeys').textContent = state.security?.passkeyCount ?? 0;
}

async function loadProfile() {
  try {
    const data = await api('/user/me');
    const p = data.profile || {};
    $('prof-display-name').value = p.display_name || '';
    $('prof-bio').value = p.bio || '';
    $('prof-location').value = p.location || '';
    $('prof-website').value = p.website || '';
    $('bio-len').textContent = (p.bio || '').length;
  } catch (e) {/* silent */ }
}

// Native form submission handles Login, Register, and 2FA Verify to support password managers.
// Event listeners for these are removed to allow default browser behavior.

$('btn-logout').addEventListener('click', async () => {
  try {
    await api('/auth/logout', { method: 'POST' });
    resetUI();
    showView('view-auth');
    showAuthForm('form-login');
  } catch (e) {
    reportError('Logout failed');
  }
});

$('go-register').addEventListener('click', e => { e.preventDefault(); showAuthForm('form-register'); });
$('go-login').addEventListener('click', e => { e.preventDefault(); showAuthForm('form-login'); });
$('go-back-login').addEventListener('click', e => { e.preventDefault(); showAuthForm('form-login'); });

$('go-recovery-login').addEventListener('click', e => { 
  e.preventDefault(); 
  $('recovery-username-field').classList.remove('hidden');
  showAuthForm('form-recovery'); 
});

$('go-recovery-2fa').addEventListener('click', e => { 
  e.preventDefault(); 
  $('recovery-username-field').classList.add('hidden'); // Hide username if coming from 2FA (it's in session)
  showAuthForm('form-recovery'); 
});

$('go-login-from-recovery').addEventListener('click', e => {
  e.preventDefault();
  showAuthForm('form-login');
});

$('btn-recover').addEventListener('click', async (e) => {
  e.preventDefault();
  const username = $('recovery-username').value.trim();
  const code = $('recovery-code').value.trim();
  if (!code) return toast('Recovery code required', 'error');

  try {
    await api('/auth/login/recovery', { method: 'POST', body: { username, code } });
    toast('Account recovered! Welcome back.');
    await refreshStatus();
    showDashboard();
  } catch (err) {
    reportError(err);
  }
});

// Enter key support
['login-username', 'login-password'].forEach(id => {
  $(id).addEventListener('keydown', e => { if (e.key === 'Enter') $('btn-login').click(); });
});
$('totp-code').addEventListener('keydown', e => { if (e.key === 'Enter') $('btn-2fa-verify').click(); });

// ─── PASSKEY LOGIN ────────────────────────────────────────────────────────────

// ─── PASSKEY AUTHENTICATION ───────────────────────────────────────────────────

// 5. Passkey Authentication Flow
// Uses the 2-step ceremony: 
// 1. Get options from server -> 2. Verify response on server.
async function verifyPasskey(options = {}) {
  if (!window.PublicKeyCredential) throw new Error('Passkeys not supported in this browser');

  const username = options.username || (state.user?.username) || undefined;
  const opts = await api('/passkeys/authenticate/options', {
    method: 'POST',
    body: { username },
  });

  console.debug('[passkey] Auth options:', opts);
  const prepared = preparePublicKeyCredentialRequestOptions(opts);
  const cred = await navigator.credentials.get({ publicKey: prepared });
  console.debug('[passkey] Auth credential:', cred);
  const serialized = serializeAuthenticationCredential(cred);

  const result = await api('/passkeys/authenticate/verify', {
    method: 'POST',
    body: { response: serialized },
  });

  state.user = result.user;
  await refreshStatus();
  return result;
}

$('btn-passkey-login').addEventListener('click', async () => {
  try {
    const username = $('login-username').value.trim() || undefined;
    await verifyPasskey({ username });
    showDashboard();
    toast('Signed in with passkey!');
  } catch (e) {
    if (e.name === 'NotAllowedError') return; // User cancelled
    reportError(e, { flow: 'passkey_login' });
  }
});

// ─── NAV TABS ─────────────────────────────────────────────────────────────────

document.querySelectorAll('.nav-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const tab = btn.dataset.tab;
    showTab(tab);
    if (tab === 'security') loadSecurityTab();
    if (tab === 'passkeys') loadPasskeys();
    if (tab === 'sessions') loadSessions();
    if (tab === 'sensitive') setupFreshAuthBanner();
  });
});

// ─── PROFILE ──────────────────────────────────────────────────────────────────

$('prof-bio').addEventListener('input', () => {
  $('bio-len').textContent = $('prof-bio').value.length;
});

$('btn-save-profile').addEventListener('click', async () => {
  try {
    await api('/user/me', {
      method: 'PATCH',
      body: {
        display_name: $('prof-display-name').value.trim() || null,
        bio: $('prof-bio').value.trim() || null,
        location: $('prof-location').value.trim() || null,
        website: $('prof-website').value.trim() || null,
      },
    });
    toast('Profile saved!');
  } catch (e) {
    reportError(e);
  }
});

// ─── SECURITY TAB ─────────────────────────────────────────────────────────────

async function loadSecurityTab() {
  await refreshStatus();
  const has2FA = state.security?.has2FA;
  state.has2FA = has2FA;

  $('badge-2fa').textContent = has2FA ? 'ON' : 'OFF';
  $('badge-2fa').className = 'security-badge' + (has2FA ? ' on' : '');
  $('totp-status-text').textContent = has2FA
    ? 'Your account is protected with a time-based one-time password.'
    : 'Protect your account with a time-based one-time password.';

  const setupBtn = $('btn-setup-2fa');
  if (has2FA) {
    setupBtn.textContent = 'Disable 2FA';
    setupBtn.className = 'btn-danger';
  } else {
    setupBtn.textContent = 'Set up 2FA';
    setupBtn.className = 'btn-secondary';
  }

  $('totp-setup-area').classList.add('hidden');
  $('totp-disable-area').classList.add('hidden');
  $('totp-action-btns').classList.remove('hidden');
}

$('btn-setup-2fa').addEventListener('click', async () => {
  if (state.has2FA) {
    $('totp-action-btns').classList.add('hidden');
    $('totp-disable-area').classList.remove('hidden');
  } else {
    try {
      const data = await api('/auth/2fa/setup', { method: 'POST' });
      $('totp-qr').src = data.qrCode;
      $('totp-secret-display').textContent = data.secret;
      $('totp-setup-area').classList.remove('hidden');
      $('totp-recovery-area').classList.add('hidden'); // Ensure recovery area is hidden
      $('totp-action-btns').classList.add('hidden');
      $('totp-confirm-code').value = '';
      $('totp-confirm-code').focus();
    } catch (e) {
      reportError(e);
    }
  }
});

$('btn-confirm-2fa').addEventListener('click', async () => {
  const token = $('totp-confirm-code').value.trim();
  if (!token) return reportError('Enter your 2FA code to confirm');
  try {
    const data = await api('/auth/2fa/verify-setup', { method: 'POST', body: { token } });
    
    // If recovery codes are provided, show them
    if (data.recoveryCodes?.length) {
      showRecoveryCodes(data.recoveryCodes);
      $('totp-setup-area').classList.add('hidden');
      $('totp-recovery-area').classList.remove('hidden');
    } else {
      toast('2FA enabled!');
      $('totp-confirm-code').value = '';
      $('totp-setup-area').classList.add('hidden');
      state.security.has2FA = true;
      state.has2FA = true;
      loadSecurityTab();
    }
  } catch (e) {
    reportError(e);
  }
});

function showRecoveryCodes(codes) {
  const grid = $('recovery-codes-grid');
  grid.innerHTML = '';
  codes.forEach(code => {
    const el = document.createElement('div');
    el.className = 'recovery-code';
    el.textContent = code;
    grid.appendChild(el);
  });
  state.lastRecoveryCodes = codes; // Temporarily store for copy-to-clipboard
}

$('btn-copy-recovery').addEventListener('click', () => {
  if (!state.lastRecoveryCodes) return;
  const text = state.lastRecoveryCodes.join('\n');
  navigator.clipboard.writeText(text).then(() => {
    toast('Recovery codes copied to clipboard');
  });
});

$('btn-finish-2fa').addEventListener('click', async () => {
  await refreshStatus();
  loadSecurityTab();
  toast('2FA setup complete!');
});

$('btn-cancel-2fa').addEventListener('click', () => {
  $('totp-setup-area').classList.add('hidden');
  $('totp-action-btns').classList.remove('hidden');
});

$('btn-confirm-disable-2fa').addEventListener('click', async () => {
  const password = $('disable-2fa-password').value;
  const token = $('disable-2fa-code').value.trim();
  if (!password) return reportError('Password required');
  try {
    await api('/auth/2fa/disable', { method: 'POST', body: { password, token } });
    toast('2FA disabled');
    $('disable-2fa-password').value = '';
    $('disable-2fa-code').value = '';
    state.security.has2FA = false;
    state.has2FA = false;
    loadSecurityTab();
  } catch (e) {
    reportError(e);
  }
});

$('btn-cancel-disable-2fa').addEventListener('click', () => {
  $('totp-disable-area').classList.add('hidden');
  $('totp-action-btns').classList.remove('hidden');
});

// ─── PASSKEYS TAB ─────────────────────────────────────────────────────────────

async function loadPasskeys() {
  const list = $('passkeys-list');
  const noticeEl = $('passkey-sync-notice');
  list.innerHTML = '<div class="empty-state">Loading…</div>';
  
  // Show compatibility notice if Signal API is missing (e.g. Safari)
  if (noticeEl) {
    if (!window.PublicKeyCredential || !PublicKeyCredential.signalAllAcceptedCredentials) {
      noticeEl.innerHTML = `
        <div class="browser-notice">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
          <div>
            <strong>Limited device sync.</strong> 
            This browser does not support automatic passkey cleanup. Deleting a passkey here will not remove it from your device settings.
          </div>
        </div>
      `;
    } else {
      noticeEl.innerHTML = '';
    }
  }

  try {
    const { passkeys } = await api('/passkeys/list');

    // SYNC WITH DEVICE: Signal the browser which credentials are still valid
    syncPasskeysWithDevice(passkeys.map(pk => pk.credential_id));

    if (!passkeys.length) {
      list.innerHTML = '<div class="empty-state">No passkeys registered yet.</div>';
      return;
    }
    list.innerHTML = passkeys.map(pk => `
      <div class="passkey-item">
        <div class="pk-icon">${pk.device_type === 'singleDevice' ? '📱' : '☁️'}</div>
        <div class="pk-info">
          <div class="pk-name">${escHtml(pk.name)}</div>
          <div class="pk-meta">Added ${formatDate(pk.created_at)} · Last used ${formatDate(pk.last_used)} · ${pk.backed_up ? 'Synced' : 'Local only'}</div>
        </div>
        <div class="pk-actions">
          <button class="btn-danger action-delete-pk" data-id="${pk.id}">Remove</button>
        </div>
      </div>
    `).join('');
  } catch (e) {
    list.innerHTML = '<div class="empty-state">Failed to load passkeys.</div>';
  }
}

// Event Delegation for Passkeys
$('passkeys-list').addEventListener('click', async e => {
  const btn = e.target.closest('.action-delete-pk');
  if (!btn) return;

  const id = btn.dataset.id;
  if (!confirm('Remove this passkey?')) return;

  try {
    const result = await api('/passkeys/' + id, { method: 'DELETE' });
    toast('Passkey removed from server');
    
    // SYNC WITH DEVICE: Immediately tell the browser this passkey is gone
    if (result.remainingCredentialIds) {
      const syncStatus = await syncPasskeysWithDevice(result.remainingCredentialIds);
      if (syncStatus && !syncStatus.supported) {
        toast('Manual cleanup needed: To remove it from your device, visit your System Settings.', 'warning');
      }
    }

    loadPasskeys();
    refreshStatus();
  } catch (err) {
    reportError(err);
  }
});

$('btn-add-passkey').addEventListener('click', () => {
  if (!window.PublicKeyCredential) return toast('Passkeys not supported in this browser', 'error');
  $('new-passkey-name').value = '';
  $('modal-add-passkey').classList.remove('hidden');
});

$('btn-cancel-add-passkey').addEventListener('click', () => {
  $('modal-add-passkey').classList.add('hidden');
});

$('btn-confirm-add-passkey').addEventListener('click', async () => {
  const name = $('new-passkey-name').value.trim();

  $('btn-confirm-add-passkey').disabled = true;
  let excludeCount = 0;
  try {
    const opts = await api('/passkeys/register/options', { method: 'POST' });
    excludeCount = opts.excludeCredentials?.length || 0;
    console.debug('[passkey] Registration options:', opts);
    const prepared = preparePublicKeyCredentialCreationOptions(opts);
    const cred = await navigator.credentials.create({ publicKey: prepared });
    console.debug('[passkey] Registration credential:', cred);
    const serialized = serializeRegistrationCredential(cred);

    await api('/passkeys/register/verify', {
      method: 'POST',
      body: { response: serialized, name: name || undefined },
    });

    $('modal-add-passkey').classList.add('hidden');
    toast('Passkey added!');
    loadPasskeys();
    refreshStatus();
  } catch (e) {
    const msg = (e.message || '').toLowerCase();
    if (e.name === 'NotAllowedError') { 
      toast('Cancelled', 'warning'); 
    } else if (e.name === 'InvalidStateError') {
      if (msg.includes('exclude') || msg.includes('already') || excludeCount > 0) {
        reportError('This device is already registered as a passkey for your account.');
      } else if (msg.includes('pending')) {
        reportError('A registration request is already in progress.');
      } else {
        reportError('The authenticator is in an invalid state. Please try again.');
      }
    } else {
      reportError(e);
    }
  } finally {
    $('btn-confirm-add-passkey').disabled = false;
  }
});

// ─── SESSIONS TAB ─────────────────────────────────────────────────────────────

async function loadSessions() {
  const list = $('sessions-list');
  list.innerHTML = '<div class="empty-state">Loading…</div>';
  try {
    const { sessions } = await api('/user/sessions');
    list.innerHTML = sessions.map(s => `
      <div class="session-item ${s.isCurrent ? 'current' : ''}">
        <div class="sess-info">
          <div class="sess-label">
            Session
            ${s.isCurrent ? '<span class="current-badge">current</span>' : ''}
          </div>
          <div class="sess-meta">
            Created ${formatDate(s.created_at)} · Last active ${formatDate(s.last_activity)} · Expires ${formatDate(s.expires_at)}
          </div>
        </div>
        ${!s.isCurrent ? `<button class="btn-danger action-revoke-session" data-id="${s.id}">Revoke</button>` : ''}
      </div>
    `).join('');
  } catch (e) {
    list.innerHTML = '<div class="empty-state">Failed to load sessions.</div>';
  }
}

// Event Delegation for Sessions
$('sessions-list').addEventListener('click', async e => {
  const btn = e.target.closest('.action-revoke-session');
  if (!btn) return;

  const id = btn.dataset.id;
  if (!confirm('Revoke this session?')) return;

  try {
    await api('/user/sessions/' + id, { method: 'DELETE' });
    toast('Session revoked');
    loadSessions();
  } catch (err) {
    reportError(err);
  }
});

// ─── FRESH AUTH ───────────────────────────────────────────────────────────────

function clearFreshAuthTimer() {
  if (state.freshAuthTimer) { clearInterval(state.freshAuthTimer); state.freshAuthTimer = null; }
}

function setupFreshAuthBanner() {
  clearFreshAuthTimer();

  const updateBanner = () => {
    const fa = state.freshAuth;
    if (fa?.active && fa.expiresAt > Date.now()) {
      $('fresh-auth-banner').classList.add('hidden');
      $('fresh-auth-ok').classList.remove('hidden');
      const rem = Math.max(0, Math.floor((fa.expiresAt - Date.now()) / 1000));
      const m = Math.floor(rem / 60), s = rem % 60;
      $('fresh-auth-expiry').textContent = `Valid for ${m}:${String(s).padStart(2, '0')}`;
    } else {
      $('fresh-auth-banner').classList.remove('hidden');
      $('fresh-auth-ok').classList.add('hidden');
    }
  };

  updateBanner();
  state.freshAuthTimer = setInterval(updateBanner, 1000);
}

$('btn-open-fresh-auth').addEventListener('click', () => {
  // Show/hide tabs based on available methods
  $('fresh-totp-tab').style.display = state.has2FA ? '' : 'none';
  $('fresh-passkey-tab').style.display = (state.security?.passkeyCount > 0) ? '' : 'none';
  
  $('modal-fresh-auth').classList.remove('hidden');
  $('fresh-password').value = '';
  $('fresh-totp').value = '';
});

$('btn-cancel-fresh-auth').addEventListener('click', () => {
  $('modal-fresh-auth').classList.add('hidden');
});

document.querySelectorAll('.method-tab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.method-tab').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.fresh-method').forEach(m => m.classList.add('hidden'));
    btn.classList.add('active');
    $('fresh-method-' + btn.dataset.method).classList.remove('hidden');
  });
});

$('btn-confirm-fresh-auth').addEventListener('click', async () => {
  const activeMethod = document.querySelector('.method-tab.active')?.dataset.method || 'password';
  
  $('btn-confirm-fresh-auth').disabled = true;
  try {
    if (activeMethod === 'passkey') {
      await verifyPasskey();
    } else {
      const body = { method: activeMethod };
      if (activeMethod === 'password') body.password = $('fresh-password').value;
      if (activeMethod === 'totp') body.token = $('fresh-totp').value.trim();
      
      const data = await api('/auth/fresh-auth', { method: 'POST', body });
      state.freshAuth = { active: true, expiresAt: data.expiresAt };
    }

    $('modal-fresh-auth').classList.add('hidden');
    setupFreshAuthBanner();
    toast('Identity verified!');
  } catch (e) {
    if (e.name === 'NotAllowedError') return; // User cancelled
    toast(e.message, 'error');
  } finally {
    $('btn-confirm-fresh-auth').disabled = false;
  }
});

// ─── SENSITIVE ACTIONS ────────────────────────────────────────────────────────

document.querySelectorAll('.action-card').forEach(card => {
  card.querySelector('.btn-action').addEventListener('click', async () => {
    const action = card.dataset.action;

    // Check fresh auth
    if (!state.freshAuth?.active || state.freshAuth.expiresAt <= Date.now()) {
      toast('Re-verify your identity first', 'warning');
      $('btn-open-fresh-auth').click();
      return;
    }

    if (action === 'change-email') {
      $('modal-change-email').classList.remove('hidden');
      return;
    }

    try {
      const result = await api('/user/sensitive-action', {
        method: 'POST',
        body: { action },
      });
      $('action-result').classList.remove('hidden');
      $('action-result-pre').textContent = JSON.stringify(result.result, null, 2);
      toast(`Action "${action}" completed`);
    } catch (e) {
      if (e.code === 'FRESH_AUTH_REQUIRED') {
        toast('Fresh auth expired, please re-verify', 'warning');
        state.freshAuth = { active: false };
        setupFreshAuthBanner();
      } else {
        reportError(e);
      }
    }
  });
});

$('btn-cancel-email-change').addEventListener('click', () => {
  $('modal-change-email').classList.add('hidden');
});

$('btn-confirm-email-change').addEventListener('click', async () => {
  const newEmail = $('new-email-input').value.trim();
  if (!newEmail) return reportError('Enter a new email');
  try {
    const result = await api('/user/sensitive-action', {
      method: 'POST',
      body: { action: 'change-email', data: { newEmail } },
    });
    $('modal-change-email').classList.add('hidden');
    $('action-result').classList.remove('hidden');
    $('action-result-pre').textContent = JSON.stringify(result.result, null, 2);
    toast('Email change initiated');
  } catch (e) {
    reportError(e);
  }
});

// Close modals on backdrop click
document.querySelectorAll('.modal').forEach(modal => {
  modal.addEventListener('click', e => {
    if (e.target === modal) modal.classList.add('hidden');
  });
});

// ─── HELPERS ──────────────────────────────────────────────────────────────────

async function refreshStatus() {
  const status = await api('/auth/status');
  if (status.authenticated) {
    state.user = status.user;
    state.security = status.security;
    state.freshAuth = status.freshAuth;
    state.has2FA = status.security?.has2FA;
    updateOverview();
  }
}

function escHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ─── BOOT ─────────────────────────────────────────────────────────────────────

init();
// ─── PASTE HANDLER ────────────────────────────────────────────────────────────

document.body.addEventListener('click', async e => {
  const btn = e.target.closest('.btn-paste');
  if (!btn) return;

  const targetId = btn.dataset.target;
  const input = document.getElementById(targetId);
  if (!input) return;

  try {
    const text = await navigator.clipboard.readText();
    // Clean code: take only first 6 digits found
    const code = text.replace(/\D/g, '').substring(0, 6);
    if (code) {
      input.value = code;
      input.focus();
      toast('Code pasted from clipboard');
    } else {
      toast('No valid code found in clipboard', 'warning');
    }
  } catch (err) {
    console.warn('[auth] Clipboard access denied:', err);
    toast('Clipboard access denied', 'error');
  }
});

// ─── SECURITY ENHANCEMENTS ───────────────────────────────────────────────────

$('btn-jump-reset').addEventListener('click', () => {
  showTab('security');
  $('block-password').scrollIntoView({ behavior: 'smooth' });
});

$('btn-confirm-change-password').addEventListener('click', async () => {
  const newPassword = $('change-password-new').value;
  const confirm = $('change-password-confirm').value;

  if (!newPassword || newPassword.length < 8) {
    return toast('Password must be at least 8 characters', 'error');
  }
  if (newPassword !== confirm) {
    return toast('Passwords do not match', 'error');
  }

  try {
    await api('/auth/change-password', {
      method: 'POST',
      body: { newPassword }
    });
    toast('Password updated successfully!');
    $('change-password-new').value = '';
    $('change-password-confirm').value = '';
    await refreshStatus();
    showDashboard(); // Refresh UI to hide banner if present
  } catch (e) {
    if (e.code === 'FRESH_AUTH_REQUIRED') {
      promptFreshAuth(() => $('btn-confirm-change-password').click());
    } else {
      reportError(e);
    }
  }
});

$('btn-save-global-config').addEventListener('click', async () => {
  const updates = {
    site_name: $('cfg-site-name').value.trim(),
    admin_email: $('cfg-admin-email').value.trim(),
    registration_enabled: $('cfg-registration-enabled').checked ? 'true' : 'false',
    force_2fa: $('cfg-force-2fa').checked ? 'true' : 'false',
    enforce_mfa_new_users: $('cfg-enforce-mfa-new-users').checked ? 'true' : 'false',
    min_password_length: $('cfg-min-password-length').value,
    fresh_auth_duration: $('cfg-fresh-auth-duration').value,
    session_duration_days: $('cfg-session-duration-days').value,
    max_login_attempts: $('cfg-max-login-attempts').value,
    lockout_duration_mins: $('cfg-lockout-duration-mins').value
  };

  try {
    await api('/auth/settings', {
      method: 'PATCH',
      body: updates
    });
    toast('Global configuration updated');
    await refreshStatus();
    showDashboard();
  } catch (err) {
    reportError(err);
  }
});

// ─── PASSWORD RESET FLOW ─────────────────────────────────────────────────────

$('go-reset-request').addEventListener('click', (e) => {
  e.preventDefault();
  showAuthForm('form-reset-request');
});

$('go-login-from-reset').addEventListener('click', (e) => {
  e.preventDefault();
  showAuthForm('form-login');
});

$('btn-submit-reset-request').addEventListener('click', async () => {
  const identifier = $('reset-request-identifier').value.trim();
  if (!identifier) return toast('Please enter your username or email', 'warning');

  try {
    const res = await api('/auth/password-reset/request', {
      method: 'POST',
      body: { username: identifier }
    });

    toast('Reset code generated!', 'success');
    showAuthForm('form-reset-confirm');

    // Simulate Mailbox Receipt
    addToMailbox({
      title: 'Password Reset Request',
      body: `A password reset was requested for ${res.user.username}.`,
      code: res.token,
      time: new Date().toLocaleTimeString()
    });
  } catch (err) {
    reportError(err);
  }
});

$('btn-submit-reset-confirm').addEventListener('click', async () => {
  const token = $('reset-token-input').value.trim();
  const newPassword = $('reset-new-password').value;

  if (!token) return toast('Enter the reset code', 'warning');
  if (!newPassword || newPassword.length < 8) return toast('Password too short', 'warning');

  try {
    await api('/auth/password-reset/reset', {
      method: 'POST',
      body: { token, newPassword }
    });

    toast('Password reset successfully. You can now login.', 'success');
    showAuthForm('form-login');
    $('reset-token-input').value = '';
    $('reset-new-password').value = '';
  } catch (err) {
    reportError(err);
  }
});

function addToMailbox({ title, body, code, time }) {
  const mailbox = $('dev-mailbox');
  const content = $('mailbox-content');
  mailbox.classList.remove('hidden');

  // Remove empty message if present
  const empty = content.querySelector('.empty-msg');
  if (empty) empty.remove();

  const item = document.createElement('div');
  item.className = 'mail-item';
  item.innerHTML = `
    <span class="time">${time}</span>
    <strong>${title}</strong>
    <p style="margin-top: 5px;">${body}</p>
    <code class="code">${code}</code>
  `;

  content.prepend(item);
  content.scrollTop = 0;
}

$('btn-close-mailbox').addEventListener('click', () => {
  $('dev-mailbox').classList.add('hidden');
});

// ─── API KEYS MANAGEMENT ─────────────────────────────────────────────────────

async function refreshApiKeys() {
  try {
    const res = await api('/user/keys');
    const container = $('key-list-container');
    
    if (!res.keys || res.keys.length === 0) {
      container.innerHTML = '<p class="empty-msg">No API keys generated yet.</p>';
      return;
    }

    container.innerHTML = res.keys.map(k => `
      <div class="key-item card-sub" style="padding: 1rem; border: 1px solid var(--border-hi); border-radius: var(--radius); margin-bottom: 1rem; display: flex; justify-content: space-between; align-items: flex-start;">
        <div>
          <div style="font-weight: 500; font-size: 1.1rem; margin-bottom: 0.25rem;">${k.name}</div>
          <div style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-3); margin-bottom: 0.5rem;">ID: ${k.id}</div>
          <div class="tag-list" style="display: flex; gap: 0.5rem; margin-bottom: 0.5rem;">
            ${k.permissions.map(p => `<span class="tag" style="font-size: 0.7rem; background: var(--bg-3); padding: 2px 8px; border-radius: 12px; border: 1px solid var(--border-hi);">${p}</span>`).join('')}
          </div>
          <div style="font-size: 0.75rem; color: var(--text-3);">
            Created: ${new Date(k.created_at).toLocaleDateString()}
            ${k.last_used ? ` | Last used: ${new Date(k.last_used).toLocaleString()}` : ''}
          </div>
        </div>
        <button class="btn-danger btn-sm" onclick="revokeApiKey('${k.id}')">Revoke</button>
      </div>
    `).join('');
  } catch (err) {
    reportError(err);
  }
}

async function revokeApiKey(id) {
  if (!confirm('Are you sure you want to revoke this API key? Applications using it will instantly lose access.')) return;
  try {
    await api(`/user/keys/${id}`, { method: 'DELETE' });
    toast('API key revoked');
    refreshApiKeys();
  } catch (err) {
    reportError(err);
  }
}

$('btn-create-key').addEventListener('click', async () => {
  const name = $('api-key-name').value.trim();
  if (!name) return toast('Please enter a name for the key', 'warning');

  const permissions = Array.from(document.querySelectorAll('input[name="api-perm"]:checked')).map(el => el.value);

  try {
    const res = await api('/user/keys', {
      method: 'POST',
      body: { name, permissions }
    });

    $('api-key-name').value = '';
    $('new-api-key-display').value = res.key;
    $('api-key-success').classList.remove('hidden');
    
    toast('API Key generated successfully', 'success');
    refreshApiKeys();
  } catch (err) {
    reportError(err);
  }
});

// Hook into tab switching logic
document.querySelectorAll('.nav-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const tab = btn.getAttribute('data-tab');
    if (tab === 'api-keys') {
      refreshApiKeys();
    }
  });
});

