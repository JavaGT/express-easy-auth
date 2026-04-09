/* ─────────────────────────────────────────────────────────────────────
   Auth Server — Frontend App
   ───────────────────────────────────────────────────────────────────── */

// ─── UTILS ───────────────────────────────────────────────────────────────────

const $ = id => document.getElementById(id);
const toast = (msg, type = 'success') => {
  const el = document.createElement('div');
  el.className = `toast${type !== 'success' ? ` ${type}` : ''}`;
  el.textContent = msg;
  $('toast-container').appendChild(el);
  setTimeout(() => el.remove(), 3800);
};

async function api(path, options = {}) {
  const res = await fetch('/api' + path, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    credentials: 'same-origin',
    ...options,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const data = await res.json();
  if (!res.ok) throw Object.assign(new Error(data.error || 'Request failed'), { code: data.code, status: res.status });
  return data;
}

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
      clientDataJSON:    bufferToBase64url(cred.response.clientDataJSON),
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
      clientDataJSON:    bufferToBase64url(cred.response.clientDataJSON),
      authenticatorData: bufferToBase64url(cred.response.authenticatorData),
      signature:         bufferToBase64url(cred.response.signature),
      userHandle:        cred.response.userHandle ? bufferToBase64url(cred.response.userHandle) : null,
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
};

// ─── ROUTING / VIEWS ─────────────────────────────────────────────────────────

function showView(id) {
  document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
  $(id)?.classList.remove('hidden');
}

function showAuthForm(id) {
  document.querySelectorAll('.auth-form').forEach(f => f.classList.remove('active'));
  $(id)?.classList.add('active');
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
  document.querySelectorAll('.dash-tab').forEach(t => t.classList.add('hidden'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  $(`tab-${name}`)?.classList.remove('hidden');
  document.querySelector(`.nav-btn[data-tab="${name}"]`)?.classList.add('active');
}

// ─── INIT ─────────────────────────────────────────────────────────────────────

async function init() {
  try {
    const status = await api('/auth/status');

    if (status.authenticated) {
      state.user = status.user;
      state.security = status.security;
      state.freshAuth = status.freshAuth;
      state.has2FA = status.security?.has2FA;
      showDashboard();
    } else {
      showView('view-auth');
    }
  } catch (e) {
    showView('view-auth');
  } finally {
    const ls = $('loading-screen');
    ls.classList.add('fade-out');
    setTimeout(() => ls.remove(), 400);
  }
}

// ─── DASHBOARD ────────────────────────────────────────────────────────────────

async function showDashboard() {
  showTab('overview'); // Ensure we start on overview
  showView('view-dashboard');
  $('dash-username').textContent = '@' + state.user.username;
  updateOverview();
  await loadProfile();
  setupFreshAuthBanner();
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
  } catch (e) {/* silent */}
}

// ─── AUTH FORMS ───────────────────────────────────────────────────────────────

$('btn-login').addEventListener('click', async () => {
  const username = $('login-username').value.trim();
  const password = $('login-password').value;
  if (!username || !password) return toast('Enter username and password', 'error');

  $('btn-login').disabled = true;
  try {
    const data = await api('/auth/login', { method: 'POST', body: { username, password } });
    if (data.requires2FA) {
      showAuthForm('form-2fa');
    } else {
      state.user = data.user;
      await refreshStatus();
      showDashboard();
    }
  } catch (e) {
    toast(e.message, 'error');
  } finally {
    $('btn-login').disabled = false;
  }
});

$('btn-2fa-verify').addEventListener('click', async () => {
  const token = $('totp-code').value.trim();
  if (!token) return toast('Enter your 2FA code', 'error');

  try {
    await api('/auth/login/2fa', { method: 'POST', body: { token } });
    $('totp-code').value = '';
    await refreshStatus();
    showDashboard();
  } catch (e) {
    toast(e.message, 'error');
  }
});

$('btn-register').addEventListener('click', async () => {
  const username = $('reg-username').value.trim();
  const email = $('reg-email').value.trim();
  const password = $('reg-password').value;
  if (!username || !email || !password) return toast('All fields required', 'error');

  $('btn-register').disabled = true;
  try {
    const data = await api('/auth/register', { method: 'POST', body: { username, email, password } });
    state.user = data.user;
    await refreshStatus();
    showDashboard();
    toast('Account created!');
  } catch (e) {
    toast(e.message, 'error');
  } finally {
    $('btn-register').disabled = false;
  }
});

$('btn-logout').addEventListener('click', async () => {
  try {
    await api('/auth/logout', { method: 'POST' });
    resetUI();
    showView('view-auth');
    showAuthForm('form-login');
  } catch (e) {
    toast('Logout failed', 'error');
  }
});

$('go-register').addEventListener('click', e => { e.preventDefault(); showAuthForm('form-register'); });
$('go-login').addEventListener('click', e => { e.preventDefault(); showAuthForm('form-login'); });
$('go-back-login').addEventListener('click', e => { e.preventDefault(); showAuthForm('form-login'); });

// Enter key support
['login-username', 'login-password'].forEach(id => {
  $(id).addEventListener('keydown', e => { if (e.key === 'Enter') $('btn-login').click(); });
});
$('totp-code').addEventListener('keydown', e => { if (e.key === 'Enter') $('btn-2fa-verify').click(); });

// ─── PASSKEY LOGIN ────────────────────────────────────────────────────────────

$('btn-passkey-login').addEventListener('click', async () => {
  if (!window.PublicKeyCredential) return toast('Passkeys not supported in this browser', 'error');

  try {
    const username = $('login-username').value.trim() || undefined;
    const opts = await api('/passkeys/authenticate/options', {
      method: 'POST',
      body: { username },
    });

    const prepared = preparePublicKeyCredentialRequestOptions(opts);
    const cred = await navigator.credentials.get({ publicKey: prepared });
    const serialized = serializeAuthenticationCredential(cred);

    const result = await api('/passkeys/authenticate/verify', {
      method: 'POST',
      body: { response: serialized },
    });

    state.user = result.user;
    await refreshStatus();
    showDashboard();
    toast('Signed in with passkey!');
  } catch (e) {
    if (e.name === 'NotAllowedError') return; // User cancelled
    toast(e.message || 'Passkey login failed', 'error');
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
    toast(e.message, 'error');
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
      $('totp-action-btns').classList.add('hidden');
      $('totp-setup-area').classList.remove('hidden');
    } catch (e) {
      toast(e.message, 'error');
    }
  }
});

$('btn-confirm-2fa').addEventListener('click', async () => {
  const token = $('totp-confirm-code').value.trim();
  if (!token) return toast('Enter your 2FA code to confirm', 'error');
  try {
    await api('/auth/2fa/verify-setup', { method: 'POST', body: { token } });
    toast('2FA enabled!');
    $('totp-confirm-code').value = '';
    $('totp-setup-area').classList.add('hidden');
    state.security.has2FA = true;
    state.has2FA = true;
    loadSecurityTab();
  } catch (e) {
    toast(e.message, 'error');
  }
});

$('btn-cancel-2fa').addEventListener('click', () => {
  $('totp-setup-area').classList.add('hidden');
  $('totp-action-btns').classList.remove('hidden');
});

$('btn-confirm-disable-2fa').addEventListener('click', async () => {
  const password = $('disable-2fa-password').value;
  const token = $('disable-2fa-code').value.trim();
  if (!password) return toast('Password required', 'error');
  try {
    await api('/auth/2fa/disable', { method: 'POST', body: { password, token } });
    toast('2FA disabled');
    $('disable-2fa-password').value = '';
    $('disable-2fa-code').value = '';
    state.security.has2FA = false;
    state.has2FA = false;
    loadSecurityTab();
  } catch (e) {
    toast(e.message, 'error');
  }
});

$('btn-cancel-disable-2fa').addEventListener('click', () => {
  $('totp-disable-area').classList.add('hidden');
  $('totp-action-btns').classList.remove('hidden');
});

// ─── PASSKEYS TAB ─────────────────────────────────────────────────────────────

async function loadPasskeys() {
  const list = $('passkeys-list');
  list.innerHTML = '<div class="empty-state">Loading…</div>';
  try {
    const { passkeys } = await api('/passkeys/list');
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
    await api('/passkeys/' + id, { method: 'DELETE' });
    toast('Passkey removed');
    loadPasskeys();
    refreshStatus();
  } catch (err) {
    toast(err.message, 'error');
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
  try {
    const opts = await api('/passkeys/register/options', { method: 'POST' });
    const prepared = preparePublicKeyCredentialCreationOptions(opts);
    const cred = await navigator.credentials.create({ publicKey: prepared });
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
    if (e.name === 'NotAllowedError') { toast('Cancelled', 'warning'); }
    else toast(e.message || 'Passkey registration failed', 'error');
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
    toast(err.message, 'error');
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
  // Show/hide TOTP option based on whether user has 2FA
  $('fresh-totp-tab').style.display = state.has2FA ? '' : 'none';
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
  const body = { method: activeMethod };
  if (activeMethod === 'password') body.password = $('fresh-password').value;
  if (activeMethod === 'totp') body.token = $('fresh-totp').value.trim();

  $('btn-confirm-fresh-auth').disabled = true;
  try {
    const data = await api('/auth/fresh-auth', { method: 'POST', body });
    state.freshAuth = { active: true, expiresAt: data.expiresAt };
    $('modal-fresh-auth').classList.add('hidden');
    setupFreshAuthBanner();
    toast('Identity verified!');
  } catch (e) {
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
        toast(e.message, 'error');
      }
    }
  });
});

$('btn-cancel-email-change').addEventListener('click', () => {
  $('modal-change-email').classList.add('hidden');
});

$('btn-confirm-email-change').addEventListener('click', async () => {
  const newEmail = $('new-email-input').value.trim();
  if (!newEmail) return toast('Enter a new email', 'error');
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
    toast(e.message, 'error');
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
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ─── BOOT ─────────────────────────────────────────────────────────────────────

init();