/**
 * DocuFlow frontend — express-easy-auth v4 demo.
 * Demonstrates: session auth, personal scopes, project-scoped access,
 * API key creation with grant selection, admin panel.
 */

import { EasyAuthClient } from '/auth/client.js';

const authClient = new EasyAuthClient({ apiBase: '/auth' });

// ── State ──────────────────────────────────────────────────────────

let state = {
    user:             null,
    projects:         [],
    currentProject:   null,
    effectiveScopes:  [],
    docs:             [],
    members:          [],
    apiKeys:          [],
    scopes:           { server: [], personal: [], project: [] },
};

// ── Utilities ──────────────────────────────────────────────────────

const $ = id => document.getElementById(id);

function esc(str) {
    return String(str ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

async function api(method, path, body) {
    const opts = {
        method,
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
    };
    if (body !== undefined) opts.body = JSON.stringify(body);
    const res  = await fetch(path, opts);
    const data = await res.json();
    if (!res.ok) {
        const err = new Error(data.message || data.error || `HTTP ${res.status}`);
        err.code  = res.status;
        err.type  = data.error;
        throw err;
    }
    return data;
}

function fmtDate(ts) {
    if (!ts) return '—';
    return new Date(ts).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

// ── View switching ─────────────────────────────────────────────────

function showView(id) {
    ['login-view', 'register-view', 'app-view'].forEach(v => $(v).classList.add('hidden'));
    $(id).classList.remove('hidden');
}

function showError(elId, msg) {
    const el = $(elId);
    if (!el) return;
    el.textContent = msg;
    el.classList.remove('hidden');
}

function clearError(elId) {
    const el = $(elId);
    if (el) { el.textContent = ''; el.classList.add('hidden'); }
}

// ── Init ───────────────────────────────────────────────────────────

async function init() {
    try {
        const me = await authClient.me();
        state.user = me.user;
        await enterApp();
    } catch (_) {
        showView('login-view');
    }
}

async function enterApp() {
    $('header-user').textContent = state.user.display_name
        ? `${state.user.display_name} (${state.user.email})`
        : state.user.email;

    showView('app-view');

    const [scopeData] = await Promise.all([
        api('GET', '/scopes'),
        loadMyProjects(),
    ]);
    state.scopes = scopeData;

    // Show admin button only if user has any server scope access
    try {
        await api('GET', '/admin/users');
        $('admin-btn').classList.remove('hidden');
    } catch (_) {}
}

// ── Auth ───────────────────────────────────────────────────────────

$('login-form').onsubmit = async e => {
    e.preventDefault();
    clearError('login-error');
    try {
        const result = await authClient.login($('login-email').value, $('login-password').value);
        state.user = result.user ?? authClient.user;
        await enterApp();
    } catch (err) {
        showError('login-error', err.message);
    }
};

$('register-form').onsubmit = async e => {
    e.preventDefault();
    clearError('register-error');
    const email    = $('reg-email').value;
    const password = $('reg-password').value;
    const name     = $('reg-name').value.trim() || undefined;
    try {
        await authClient.register(email, password, name);
        // Auto-login
        const result = await authClient.login(email, password);
        state.user = result.user ?? authClient.user;
        await enterApp();
    } catch (err) {
        showError('register-error', err.message);
    }
};

$('goto-register').onclick = e => { e.preventDefault(); showView('register-view'); };
$('goto-login').onclick    = e => { e.preventDefault(); showView('login-view'); };

$('logout-btn').onclick = async () => {
    await authClient.logout();
    state = { user: null, projects: [], currentProject: null, effectiveScopes: [], docs: [], members: [], apiKeys: [], scopes: { server: [], personal: [], project: [] } };
    $('admin-btn').classList.add('hidden');
    showView('login-view');
};

// ── Projects ───────────────────────────────────────────────────────

async function loadMyProjects() {
    const data = await api('GET', '/me/projects');
    state.projects = data.projects || [];
    renderProjects();
}

function renderProjects() {
    const list = $('projects-list');
    list.innerHTML = '';
    if (state.projects.length === 0) {
        list.innerHTML = '<li class="nav-empty">No projects yet</li>';
        return;
    }
    for (const p of state.projects) {
        const li      = document.createElement('li');
        li.className  = 'nav-item' + (state.currentProject?.id === p.id ? ' active' : '');
        li.innerHTML  = `<span class="nav-item-name">${esc(p.name)}</span>${p.isOwner ? '<span class="badge-mini">owner</span>' : ''}`;
        li.onclick    = () => selectProject(p);
        list.appendChild(li);
    }
}

async function selectProject(project) {
    state.currentProject  = project;
    state.effectiveScopes = [];
    renderProjects();

    $('no-project').classList.add('hidden');
    $('project-workspace').classList.remove('hidden');
    $('ws-project-name').textContent = project.name;
    $('ws-owner-badge').classList.toggle('hidden', !project.isOwner);
    $('delete-project-btn').classList.toggle('hidden', !project.isOwner);
    $('transfer-btn').classList.toggle('hidden', !project.isOwner);

    // Reset tabs
    switchTab('docs');
    await Promise.all([loadDocs(), loadMembers()]);
}

$('new-project-btn').onclick = () => {
    showModal('New Project', `
        <label>Project Name</label>
        <input type="text" id="new-proj-name" class="modal-input" placeholder="e.g. Q4 Campaign" required>
    `, async () => {
        const name = $('new-proj-name').value.trim();
        if (!name) return;
        const data = await api('POST', '/projects', { name });
        hideModal();
        await loadMyProjects();
        const fresh = state.projects.find(p => p.id === data.id);
        if (fresh) await selectProject(fresh);
    });
};

$('delete-project-btn').onclick = () => {
    const p = state.currentProject;
    showModal(
        'Delete Project',
        `<p>Permanently delete <strong>${esc(p.name)}</strong>? This cannot be undone.</p>`,
        async () => {
            await api('DELETE', `/projects/${p.id}`);
            state.currentProject = null;
            $('project-workspace').classList.add('hidden');
            $('no-project').classList.remove('hidden');
            hideModal();
            await loadMyProjects();
        },
    );
};

$('transfer-btn').onclick = () => {
    showModal('Transfer Ownership', `
        <p>Transfer <strong>${esc(state.currentProject.name)}</strong> to another user.</p>
        <label>New Owner — User ID</label>
        <input type="number" id="transfer-uid" class="modal-input" placeholder="User ID" min="1" required>
    `, async () => {
        const newOwnerId = Number($('transfer-uid').value);
        if (!newOwnerId) return;
        try {
            await api('PUT', `/projects/${state.currentProject.id}/owner`, { newOwnerId });
            hideModal();
            await loadMyProjects();
            // Project may no longer appear if user is no longer owner or member
            const still = state.projects.find(p => p.id === state.currentProject?.id);
            if (!still) {
                state.currentProject = null;
                $('project-workspace').classList.add('hidden');
                $('no-project').classList.remove('hidden');
            }
        } catch (err) {
            if (err.code === 401) {
                alert('Step-up required: please log out and log back in, then try again.');
            } else {
                alert(err.message);
            }
        }
    });
};

// ── Tabs ───────────────────────────────────────────────────────────

document.querySelectorAll('.tab[data-tab]').forEach(btn => {
    btn.onclick = () => switchTab(btn.dataset.tab);
});

function switchTab(tab) {
    document.querySelectorAll('.tab[data-tab]').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
    $('docs-panel').classList.toggle('hidden',    tab !== 'docs');
    $('members-panel').classList.toggle('hidden', tab !== 'members');
}

// ── Documents ──────────────────────────────────────────────────────

async function loadDocs() {
    if (!state.currentProject) return;
    try {
        const data       = await api('GET', `/projects/${state.currentProject.id}/docs`);
        state.docs       = data.docs || [];
        state.effectiveScopes = data.effectiveScopes || [];

        const canWrite   = state.currentProject.isOwner
            || state.effectiveScopes.includes('*')
            || state.effectiveScopes.includes('docs:write');
        const canManage  = state.currentProject.isOwner
            || state.effectiveScopes.includes('*')
            || state.effectiveScopes.includes('members:manage');

        $('new-doc-btn').classList.toggle('hidden', !canWrite);
        $('add-member-btn').classList.toggle('hidden', !canManage);

        renderDocs();
    } catch (err) {
        $('docs-list').innerHTML = `<div class="error-msg">${esc(err.message)}</div>`;
    }
}

function renderDocs() {
    const list = $('docs-list');
    if (state.docs.length === 0) {
        list.innerHTML = '<div class="empty-msg">No documents yet.</div>';
        return;
    }
    const canDelete = state.currentProject.isOwner
        || state.effectiveScopes.includes('*')
        || state.effectiveScopes.includes('docs:delete');

    list.innerHTML = state.docs.map(doc => `
        <div class="list-item" data-id="${esc(doc.id)}">
            <div class="item-info">
                <div class="item-title">${esc(doc.title)}</div>
                <div class="item-meta">Created ${fmtDate(doc.created_at)}${doc.body ? ' · ' + esc(doc.body.slice(0, 60)) + (doc.body.length > 60 ? '…' : '') : ''}</div>
            </div>
            ${canDelete ? `<button class="btn-danger btn-xs delete-doc-btn" data-id="${esc(doc.id)}">Delete</button>` : ''}
        </div>
    `).join('');

    list.querySelectorAll('.delete-doc-btn').forEach(btn => {
        btn.onclick = () => deleteDoc(btn.dataset.id);
    });
}

$('new-doc-btn').onclick = () => {
    showModal('New Document', `
        <label>Title</label>
        <input type="text" id="doc-title" class="modal-input" placeholder="Document title" required>
        <label>Body</label>
        <textarea id="doc-body" class="modal-textarea" placeholder="Content (optional)…"></textarea>
    `, async () => {
        const title = $('doc-title').value.trim();
        if (!title) return;
        await api('POST', `/projects/${state.currentProject.id}/docs`, {
            title,
            body: $('doc-body').value,
        });
        hideModal();
        await loadDocs();
    });
};

async function deleteDoc(docId) {
    if (!confirm('Delete this document?')) return;
    await api('DELETE', `/projects/${state.currentProject.id}/docs/${docId}`);
    await loadDocs();
}

// ── Members ────────────────────────────────────────────────────────

async function loadMembers() {
    if (!state.currentProject) return;
    try {
        const data    = await api('GET', `/projects/${state.currentProject.id}/members`);
        state.members = data.members || [];
        renderMembers();
    } catch (err) {
        $('members-list').innerHTML = `<div class="error-msg">${esc(err.message)}</div>`;
    }
}

function renderMembers() {
    const list     = $('members-list');
    const canManage = state.currentProject.isOwner
        || state.effectiveScopes.includes('*')
        || state.effectiveScopes.includes('members:manage');

    if (state.members.length === 0) {
        list.innerHTML = '<div class="empty-msg">No members added yet.</div>';
        return;
    }

    list.innerHTML = state.members.map(m => {
        let perms = [];
        try { perms = JSON.parse(m.permissions); } catch (_) {}
        return `
            <div class="list-item">
                <div class="item-info">
                    <div class="item-title">User #${esc(m.user_id)}</div>
                    <div class="scope-tags">
                        ${perms.map(s => `<span class="scope-tag">${esc(s)}</span>`).join('')}
                    </div>
                </div>
                ${canManage ? `<button class="btn-danger btn-xs remove-member-btn" data-uid="${esc(m.user_id)}">Remove</button>` : ''}
            </div>
        `;
    }).join('');

    list.querySelectorAll('.remove-member-btn').forEach(btn => {
        btn.onclick = () => removeMember(Number(btn.dataset.uid));
    });
}

$('add-member-btn').onclick = () => {
    const projectScopes = state.scopes.project || [];
    showModal('Add / Update Member', `
        <label>User ID</label>
        <input type="number" id="member-uid" class="modal-input" placeholder="e.g. 2" min="1" required>
        <label>Permissions</label>
        <div class="scope-checkboxes">
            ${projectScopes.map(s => `
                <label class="scope-check">
                    <input type="checkbox" value="${esc(s)}" name="member-scope"> ${esc(s)}
                </label>
            `).join('')}
        </div>
    `, async () => {
        const uid = Number($('member-uid').value);
        if (!uid) return;
        const permissions = [...document.querySelectorAll('input[name="member-scope"]:checked')]
            .map(c => c.value);
        await api('PUT', `/projects/${state.currentProject.id}/members/${uid}`, { permissions });
        hideModal();
        await loadMembers();
    });
};

async function removeMember(userId) {
    if (!confirm(`Remove user #${userId} from this project?`)) return;
    await api('DELETE', `/projects/${state.currentProject.id}/members/${userId}`);
    await loadMembers();
}

// ── API Keys ───────────────────────────────────────────────────────

$('apikeys-btn').onclick = async () => {
    $('apikeys-overlay').classList.remove('hidden');
    await loadApiKeys();
};

$('close-apikeys-btn').onclick = () => $('apikeys-overlay').classList.add('hidden');

$('apikeys-overlay').addEventListener('click', e => {
    if (e.target === $('apikeys-overlay')) $('apikeys-overlay').classList.add('hidden');
});

async function loadApiKeys() {
    try {
        const data    = await authClient.getApiKeys();
        state.apiKeys = Array.isArray(data) ? data : (data.keys || []);
        renderApiKeys();
    } catch (err) {
        $('apikeys-list').innerHTML = `<div class="error-msg">${esc(err.message)}</div>`;
    }
}

function renderApiKeys() {
    const list = $('apikeys-list');
    if (state.apiKeys.length === 0) {
        list.innerHTML = '<div class="empty-msg">No API keys yet.</div>';
        return;
    }
    list.innerHTML = state.apiKeys.map(k => `
        <div class="list-item">
            <div class="item-info">
                <div class="item-title">
                    ${esc(k.name)}
                    <code class="key-prefix">${esc(k.prefix)}…</code>
                </div>
                <div class="item-meta">
                    Expires: ${fmtDate(k.expiresAt)} &nbsp;·&nbsp; Last used: ${fmtDate(k.lastUsedAt)}
                </div>
                <div class="scope-tags">
                    ${(k.grants?.server?.length  ? k.grants.server.map(s  => `<span class="scope-tag server">${esc(s)}</span>`).join('') : '')}
                    ${(k.grants?.personal?.length ? k.grants.personal.map(s => `<span class="scope-tag personal">${esc(s)}</span>`).join('') : '')}
                    ${(k.grants?.projects?.length ? k.grants.projects.map(g => g.scopes.map(s => `<span class="scope-tag project" title="${esc(g.projectId)}">${esc(g.projectId.slice(0,12))}… ${esc(s)}</span>`).join('')).join('') : '')}
                </div>
            </div>
            <button class="btn-danger btn-xs revoke-key-btn" data-id="${k.id}">Revoke</button>
        </div>
    `).join('');

    list.querySelectorAll('.revoke-key-btn').forEach(btn => {
        btn.onclick = async () => {
            if (!confirm('Revoke this key? This cannot be undone.')) return;
            await authClient.revokeApiKey(Number(btn.dataset.id));
            await loadApiKeys();
        };
    });
}

$('create-key-btn').onclick = async () => {
    const scopeData      = await api('GET', '/scopes');
    const serverScopes   = scopeData.server   || [];
    const personalScopes = scopeData.personal  || [];
    const projectScopes  = scopeData.project   || [];

    const serverSection = serverScopes.length ? `
        <label>Server Scopes</label>
        <div class="scope-checkboxes">
            ${serverScopes.map(s => `<label class="scope-check"><input type="checkbox" value="${esc(s)}" name="ks"> ${esc(s)}</label>`).join('')}
        </div>
    ` : '';

    const projectSection = state.projects.length && projectScopes.length ? `
        <label>Project Grants</label>
        <div class="scope-checkboxes">
            ${state.projects.flatMap(p =>
                projectScopes.map(s => `
                    <label class="scope-check">
                        <input type="checkbox" value="${esc(p.id)}::${esc(s)}" name="kp">
                        <span class="scope-proj">${esc(p.name)}</span>&nbsp;${esc(s)}
                    </label>
                `)
            ).join('')}
        </div>
    ` : '';

    showModal('Create API Key', `
        <label>Name</label>
        <input type="text" id="key-name" class="modal-input" placeholder="e.g. CI Pipeline" required>
        <label>Expiry (optional)</label>
        <input type="date" id="key-expires" class="modal-input">
        ${serverSection}
        <label>Personal Scopes</label>
        <div class="scope-checkboxes">
            ${personalScopes.map(s => `<label class="scope-check"><input type="checkbox" value="${esc(s)}" name="kps"> ${esc(s)}</label>`).join('')}
        </div>
        ${projectSection}
    `, async () => {
        const name = $('key-name').value.trim();
        if (!name) { alert('Name is required.'); return; }

        const expiresRaw = $('key-expires').value;
        const expiresAt  = expiresRaw ? new Date(expiresRaw).getTime() : undefined;

        const server   = [...document.querySelectorAll('input[name="ks"]:checked')].map(c => c.value);
        const personal = [...document.querySelectorAll('input[name="kps"]:checked')].map(c => c.value);

        const projMap  = {};
        for (const c of document.querySelectorAll('input[name="kp"]:checked')) {
            const [projectId, scope] = c.value.split('::');
            (projMap[projectId] ??= []).push(scope);
        }
        const projects = Object.entries(projMap).map(([projectId, scopes]) => ({ projectId, scopes }));

        const result = await authClient.createApiKey({
            name,
            grants: { server, personal, projects },
            expiresAt,
        });

        hideModal();

        // Show raw key — only opportunity
        const rawKey = result.key;
        showModal('Key Created — Copy Now', `
            <p>This key will <strong>not</strong> be shown again.</p>
            <div class="code-block" id="new-key-value">${esc(rawKey)}</div>
            <button id="copy-key-btn" class="btn-ghost btn-sm mt-copy">Copy to Clipboard</button>
        `, async () => { hideModal(); await loadApiKeys(); }, true);

        setTimeout(() => {
            const btn = $('copy-key-btn');
            if (btn) btn.onclick = () => navigator.clipboard.writeText(rawKey)
                .then(() => alert('Copied!'))
                .catch(() => alert('Copy failed — select the key manually.'));
        }, 0);
    });
};

// ── Admin ──────────────────────────────────────────────────────────

$('admin-btn').onclick = async () => {
    $('admin-overlay').classList.remove('hidden');
    await loadAdminUsers();
};

$('close-admin-btn').onclick = () => $('admin-overlay').classList.add('hidden');

$('admin-overlay').addEventListener('click', e => {
    if (e.target === $('admin-overlay')) $('admin-overlay').classList.add('hidden');
});

document.querySelectorAll('.tab[data-admin-tab]').forEach(btn => {
    btn.onclick = async () => {
        document.querySelectorAll('.tab[data-admin-tab]').forEach(b => b.classList.toggle('active', b === btn));
        const tab = btn.dataset.adminTab;
        $('admin-users-panel').classList.toggle('hidden',    tab !== 'users');
        $('admin-projects-panel').classList.toggle('hidden', tab !== 'projects');
        if (tab === 'users')    await loadAdminUsers();
        else                    await loadAdminProjects();
    };
});

async function loadAdminUsers() {
    try {
        const data  = await api('GET', '/admin/users');
        const users = data.users || [];
        const list  = $('admin-users-list');

        if (users.length === 0) {
            list.innerHTML = '<div class="empty-msg">No users.</div>';
            return;
        }

        list.innerHTML = users.map(u => `
            <div class="list-item">
                <div class="item-info">
                    <div class="item-title">
                        #${esc(u.id)} ${esc(u.email)}
                        ${u.id === state.user?.id ? '<span class="badge-you">you</span>' : ''}
                    </div>
                    <div class="item-meta">
                        ${u.display_name ? esc(u.display_name) + ' &nbsp;·&nbsp; ' : ''}
                        Joined ${fmtDate(u.created_at)}
                    </div>
                </div>
                ${u.id !== state.user?.id
                    ? `<button class="btn-danger btn-xs delete-user-btn" data-id="${u.id}" data-email="${esc(u.email)}">Delete</button>`
                    : ''}
            </div>
        `).join('');

        list.querySelectorAll('.delete-user-btn').forEach(btn => {
            btn.onclick = () => deleteAdminUser(Number(btn.dataset.id), btn.dataset.email);
        });
    } catch (err) {
        $('admin-users-list').innerHTML = `<div class="error-msg">${esc(err.message)}</div>`;
    }
}

async function deleteAdminUser(userId, email) {
    if (!confirm(`Delete user ${email}?\nThis will orphan any projects they own.`)) return;
    try {
        const result = await api('DELETE', `/admin/users/${userId}`);
        if (result.warnings?.length) {
            alert('User deleted.\n\nWarnings:\n' + result.warnings.map(w => '• ' + w.message).join('\n'));
        }
        await loadAdminUsers();
    } catch (err) {
        alert(err.message);
    }
}

async function loadAdminProjects() {
    try {
        const data     = await api('GET', '/admin/projects');
        const projects = data.projects || [];
        const list     = $('admin-projects-list');

        if (projects.length === 0) {
            list.innerHTML = '<div class="empty-msg">No projects.</div>';
            return;
        }

        list.innerHTML = projects.map(p => `
            <div class="list-item">
                <div class="item-info">
                    <div class="item-title">${esc(p.name)}</div>
                    <div class="item-meta">
                        ID: <code>${esc(p.id)}</code> &nbsp;·&nbsp;
                        Owner: ${p.owner_id ? '#' + p.owner_id : '<em>none</em>'} &nbsp;·&nbsp;
                        Created ${fmtDate(p.created_at)}
                    </div>
                </div>
            </div>
        `).join('');
    } catch (err) {
        $('admin-projects-list').innerHTML = `<div class="error-msg">${esc(err.message)}</div>`;
    }
}

// ── Modal ──────────────────────────────────────────────────────────

let _confirmFn = null;

function showModal(title, bodyHtml, onConfirm, infoOnly = false) {
    $('modal-title').textContent  = title;
    $('modal-body').innerHTML     = bodyHtml;
    $('modal-overlay').classList.remove('hidden');
    _confirmFn = onConfirm;
    $('modal-cancel').classList.toggle('hidden', infoOnly);
    $('modal-confirm').textContent = infoOnly ? 'Close' : 'Confirm';
}

function hideModal() {
    $('modal-overlay').classList.add('hidden');
    _confirmFn = null;
}

$('modal-confirm').onclick = async () => {
    try {
        if (_confirmFn) await _confirmFn();
        else hideModal();
    } catch (err) {
        alert(err.message);
    }
};

$('modal-cancel').onclick  = hideModal;
$('modal-overlay').addEventListener('click', e => {
    if (e.target === $('modal-overlay')) hideModal();
});

// ── Start ──────────────────────────────────────────────────────────

window.showView  = showView;
window.hideModal = hideModal;

init();
