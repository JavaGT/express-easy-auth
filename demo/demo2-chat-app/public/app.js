/**
 * Easy Auth Chat - Frontend App
 * Demonstrates EasyAuthClient integration within a multi-channel SPA.
 */

import { EasyAuthClient } from '/auth/client.js';

const client = new EasyAuthClient({ apiBase: '/auth' });
let currentUser = null;
let currentRoom = null;
let pollInterval = null;

// -- DOM Elements --
const views = ['login-view', 'signup-view', 'verify-view', 'chat-view'];
const state = {
    rooms: [],
    messages: []
};

// -- Navigation --
function showView(viewId) {
    views.forEach(v => document.getElementById(v).classList.add('hidden'));
    document.getElementById(viewId).classList.remove('hidden');
    
    // Cleanup polling if leaving chat
    if (viewId !== 'chat-view' && pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
    }
}

// -- Auth Handlers --
async function checkSession() {
    try {
        const me = await client.me();
        if (me.success) {
            currentUser = me.user;
            document.getElementById('user-display-name').textContent = currentUser.display_name || currentUser.email;
            showView('chat-view');
            loadRooms();
        } else {
            showView('login-view');
        }
    } catch (err) {
        showView('login-view');
    }
}

document.getElementById('login-form').onsubmit = async (e) => {
    e.preventDefault();
    const identifier = document.getElementById('login-identifier').value;
    const password = document.getElementById('login-password').value;
    try {
        const result = await client.login(identifier, password);
        if (result.success) {
            location.reload();
        }
    } catch (err) {
        alert('Login failed: ' + err.message);
    }
};

document.getElementById('signup-form').onsubmit = async (e) => {
    e.preventDefault();
    const email = document.getElementById('signup-email').value;
    const password = document.getElementById('signup-password').value;
    const displayName = document.getElementById('signup-displayname').value;
    try {
        const result = await fetch('/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password, displayName })
        });
        const data = await result.json();
        if (data.success) {
            showView('verify-view');
        } else {
            alert('Signup failed: ' + data.error);
        }
    } catch (err) {
        alert('Signup failed: ' + err.message);
    }
};

document.getElementById('verify-form').onsubmit = async (e) => {
    e.preventDefault();
    const code = document.getElementById('verify-code').value;
    // In a real app, you'd call a verification endpoint.
    // In this demo, verifying means just logging in now that the account is created.
    alert('Account verified! Please login.');
    showView('login-view');
};

document.getElementById('logout-btn').onclick = async () => {
    await client.logout();
    location.reload();
};

// -- Chat Logic --
async function loadRooms() {
    try {
        const res = await fetch('/api/v1/rooms', {
            headers: { 'Authorization': `Bearer ${client.sessionToken}` }
        });
        const data = await res.json();
        state.rooms = data.rooms || [];
        renderRooms();
    } catch (err) {
        console.error('Failed to load rooms', err);
    }
}

function renderRooms() {
    const list = document.getElementById('rooms-list');
    list.innerHTML = '';
    state.rooms.forEach(room => {
        const li = document.createElement('li');
        li.className = 'room-item' + (currentRoom?.id === room.id ? ' active' : '');
        li.textContent = '# ' + room.name;
        li.onclick = () => selectRoom(room);
        list.appendChild(li);
    });
}

function selectRoom(room) {
    currentRoom = room;
    document.getElementById('current-room-name').textContent = '# ' + room.name;
    document.getElementById('room-actions').classList.remove('hidden');
    document.getElementById('message-form').classList.remove('hidden');
    renderRooms();
    loadMessages();
    
    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(loadMessages, 2000);
}

async function loadMessages() {
    if (!currentRoom) return;
    try {
        const res = await fetch(`/api/v1/messages/${currentRoom.id}`, {
            headers: { 'Authorization': `Bearer ${client.sessionToken}` }
        });
        const data = await res.json();
        const messages = data.messages || [];
        
        // Only re-render if count changed
        if (messages.length !== state.messages.length) {
            state.messages = messages;
            renderMessages();
        }
    } catch (err) {
        console.error('Failed to load messages', err);
    }
}

function renderMessages() {
    const container = document.getElementById('messages-container');
    container.innerHTML = '';
    state.messages.forEach(msg => {
        const div = document.createElement('div');
        div.className = 'message';
        div.innerHTML = `
            <div class="message-meta">${msg.user_email} • ${new Date(msg.sent_at).toLocaleTimeString()}</div>
            <div class="message-body">${msg.body}</div>
        `;
        container.appendChild(div);
    });
    container.scrollTop = container.scrollHeight;
}

document.getElementById('message-form').onsubmit = async (e) => {
    e.preventDefault();
    const input = document.getElementById('message-input');
    const body = input.value;
    if (!body || !currentRoom) return;

    try {
        const res = await fetch(`/api/v1/messages/${currentRoom.id}`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${client.sessionToken}`
            },
            body: JSON.stringify({ body })
        });
        if (res.ok) {
            input.value = '';
            loadMessages();
        }
    } catch (err) {
        console.error('Failed to send message', err);
    }
};

// -- Room Creation --
document.getElementById('create-room-btn').onclick = () => {
    showModal('New Room', `
        <input type="text" id="new-room-name" placeholder="Room Name" style="width:100%; padding:0.8rem; margin-top:1rem; border-radius:0.5rem; background:#0f172a; border:1px solid #334155; color:white;">
    `, async () => {
        const name = document.getElementById('new-room-name').value;
        if (!name) return;
        const res = await fetch('/api/v1/rooms', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${client.sessionToken}`
            },
            body: JSON.stringify({ name })
        });
        const data = await res.json();
        if (data.success) {
            loadRooms();
            hideModal();
        }
    });
};

// -- Bot Management --
document.getElementById('show-bots-btn').onclick = async () => {
    document.getElementById('bots-sidebar').classList.toggle('hidden');
    loadBots();
};

document.getElementById('close-bots-btn').onclick = () => {
    document.getElementById('bots-sidebar').classList.add('hidden');
};

async function loadBots() {
    try {
        const res = await fetch('/api/v1/bots', {
            headers: { 'Authorization': `Bearer ${client.sessionToken}` }
        });
        const data = await res.json();
        const list = document.getElementById('bots-list');
        list.innerHTML = '';
        data.bots.forEach(bot => {
            const div = document.createElement('div');
            div.style.padding = '0.5rem 0';
            div.style.borderBottom = '1px solid #334155';
            div.innerHTML = `<span style="color:#38bdf8">🤖 ${bot.name}</span>`;
            list.appendChild(div);
        });
    } catch (err) {}
}

document.getElementById('create-bot-btn').onclick = () => {
    showModal('Create Bot Key', `
        <p>This will require "Fresh Auth". If prompted, please re-authenticate.</p>
        <input type="text" id="bot-name" placeholder="Bot Name" style="width:100%; padding:0.8rem; margin-top:1rem; border-radius:0.5rem; background:#0f172a; border:1px solid #334155; color:white;">
    `, async () => {
        const name = document.getElementById('bot-name').value;
        try {
            const res = await fetch(`/api/v1/bots/${currentRoom.id}`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${client.sessionToken}`
                },
                body: JSON.stringify({ name })
            });
            const data = await res.json();
            
            // If using older version where user is returned vs object in error
            if (res.status === 401 && (data.error === 'FRESH_AUTH_REQUIRED' || data.error?.type === 'FRESH_AUTH_REQUIRED')) {
                alert('Account protection active: Please logout and login again to create a bot (Step-up auth sim).');
                return;
            }

            if (data.success) {
                showModal('Bot Created', `
                    <p>API Key (Copy this!):</p>
                    <div class="code-block">${data.apiKey}</div>
                `, () => hideModal(), true);
                loadBots();
            } else {
                alert('Failed to create bot: ' + data.error);
            }
        } catch (err) {
            alert('Error: ' + err.message);
        }
    });
};

// -- Modal System --
function showModal(title, content, onConfirm, singleAction = false) {
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-content').innerHTML = content;
    document.getElementById('modal-container').classList.remove('hidden');
    
    const confirmBtn = document.getElementById('modal-confirm');
    const cancelBtn = document.getElementById('modal-cancel');
    
    confirmBtn.onclick = onConfirm;
    if (singleAction) {
        cancelBtn.classList.add('hidden');
        confirmBtn.textContent = 'Close';
    } else {
        cancelBtn.classList.remove('hidden');
        confirmBtn.textContent = 'Confirm';
        cancelBtn.onclick = hideModal;
    }
}

window.showView = showView;
window.hideModal = hideModal;

function hideModal() {
    document.getElementById('modal-container').classList.add('hidden');
}

// Init
checkSession();
