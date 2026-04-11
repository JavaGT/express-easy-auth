/**
 * Example 08: External Database Linking
 * 
 * Demonstrates the "contained identity" model: 
 * Auth server handles identity, while your app database handles profile data.
 */

import express from 'express';
import session from 'express-session';
import { DatabaseSync } from 'node:sqlite';
import { 
  setupAuth, 
  authRouter, 
  SQLiteSessionStore, 
  requireAuth,
  AuthClient 
} from '../src/index.js';

const app = express();
app.use(express.json());

// ─── 1. SETUP AUTH SERVER ────────────────────────────────────────────────────
setupAuth(app, {
  dataDir: './data-example-external',
  config: { domain: 'localhost' }
});

app.use(session({
  secret: 'external-db-secret',
  store: new SQLiteSessionStore(),
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

// Standard mount point
app.use('/api/v1/auth', authRouter);

// ─── 2. SETUP APPLICATION DATABASE (Managed by Developer) ────────────────────
const appDataDb = new DatabaseSync('./data-example-external/app_data.db');
appDataDb.exec(`
  CREATE TABLE IF NOT EXISTS user_profiles (
    user_id TEXT PRIMARY KEY,
    bio TEXT,
    website TEXT,
    theme TEXT DEFAULT 'light'
  )
`);

const getProfile = appDataDb.prepare('SELECT * FROM user_profiles WHERE user_id = ?');
const upsertProfile = appDataDb.prepare(`
  INSERT INTO user_profiles (user_id, bio, website) 
  VALUES (?, ?, ?)
  ON CONFLICT(user_id) DO UPDATE SET bio=excluded.bio, website=excluded.website
`);

// ─── 3. APP ROUTES (Combining Identity + Data) ───────────────────────────────

// Get merged profile (Auth Identity + App Data)
app.get('/api/app/profile', requireAuth, async (req, res) => {
  // req.userId comes from the Auth Server middleware
  const profile = getProfile.get(req.userId) || { bio: '', website: '' };
  
  res.json({
    userId: req.userId,
    username: req.session.user.username, // From session
    ...profile
  });
});

// Update app-specific data
app.post('/api/app/profile', requireAuth, (req, res) => {
  const { bio, website } = req.body;
  upsertProfile.run(req.userId, bio, website);
  res.json({ success: true });
});

app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Auth SDK Demo - External DB</title></head>
    <body style="font-family: sans-serif; padding: 2rem; background: #f8fafc;">
      <h1>Auth SDK Demo: External DB Linking</h1>
      <p>This demo shows how to keep Identity (Auth Server) separate from Application Data.</p>
      
      <div id="status">Checking Auth...</div>
      <hr>
      
      <div id="profileSection" style="display:none; background:white; padding:1.5 val rem; border:1px solid #e2e8f0; border-radius:8px; max-width:400px;">
        <h3>Your Profile (App Data)</h3>
        <p>User ID: <span id="uidDisplay"></span></p>
        <div style="margin-bottom:1rem">
          <label>Bio:</label><br>
          <textarea id="bioInput" style="width:100%"></textarea>
        </div>
        <div style="margin-bottom:1rem">
          <label>Website:</label><br>
          <input type="text" id="webInput" style="width:100%">
        </div>
        <button id="saveBtn">Save App Data</button>
      </div>

      <div id="authSection" style="display:none;">
        <button id="loginBtn">Login / Register</button>
      </div>

      <script type="module">
        import { AuthClient } from '/auth-sdk.js';
        const auth = new AuthClient();
        
        async function init() {
          const status = await auth.getStatus();
          if (status.authenticated) {
            document.getElementById('profileSection').style.display = 'block';
            document.getElementById('uidDisplay').innerText = status.userId;
            
            // Fetch app data
            const res = await fetch('/api/app/profile');
            const profile = await res.json();
            document.getElementById('bioInput').value = profile.bio;
            document.getElementById('webInput').value = profile.website;
            document.getElementById('status').innerText = 'Logged in as ' + status.username;
          } else {
            document.getElementById('authSection').style.display = 'block';
            document.getElementById('status').innerText = 'Not logged in';
          }
        }

        document.getElementById('loginBtn').onclick = async () => {
          const u = 'db_user_' + Math.floor(Math.random()*1000);
          await auth.register(u, u+'@example.com', 'password123').catch(()=>{});
          await auth.login(u, 'password123');
          location.reload();
        };

        document.getElementById('saveBtn').onclick = async () => {
          const bio = document.getElementById('bioInput').value;
          const website = document.getElementById('webInput').value;
          await fetch('/api/app/profile', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ bio, website })
          });
          alert('Saved to App Database!');
        };

        init();
      </script>
    </body>
    </html>
  `);
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Example 08 running at http://localhost:${PORT}`);
});
