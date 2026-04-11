/**
 * Example 02: Passkeys (WebAuthn)
 * 
 * Demonstrates how to enable and manage biometric passkeys.
 */

import express from 'express';
import session from 'express-session';
import { 
  setupAuth, 
  authRouter, 
  SQLiteSessionStore, 
  requireAuth 
} from '../src/index.js';

const app = express();
app.use(express.json());

setupAuth(app, {
  dataDir: './data-example',
  config: {
    domain: 'localhost',
    rpName: 'Passkey Example',
    rpID: 'localhost',
    origin: 'http://localhost:3000'
  }
});

app.use(session({
  secret: 'passkey-secret',
  store: new SQLiteSessionStore(),
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

// 1. Mount Auth (Unified Router)
app.use('/api/v1/auth', authRouter);

// 2. The SDK will now automatically use /api/v1/auth/...

app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Auth SDK Demo - Passkeys</title></head>
    <body style="font-family: sans-serif; padding: 2rem; background: #fdf6e3;">
      <h1>Auth SDK Demo: Passkeys</h1>
      <p>This page demonstrates <b>WebAuthn</b> registration and login via the SDK.</p>
      <div id="status">Checking status...</div>
      <hr>
      <div id="controls">
        <button id="regBtn">1. Register Password Account</button>
        <button id="pkRegBtn">2. Register Passkey</button>
        <button id="pkLoginBtn">3. Login with Passkey</button>
      </div>

      <script type="module">
        import { AuthClient } from '/auth-sdk.js';
        const auth = new AuthClient();
        
        async function updateStatus() {
          const status = await auth.getStatus();
          document.getElementById('status').innerHTML = \`
            <strong>Authenticated:</strong> \${status.authenticated}<br>
            <strong>User ID:</strong> \${status.userId || 'None'}<br>
            <strong>Passkeys:</strong> \${status.passkeyCount || 0}
          \`;
        }

        document.getElementById('regBtn').onclick = async () => {
          const u = 'pk_user_' + Math.floor(Math.random()*1000);
          try {
            await auth.register(u, u + '@example.com', 'password123');
            alert('Created password account: ' + u + '. Now register a passkey!');
            await updateStatus();
          } catch (e) { alert(e.message); }
        };

        document.getElementById('pkRegBtn').onclick = async () => {
          try {
            await auth.registerPasskey('My Laptop');
            alert('Passkey Registered!');
            await updateStatus();
          } catch (e) { alert(e.message); }
        };

        document.getElementById('pkLoginBtn').onclick = async () => {
          try {
            const res = await auth.loginWithPasskey();
            alert('Logged in with Passkey!');
            await updateStatus();
          } catch (e) { alert(e.message); }
        };

        updateStatus();
      </script>
    </body>
    </html>
  `);
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Example 02 running at http://localhost:${PORT}`);
});
