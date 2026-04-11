/**
 * Example 04: TOTP 2FA
 * 
 * Demonstrates the full lifecycle of setting up and using TOTP 2FA.
 */

import express from 'express';
import session from 'express-session';
import { 
  setupAuth, 
  authRouter, 
  SQLiteSessionStore, 
  requireAuth,
  requireFreshAuth
} from '../src/index.js';

const app = express();
app.use(express.json());

setupAuth(app, {
  dataDir: './data-example',
  config: { domain: 'localhost' }
});

app.use(session({
  secret: 'totp-secret',
  store: new SQLiteSessionStore(),
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

// 1. Mount Auth (Unified Router)
app.use('/api/v1/auth', authRouter);

// 1. Initial login (Password only)
// POST /api/auth/login

// 2. Setup 2FA (Requires valid session)
// POST /api/auth/2fa/setup -> Returns { secret, qrCode }

// 3. Verify Setup (Enables 2FA for the account)
// POST /api/auth/2fa/verify-setup { token: "123456" }

// 4. Test Fresh Auth (Protecting sensitive actions)
// requireFreshAuth ensures the user has authed within the last few minutes
app.post('/api/user/delete-account', requireAuth, requireFreshAuth, (req, res) => {
  res.json({ success: true, message: 'Sensitive action authorized' });
});

app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Auth SDK Demo - TOTP 2FA</title></head>
    <body style="font-family: sans-serif; padding: 2rem; background: #fff5f5;">
      <h1>Auth SDK Demo: TOTP 2FA</h1>
      <p>This page demonstrates <b>TOTP</b> (Authenticator App) setup via the SDK.</p>
      <div id="status">Checking status...</div>
      <hr>
      <div id="controls">
        <button id="loginBtn">1. Login</button>
        <button id="setupBtn">2. Setup 2FA</button>
      </div>
      <div id="qrArea" style="margin: 1rem 0; display: none;">
        <p>Scan this QR code in your app (Google Authenticator, etc):</p>
        <img id="qrImg" src="" style="border: 1px solid #ccc; padding: 10px;">
        <p>Then enter the token below:</p>
        <input type="text" id="tokenIn" placeholder="123456">
        <button id="verifyBtn">Verify & Enable</button>
      </div>

      <script type="module">
        import { AuthClient } from '/auth-sdk.js';
        const auth = new AuthClient();
        
        async function updateStatus() {
          const status = await auth.getStatus();
          document.getElementById('status').innerHTML = \`
            <strong>Authenticated:</strong> \${status.authenticated}<br>
            <strong>2FA Enabled:</strong> \${status.totpEnabled}<br>
            <strong>Current User:</strong> \${status.username || 'None'}
          \`;
        }

        document.getElementById('loginBtn').onclick = async () => {
          const u = 'totp_user_' + Math.floor(Math.random()*1000);
          try {
            await auth.register(u, u + '@example.com', 'password123');
            await auth.login(u, 'password123');
            alert('Logged in! Now setup 2FA.');
            await updateStatus();
          } catch (e) { alert(e.message); }
        };

        document.getElementById('setupBtn').onclick = async () => {
          try {
            const res = await auth.setup2FA();
            document.getElementById('qrImg').src = res.qrCode;
            document.getElementById('qrArea').style.display = 'block';
            alert('Scan the QR code!');
          } catch (e) { alert(e.message); }
        };

        document.getElementById('verifyBtn').onclick = async () => {
          const token = document.getElementById('tokenIn').value;
          try {
            await auth.verify2FASetup(token);
            alert('2FA Enabled Successfully!');
            document.getElementById('qrArea').style.display = 'none';
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
  console.log(`Example 04 running at http://localhost:${PORT}`);
});
