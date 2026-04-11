/**
 * Example 01: Basic setup
 * 
 * Demonstrates how to initialize the auth library and protect a basic route.
 */

import express from 'express';
import session from 'express-session';
// In your app, use: import { setupAuth, authRouter, SQLiteSessionStore, requireAuth } from 'auth-server';
import { 
  setupAuth, 
  authRouter, 
  SQLiteSessionStore, 
  requireAuth,
  AuthClient 
} from '../src/index.js';

const app = express();

// 1. JSON Middleware is required for API routes
app.use(express.json());

// 2. Initialize the Library
setupAuth(app, {
  dataDir: './data-example', // Directory for SQLite DBs
  exposeErrors: process.env.NODE_ENV !== 'production', // Explicit debug setting
  config: {
    domain: 'localhost',
    rpName: 'Basic Example App',
    rpID: 'localhost',
    origin: 'http://localhost:3000'
  }
});

// 3. Configure Sessions
// The library provides SQLiteSessionStore which is optimized for auth-server
app.use(session({
  secret: 'keyboard-cat-secret',
  store: new SQLiteSessionStore(),
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // 'true' in production with HTTPS
}));

// 1. Mount Auth (Unified Router)
app.use('/api/v1/auth', authRouter);

// 5. Protect your routes
app.get('/dashboard', requireAuth, (req, res) => {
  res.json({
    message: 'Access granted!',
    userId: req.userId,
    sessionID: req.sessionID
  });
});

// 6. Client-side SDK Demo
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Auth SDK Demo - Basic</title></head>
    <body style="font-family: sans-serif; padding: 2rem; background: #f4f4f9;">
      <h1>Auth SDK Demo: Basic Setup</h1>
      <p>This page uses the <b>AuthClient</b> SDK to interact with the backend.</p>
      <div id="status">Checking status...</div>
      <hr>
      <button id="regBtn">Register Demo User</button>
      <button id="loginBtn">Login Demo User</button>
      <button id="logoutBtn">Logout</button>
      
      <script type="module">
        import { AuthClient } from '/auth-sdk.js';
        const auth = new AuthClient();
        
        async function updateStatus() {
          const status = await auth.getStatus();
          document.getElementById('status').innerText = 'Authenticated: ' + status.authenticated + (status.username ? ' (' + status.username + ')' : '');
          console.log('Current Status:', status);
        }

        document.getElementById('regBtn').onclick = async () => {
          const username = 'user_' + Math.floor(Math.random()*1000);
          try {
            const res = await auth.register(username, username + '@example.com', 'password123');
            alert('Registered: ' + username);
            await updateStatus();
          } catch (e) { alert('Error: ' + e.message); }
        };

        document.getElementById('loginBtn').onclick = async () => {
          const username = prompt('Username?');
          try {
            await auth.login(username, 'password123');
            alert('Logged in!');
            await updateStatus();
          } catch (e) { alert('Error: ' + e.message); }
        };

        document.getElementById('logoutBtn').onclick = async () => {
          await auth.logout();
          alert('Logged out');
          await updateStatus();
        };

        updateStatus();
      </script>
    </body>
    </html>
  `);
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Example 01 running at http://localhost:${PORT}`);
  console.log(`- Try: GET http://localhost:${PORT}/api/v1/auth/status`);
  console.log(`- Try: GET http://localhost:${PORT}/dashboard (will return 401 until login)`);
});
