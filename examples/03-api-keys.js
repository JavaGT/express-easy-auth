/**
 * Example 03: API Keys
 * 
 * Demonstrates service-to-service authentication using API keys.
 */

import express from 'express';
import { setupAuth, authRouter, requireApiKey } from '../src/index.js';

const app = express();
app.use(express.json());

setupAuth(app, {
  dataDir: './data-example',
  config: { domain: 'localhost' }
});

// 1. Mount Auth router for identity management
app.use('/api/v1/auth', authRouter);

// 2. Protect routes with the requireApiKey middleware
// It looks for 'X-API-Key' or 'Authorization: Bearer <key>'
app.get('/api/v1/protected-data', requireApiKey, (req, res) => {
  // Authentication verified
  // req.userId is set to the owner of the key
  // req.permissions contains the key's allowed scopes
  
  res.json({
    success: true,
    message: 'Accessed via API key',
    owner: req.userId,
    permissions: req.permissions
  });
});

// 3. Granular permission check
app.post('/api/v1/write-data', requireApiKey, (req, res) => {
  if (!req.permissions.includes('action:write')) {
    return res.status(403).json({ error: 'Key lacks action:write permission' });
  }
  
  res.json({ success: true, message: 'Write operation authorized' });
});

app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Auth SDK Demo - API Keys</title></head>
    <body style="font-family: sans-serif; padding: 2rem; background: #eef2ff;">
      <h1>Auth SDK Demo: API Keys</h1>
      <p>This page demonstrates API key lifecycle management via the SDK.</p>
      
      <div id="controls">
        <button id="loginBtn">1. Login as Admin</button>
        <button id="createKeyBtn">2. Create API Key</button>
        <button id="testKeyBtn">3. Test Created Key</button>
      </div>
      <hr>
      <div id="output" style="background: #333; color: #fff; padding: 1rem; border-radius: 4px; font-family: monospace; min-height: 100px; white-space: pre-wrap;">Console Output...</div>

      <script type="module">
        import { AuthClient } from '/auth-sdk.js';
        const auth = new AuthClient();
        let lastKey = null;

        const log = (msg) => {
          document.getElementById('output').innerText += '\\n> ' + msg;
        };

        document.getElementById('loginBtn').onclick = async () => {
          try {
            // Ensure a user exists first
            await auth.register('api_admin', 'api@example.com', 'admin123').catch(() => {});
            await auth.login('api_admin', 'admin123');
            log('Logged in as api_admin');
          } catch (e) { log('Login Error: ' + e.message); }
        };

        document.getElementById('createKeyBtn').onclick = async () => {
          try {
            const res = await auth.createApiKey('Demo Key', ['action:read']);
            lastKey = res.key;
            log('Key Created: ' + lastKey);
          } catch (e) { log('Error: ' + e.message); }
        };

        document.getElementById('testKeyBtn').onclick = async () => {
          if (!lastKey) return alert('Create a key first!');
          try {
            const res = await fetch('/api/v1/protected-data', {
              headers: { 'X-API-Key': lastKey }
            });
            const data = await res.json();
            log('Test Result: ' + JSON.stringify(data));
          } catch (e) { log('Test Error: ' + e.message); }
        };
      </script>
    </body>
    </html>
  `);
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Example 03 running at http://localhost:${PORT}`);
  console.log(`- Request with: curl -H "X-API-Key: YOUR_KEY" http://localhost:${PORT}/api/v1/protected-data`);
});
