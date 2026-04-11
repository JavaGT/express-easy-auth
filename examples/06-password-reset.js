/**
 * Example 06: Password Reset
 * 
 * Demonstrates the full flow of requesting a reset token and resetting a password.
 */

import express from 'express';
import session from 'express-session';
import { 
  setupAuth, 
  authRouter, 
  SQLiteSessionStore, 
  authDb 
} from '../src/index.js';

const app = express();
app.use(express.json());

setupAuth(app, {
  dataDir: './data-example-reset',
  exposeErrors: true,
  config: { domain: 'localhost' }
});

app.use(session({
  secret: 'reset-secret',
  store: new SQLiteSessionStore(),
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

// Standard mount point
app.use('/api/v1/auth', authRouter);

app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Auth SDK Demo - Password Reset</title></head>
    <body style="font-family: sans-serif; padding: 2rem; background: #f0fdf4;">
      <h1>Auth SDK Demo: Password Reset</h1>
      <p>This demo shows how to request a reset token and use it to change a password.</p>
      
      <div id="controls">
        <button id="regBtn">1. Register User (user_reset)</button>
        <button id="forgotBtn">2. Forgot Password</button>
      </div>
      
      <div id="resetArea" style="margin-top: 2rem; display: none; background: #fff; padding: 1.5rem; border: 1px solid #dcfce7; border-radius: 8px;">
        <h3>Reset Password</h3>
        <p>A token was generated in the database (simulating an email).</p>
        <input type="text" id="tokenIn" placeholder="Enter Token">
        <input type="password" id="passIn" placeholder="New Password">
        <button id="resetBtn">3. Reset Password</button>
      </div>

      <hr>
      <div id="output" style="background: #333; color: #fff; padding: 1rem; border-radius: 4px; font-family: monospace; min-height: 100px; white-space: pre-wrap;">Console Output...</div>

      <script type="module">
        import { AuthClient } from '/auth-sdk.js';
        const auth = new AuthClient();
        
        const log = (msg) => {
          document.getElementById('output').innerText += '\\n> ' + msg;
        };

        document.getElementById('regBtn').onclick = async () => {
          try {
            await auth.register('user_reset', 'reset@example.com', 'oldpassword');
            log('User registered with password: oldpassword');
          } catch (e) { log('Error: ' + e.message); }
        };

        document.getElementById('forgotBtn').onclick = async () => {
          try {
            log('Requesting reset for user_reset...');
            const res = await auth.forgotPassword('user_reset');
            log('Request success! Check the server logs (or DB) for the token.');
            document.getElementById('resetArea').style.display = 'block';
          } catch (e) { log('Error: ' + e.message); }
        };

        document.getElementById('resetBtn').onclick = async () => {
          const token = document.getElementById('tokenIn').value;
          const pass = document.getElementById('passIn').value;
          try {
            await auth.resetPassword(token, pass);
            log('Password successfully reset! You can now login with the new password.');
            document.getElementById('resetArea').style.display = 'none';
          } catch (e) { log('Error: ' + e.message); }
        };
      </script>
    </body>
    </html>
  `);
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Example 06 running at http://localhost:${PORT}`);
  console.log(`NOTE: In a real app, you would email the token to the user.`);
});
