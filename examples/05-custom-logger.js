/**
 * Example 05: Custom Logger
 * 
 * Shows how to plug in a custom logger implementation (e.g. for Winston or Pino)
 */

import express from 'express';
import { setupAuth, authRouter, DefaultLogger } from '../src/index.js';

const app = express();
app.use(express.json());

// 1. Define a custom logger
// It must implement: error, warn, info, debug
class MyCustomLogger {
  error(msg, meta) {
    console.log(`[MY-APP-ERROR] ${msg}`, meta.err?.stack || '');
    // You could send to Sentry, Datadog, etc. here
  }
  warn(msg, meta) { console.log(`[MY-APP-WARN] ${msg}`); }
  info(msg, meta) { console.log(`[MY-APP-INFO] ${msg}`); }
  debug(msg, meta) { console.log(`[MY-APP-DEBUG] ${msg}`); }
}

// 2. Or extend the DefaultLogger to keep DB logging but change console output
class EnhancedLogger extends DefaultLogger {
  info(msg, meta) {
    super.info(msg, meta); // Keep default behavior (DB + Console)
    console.log('--- Custom log decorator ---');
  }
}

// 3. Initialize with custom logger
setupAuth(app, {
  dataDir: './data-example',
  exposeErrors: true, // Always show details for this demo
  logger: new MyCustomLogger(), // Plug in your implementation
  config: { domain: 'localhost' }
});

// Standard mount point
app.use('/api/v1/auth', authRouter);

// Test route to trigger an error
app.get('/test-error', (req, res, next) => {
  next(new Error('This is a simulated system error'));
});

// Import the error logger middleware last!
import { authErrorLogger } from '../src/index.js';
app.use(authErrorLogger);

app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Auth SDK Demo - Custom Logger</title></head>
    <body style="font-family: sans-serif; padding: 2rem; background: #fafafa;">
      <h1>Auth SDK Demo: Custom Logger</h1>
      <p>This page demonstrates how the SDK interacts with a custom server-side logger.</p>
      
      <div id="controls">
        <button id="triggerErrorBtn">1. Trigger Server Error (500)</button>
        <button id="reportBtn">2. Manually Report SDK Error</button>
      </div>
      <hr>
      <div id="output" style="background: #333; color: #fff; padding: 1rem; border-radius: 4px; font-family: monospace; min-height: 100px; white-space: pre-wrap;">Console Output...</div>
      <p><small>Check the <b>Node.js terminal</b> to see the [MY-APP-ERROR] logs!</small></p>

      <script type="module">
        import { AuthClient } from '/auth-sdk.js';
        const auth = new AuthClient();

        const log = (msg) => {
          document.getElementById('output').innerText += '\\n> ' + msg;
        };

        document.getElementById('triggerErrorBtn').onclick = async () => {
          try {
            log('Fetching /test-error...');
            const res = await fetch('/test-error');
            const data = await res.json();
            log('Server matched error: ' + JSON.stringify(data));
          } catch (e) { log('Fetch error: ' + e.message); }
        };

        document.getElementById('reportBtn').onclick = async () => {
          try {
            log('Reporting client-side error to server...');
            await auth.reportError(new Error('Something went wrong on the client!'), { 
              browser: navigator.userAgent 
            });
            log('Error reported successfully!');
          } catch (e) { log('Report Error: ' + e.message); }
        };
      </script>
    </body>
    </html>
  `);
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Example 05 running at http://localhost:${PORT}`);
});
