import express from 'express';
import { AuthManager, ConsoleContactAdaptor, SQLiteAdaptor, EasyAuth } from '../../src/router/auth/auth.mjs';
import router_api from './api/main.mjs';
import router_interface from './interface/main.mjs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const consoleContact = new ConsoleContactAdaptor();

const app = express();
const authManager = new AuthManager({
    databaseAdapter: SQLiteAdaptor,
    databasePath: path.join(__dirname, 'data/auth.db'),
    mkdirp: true,
    contactAdaptors: [consoleContact],
    webAuthn: {
        rpName: 'Easy Auth Demo',
        rpID: 'localhost',
        origin: 'http://localhost:3000'
    }
});

// Initialize auth system
await authManager.init();

// Simplify: Use EasyAuth facade
const authMiddleware = EasyAuth.attach(app, authManager, { basePath: '/auth' });

// Add Rate Limiting to sensitive auth routes (via the middleware we just got)
app.use('/auth', authMiddleware.rateLimit({ max: 10, windowMs: 60000 }));

// Simple request logger
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} ${res.statusCode} - ${duration}ms`);
    });
    next();
});

app.use((req, res, next) => {
    req.authManager = authManager;
    req.authMiddleware = authMiddleware;
    next();
});

app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.use('/api/v1', router_api);
app.use(router_interface);

app.listen(3000, () => {
    console.log('Easy Auth Demo Server running at http://localhost:3000');
    console.log('OpenAPI Spec available at http://localhost:3000/auth/openapi.json');
});
