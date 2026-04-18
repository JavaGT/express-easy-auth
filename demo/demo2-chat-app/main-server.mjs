import express from 'express';
import { AuthManager, ConsoleContactAdaptor, SQLiteAdaptor, EasyAuth } from '../../src/router/auth/auth.mjs';
import router_api from './api/main.mjs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// 1. Initialize AuthManager
const consoleContact = new ConsoleContactAdaptor();
const authManager = new AuthManager({
    databaseAdapter: SQLiteAdaptor,
    databasePath: path.join(__dirname, 'data/auth.db'),
    mkdirp: true,
    contactAdaptors: [consoleContact],
    webAuthn: {
        rpName: 'Easy Auth Chat Demo',
        rpID: 'localhost',
        origin: 'http://localhost:3001'
    },
    // Define Chat permissions taxonomy
    scopes: [
        { 
            name: 'room', 
            children: [
                { name: 'read' },
                { name: 'send' },
                { name: 'manage' }
            ]
        }
    ]
});

await authManager.init();

// 2. Initialize Chat Domain Database
const chatDbPath = path.join(__dirname, 'data/chat.db');
const chatDb = new DatabaseSync(chatDbPath);

chatDb.exec(`
    CREATE TABLE IF NOT EXISTS rooms (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        owner_user_id INTEGER NOT NULL,
        created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS memberships (
        room_id TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        role TEXT CHECK(role IN ('member', 'moderator', 'owner')),
        PRIMARY KEY (room_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY,
        room_id TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        user_email TEXT NOT NULL,
        body TEXT NOT NULL,
        sent_at INTEGER NOT NULL
    );
`);

const app = express();

// 3. Mount Easy Auth
const authMiddleware = EasyAuth.attach(app, authManager, { basePath: '/auth' });

// Add Rate Limiting to auth routes
app.use('/auth', authMiddleware.rateLimit({ max: 5, windowMs: 60000 }));

// Inject dependencies into request
app.use((req, res, next) => {
    req.authManager = authManager;
    req.authMiddleware = authMiddleware;
    req.chatDb = chatDb;
    next();
});

app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Routes
app.use('/api/v1', router_api);

// Global error handler
app.use((err, req, res, next) => {
    console.error('[SERVER ERROR]', err);
    const statusCode = err.code || 500;
    res.status(statusCode).json({
        error: err.type || 'SERVER_ERROR',
        message: err.message || 'An unexpected error occurred'
    });
});

const PORT = 3001;
app.listen(PORT, () => {
    console.log(`Easy Auth Chat Demo running at http://localhost:${PORT}`);
    console.log('OpenAPI Spec available at http://localhost:3001/auth/openapi.json');
});
