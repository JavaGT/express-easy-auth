import express from 'express';
import { AuthManager, ConsoleContactAdaptor, SQLiteAdaptor, EasyAuth, AuthMiddleware } from '../../src/server.mjs';
import router_api from './api/main.mjs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
app.use(express.json({ limit: '10kb' }));

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
fs.mkdirSync(path.dirname(chatDbPath), { recursive: true });
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

// 3. Mount Easy Auth (mounts express-session internally)
const authMiddleware = EasyAuth.attach(app, authManager, {
    basePath: '/auth',
    session: { secret: process.env.SESSION_SECRET || 'chat-demo-secret-change-in-production' }
});

// Add Rate Limiting to auth routes
app.use('/auth', authMiddleware.rateLimit({ max: 5, windowMs: 60000 }));

// Inject dependencies into request
app.use((req, res, next) => {
    req.authManager = authManager;
    req.authMiddleware = authMiddleware;
    req.chatDb = chatDb;
    next();
});

app.use(express.static(path.join(__dirname, 'public')));

// Routes
app.use('/api/v1', router_api);

// Global error handler for API
app.use('/api', AuthMiddleware.errorHandler);

// Fallback error handler
app.use((err, req, res, next) => {
    console.error('[FATAL ERROR]', err);
    res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
});

const PORT = 3001;
app.listen(PORT, () => {
    console.log(`Easy Auth Chat Demo running at http://localhost:${PORT}`);
    console.log('OpenAPI Spec available at http://localhost:3001/auth/openapi.json');
});
