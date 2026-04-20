/**
 * DocuFlow — express-easy-auth v4 reference demo.
 *
 * Demonstrates all three scope levels (server, personal, project) with both
 * session and API key authentication. Project membership is managed entirely
 * by DocuFlow's own database; the auth library only tracks ownership and
 * validates API key grants.
 *
 * Start: node demo/demo3-docuflow/server.mjs
 */

import express from 'express';
import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
    AuthManager,
    EasyAuth,
    AuthMiddleware,
    ConsoleContactAdaptor,
    SQLiteAdaptor,
} from '../../src/server.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR  = path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

// ---------------------------------------------------------------------------
// 1. Auth setup
// ---------------------------------------------------------------------------

const authManager = new AuthManager({
    databaseAdapter: SQLiteAdaptor,
    databasePath:    path.join(DATA_DIR, 'auth.db'),
    contactAdaptors: [new ConsoleContactAdaptor()],
    webAuthn: {
        rpName: 'DocuFlow',
        rpID:   'localhost',
        origin: 'http://localhost:3002',
    },
    serverScopes:  ['users.read', 'users.delete', 'projects.list'],
    projectScopes: ['docs:read', 'docs:write', 'docs:delete', 'members:read', 'members:manage'],
});

// ---------------------------------------------------------------------------
// 2. DocuFlow's own app database (project membership lives here)
// ---------------------------------------------------------------------------

const appDb = new DatabaseSync(path.join(DATA_DIR, 'docuflow.db'));
appDb.exec(`
    CREATE TABLE IF NOT EXISTS projects (
        id         TEXT PRIMARY KEY,
        name       TEXT NOT NULL,
        owner_id   INTEGER NOT NULL,
        created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS project_members (
        project_id  TEXT NOT NULL,
        user_id     INTEGER NOT NULL,
        permissions TEXT NOT NULL,
        PRIMARY KEY (project_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS documents (
        id         TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        title      TEXT NOT NULL,
        body       TEXT NOT NULL DEFAULT '',
        author_id  INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    );
`);

// ---------------------------------------------------------------------------
// 3. Express app
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json());

const auth = EasyAuth.attach(app, authManager, {
    basePath: '/auth',
    session:  { secret: process.env.SESSION_SECRET || 'docuflow-dev-secret' },
});

app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// 4. App middleware — load project permissions onto req
//
// This is the bridge between DocuFlow's membership model and the auth
// library's scope enforcement. It runs before auth.requireProjectAccess on
// any project route.
// ---------------------------------------------------------------------------

async function loadProjectPermissions(req, res, next) {
    const projectId = req.params.projectId ?? req.params.id ?? req.projectId;
    if (!projectId) return next(new Error('loadProjectPermissions: no projectId on req.params'));
    if (!req.user)  return next(new Error('loadProjectPermissions must run after requireAuth'));

    try {
        // Owners always have full access — auth library is authoritative for this.
        const isOwner = await authManager.isProjectOwner(projectId, req.user.id);
        if (isOwner) {
            req.projectPermissions = ['*'];
            return next();
        }

        // Non-owners: permissions come from DocuFlow's own table.
        const row = appDb.prepare(
            'SELECT permissions FROM project_members WHERE project_id = ? AND user_id = ?'
        ).get(projectId, req.user.id);

        req.projectPermissions = row ? JSON.parse(row.permissions) : [];
        next();
    } catch (err) {
        next(err);
    }
}

// ---------------------------------------------------------------------------
// 5. Server-scoped routes (admin)
// ---------------------------------------------------------------------------

// List all users — requires server scope users.read
app.get('/admin/users',
    auth.requireAuth,
    auth.requireServerScope('users.read'),
    async (req, res) => {
        const users = await authManager.listUsers();
        res.json({ users });
    }
);

// Delete a user — requires fresh session + users.delete
// Warns if the user owns projects.
app.delete('/admin/users/:id',
    auth.requireAuth,
    auth.requireFreshAuth,
    auth.requireServerScope('users.delete'),
    async (req, res, next) => {
        try {
            const result = await authManager.deleteUser(Number(req.params.id));

            if (result.warnings.length > 0) {
                for (const w of result.warnings) {
                    if (w.code === 'USER_OWNS_PROJECTS') {
                        // In production: trigger reassignment workflow.
                        // Here we just orphan them and return the warning.
                        console.warn('[DocuFlow] Orphaned projects after user delete:', w.projectIds);
                        appDb.prepare(
                            `UPDATE projects SET owner_id = 0 WHERE id IN (${w.projectIds.map(() => '?').join(',')})`
                        ).run(...w.projectIds);
                    }
                }
            }

            res.json(result);
        } catch (err) {
            next(err);
        }
    }
);

// Admin view of all projects
app.get('/admin/projects',
    auth.requireAuth,
    auth.requireServerScope('projects.list'),
    (req, res) => {
        const projects = appDb.prepare('SELECT * FROM projects ORDER BY created_at DESC').all();
        res.json({ projects });
    }
);

// ---------------------------------------------------------------------------
// 6. Personal routes
// ---------------------------------------------------------------------------

// Read own profile — session or API key with personal:profile.read
app.get('/me',
    auth.requireAuthOrApiKey,
    auth.requirePersonalScope('personal:profile.read'),
    (req, res) => res.json({ user: req.user })
);

// List own API keys — session or API key with personal:apikeys.read
app.get('/me/api-keys',
    auth.requireAuthOrApiKey,
    auth.requirePersonalScope('personal:apikeys.read'),
    async (req, res) => {
        const keys = await authManager.listApiKeys(req.user.id);
        res.json({ keys });
    }
);

// Create API key — session only (personal:apikeys.write blocks API key callers)
app.post('/me/api-keys',
    auth.requireAuthOrApiKey,
    auth.requirePersonalScope('personal:apikeys.write'),
    async (req, res, next) => {
        try {
            const { name, grants = {}, expiresAt } = req.body;

            // Recommended: validate project grants don't exceed user's current permissions.
            // The auth library enforces this via intersection at runtime anyway, but
            // catching it here gives a better error message.
            if (grants.projects?.length > 0) {
                for (const g of grants.projects) {
                    const isOwner = await authManager.isProjectOwner(g.projectId, req.user.id);
                    if (!isOwner) {
                        const membership = appDb.prepare(
                            'SELECT permissions FROM project_members WHERE project_id = ? AND user_id = ?'
                        ).get(g.projectId, req.user.id);
                        if (!membership) {
                            return res.status(403).json({ error: `Not a member of project ${g.projectId}` });
                        }
                        const perms    = JSON.parse(membership.permissions);
                        const exceeds  = g.scopes.filter(s => !perms.includes(s));
                        if (exceeds.length > 0) {
                            return res.status(403).json({
                                error:  `Scopes exceed your permissions on ${g.projectId}`,
                                scopes: exceeds,
                            });
                        }
                    }
                }
            }

            const result = await authManager.createApiKey(req.user.id, { name, grants, expiresAt });
            res.status(201).json({ success: true, ...result });
        } catch (err) {
            next(err);
        }
    }
);

// Revoke API key — session only
app.delete('/me/api-keys/:id',
    auth.requireAuth,
    async (req, res, next) => {
        try {
            await authManager.revokeApiKey(req.user.id, Number(req.params.id));
            res.json({ success: true });
        } catch (err) {
            next(err);
        }
    }
);

// Rename or update expiry — session only
app.patch('/me/api-keys/:id',
    auth.requireAuth,
    async (req, res, next) => {
        try {
            const { name, expiresAt } = req.body;
            await authManager.updateApiKey(req.user.id, Number(req.params.id), { name, expiresAt });
            res.json({ success: true });
        } catch (err) {
            next(err);
        }
    }
);

// ---------------------------------------------------------------------------
// 7. Project routes
// ---------------------------------------------------------------------------

// Create project — session only; registers ownership with auth library
app.post('/projects',
    auth.requireAuth,
    async (req, res, next) => {
        try {
            const { name } = req.body;
            const projectId = `proj_${randomUUID().replace(/-/g, '').slice(0, 16)}`;
            const now = Date.now();

            appDb.prepare(
                'INSERT INTO projects (id, name, owner_id, created_at) VALUES (?, ?, ?, ?)'
            ).run(projectId, name, req.user.id, now);

            // Sync ownership to auth library.
            // This is idempotent — safe to call on retry.
            await authManager.registerProject(projectId, req.user.id);

            res.status(201).json({ id: projectId, name, ownerId: req.user.id });
        } catch (err) {
            next(err);
        }
    }
);

// Delete project — owner only, fresh session
app.delete('/projects/:id',
    auth.requireAuth,
    auth.requireFreshAuth,
    auth.requireProjectOwner,
    async (req, res, next) => {
        try {
            const projectId = req.params.id;
            appDb.prepare('DELETE FROM documents WHERE project_id = ?').run(projectId);
            appDb.prepare('DELETE FROM project_members WHERE project_id = ?').run(projectId);
            appDb.prepare('DELETE FROM projects WHERE id = ?').run(projectId);
            await authManager.unregisterProject(projectId);
            res.json({ success: true });
        } catch (err) {
            next(err);
        }
    }
);

// Transfer ownership — owner only, fresh session
app.put('/projects/:id/owner',
    auth.requireAuth,
    auth.requireFreshAuth,
    auth.requireProjectOwner,
    async (req, res, next) => {
        try {
            const projectId   = req.params.id;
            const newOwnerId  = Number(req.body.newOwnerId);
            await authManager.transferProjectOwnership(projectId, newOwnerId);
            appDb.prepare('UPDATE projects SET owner_id = ? WHERE id = ?').run(newOwnerId, projectId);
            res.json({ success: true });
        } catch (err) {
            next(err);
        }
    }
);

// List documents — any member with docs:read, or API key declaring docs:read on this project
app.get('/projects/:id/docs',
    auth.requireAuthOrApiKey,
    loadProjectPermissions,
    auth.requireProjectAccess('docs:read'),
    (req, res) => {
        const docs = appDb.prepare('SELECT * FROM documents WHERE project_id = ?').all(req.params.id);
        res.json({ docs, effectiveScopes: req.effectiveProjectScopes });
    }
);

// Create document — needs docs:write
app.post('/projects/:id/docs',
    auth.requireAuthOrApiKey,
    loadProjectPermissions,
    auth.requireProjectAccess('docs:write'),
    (req, res, next) => {
        try {
            const { title, body = '' } = req.body;
            const doc = {
                id:         randomUUID(),
                project_id: req.params.id,
                title,
                body,
                author_id:  req.user.id,
                created_at: Date.now(),
                updated_at: Date.now(),
            };
            appDb.prepare(
                'INSERT INTO documents (id, project_id, title, body, author_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
            ).run(doc.id, doc.project_id, doc.title, doc.body, doc.author_id, doc.created_at, doc.updated_at);
            res.status(201).json(doc);
        } catch (err) {
            next(err);
        }
    }
);

// Delete document — needs docs:delete
app.delete('/projects/:id/docs/:docId',
    auth.requireAuthOrApiKey,
    loadProjectPermissions,
    auth.requireProjectAccess('docs:delete'),
    (req, res, next) => {
        try {
            appDb.prepare('DELETE FROM documents WHERE id = ? AND project_id = ?')
                 .run(req.params.docId, req.params.id);
            res.json({ success: true });
        } catch (err) {
            next(err);
        }
    }
);

// ---------------------------------------------------------------------------
// 8. Member management — app-side (auth library not involved)
//
// Privilege ceiling: members:manage holders can only grant permissions they
// themselves hold. This is DocuFlow's rule, enforced in app code.
// ---------------------------------------------------------------------------

// View member list — needs members:read
app.get('/projects/:id/members',
    auth.requireAuthOrApiKey,
    loadProjectPermissions,
    auth.requireProjectAccess('members:read'),
    (req, res) => {
        const members = appDb.prepare(
            'SELECT user_id, permissions FROM project_members WHERE project_id = ?'
        ).all(req.params.id);
        res.json({ members });
    }
);

// Add or update a member's permissions — needs members:manage
app.put('/projects/:id/members/:userId',
    auth.requireAuthOrApiKey,
    loadProjectPermissions,
    auth.requireProjectAccess('members:manage'),
    (req, res, next) => {
        try {
            const { permissions } = req.body; // e.g. ['docs:read', 'docs:write', 'members:read']
            const callerPerms = req.effectiveProjectScopes;

            // Privilege ceiling: can only grant permissions you hold yourself.
            if (!callerPerms.includes('*')) {
                const exceeds = permissions.filter(p => !callerPerms.includes(p));
                if (exceeds.length > 0) {
                    return res.status(403).json({ error: 'Cannot grant permissions you do not hold', scopes: exceeds });
                }
            }

            appDb.prepare(`
                INSERT INTO project_members (project_id, user_id, permissions) VALUES (?, ?, ?)
                ON CONFLICT(project_id, user_id) DO UPDATE SET permissions = excluded.permissions
            `).run(req.params.id, Number(req.params.userId), JSON.stringify(permissions));

            res.json({ success: true });
        } catch (err) {
            next(err);
        }
    }
);

// Remove a member — needs members:manage
app.delete('/projects/:id/members/:userId',
    auth.requireAuthOrApiKey,
    loadProjectPermissions,
    auth.requireProjectAccess('members:manage'),
    (req, res, next) => {
        try {
            appDb.prepare(
                'DELETE FROM project_members WHERE project_id = ? AND user_id = ?'
            ).run(req.params.id, Number(req.params.userId));
            res.json({ success: true });
        } catch (err) {
            next(err);
        }
    }
);

// ---------------------------------------------------------------------------
// 9. User's own projects (owned + member)
// ---------------------------------------------------------------------------

app.get('/me/projects',
    auth.requireAuth,
    async (req, res, next) => {
        try {
            const [ownedIds, memberRows] = await Promise.all([
                authManager.getOwnedProjects(req.user.id),
                Promise.resolve(
                    appDb.prepare('SELECT project_id FROM project_members WHERE user_id = ?')
                        .all(req.user.id).map(r => r.project_id)
                ),
            ]);
            const allIds = [...new Set([...ownedIds, ...memberRows])];
            if (allIds.length === 0) return res.json({ projects: [] });
            const ph       = allIds.map(() => '?').join(',');
            const projects = appDb.prepare(
                `SELECT * FROM projects WHERE id IN (${ph}) ORDER BY created_at DESC`
            ).all(...allIds).map(p => ({ ...p, isOwner: ownedIds.includes(p.id) }));
            res.json({ projects });
        } catch (err) {
            next(err);
        }
    }
);

// ---------------------------------------------------------------------------
// 11. Scope taxonomy — useful for building key-creation UIs
// ---------------------------------------------------------------------------

app.get('/scopes', (req, res) => {
    res.json(authManager.getScopeTaxonomy());
});

// ---------------------------------------------------------------------------
// 12. Bootstrap — grant server scopes (localhost only, demo convenience)
//
// Usage: curl -X POST http://localhost:3002/bootstrap/grant-scope \
//          -H 'Content-Type: application/json' \
//          -d '{"userId":1,"scope":"users.read"}'
// ---------------------------------------------------------------------------

app.post('/bootstrap/grant-scope', async (req, res, next) => {
    const ip = req.ip || req.connection?.remoteAddress;
    if (!['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(ip)) {
        return res.status(403).json({ error: 'Localhost only' });
    }
    try {
        const { userId, scope } = req.body;
        await authManager.grantServerScope(Number(userId), scope, null);
        res.json({ success: true });
    } catch (err) {
        next(err);
    }
});

// ---------------------------------------------------------------------------
// 13. Global error handler
// ---------------------------------------------------------------------------

app.use(AuthMiddleware.errorHandler);

app.use((err, req, res, next) => {
    console.error('[DocuFlow Error]', err.message);
    res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

await authManager.init();

const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
    console.log(`\nDocuFlow v4 demo  →  http://localhost:${PORT}`);
    console.log(`Auth API          →  http://localhost:${PORT}/auth`);
    console.log(`\nTo enable the Admin panel, grant yourself server scopes after registering:`);
    console.log(`  curl -X POST http://localhost:${PORT}/bootstrap/grant-scope \\`);
    console.log(`       -H 'Content-Type: application/json' \\`);
    console.log(`       -d '{"userId":1,"scope":"users.read"}'`);
    console.log(`  curl -X POST http://localhost:${PORT}/bootstrap/grant-scope \\`);
    console.log(`       -H 'Content-Type: application/json' \\`);
    console.log(`       -d '{"userId":1,"scope":"users.delete"}'`);
    console.log(`  curl -X POST http://localhost:${PORT}/bootstrap/grant-scope \\`);
    console.log(`       -H 'Content-Type: application/json' \\`);
    console.log(`       -d '{"userId":1,"scope":"projects.list"}'`);
});
