import { Router } from 'express';
import { randomUUID } from 'node:crypto';

const router = Router();

// Create room
router.post('/', (req, res, next) => req.authMiddleware.requireAuth(req, res, next), async (req, res) => {
    try {
        const { name } = req.body;
        if (!name) return res.status(400).json({ error: 'Name required' });

        const roomId = randomUUID();
        const now = Date.now();

        // 1. Create room
        req.chatDb.prepare('INSERT INTO rooms (id, name, owner_user_id, created_at) VALUES (?, ?, ?, ?)').run(
            roomId, name, req.user.id, now
        );

        // 2. Add creator as owner
        req.chatDb.prepare('INSERT INTO memberships (room_id, user_id, role) VALUES (?, ?, ?)').run(
            roomId, req.user.id, 'owner'
        );

        res.status(201).json({ success: true, roomId, name });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// List rooms (rooms user is member of)
router.get('/', (req, res, next) => req.authMiddleware.requireAuth(req, res, next), async (req, res) => {
    try {
        const rooms = req.chatDb.prepare(`
            SELECT r.*, m.role 
            FROM rooms r 
            JOIN memberships m ON r.id = m.room_id 
            WHERE m.user_id = ?
        `).all(req.user.id);
        res.json({ success: true, rooms });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get room members
router.get('/:id/members', (req, res, next) => req.authMiddleware.requireAuth(req, res, next), async (req, res) => {
    try {
        const members = req.chatDb.prepare('SELECT user_id, role FROM memberships WHERE room_id = ?').all(req.params.id);
        res.json({ success: true, members });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

export default router;
