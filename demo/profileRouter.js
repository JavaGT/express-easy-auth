import express from 'express';
import { userDb } from '../src/db/init.js';
import { requireAuth } from '../src/middleware/auth.js';

const router = express.Router();

// ─── PROFILE (Demo Only) ───────────────────────────────────────────────────

router.get('/me', requireAuth, (req, res) => {
    const appDataDb = req.app.get('appDataDb');
    
    // 1. Get Identity Data (from Auth Server / Session)
    // In a real app, you might query your auth DB here if you need more fields,
    // but we have username/email in the session or can query authDb if needed.
    // For the demo, we'll just return what's in the profile table for this user.
    
    const profile = appDataDb.prepare(
        'SELECT display_name, bio, avatar_url, location, website, preferences, updated_at FROM profiles WHERE user_id = ?'
    ).get(req.userId) || {};

    res.json({ 
        userId: req.userId,
        username: req.session.username, // From session
        profile: {
            ...profile,
            preferences: profile.preferences ? JSON.parse(profile.preferences) : {}
        }
    });
});

router.patch('/me', requireAuth, (req, res) => {
    const appDataDb = req.app.get('appDataDb');
    const { display_name, bio, location, website, preferences } = req.body;

    if (bio && bio.length > 500) {
        return res.status(400).json({ error: 'Bio must be under 500 characters' });
    }

    const now = Date.now();
    appDataDb.prepare(`
    INSERT INTO profiles (user_id, display_name, bio, location, website, preferences, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET
      display_name = COALESCE(excluded.display_name, display_name),
      bio = COALESCE(excluded.bio, bio),
      location = COALESCE(excluded.location, location),
      website = COALESCE(excluded.website, website),
      preferences = COALESCE(excluded.preferences, preferences),
      updated_at = excluded.updated_at
  `).run(
      req.userId, 
      display_name || null, 
      bio || null, 
      location || null, 
      website || null, 
      preferences ? JSON.stringify(preferences) : null,
      now, 
      now
    );

    res.json({ success: true });
});

export default router;
