import { DatabaseSync } from 'node:sqlite';
const db = new DatabaseSync(':memory:');
db.exec('CREATE TABLE users (id TEXT, username TEXT, email TEXT)');
const username = 'testuser';
const email = undefined;

// This mimics the problematic call
try {
    const user = db.prepare('SELECT * FROM users WHERE username=? OR email=?').get([username || null, email || null]);
    console.log('Final verification: Array format with null fallbacks succeeded!');
    console.log('Result:', user);
} catch (e) {
    console.error('Final verification failed:', e.message);
}
