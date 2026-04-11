import { DatabaseSync } from 'node:sqlite';
const db = new DatabaseSync(':memory:');
db.exec('CREATE TABLE test (a TEXT, b TEXT)');
const p1 = 'val1';
const p2 = undefined;

try {
    // This represents my "fix" that failed
    db.prepare('SELECT * FROM test WHERE a=? AND b=?').get([p1 || null, p2 || null]);
    console.log('Array format worked');
} catch (e) {
    console.error('Array format failed:', e.message);
}

try {
    // This represents the original problematic call
    db.prepare('SELECT * FROM test WHERE a=? AND b=?').get(p1, p2);
    console.log('Positional with undefined worked');
} catch (e) {
    console.error('Positional with undefined failed:', e.message);
}

try {
    // This represents the REAL fix
    db.prepare('SELECT * FROM test WHERE a=? AND b=?').get(p1 || null, p2 || null);
    console.log('Positional with null fallback worked');
} catch (e) {
    console.error('Positional with null fallback failed:', e.message);
}
