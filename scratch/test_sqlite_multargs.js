import { DatabaseSync } from 'node:sqlite';
const db = new DatabaseSync(':memory:');
db.exec('CREATE TABLE test (a TEXT, b TEXT)');
// This SHOULD fail if it only takes one argument because ? ? needs two values
try {
    db.prepare('INSERT INTO test (a, b) VALUES (?, ?)').run('a', 'b');
    console.log('Run with 2 args succeeded (Wait, how?)');
} catch (e) {
    console.error('Run with 2 args failed:', e.message);
}

try {
    const row = db.prepare('SELECT * FROM test WHERE a=? AND b=?').get('a', 'b');
    console.log('Get with 2 args returned:', row);
} catch (e) {
    console.error('Get with 2 args failed:', e.message);
}
