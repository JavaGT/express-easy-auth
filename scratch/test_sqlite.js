import { DatabaseSync } from 'node:sqlite';
const db = new DatabaseSync(':memory:');
db.exec('CREATE TABLE test (a TEXT, b TEXT)');
db.prepare('INSERT INTO test (a, b) VALUES (?, ?)').run('val1', 'val2');
console.log('Single run with multiple args finished');
const row = db.prepare('SELECT * FROM test WHERE a=? AND b=?').get('val1', 'val2');
console.log('Result:', row);
