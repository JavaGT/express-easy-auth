import { DatabaseSync } from 'node:sqlite';
const db = new DatabaseSync(':memory:');
db.exec('CREATE TABLE test (a TEXT, b TEXT)');
try {
    db.prepare('SELECT * FROM test WHERE a=? AND b=?').get('val1', undefined);
    console.log('Finished with undefined');
} catch (e) {
    console.error('Error with undefined:', e);
}
