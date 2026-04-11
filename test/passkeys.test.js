import request from 'supertest';
import express from 'express';
import passkeysRouter from '../src/routes/passkeys.js';

describe('Passkeys API', () => {
    let app;
    beforeAll(() => {
        app = express();
        app.use(express.json());
        app.use('/api/v1/passkeys', passkeysRouter);
    });

    describe('GET /api/v1/passkeys/list', () => {
        it('should return 401 if not authenticated', async () => {
            const res = await request(app).get('/api/v1/passkeys/list');
            expect([401, 403]).toContain(res.status);
        });
    });
});
