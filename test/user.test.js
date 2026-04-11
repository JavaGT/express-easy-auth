import request from 'supertest';
import express from 'express';
import userRouter from '../src/routes/user.js';

describe('User API', () => {
    let app;
    beforeAll(() => {
        app = express();
        app.use(express.json());
        app.use('/api/v1/user', userRouter);
    });

    describe('GET /api/v1/user/me', () => {
        it('should return 401 if not authenticated', async () => {
            const res = await request(app).get('/api/v1/user/me');
            expect([401, 403]).toContain(res.status);
        });
    });

    describe('POST /api/v1/user/keys', () => {
        it('should return 400 if name is missing', async () => {
            const res = await request(app)
                .post('/api/v1/user/keys')
                .send({ permissions: ['action:read'] });
            expect(res.status).toBe(400);
            expect(res.body.error).toBeDefined();
        });
    });
});
