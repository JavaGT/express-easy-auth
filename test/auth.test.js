import request from 'supertest';
import express from 'express';
import authRouter from '../src/routes/auth.js';

describe('Auth API', () => {
    let app;
    beforeAll(() => {
        app = express();
        app.use(express.json());
        app.use('/api/v1/auth', authRouter);
    });

    describe('POST /api/v1/auth/register', () => {
        it('should return 400 if missing fields', async () => {
            const res = await request(app)
                .post('/api/v1/auth/register')
                .send({ username: 'user' });
            expect(res.status).toBe(400);
            expect(res.body.error).toBeDefined();
        });
    });

    describe('POST /api/v1/auth/login', () => {
        it('should return 400 if missing credentials', async () => {
            const res = await request(app)
                .post('/api/v1/auth/login')
                .send({ username: 'user' });
            expect(res.status).toBe(400);
            expect(res.body.error).toBeDefined();
        });
    });
});
