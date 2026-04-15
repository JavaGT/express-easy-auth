import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import express from 'express';
import session from 'express-session';
import request from 'supertest';
import authRouter from '../src/routes/auth.js';
import { initAuthDb } from '../src/db/init.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const testDataDir = path.join(__dirname, 'fixture-data');

describe('Auth API', () => {
  let app;
  before(() => {
    if (fs.existsSync(testDataDir)) fs.rmSync(testDataDir, { recursive: true });
    fs.mkdirSync(testDataDir, { recursive: true });
    initAuthDb(testDataDir);

    app = express();
    app.set('config', {});
    app.set('exposeErrors', false);
    app.set('getWebAuthnOptions', null);
    app.set('enableApiKeys', true);
    app.use(express.json());
    app.use('/api/v1/auth', authRouter);
  });

  it('POST /register returns nested error when missing fields', async () => {
    const res = await request(app).post('/api/v1/auth/register').send({ username: 'user' });
    assert.equal(res.status, 400);
    assert.ok(res.body.error);
    assert.equal(res.body.error.code, 'MISSING_CREDENTIALS');
    assert.equal(typeof res.body.error.message, 'string');
  });

  it('POST /login returns nested error when missing credentials', async () => {
    const res = await request(app).post('/api/v1/auth/login').send({ username: 'user' });
    assert.equal(res.status, 400);
    assert.equal(res.body.error.code, 'MISSING_CREDENTIALS');
  });

  it('GET /passkeys returns 401 with nested error', async () => {
    const res = await request(app).get('/api/v1/auth/passkeys');
    assert.equal(res.status, 401);
    assert.equal(res.body.error.code, 'NOT_AUTHENTICATED');
  });

  it('enableApiKeys false returns 404 for /api-keys when authenticated', async () => {
    const a = express();
    a.set('config', {});
    a.set('exposeErrors', false);
    a.set('getWebAuthnOptions', null);
    a.set('enableApiKeys', false);
    a.use(express.json());
    a.use(
      session({
        secret: 'test-secret',
        resave: false,
        saveUninitialized: true,
        cookie: { httpOnly: true },
      })
    );
    a.use('/api/v1/auth', authRouter);

    const agent = request.agent(a);
    const u = `u_${Date.now()}`;
    await agent.post('/api/v1/auth/register').send({
      username: u,
      email: `${u}@test.local`,
      password: 'password123',
    });
    const login = await agent.post('/api/v1/auth/login').send({
      username: u,
      password: 'password123',
    });
    assert.equal(login.status, 200);
    const res = await agent.get('/api/v1/auth/api-keys');
    assert.equal(res.status, 404);
    assert.equal(res.body.error.code, 'NOT_FOUND');
  });
});
