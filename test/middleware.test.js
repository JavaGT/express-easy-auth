import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import express from 'express';
import request from 'supertest';
import { requireAuth } from '../src/middleware/auth.js';
import { initAuthDb } from '../src/db/init.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const testDataDir = path.join(__dirname, 'fixture-data-mw');

describe('middleware', () => {
  before(() => {
    if (fs.existsSync(testDataDir)) fs.rmSync(testDataDir, { recursive: true });
    fs.mkdirSync(testDataDir, { recursive: true });
    initAuthDb(testDataDir);
  });

  it('requireAuth returns nested error when unauthenticated', async () => {
    const app = express();
    app.set('config', {});
    app.get('/protected', requireAuth, (req, res) => res.json({ ok: true }));
    const res = await request(app).get('/protected');
    assert.equal(res.status, 401);
    assert.equal(res.body.error.code, 'NOT_AUTHENTICATED');
    assert.equal(typeof res.body.error.message, 'string');
  });
});
