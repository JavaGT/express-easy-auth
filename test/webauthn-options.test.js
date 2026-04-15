import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { resolveWebAuthnOptions } from '../src/utils/authHelpers.js';

function mockReq({ config, getWebAuthnOptions, protocol = 'https', host = 'app.example.com' }) {
  const map = new Map();
  if (config !== undefined) map.set('config', config);
  map.set('getWebAuthnOptions', getWebAuthnOptions ?? null);
  return {
    app: { get: (k) => map.get(k) },
    protocol,
    get: (name) => (name === 'host' ? host : undefined),
  };
}

describe('resolveWebAuthnOptions', () => {
  it('uses getWebAuthnOptions when provided', () => {
    const req = mockReq({
      config: {},
      getWebAuthnOptions: () => ({
        rpName: 'Custom',
        rpID: 'id.example',
        origin: 'https://id.example',
      }),
    });
    const out = resolveWebAuthnOptions(req);
    assert.equal(out.rpName, 'Custom');
    assert.equal(out.rpID, 'id.example');
    assert.equal(out.origin, 'https://id.example');
  });

  it('throws when getWebAuthnOptions omits rpID or origin', () => {
    const req = mockReq({
      config: {},
      getWebAuthnOptions: () => ({ rpID: 'x' }),
    });
    assert.throws(() => resolveWebAuthnOptions(req), /getWebAuthnOptions must return rpID and origin/);
  });

  it('derives origin and rpID from Host when config omits them', () => {
    const req = mockReq({
      config: {},
      protocol: 'http',
      host: '127.0.0.1:3000',
    });
    const out = resolveWebAuthnOptions(req);
    assert.equal(out.origin, 'http://127.0.0.1:3000');
    assert.equal(out.rpID, '127.0.0.1');
    assert.equal(out.rpName, 'Auth Server');
  });

  it('uses static config.origin and config.rpID when both set', () => {
    const req = mockReq({
      config: {
        rpName: 'Static',
        origin: 'https://proxy.example.com',
        rpID: 'proxy.example.com',
      },
      protocol: 'http',
      host: 'localhost:3000',
    });
    const out = resolveWebAuthnOptions(req);
    assert.equal(out.origin, 'https://proxy.example.com');
    assert.equal(out.rpID, 'proxy.example.com');
    assert.equal(out.rpName, 'Static');
  });

  it('fills rpID from origin hostname when rpID omitted', () => {
    const req = mockReq({
      config: { origin: 'https://app.example.com/foo' },
      host: 'ignored:1',
    });
    const out = resolveWebAuthnOptions(req);
    assert.equal(out.origin, 'https://app.example.com/foo');
    assert.equal(out.rpID, 'app.example.com');
  });
});
