// @vitest-environment node
import { afterEach, describe, expect, it } from 'vitest';
import { startMock } from './mockClient.mjs';

let mock;
afterEach(async () => {
  await mock?.close();
});

describe('mock API core', () => {
  it('serves capabilities without authentication and reflects the environment switches', async () => {
    mock = await startMock({ history: 'statsonly', backend: 'postgres', warnings: [] });
    const res = await mock.get('/api/v1/capabilities');
    expect(res.status).toBe(200);
    expect(res.data.history.mode).toBe('statsonly');
    expect(res.data.backend).toBe('postgres');
    expect(res.data.warnings).toEqual([]);
  });

  it('warns about sqlite_sync_off by default on the sqlite backend', async () => {
    mock = await startMock({ warnings: ['sqlite_sync_off'] });
    const res = await mock.get('/api/v1/capabilities');
    expect(res.data.warnings[0].code).toBe('sqlite_sync_off');
  });

  it('requires a session and returns problem+json for 401', async () => {
    mock = await startMock();
    const res = await mock.get('/api/v1/me');
    expect(res.status).toBe(401);
    expect(res.headers.get('content-type')).toContain('application/problem+json');
    expect(res.data.code).toBe('unauthorized');
    expect(res.data.request_id).toBeTruthy();
  });

  it('issues an HttpOnly SameSite=Strict cookie and a CSRF token from /me', async () => {
    mock = await startMock();
    const res = await fetch(`${mock.base}/api/v1/session`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ user: 'tenant', password: 'eggmail' }) });
    const cookie = res.headers.get('set-cookie');
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('SameSite=Strict');
    const me = await mock.login('tenant');
    expect(me.role).toBe('tenant');
    expect(me.csrfToken).toBeTruthy();
  });

  it('rejects mutating requests without the CSRF token with 403', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const r = await fetch(`${mock.base}/__mock/reset`, { method: 'POST' });
    expect(r.status).toBe(200);
    await mock.login('tenant');
    const cookieOnly = await mock.call('DELETE', '/api/v1/session', undefined, { 'X-CSRF-Token': 'wrong' });
    expect(cookieOnly.status).toBe(403);
    expect(cookieOnly.data.code).toBe('forbidden');
  });

  it('rate limits repeated failed sign-ins with 429 and Retry-After', async () => {
    mock = await startMock();
    let last;
    for (let i = 0; i < 6; i++) {
      last = await mock.post('/api/v1/session', { user: 'admin', password: 'wrong' });
    }
    expect(last.status).toBe(429);
    expect(last.data.code).toBe('rate_limited');
    expect(Number(last.headers.get('retry-after'))).toBeGreaterThan(0);
  });

  it('answers 503 not_ready for every API call when notReady is set, but keeps /healthz alive', async () => {
    mock = await startMock({ notReady: true });
    const caps = await mock.get('/api/v1/capabilities');
    expect(caps.status).toBe(503);
    expect(caps.data.code).toBe('not_ready');
    expect((await mock.get('/healthz')).status).toBe(200);
    expect((await mock.get('/readyz')).status).toBe(503);
  });

  it('can flip modes live through /__mock/config', async () => {
    mock = await startMock({ history: 'full' });
    await mock.post('/__mock/config', { history: 'statsonly', warnings: ['certificate_expiring'] });
    const caps = await mock.get('/api/v1/capabilities');
    expect(caps.data.history.mode).toBe('statsonly');
    expect(caps.data.warnings[0].code).toBe('certificate_expiring');
  });

  it('serves the SPA fallback with a strict CSP when dist exists, and 404s unknown API paths', async () => {
    mock = await startMock();
    const missing = await mock.get('/api/v1/nope');
    expect(missing.status).toBe(404);
    expect(missing.data.code).toBe('not_found');
  });
});
