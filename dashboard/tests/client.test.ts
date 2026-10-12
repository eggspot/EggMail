import { describe, expect, it, vi } from 'vitest';
import { ApiError, getCsrfToken, itemsOf, request, setCsrfToken, setTenantId, setUnauthorizedHandler } from '../src/api/client';
import { api } from '../src/api/endpoints';
import { json, mockFetch, problem } from './helpers';

describe('API client', () => {
  it('sends the CSRF token on every mutating method and never on GET', async () => {
    const { calls } = mockFetch({
      'GET /api/v1/domains': [],
      'POST /api/v1/domains': { id: 'd1' },
      'PUT /api/v1/settings': { items: [] },
      'PATCH /api/v1/webhooks/w1': { id: 'w1' },
      'DELETE /api/v1/domains/d1': undefined,
    });
    setCsrfToken('tok-123');
    await api.domains();
    await api.createDomain('example.com');
    await api.updateSettings({ a: 1 });
    await api.updateWebhook('w1', { enabled: false });
    await api.deleteDomain('d1');
    const byMethod = Object.fromEntries(calls.map((c) => [c.method, c.headers.get('X-CSRF-Token')]));
    expect(byMethod.GET).toBeNull();
    expect(byMethod.POST).toBe('tok-123');
    expect(byMethod.PUT).toBe('tok-123');
    expect(byMethod.PATCH).toBe('tok-123');
    expect(byMethod.DELETE).toBe('tok-123');
  });

  it('uses same-origin credentials, JSON content type only with a body, and disables caching', async () => {
    const { fn, calls } = mockFetch({ 'GET /api/v1/domains': [], 'POST /api/v1/domains': {} });
    await api.domains();
    await api.createDomain('a.test');
    const init = fn.mock.calls[0][1] as RequestInit;
    expect(init.credentials).toBe('same-origin');
    expect(init.cache).toBe('no-store');
    expect(calls[0].headers.get('Content-Type')).toBeNull();
    expect(calls[1].headers.get('Content-Type')).toBe('application/json');
    expect(calls[1].body).toEqual({ name: 'a.test' });
  });

  it('only talks to same-origin relative URLs', async () => {
    const { fn } = mockFetch({ 'GET /api/v1/capabilities': {} });
    await api.capabilities();
    const url = String(fn.mock.calls[0][0]);
    expect(url.startsWith('/api/v1/')).toBe(true);
  });

  it('adds X-Tenant-Id when an admin selected a tenant', async () => {
    const { calls } = mockFetch({ 'GET /api/v1/messages': { items: [] } });
    setTenantId('t_globex');
    await api.searchMessages({});
    expect(calls[0].headers.get('X-Tenant-Id')).toBe('t_globex');
  });

  it('drops empty query values and encodes the rest', async () => {
    const { calls } = mockFetch({ 'GET /api/v1/messages': { items: [] } });
    await api.searchMessages({ recipient: 'a b@x.test', subject: '', limit: 25 });
    expect(calls[0].query.get('recipient')).toBe('a b@x.test');
    expect(calls[0].query.has('subject')).toBe(false);
    expect(calls[0].query.get('limit')).toBe('25');
  });

  it('turns problem+json into ApiError with code, detail, request id and field errors', async () => {
    mockFetch({
      'POST /api/v1/domains': () =>
        problem(400, 'validation_failed', { detail: 'bad', errors: [{ field: 'name', message: 'invalid hostname' }] }),
    });
    const err = await api.createDomain('x').catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(400);
    expect(err.code).toBe('validation_failed');
    expect(err.requestId).toBe('req-test');
    expect(err.fieldErrors).toEqual([{ field: 'name', message: 'invalid hostname' }]);
  });

  it('reads Retry-After from 429 responses', async () => {
    mockFetch({ 'POST /api/v1/domains/d1/verify': () => problem(429, 'rate_limited', {}, { 'Retry-After': '17' }) });
    const err = await api.verifyDomain('d1').catch((e) => e);
    expect(err.code).toBe('rate_limited');
    expect(err.retryAfter).toBe(17);
  });

  it('maps 410 history_not_recorded and body_expired codes', async () => {
    mockFetch({
      'GET /api/v1/messages': () => problem(410, 'history_not_recorded', { history_mode: 'StatsOnly' }),
      'GET /api/v1/messages/m1/content': () => problem(410, 'body_expired', { expired_at: '2026-10-01T00:00:00Z', retention_days: 7 }),
    });
    const a = await api.searchMessages({}).catch((e) => e);
    const b = await api.messageContent('m1').catch((e) => e);
    expect(a.status).toBe(410);
    expect(a.code).toBe('history_not_recorded');
    expect(b.code).toBe('body_expired');
    expect(b.problem.retention_days).toBe(7);
  });

  it('synthesizes a problem for non-JSON error bodies and defaults 503 to not_ready', async () => {
    mockFetch({ 'GET /api/v1/domains': () => new Response('upstream down', { status: 503, headers: { 'Content-Type': 'text/plain' } }) });
    const err = await api.domains().catch((e) => e);
    expect(err.code).toBe('not_ready');
    expect(err.detail).toContain('upstream down');
  });

  it('wraps network failures as ApiError network_error with status 0', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')));
    const err = await api.domains().catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(0);
    expect(err.code).toBe('network_error');
  });

  it('rethrows aborts untouched', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new DOMException('aborted', 'AbortError')));
    await expect(request('GET', '/api/v1/domains')).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('returns undefined for 204 and rejects non-JSON success bodies', async () => {
    mockFetch({ 'DELETE /api/v1/domains/d1': undefined, 'GET /api/v1/capabilities': () => new Response('<html>', { status: 200 }) });
    await expect(api.deleteDomain('d1')).resolves.toBeUndefined();
    const err = await api.capabilities().catch((e) => e);
    expect(err.code).toBe('bad_response');
  });

  it('calls the unauthorized handler on 401 except for the session probe and login', async () => {
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);
    mockFetch({
      'GET /api/v1/domains': () => problem(401, 'unauthorized'),
      'GET /api/v1/me': () => problem(401, 'unauthorized'),
      'POST /api/v1/session': () => problem(401, 'unauthorized'),
    });
    await api.domains().catch(() => {});
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
    await api.me().catch(() => {});
    await api.login('u', 'p').catch(() => {});
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
  });

  it('login posts credentials without a CSRF token, then reads the token from /me', async () => {
    const { calls } = mockFetch({
      'POST /api/v1/session': { user: 'admin', role: 'admin', tenantId: null },
      'GET /api/v1/me': { user: 'admin', role: 'admin', tenantId: null, csrfToken: 'csrf-after-login' },
    });
    const me = await api.login('admin', 'secret');
    expect(me.role).toBe('admin');
    expect(calls[0].headers.get('X-CSRF-Token')).toBeNull();
    expect(calls[0].body).toEqual({ user: 'admin', password: 'secret' });
    expect(getCsrfToken()).toBe('csrf-after-login');
  });

  it('logout clears the CSRF token even when the request fails', async () => {
    setCsrfToken('x');
    mockFetch({ 'DELETE /api/v1/session': () => problem(500, 'server_error') });
    await api.logout().catch(() => {});
    expect(getCsrfToken()).toBeNull();
  });

  it('sends the Idempotency-Key header when provided', async () => {
    const { calls } = mockFetch({ 'POST /api/v1/messages': () => json({ id: 'm', status: 'queued', recipients: 1 }, 202) });
    await api.send({ from: 'a@x.test', to: ['b@y.test'], subject: 's', text: 't' }, 'key-1');
    expect(calls[0].headers.get('Idempotency-Key')).toBe('key-1');
  });

  it('url-encodes path parameters such as suppression addresses', async () => {
    const { calls } = mockFetch({ 'DELETE /api/v1/suppressions/:address': undefined });
    await api.removeSuppression('a+b@x.test');
    expect(calls[0].path).toBe('/api/v1/suppressions/a%2Bb%40x.test');
  });

  it('tolerates both bare arrays and { items } list shapes', () => {
    expect(itemsOf([1, 2])).toEqual([1, 2]);
    expect(itemsOf({ items: [3] })).toEqual([3]);
    expect(itemsOf(undefined)).toEqual([]);
  });

  it('accepts bare-array and { rows } stats responses', async () => {
    mockFetch({ 'GET /api/v1/stats': () => json({ rows: [{ period: 'p' }] }) });
    expect(await api.stats({})).toHaveLength(1);
    mockFetch({ 'GET /api/v1/stats': () => json([{ period: 'p' }, { period: 'q' }]) });
    expect(await api.stats({})).toHaveLength(2);
  });
});
