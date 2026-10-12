// Test helper: starts the mock API on an ephemeral port and talks to it like the dashboard does
// (session cookie + X-CSRF-Token). Use from `// @vitest-environment node` test files.
import { createMockServer } from '../mock/app.mjs';

export async function startMock(options = {}) {
  const app = await createMockServer({ quiet: true, ...options });
  const port = await app.listen(0);
  const base = `http://127.0.0.1:${port}`;
  let cookie = '';
  let csrf = '';
  let tenant = '';

  async function call(method, path, body, headers = {}) {
    const h = { Accept: 'application/json' };
    if (cookie) h.Cookie = cookie;
    if (csrf && method !== 'GET') h['X-CSRF-Token'] = csrf;
    if (tenant) h['X-Tenant-Id'] = tenant;
    if (body !== undefined) h['Content-Type'] = 'application/json';
    Object.assign(h, headers); // explicit headers win (for example a wrong CSRF token)
    const res = await fetch(base + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await res.text();
    let data;
    try {
      data = text ? JSON.parse(text) : undefined;
    } catch {
      data = text;
    }
    return { status: res.status, data, headers: res.headers, ok: res.ok };
  }

  return {
    app,
    base,
    options: app.options,
    state: app.state,
    call,
    get: (p, h) => call('GET', p, undefined, h),
    post: (p, b, h) => call('POST', p, b, h),
    put: (p, b, h) => call('PUT', p, b, h),
    patch: (p, b, h) => call('PATCH', p, b, h),
    del: (p, h) => call('DELETE', p, undefined, h),
    /** Signs in as `admin` or `tenant`; admins act on `tenantId` (default t_acme). */
    async login(user = 'tenant', tenantId = 't_acme') {
      const res = await fetch(`${base}/api/v1/session`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ user, password: 'eggmail' }) });
      if (!res.ok) throw new Error(`login failed: ${res.status}`);
      cookie = (res.headers.get('set-cookie') || '').split(';')[0];
      const me = await (await fetch(`${base}/api/v1/me`, { headers: { Cookie: cookie } })).json();
      csrf = me.csrfToken;
      tenant = me.role === 'admin' ? tenantId : '';
      return me;
    },
    setTenant: (id) => (tenant = id),
    close: () => app.close(),
  };
}
