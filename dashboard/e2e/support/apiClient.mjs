// A small cookie/CSRF-aware client for the server's HTTP API, used by the tests for set-up and for checks that must not go through the UI.
export class ApiClient {
  constructor(baseURL) {
    this.baseURL = baseURL;
    this.cookie = null;
    this.csrfToken = null;
  }

  /** Signs in like the dashboard does (POST /session, then GET /me for the CSRF token). */
  async signIn(user, password) {
    const response = await fetch(`${this.baseURL}/api/v1/session`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ user, password }),
    });
    if (!response.ok) throw new Error(`sign-in failed: ${response.status} ${await response.text()}`);
    const setCookie = response.headers.getSetCookie().find((c) => c.startsWith('eggmail_session='));
    if (!setCookie) throw new Error('the session cookie was not set');
    this.cookie = setCookie.split(';')[0];
    this.csrfToken = (await this.request('GET', '/api/v1/me')).body.csrfToken;
    return this;
  }

  get sessionCookieValue() {
    return this.cookie?.slice('eggmail_session='.length);
  }

  /** Returns `{ status, body, headers }`; never throws on an HTTP error status. */
  async request(method, path, body, { tenantId, bearer, headers = {}, csrf = true } = {}) {
    const h = { ...headers };
    if (body !== undefined) h['content-type'] = 'application/json';
    if (bearer) h.authorization = `Bearer ${bearer}`;
    else if (this.cookie) {
      h.cookie = this.cookie;
      if (csrf && method !== 'GET' && this.csrfToken) h['x-csrf-token'] = this.csrfToken;
    }
    if (tenantId) h['x-tenant-id'] = tenantId;
    const response = await fetch(`${this.baseURL}${path}`, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await response.text();
    let parsed = text;
    try { parsed = text ? JSON.parse(text) : undefined; } catch { /* not JSON */ }
    return { status: response.status, body: parsed, headers: response.headers };
  }

  /** Like request, but throws unless the status is 2xx. */
  async ok(method, path, body, options) {
    const r = await this.request(method, path, body, options);
    if (r.status < 200 || r.status > 299) throw new Error(`${method} ${path} -> ${r.status} ${JSON.stringify(r.body)}`);
    return r.body;
  }
}
