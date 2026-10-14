// Mock EggMail API (docs/api.md) with in-memory fixtures. Plain Node, no dependencies.
//
//   createMockServer(options) -> { server, state, listen(port) }
//
// Route modules live in mock/routes/*.mjs and are loaded automatically. Each exports
//   register(router, state)           // add routes: router.get('/api/v1/x/:id', (ctx) => body)
// Handlers receive ctx = { method, path, params, query, body, headers, session, tenantId, state, options,
//   tenantData(key, factory) } and return a JSON body, or { status, body, headers }, or throw HttpError.
// Runtime switches (also changeable live with POST /__mock/config): history, backend, warnings, notReady.
import { createServer, request as httpRequest } from 'node:http';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, extname, join, normalize, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';
import { HttpError, newId, problemBody, sleep } from './lib.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
  '.txt': 'text/plain; charset=utf-8',
  '.woff2': 'font/woff2',
};

/** The strict CSP the real host is meant to send with the dashboard (docs/components/dashboard.md). */
export const DASHBOARD_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  "font-src 'self'",
  "connect-src 'self'",
  "frame-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

export const USERS = {
  admin: { password: 'eggmail', role: 'admin', tenantId: null },
  tenant: { password: 'eggmail', role: 'tenant', tenantId: 't_acme' },
};

/** The mock's dashboard accounts (the ones in USERS), as the user management API lists them. */
function seedAccounts() {
  return Object.entries(USERS).map(([userName, u], i) => ({
    id: `u_${userName}`,
    userName,
    password: u.password,
    role: u.role,
    tenantId: u.tenantId,
    enabled: true,
    createdAt: `2026-08-0${i + 1}T09:00:00.000Z`,
  }));
}

export function defaultOptions(env = {}) {
  const history = String(env.MOCK_HISTORY || 'full').toLowerCase();
  const backend = String(env.MOCK_BACKEND || 'sqlite').toLowerCase();
  const warnings = env.MOCK_WARNINGS !== undefined ? String(env.MOCK_WARNINGS).split(',').map((s) => s.trim()).filter(Boolean) : backend === 'sqlite' ? ['sqlite_sync_off'] : [];
  return {
    history: history === 'statsonly' ? 'statsonly' : 'full',
    backend,
    warnings,
    notReady: env.MOCK_NOT_READY === '1' || env.MOCK_NOT_READY === 'true',
    latencyMs: Number(env.MOCK_LATENCY_MS || 0),
    distDir: env.MOCK_DIST || join(here, '..', 'dist'),
    viteUrl: env.VITE_URL || '',
    quiet: !!env.MOCK_QUIET,
  };
}

export const WARNING_TEXT = {
  sqlite_sync_off: 'SQLite runs with synchronous=OFF: an OS crash or power loss can corrupt the database and lose queued mail.',
  certificate_expiring: 'The TLS certificate for mail.example.com expires in 9 days.',
  self_signed_certificate: 'The server is using a self-signed certificate.',
};

function matcher(pattern) {
  const names = [];
  const re = new RegExp('^' + pattern.replace(/:([A-Za-z_]+)/g, (_m, n) => (names.push(n), '([^/]+)')) + '/?$');
  return { re, names };
}

class Router {
  constructor() {
    this.routes = [];
  }
  add(method, pattern, handler, opts = {}) {
    this.routes.push({ method, ...matcher(pattern), handler, opts });
  }
  get(p, h, o) { this.add('GET', p, h, o); }
  post(p, h, o) { this.add('POST', p, h, o); }
  put(p, h, o) { this.add('PUT', p, h, o); }
  patch(p, h, o) { this.add('PATCH', p, h, o); }
  delete(p, h, o) { this.add('DELETE', p, h, o); }
  match(method, path) {
    let pathMatched = false;
    for (const r of this.routes) {
      const m = r.re.exec(path);
      if (!m) continue;
      pathMatched = true;
      if (r.method !== method) continue;
      const params = {};
      r.names.forEach((n, i) => (params[n] = decodeURIComponent(m[i + 1])));
      return { route: r, params };
    }
    return { route: null, params: {}, pathMatched };
  }
}

function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > 40 * 1024 * 1024) throw new HttpError(413, 'payload_too_large', 'Request body too large.');
    chunks.push(c);
  }
  if (!chunks.length) return undefined;
  const text = Buffer.concat(chunks).toString('utf8');
  if (!text.trim()) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    throw new HttpError(400, 'validation_failed', 'The request body is not valid JSON.', { errors: [{ field: '$', message: 'Invalid JSON' }] });
  }
}

export async function createMockServer(optionOverrides = {}) {
  const options = { ...defaultOptions(process.env), ...optionOverrides };
  const state = {
    options,
    sessions: new Map(), // sid -> { userId, user, role, tenantId, csrf }
    accounts: seedAccounts(), // dashboard users (mock/routes/users.mjs manages them)
    loginFailures: new Map(), // user -> { count, until }
    tenantStores: new Map(),
    shared: {}, // modules keep cross-tenant data here
    tenants: [
      { id: 't_acme', name: 'Acme Corp', status: 'active', createdAt: '2026-08-01T09:00:00.000Z' },
      { id: 't_globex', name: 'Globex', status: 'active', createdAt: '2026-09-02T10:30:00.000Z' },
      { id: 't_initech', name: 'Initech', status: 'suspended', createdAt: '2026-09-20T14:00:00.000Z' },
    ],
    resetHooks: [],
    startedAt: Date.now(),
  };

  const router = new Router();
  const files = readdirSync(join(here, 'routes')).filter((f) => f.endsWith('.mjs')).sort();
  for (const f of files) {
    const mod = await import(pathToFileURL(join(here, 'routes', f)).href);
    if (typeof mod.register === 'function') mod.register(router, state);
  }

  state.reset = () => {
    state.tenantStores.clear();
    state.shared = {};
    state.sessions.clear();
    state.accounts = seedAccounts();
    state.loginFailures.clear();
    for (const hook of state.resetHooks) hook();
  };

  function tenantData(tenantId, key, factory) {
    let store = state.tenantStores.get(tenantId);
    if (!store) state.tenantStores.set(tenantId, (store = {}));
    if (!(key in store)) store[key] = factory(tenantId);
    return store[key];
  }

  function sidFor(req) {
    return parseCookies(req.headers.cookie).eggmail_session || null;
  }

  function send(res, status, body, headers = {}) {
    const json = body === undefined ? '' : JSON.stringify(body);
    res.writeHead(status, {
      'Content-Type': status >= 400 ? 'application/problem+json' : 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...headers,
    });
    res.end(status === 204 ? undefined : json);
  }

  async function handleApi(req, res, url) {
    if (options.latencyMs) await sleep(options.latencyMs);
    const method = req.method;
    const path = url.pathname;
    const query = Object.fromEntries(url.searchParams);
    const { route, params, pathMatched } = router.match(method, path);
    const requestId = 'req_' + randomBytes(4).toString('hex');
    try {
      if (options.notReady && !path.startsWith('/__mock') && path !== '/healthz') {
        throw new HttpError(503, 'not_ready', 'The storage backend is not available.', {}, { 'Retry-After': '5' });
      }
      if (!route) {
        if (pathMatched) throw new HttpError(405, 'not_found', `Method ${method} is not allowed here.`);
        throw new HttpError(404, 'not_found', `No endpoint ${method} ${path}.`);
      }
      const opts = route.opts;
      const sid = sidFor(req);
      const session = sid ? state.sessions.get(sid) ?? null : null;
      if (!opts.public) {
        if (!session) throw new HttpError(401, 'unauthorized', 'Sign in to continue.');
        if (method !== 'GET' && method !== 'HEAD' && req.headers['x-csrf-token'] !== session.csrf) {
          throw new HttpError(403, 'forbidden', 'Missing or invalid X-CSRF-Token header.');
        }
        if (path.startsWith('/api/v1/admin/') && session.role !== 'admin') {
          throw new HttpError(403, 'forbidden', 'This endpoint requires the admin role.');
        }
      }
      let tenantId = session ? session.tenantId : null;
      if (session && session.role === 'admin') {
        const hdr = req.headers['x-tenant-id'];
        tenantId = hdr ? String(hdr) : null;
        if (hdr && !state.tenants.some((t) => t.id === tenantId)) throw new HttpError(404, 'not_found', 'Unknown tenant.');
      }
      if (opts.tenant && !tenantId) {
        throw new HttpError(400, 'validation_failed', 'Admins must send the X-Tenant-Id header for tenant-scoped endpoints.', {
          errors: [{ field: 'X-Tenant-Id', message: 'required for admins' }],
        });
      }
      const body = method === 'GET' || method === 'HEAD' ? undefined : await readBody(req);
      const ctx = {
        method,
        path,
        params,
        query,
        body,
        headers: req.headers,
        session,
        sid,
        tenantId,
        state,
        options,
        requestId,
        tenantData: (key, factory) => tenantData(tenantId, key, factory),
        setCookie: [],
      };
      const out = await route.handler(ctx);
      const extra = ctx.setCookie.length ? { 'Set-Cookie': ctx.setCookie } : {};
      if (out === undefined) return send(res, 204, undefined, extra);
      if (out && typeof out === 'object' && 'status' in out && ('body' in out || 'headers' in out) && Object.keys(out).every((k) => ['status', 'body', 'headers'].includes(k))) {
        return send(res, out.status, out.body, { ...extra, ...out.headers });
      }
      return send(res, 200, out, extra);
    } catch (e) {
      if (e instanceof HttpError) {
        return send(res, e.status, problemBody(e.status, e.code, e.detail, e.extra, requestId), e.headers);
      }
      if (!options.quiet) console.error('mock error', e);
      return send(res, 500, problemBody(500, 'server_error', String(e?.message || e), {}, requestId));
    }
  }

  function serveStatic(req, res, url) {
    const dist = options.distDir;
    if (options.viteUrl) return proxyToVite(req, res);
    if (!existsSync(join(dist, 'index.html'))) {
      res.writeHead(503, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('dashboard/dist not found. Run `npm run build` first, or use `npm run dev:mock`.');
    }
    let rel = normalize(decodeURIComponent(url.pathname)).replace(/^([/\\])+/, '');
    let file = join(dist, rel);
    if (!file.startsWith(dist + sep) && file !== dist) {
      res.writeHead(403);
      return res.end();
    }
    const exists = existsSync(file) && statSync(file).isFile();
    // SPA fallback: unknown paths without an extension serve index.html; missing assets stay 404.
    if (!exists) {
      if (extname(rel)) {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        return res.end('not found');
      }
      file = join(dist, 'index.html');
    }
    const type = MIME[extname(file)] || 'application/octet-stream';
    const immutable = file.includes(`${sep}assets${sep}`);
    res.writeHead(200, {
      'Content-Type': type,
      'Cache-Control': immutable ? 'public, max-age=31536000, immutable' : 'no-cache',
      'Content-Security-Policy': DASHBOARD_CSP,
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'X-Frame-Options': 'DENY',
    });
    res.end(readFileSync(file));
  }

  function proxyToVite(req, res) {
    const target = new URL(options.viteUrl);
    const p = httpRequest({ host: target.hostname, port: target.port, path: req.url, method: req.method, headers: req.headers }, (pr) => {
      res.writeHead(pr.statusCode || 502, pr.headers);
      pr.pipe(res);
    });
    p.on('error', () => {
      res.writeHead(502);
      res.end('Vite dev server not reachable');
    });
    req.pipe(p);
  }

  const server = createServer(async (req, res) => {
    const url = new URL(req.url || '/', 'http://localhost');
    try {
      if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/__mock/') || url.pathname === '/healthz' || url.pathname === '/readyz') {
        return await handleApi(req, res, url);
      }
      return serveStatic(req, res, url);
    } catch (e) {
      if (!options.quiet) console.error(e);
      res.writeHead(500);
      res.end('internal error');
    }
  });

  return {
    server,
    state,
    options,
    listen: (port = 8787, host = '127.0.0.1') =>
      new Promise((resolve) => server.listen(port, host, () => resolve(server.address().port))),
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

export { newId };
