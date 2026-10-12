// Core endpoints: health, capabilities, session, me, and the /__mock control endpoints.
import { randomBytes } from 'node:crypto';
import { HttpError } from '../lib.mjs';
import { USERS, WARNING_TEXT } from '../app.mjs';

export function capabilities(state) {
  const o = state.options;
  return {
    version: '0.1.0',
    backend: o.backend,
    history: { mode: o.history },
    content: { retentionDays: 7, storeAttachments: false },
    limits: { maxMessageBytes: 26214400, maxRecipients: 50 },
    warnings: o.warnings.map((code) => ({ code, message: WARNING_TEXT[code] || `Warning: ${code}` })),
  };
}

const COOKIE = 'eggmail_session';
const MAX_FAILURES = 5;

export function register(r, state) {
  r.get('/healthz', () => ({ status: 'ok' }), { public: true });
  r.get('/readyz', () => ({ status: 'ready', warnings: capabilities(state).warnings }), { public: true });
  r.get('/api/v1/capabilities', () => capabilities(state), { public: true });

  r.post(
    '/api/v1/session',
    (ctx) => {
      const { user, password } = ctx.body || {};
      const errors = [];
      if (!user || typeof user !== 'string') errors.push({ field: 'user', message: 'required' });
      if (!password || typeof password !== 'string') errors.push({ field: 'password', message: 'required' });
      if (errors.length) throw new HttpError(400, 'validation_failed', 'User and password are required.', { errors });
      const fails = state.loginFailures.get(user);
      if (fails && fails.count >= MAX_FAILURES && fails.until > Date.now()) {
        throw new HttpError(429, 'rate_limited', 'Too many failed sign-in attempts.', {}, { 'Retry-After': String(Math.ceil((fails.until - Date.now()) / 1000)) });
      }
      const account = USERS[user];
      if (!account || account.password !== password) {
        const f = fails && fails.until > Date.now() ? fails : { count: 0, until: Date.now() + 60_000 };
        f.count += 1;
        state.loginFailures.set(user, f);
        throw new HttpError(401, 'unauthorized', 'Invalid user or password.');
      }
      state.loginFailures.delete(user);
      const sid = randomBytes(24).toString('hex');
      const csrf = randomBytes(16).toString('hex');
      state.sessions.set(sid, { user, role: account.role, tenantId: account.tenantId, csrf });
      ctx.setCookie.push(`${COOKIE}=${sid}; Path=/; HttpOnly; SameSite=Strict`);
      return { user, role: account.role, tenantId: account.tenantId };
    },
    { public: true },
  );

  r.delete('/api/v1/session', (ctx) => {
    if (ctx.sid) state.sessions.delete(ctx.sid);
    ctx.setCookie.push(`${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`);
    return undefined;
  });

  r.get('/api/v1/me', (ctx) => ({
    status: 200,
    body: { user: ctx.session.user, role: ctx.session.role, tenantId: ctx.session.tenantId, csrfToken: ctx.session.csrf },
    headers: { 'X-CSRF-Token': ctx.session.csrf },
  }));

  // ---- mock control (not part of the API) ----
  r.get('/__mock/config', () => ({ history: state.options.history, backend: state.options.backend, warnings: state.options.warnings, notReady: state.options.notReady }), { public: true });
  r.post(
    '/__mock/config',
    (ctx) => {
      const b = ctx.body || {};
      if (b.history === 'full' || b.history === 'statsonly') state.options.history = b.history;
      if (typeof b.backend === 'string') state.options.backend = b.backend;
      if (Array.isArray(b.warnings)) state.options.warnings = b.warnings.map(String);
      if (typeof b.notReady === 'boolean') state.options.notReady = b.notReady;
      return { history: state.options.history, backend: state.options.backend, warnings: state.options.warnings, notReady: state.options.notReady };
    },
    { public: true },
  );
  r.post('/__mock/reset', () => (state.reset(), { ok: true }), { public: true });
}
