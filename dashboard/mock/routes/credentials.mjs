// API keys and SMTP credentials. The secret is returned only by the create call.
import { randomBytes } from 'node:crypto';
import { HttpError, daysAgo, hoursAgo, iso, newId, validate } from '../lib.mjs';

const SCOPES = ['send', 'read', 'domains', 'webhooks', 'suppressions', 'keys', 'inbound'];

function seed() {
  return {
    keys: [
      { id: newId(), name: 'Production sender', prefix: 'egk_a1b2c3', scopes: ['send'], createdAt: daysAgo(40), lastUsedAt: hoursAgo(1) },
      { id: newId(), name: 'Reporting', prefix: 'egk_d4e5f6', scopes: ['read', 'suppressions'], createdAt: daysAgo(12), lastUsedAt: null },
    ],
    smtp: [{ id: newId(), username: 'app-mailer', createdAt: daysAgo(33) }],
  };
}

const store = (ctx) => ctx.tenantData('credentials', seed);

export function register(r) {
  r.get('/api/v1/api-keys', (ctx) => store(ctx).keys, { tenant: true });
  r.post(
    '/api/v1/api-keys',
    (ctx) => {
      const { name, scopes } = ctx.body || {};
      validate((fail) => {
        if (!name || !String(name).trim()) fail('name', 'A name is required.');
        if (!Array.isArray(scopes) || scopes.length === 0) fail('scopes', 'Select at least one scope.');
        else if (scopes.some((s) => !SCOPES.includes(s))) fail('scopes', 'Unknown scope.');
      });
      const key = 'egk_' + randomBytes(24).toString('base64url');
      const rec = { id: newId(), name: String(name).trim(), prefix: key.slice(0, 10), scopes, createdAt: iso(), lastUsedAt: null };
      store(ctx).keys.push(rec);
      return { status: 201, body: { ...rec, key } };
    },
    { tenant: true },
  );
  r.delete(
    '/api/v1/api-keys/:id',
    (ctx) => {
      const s = store(ctx);
      const i = s.keys.findIndex((k) => k.id === ctx.params.id);
      if (i < 0) throw new HttpError(404, 'not_found', 'API key not found.');
      s.keys.splice(i, 1);
      return undefined;
    },
    { tenant: true },
  );

  r.get('/api/v1/smtp-credentials', (ctx) => store(ctx).smtp, { tenant: true });
  r.post(
    '/api/v1/smtp-credentials',
    (ctx) => {
      const username = String(ctx.body?.username ?? '').trim();
      validate((fail) => {
        if (!username) fail('username', 'A username is required.');
        else if (!/^[A-Za-z0-9._@-]{3,64}$/.test(username)) fail('username', 'Use 3-64 letters, digits, dot, dash, underscore or @.');
        else if (store(ctx).smtp.some((c) => c.username === username)) fail('username', 'This username already exists.');
      });
      const password = randomBytes(18).toString('base64url');
      const rec = { id: newId(), username, createdAt: iso() };
      store(ctx).smtp.push(rec);
      return { status: 201, body: { ...rec, password } };
    },
    { tenant: true },
  );
  r.delete(
    '/api/v1/smtp-credentials/:id',
    (ctx) => {
      const s = store(ctx);
      const i = s.smtp.findIndex((k) => k.id === ctx.params.id);
      if (i < 0) throw new HttpError(404, 'not_found', 'SMTP credential not found.');
      s.smtp.splice(i, 1);
      return undefined;
    },
    { tenant: true },
  );
}
