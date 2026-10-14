// Webhook endpoints, signing secrets (shown once), attempts log, replay.
import { randomBytes } from 'node:crypto';
import { HttpError, minutesAgo, hoursAgo, newId, validate, iso } from '../lib.mjs';

export const EVENT_TYPES = ['message.delivered', 'message.deferred', 'message.bounced', 'message.complained', 'message.expired', 'message.suppressed', 'message.cancelled', 'webhook.endpoint.disabled', 'webhook.test'];

const secret = () => 'whsec_' + randomBytes(24).toString('base64');

/** SSRF guard of the mock: https only, no internal addresses. */
export function checkWebhookUrl(url, fail) {
  let u;
  try {
    u = new URL(String(url));
  } catch {
    fail('url', 'Enter a full URL such as https://example.com/hooks/eggmail.');
    return;
  }
  if (u.protocol !== 'https:') {
    fail('url', 'Only https:// URLs are allowed on this server.');
    return;
  }
  const h = u.hostname.toLowerCase();
  const internal = h === 'localhost' || h.endsWith('.internal') || /^127\./.test(h) || /^10\./.test(h) || /^192\.168\./.test(h) || /^169\.254\./.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h) || h === '[::1]';
  if (internal) fail('url', 'Internal addresses are blocked (SSRF protection). Ask an administrator to add the host to the tenant allowlist.');
}

function checkEvents(types, fail) {
  if (!Array.isArray(types) || types.length === 0) fail('event_types', 'Select at least one event type.');
  else if (types.some((t) => !EVENT_TYPES.includes(t))) fail('event_types', 'Unknown event type.');
}

function attempt(eventType, status, durationMs, errorClass, snippet, ago) {
  return { id: newId(), outboxId: newId(), eventType, at: ago, status, durationMs, errorClass: errorClass ?? null, snippet: snippet ?? null };
}

function seed() {
  const a = {
    id: newId(),
    url: 'https://hooks.acme.example/eggmail',
    event_types: ['message.delivered', 'message.bounced', 'message.complained'],
    enabled: true,
    disabledReason: null,
    createdAt: hoursAgo(24 * 20),
  };
  const b = {
    id: newId(),
    url: 'https://old-crm.acme.example/mail-events',
    event_types: ['message.delivered'],
    enabled: false,
    disabledReason: 'Endpoint answered 410 Gone; disabled automatically.',
    createdAt: hoursAgo(24 * 50),
  };
  return {
    endpoints: [a, b],
    secrets: new Map([[a.id, secret()], [b.id, secret()]]),
    attempts: new Map([
      [
        a.id,
        [
          attempt('message.delivered', 200, 142, null, '{"ok":true}', minutesAgo(3)),
          attempt('message.bounced', 500, 1210, 'http_5xx', '<html><body>Internal Server Error</body></html>', minutesAgo(30)),
          attempt('message.bounced', null, 15000, 'timeout', null, minutesAgo(32)),
          attempt('message.complained', 200, 88, null, 'accepted', hoursAgo(5)),
          attempt('message.delivered', 429, 210, 'http_429', 'rate limit exceeded, retry later', hoursAgo(6)),
        ],
      ],
      [b.id, [attempt('message.delivered', 410, 95, 'http_410', 'Gone', hoursAgo(26))]],
    ]),
  };
}

const store = (ctx) => ctx.tenantData('webhooks', seed);
const pub = (w) => ({ ...w });

function find(ctx) {
  const w = store(ctx).endpoints.find((x) => x.id === ctx.params.id);
  if (!w) throw new HttpError(404, 'not_found', 'Webhook endpoint not found.');
  return w;
}

export function register(r) {
  r.get('/api/v1/webhooks', (ctx) => store(ctx).endpoints.map(pub), { tenant: true });
  r.get('/api/v1/webhooks/:id', (ctx) => pub(find(ctx)), { tenant: true });

  r.post(
    '/api/v1/webhooks',
    (ctx) => {
      const { url, event_types } = ctx.body || {};
      validate((fail) => {
        checkWebhookUrl(url, fail);
        checkEvents(event_types, fail);
      });
      const s = store(ctx);
      const w = { id: newId(), url, event_types, enabled: true, disabledReason: null, createdAt: iso() };
      const sec = secret();
      s.endpoints.push(w);
      s.secrets.set(w.id, sec);
      s.attempts.set(w.id, []);
      return { status: 201, body: { ...w, secret: sec } };
    },
    { tenant: true },
  );

  r.patch(
    '/api/v1/webhooks/:id',
    (ctx) => {
      const w = find(ctx);
      const b = ctx.body || {};
      validate((fail) => {
        if ('url' in b) checkWebhookUrl(b.url, fail);
        if ('event_types' in b) checkEvents(b.event_types, fail);
        if ('enabled' in b && typeof b.enabled !== 'boolean') fail('enabled', 'Must be true or false.');
      });
      if ('url' in b) w.url = b.url;
      if ('event_types' in b) w.event_types = b.event_types;
      if ('enabled' in b) {
        w.enabled = b.enabled;
        if (b.enabled) w.disabledReason = null;
      }
      return pub(w);
    },
    { tenant: true },
  );

  r.delete(
    '/api/v1/webhooks/:id',
    (ctx) => {
      const s = store(ctx);
      const w = find(ctx);
      s.endpoints.splice(s.endpoints.indexOf(w), 1);
      s.secrets.delete(w.id);
      s.attempts.delete(w.id);
      return undefined;
    },
    { tenant: true },
  );

  r.post(
    '/api/v1/webhooks/:id/rotate-secret',
    (ctx) => {
      const w = find(ctx);
      const sec = secret();
      store(ctx).secrets.set(w.id, sec);
      w.secretRotationPending = true;
      return { ...w, secret: sec };
    },
    { tenant: true },
  );

  r.delete(
    '/api/v1/webhooks/:id/previous-secret',
    (ctx) => {
      const w = find(ctx);
      if (!w.secretRotationPending) throw new HttpError(404, 'not_found', 'No secret rotation is pending.');
      w.secretRotationPending = false;
      return undefined;
    },
    { tenant: true },
  );

  r.post(
    '/api/v1/webhooks/:id/test',
    (ctx) => {
      const w = find(ctx);
      const a = attempt('webhook.test', 200, 120, null, '{"received":true}', iso());
      store(ctx).attempts.get(w.id).unshift(a);
      return { outboxId: a.outboxId };
    },
    { tenant: true },
  );

  r.get(
    '/api/v1/webhooks/:id/attempts',
    (ctx) => {
      const w = find(ctx);
      const limit = Math.min(parseInt(ctx.query.limit, 10) || 50, 200);
      return store(ctx).attempts.get(w.id).slice(0, limit);
    },
    { tenant: true },
  );

  r.post(
    '/api/v1/webhook-events/:outboxId/replay',
    (ctx) => {
      const s = store(ctx);
      for (const [wid, list] of s.attempts) {
        const found = list.find((a) => a.outboxId === ctx.params.outboxId);
        if (found) {
          list.unshift({ ...found, id: newId(), at: iso(), status: 200, durationMs: 101, errorClass: null, snippet: 'replayed ok' });
          void wid;
          return { status: 202, body: { outboxId: ctx.params.outboxId, status: 'queued' } };
        }
      }
      throw new HttpError(404, 'not_found', 'Webhook event not found.');
    },
    { tenant: true },
  );
}
