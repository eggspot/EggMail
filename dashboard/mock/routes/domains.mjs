// Domains: list/create/delete, verify (30 s rate limit), DKIM rotation.
import { randomBytes } from 'node:crypto';
import { HttpError, daysAgo, minutesAgo, newId, validate, iso } from '../lib.mjs';

const HOST_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const VERIFY_COOLDOWN_MS = 30_000;

function fakeKey(seed) {
  // ~392 chars, looks like a base64 RSA-2048 SubjectPublicKeyInfo
  let s = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA';
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let x = seed;
  while (s.length < 388) {
    x = (x * 1103515245 + 12345) & 0x7fffffff;
    s += alphabet[x % alphabet.length];
  }
  return s + 'IDAQAB';
}

function makeRecords(name, selector, key, statuses = {}) {
  const dkimValue = `v=DKIM1; k=rsa; p=${key}`;
  return [
    { type: 'TXT', host: `${selector}._domainkey.${name}`, value: dkimValue, ttl: 3600, purpose: 'dkim', status: statuses.dkim || 'ok', expected: dkimValue, found: statuses.dkimFound ?? (statuses.dkim === 'ok' || !statuses.dkim ? dkimValue : null) },
    { type: 'CNAME', host: `bounces.${name}`, value: 'bounce.eggmail.example.net', ttl: 3600, purpose: 'return_path', status: statuses.return_path || 'ok', expected: 'bounce.eggmail.example.net', found: statuses.return_path && statuses.return_path !== 'ok' ? null : 'bounce.eggmail.example.net' },
    { type: 'TXT', host: name, value: 'v=spf1 include:spf.eggmail.example.net ~all', ttl: 3600, purpose: 'spf', status: statuses.spf || 'ok', expected: 'v=spf1 include:spf.eggmail.example.net ~all', found: statuses.spf && statuses.spf !== 'ok' ? null : 'v=spf1 include:spf.eggmail.example.net ~all' },
    { type: 'TXT', host: `_dmarc.${name}`, value: 'v=DMARC1; p=none; rua=mailto:dmarc@' + name, ttl: 3600, purpose: 'dmarc', status: statuses.dmarc || 'ok', expected: 'v=DMARC1; p=none; rua=mailto:dmarc@' + name, found: statuses.dmarc && statuses.dmarc !== 'ok' ? null : 'v=DMARC1; p=none; rua=mailto:dmarc@' + name },
  ];
}

function makeDomain(name, status, opts = {}) {
  const selector = opts.selector || 'eggmail1';
  const key = fakeKey(name.length * 7919 + 13);
  return {
    id: newId(),
    name,
    status,
    sendingPaused: !!opts.sendingPaused,
    lastCheckedAt: opts.lastCheckedAt ?? minutesAgo(12),
    nextCheckAt: opts.nextCheckAt ?? iso(Date.now() + 3_600_000),
    lastError: opts.lastError ?? null,
    records: makeRecords(name, selector, key, opts.statuses),
    dkim: { selector, publicKey: key, active: true, createdAt: daysAgo(opts.ageDays ?? 30), retiredAt: null },
    dkimKeys: [{ selector, publicKey: key, active: true, createdAt: daysAgo(opts.ageDays ?? 30), retiredAt: null }],
    _verifies: 0,
    _lastVerifyAt: 0,
  };
}

function seed() {
  return [
    makeDomain('example.com', 'verified', { ageDays: 60 }),
    makeDomain('mail.example.com', 'temporary_failure', {
      statuses: { dkim: 'invalid', dkimFound: 'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA-truncated' },
      lastError: 'DKIM record at eggmail1._domainkey.mail.example.com does not match the expected public key.',
      lastCheckedAt: minutesAgo(4),
      nextCheckAt: iso(Date.now() + 3_600_000),
      ageDays: 20,
    }),
    makeDomain('newsletter.example.net', 'pending', {
      statuses: { dkim: 'pending', return_path: 'missing', spf: 'pending', dmarc: 'pending' },
      lastCheckedAt: null,
      nextCheckAt: iso(Date.now() + 120_000),
      ageDays: 0,
    }),
    makeDomain('old.example.org', 'failed', {
      statuses: { dkim: 'missing', return_path: 'missing', spf: 'missing', dmarc: 'missing' },
      sendingPaused: true,
      lastError: 'Records were not found for more than 72 hours; sending is paused.',
      lastCheckedAt: minutesAgo(50),
      ageDays: 90,
    }),
  ];
}

/** Domains of the effective tenant (shared with the messages mock for From-domain validation). */
export function getDomains(ctx) {
  return ctx.tenantData('domains', seed);
}

const view = (d) => {
  const { _verifies, _lastVerifyAt, ...pub } = d;
  return pub;
};

function find(ctx) {
  const d = getDomains(ctx).find((x) => x.id === ctx.params.id);
  if (!d) throw new HttpError(404, 'not_found', 'Domain not found.');
  return d;
}

function allOk(d) {
  for (const r of d.records) {
    r.status = 'ok';
    r.found = r.expected;
  }
}

export function register(r) {
  r.get('/api/v1/domains', (ctx) => getDomains(ctx).map(view), { tenant: true });

  r.post(
    '/api/v1/domains',
    (ctx) => {
      const name = String(ctx.body?.name ?? '').trim().toLowerCase();
      validate((fail) => {
        if (!name) fail('name', 'A domain name is required.');
        else if (!HOST_RE.test(name)) fail('name', 'Enter a valid domain name such as mail.example.com.');
        else if (getDomains(ctx).some((d) => d.name === name)) fail('name', 'This domain already exists.');
      });
      const d = makeDomain(name, 'pending', {
        statuses: { dkim: 'pending', return_path: 'pending', spf: 'pending', dmarc: 'pending' },
        lastCheckedAt: null,
        nextCheckAt: iso(Date.now() + 120_000),
        ageDays: 0,
      });
      d.dkim.publicKey = fakeKey(Date.now() % 100000);
      d.dkimKeys[0].publicKey = d.dkim.publicKey;
      d.records[0].value = d.records[0].expected = `v=DKIM1; k=rsa; p=${d.dkim.publicKey}`;
      getDomains(ctx).push(d);
      return { status: 201, body: view(d) };
    },
    { tenant: true },
  );

  r.get('/api/v1/domains/:id', (ctx) => view(find(ctx)), { tenant: true });

  r.delete(
    '/api/v1/domains/:id',
    (ctx) => {
      const list = getDomains(ctx);
      const d = find(ctx);
      list.splice(list.indexOf(d), 1);
      return undefined;
    },
    { tenant: true },
  );

  r.post(
    '/api/v1/domains/:id/verify',
    (ctx) => {
      const d = find(ctx);
      const since = Date.now() - d._lastVerifyAt;
      if (since < VERIFY_COOLDOWN_MS) {
        const wait = Math.ceil((VERIFY_COOLDOWN_MS - since) / 1000);
        throw new HttpError(429, 'rate_limited', 'Verify now is limited to once per 30 seconds per domain.', {}, { 'Retry-After': String(wait) });
      }
      d._lastVerifyAt = Date.now();
      d._verifies += 1;
      d.lastCheckedAt = iso();
      if (d.status === 'pending') {
        d.status = 'verifying';
        d.records.forEach((rec) => (rec.status = 'pending'));
      } else if (d.status === 'verifying' && d._verifies >= 2) {
        d.status = 'verified';
        allOk(d);
        d.lastError = null;
      }
      return view(d);
    },
    { tenant: true },
  );

  // Like the server: the new key is published as advice and does not sign until its record is found; one rotation at a time.
  r.post(
    '/api/v1/domains/:id/dkim/rotate',
    (ctx) => {
      const d = find(ctx);
      if (d.dkimKeys.some((k) => !k.active && !k.retiredAt)) throw new HttpError(409, 'conflict', 'A key rotation is already pending.');
      const n = Math.max(...d.dkimKeys.map((k) => parseInt(k.selector.replace(/\D+/g, ''), 10) || 1));
      const selector = `eggmail${n + 1}`;
      const key = fakeKey(n * 31 + randomBytes(1)[0]);
      const value = `v=DKIM1; k=rsa; p=${key}`;
      const created = { selector, publicKey: key, active: false, createdAt: iso(), retiredAt: null };
      d.dkimKeys.push(created);
      d.dkim = created;
      d.records.push({ type: 'TXT', host: `${selector}._domainkey.${d.name}`, value, ttl: 3600, purpose: 'dkim', status: 'pending', expected: value, found: null });
      return view(d);
    },
    { tenant: true },
  );

  r.delete(
    '/api/v1/domains/:id/dkim/rotate',
    (ctx) => {
      const d = find(ctx);
      const pending = d.dkimKeys.filter((k) => !k.active && !k.retiredAt);
      if (!pending.length) throw new HttpError(404, 'not_found', 'No key rotation is pending.');
      d.dkimKeys = d.dkimKeys.filter((k) => !pending.includes(k));
      d.records = d.records.filter((rec) => !(rec.purpose === 'dkim' && pending.some((k) => rec.host.startsWith(`${k.selector}._domainkey.`))));
      d.dkim = d.dkimKeys[d.dkimKeys.length - 1];
      return view(d);
    },
    { tenant: true },
  );
}
