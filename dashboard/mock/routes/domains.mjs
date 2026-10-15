// Domains: list/create/delete, records (zone file), verify (30 s rate limit), DKIM rotation.
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

const ALL_PURPOSES = ['dkim', 'return_path', 'spf', 'dmarc', 'tls_rpt', 'mta_sts', 'mta_sts_host', 'bounce_mx', 'ptr'];

/** Every record in one state (the common case of the seeded domains), with single purposes overridden. */
function statusesFor(state, overrides = {}) {
  return { ...Object.fromEntries(ALL_PURPOSES.map((p) => [p, state])), ...overrides };
}

function makeRecords(name, selector, key, statuses = {}) {
  const dkimValue = `v=DKIM1; k=rsa; p=${key}`;
  const state = (purpose) => statuses[purpose] || 'ok';
  const rec = (type, host, value, purpose, required, note) => {
    const status = state(purpose);
    return { type, host, value, ttl: 3600, purpose, required, note, status, expected: value, found: status === 'ok' ? value : null };
  };
  const dkim = rec('TXT', `${selector}._domainkey.${name}`, dkimValue, 'dkim', true, 'Lets receivers verify that mail from this domain is signed by EggMail.');
  if (statuses.dkimFound !== undefined) dkim.found = statuses.dkimFound;
  return [
    dkim,
    rec('CNAME', `bounces.${name}`, 'bounce.eggmail.example.net', 'return_path', true, 'Makes bounce messages for this domain reach EggMail.'),
    rec('TXT', name, 'v=spf1 include:spf.eggmail.example.net ~all', 'spf', false, 'Authorizes this server to send for the domain. Keep a single SPF record per domain: merge this into an existing one.'),
    rec('TXT', `_dmarc.${name}`, `v=DMARC1; p=none; rua=mailto:dmarc@${name}`, 'dmarc', false, 'Tells receivers what to do with mail that fails authentication and where to send reports. The default only monitors (p=none).'),
    rec('TXT', `_smtp._tls.${name}`, `v=TLSRPTv1; rua=mailto:tls-rpt@${name}`, 'tls_rpt', false, 'Asks receivers to send daily TLS reports (RFC 8460) to the address in rua.'),
    rec('TXT', `_mta-sts.${name}`, 'v=STSv1; id=0123456789abcdef', 'mta_sts', false, `Announces the MTA-STS policy that EggMail serves at https://mta-sts.${name}/.well-known/mta-sts.txt. The id changes when the policy changes.`),
    rec('CNAME', `mta-sts.${name}`, 'mta.eggmail.example.net', 'mta_sts_host', false, `Must lead to this server (mta.eggmail.example.net) so it can serve the policy over HTTPS; its certificate has to cover mta-sts.${name}.`),
    rec('MX', 'bounce.eggmail.example.net', '10 mta.eggmail.example.net', 'bounce_mx', false, 'Published once by the operator for all domains: delivers bounces for the bounce domain to this server (port 25 reaches the bounce listener).'),
    rec('PTR', 'mta.eggmail.example.net', 'mta.eggmail.example.net', 'ptr', false, "Advice: the reverse DNS of the sending IP should be this server's host name. It is set at whoever owns the IP address (your hosting provider), not in your zone."),
  ];
}

const PURPOSE_LABEL = { dkim: 'DKIM', return_path: 'Return-path', spf: 'SPF', dmarc: 'DMARC', bounce_mx: 'Bounce MX', tls_rpt: 'TLS-RPT', mta_sts: 'MTA-STS', mta_sts_host: 'MTA-STS host', ptr: 'Reverse DNS' };
const fqdn = (n) => (n.endsWith('.') ? n : `${n}.`);
const quoted = (v) =>
  v
    .match(/.{1,255}/g)
    .map((piece) => `"${piece.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`)
    .join(' ');

function zoneLine(r, zone) {
  const inZone = r.host === zone || r.host.endsWith(`.${zone}`);
  if (r.type === 'TXT') return `${fqdn(r.host)} ${r.ttl} IN TXT ${quoted(r.value)}`;
  if (r.type === 'CNAME') return `${fqdn(r.host)} ${r.ttl} IN CNAME ${fqdn(r.value)}`;
  if (r.type === 'MX' && !inZone) return `; MX ${r.host} -> ${r.value} (published once by whoever runs EggMail, not in this zone)`;
  if (r.type === 'MX') {
    const [preference, target] = r.value.split(' ');
    return `${fqdn(r.host)} ${r.ttl} IN MX ${preference} ${fqdn(target)}`;
  }
  return `; ${r.type} ${r.host} -> ${r.value}`;
}

function zoneFile(d) {
  const lines = [`; DNS records for ${d.name}`, '; Required records decide whether the domain can send; recommended ones improve delivery and give you reports.'];
  for (const r of d.records) lines.push('', `; ${PURPOSE_LABEL[r.purpose]} (${r.required ? 'required' : 'recommended'}): ${r.note}`, zoneLine(r, d.name));
  return `${lines.join('\n')}\n`;
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
      statuses: { dkim: 'mismatch', dkimFound: 'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA-truncated' },
      lastError: 'DKIM record at eggmail1._domainkey.mail.example.com does not match the expected public key.',
      lastCheckedAt: minutesAgo(4),
      nextCheckAt: iso(Date.now() + 3_600_000),
      ageDays: 20,
    }),
    makeDomain('newsletter.example.net', 'pending', {
      statuses: statusesFor('pending', { return_path: 'missing' }),
      lastCheckedAt: null,
      nextCheckAt: iso(Date.now() + 120_000),
      ageDays: 0,
    }),
    makeDomain('old.example.org', 'failed', {
      statuses: statusesFor('missing'),
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

/** Verified, or in the grace period of a temporary failure, and not paused (design section 8). */
const readyToSend = (d) => (d.status === 'verified' || d.status === 'temporary_failure') && !d.sendingPaused;

const view = (d) => {
  const { _verifies, _lastVerifyAt, ...pub } = d;
  return { ...pub, readyToSend: readyToSend(d) };
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
        statuses: statusesFor('pending'),
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

  // What to publish, as records and as zone-file text; nothing is looked up.
  r.get(
    '/api/v1/domains/:id/records',
    (ctx) => {
      const d = find(ctx);
      return {
        id: d.id,
        name: d.name,
        readyToSend: readyToSend(d),
        checkedAt: d.lastCheckedAt,
        records: d.records,
        zoneFile: zoneFile(d),
        mtaStsPolicy: {
          url: `https://mta-sts.${d.name}/.well-known/mta-sts.txt`,
          host: `mta-sts.${d.name}`,
          content: 'version: STSv1\r\nmode: testing\r\nmx: mta.eggmail.example.net\r\nmax_age: 604800\r\n',
        },
      };
    },
    { tenant: true },
  );

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
        throw new HttpError(429, 'rate_limited', 'Checking is limited to once per 30 seconds per domain.', {}, { 'Retry-After': String(wait) });
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
      const note = 'Lets receivers verify that mail from this domain is signed by EggMail.';
      d.records.splice(1, 0, { type: 'TXT', host: `${selector}._domainkey.${d.name}`, value, ttl: 3600, purpose: 'dkim', required: false, note, status: 'pending', expected: value, found: null });
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
