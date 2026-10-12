// Statistics and the recent-events ring. Available on every backend and in both history modes.
// Rows are generated deterministically per (tenant, hour, sending domain, recipient domain), so repeated
// calls agree and day granularity is the exact sum of its hours.
import { HttpError, iso, rng } from '../lib.mjs';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const SENDING = { t_acme: ['example.com', 'mail.example.com'], t_globex: ['globex.test'], t_initech: ['initech.test'] };
const SENDING_SHARE = { 0: 0.7, 1: 0.3 };
const RECIPIENT = [
  ['gmail.com', 0.38, 1],
  ['outlook.com', 0.18, 1],
  ['yahoo.com', 0.1, 2.2],
  ['icloud.com', 0.08, 1],
  ['example.org', 0.06, 0.5],
  ['other', 0.2, 1.3],
];
const FACTOR = { t_acme: 1, t_globex: 0.2, t_initech: 0.05 };
const PEAK_PER_HOUR = 900;
const HOURLY_RETENTION_DAYS = 30;
const DAILY_RETENTION_DAYS = 400;

function hash(...parts) {
  let h = 2166136261;
  for (const p of parts) {
    const s = String(p);
    for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619) >>> 0;
    h = Math.imul(h ^ 0x9e37, 16777619) >>> 0;
  }
  return h;
}

function hourWeight(hourStart) {
  const d = new Date(hourStart);
  const h = d.getUTCHours();
  const dow = d.getUTCDay();
  const daytime = 0.25 + 0.75 * Math.max(0, Math.sin(((h - 5) / 24) * 2 * Math.PI * 0.95 + 0.2));
  return daytime * (dow === 0 || dow === 6 ? 0.55 : 1);
}

function hourRow(tenantId, hourStart, sdIndex, sd, rdIndex) {
  const [rd, share, badness] = RECIPIENT[rdIndex];
  const r = rng(hash(tenantId, hourStart, sd, rd));
  const sdShare = (SENDING[tenantId] || [])[1] === undefined ? 1 : SENDING_SHARE[sdIndex];
  const expected = PEAK_PER_HOUR * (FACTOR[tenantId] ?? 0.1) * hourWeight(hourStart) * sdShare * share * (0.8 + 0.4 * r());
  const accepted = Math.round(expected);
  if (accepted <= 0) return null;
  const frac = (x) => Math.round(accepted * x * (0.5 + r()));
  const hardBounce = frac(0.012 * badness);
  const softBounce = frac(0.005 * badness);
  const deferred = frac(0.04 * badness);
  const expired = frac(0.0008);
  const complained = frac(0.0004);
  const suppressed = frac(0.01);
  const rejected = frac(0.003);
  const delivered = Math.max(0, accepted - hardBounce - softBounce - expired - suppressed - Math.round(deferred * 0.2));
  return { sendingDomain: sd, recipientDomain: rd, accepted, delivered, deferred, hardBounce, softBounce, expired, complained, rejected, suppressed };
}

const SUM_KEYS = ['accepted', 'delivered', 'deferred', 'hardBounce', 'softBounce', 'expired', 'complained', 'rejected', 'suppressed'];

function buildRows(tenantId, fromMs, toMs, granularity, domain) {
  const step = granularity === 'day' ? DAY : HOUR;
  const now = Date.now();
  const end = Math.min(toMs, now);
  const firstHour = Math.floor(fromMs / HOUR) * HOUR;
  const sds = SENDING[tenantId] || ['example.com'];
  const rows = [];
  let bucket = null;
  const acc = new Map();
  const flush = () => {
    if (!bucket) return;
    for (const row of acc.values()) rows.push({ period: iso(bucket), ...row });
    acc.clear();
  };
  for (let h = firstHour; h <= end; h += HOUR) {
    const period = Math.floor(h / step) * step;
    if (period !== bucket) {
      flush();
      bucket = period;
    }
    sds.forEach((sd, si) => {
      if (domain && sd !== domain) return;
      RECIPIENT.forEach((_, ri) => {
        const row = hourRow(tenantId, h, si, sd, ri);
        if (!row) return;
        const k = `${row.sendingDomain}|${row.recipientDomain}`;
        const cur = acc.get(k);
        if (!cur) acc.set(k, { ...row });
        else for (const key of SUM_KEYS) cur[key] += row[key];
      });
    });
  }
  flush();
  return rows;
}

function recentEvents(tenantId, limit) {
  const r = rng(hash(tenantId, 'ring'));
  const sds = SENDING[tenantId] || ['example.com'];
  const types = ['delivered', 'delivered', 'delivered', 'delivered', 'delivered', 'delivered', 'deferred', 'bounced', 'queued', 'suppressed', 'complained'];
  const out = [];
  let t = Date.now() - 5000;
  for (let i = 0; i < Math.min(limit, 1000); i++) {
    const rd = RECIPIENT[Math.floor(r() * RECIPIENT.length)][0];
    out.push({ at: iso(t), type: r.pick(types), recipientDomain: rd === 'other' ? 'fastmail.com' : rd, sendingDomain: r.pick(sds), tenantId });
    t -= Math.round(8000 + r() * 40000);
  }
  return out;
}

export function register(r) {
  r.get(
    '/api/v1/stats',
    (ctx) => {
      const q = ctx.query;
      const errors = [];
      const granularity = q.granularity || 'hour';
      if (granularity !== 'hour' && granularity !== 'day') errors.push({ field: 'granularity', message: 'Must be "hour" or "day"' });
      const to = q.to ? Date.parse(q.to) : Date.now();
      let from = q.from ? Date.parse(q.from) : to - DAY;
      if (Number.isNaN(to)) errors.push({ field: 'to', message: 'Not a valid ISO 8601 timestamp' });
      if (Number.isNaN(from)) errors.push({ field: 'from', message: 'Not a valid ISO 8601 timestamp' });
      if (!errors.length && from > to) errors.push({ field: 'from', message: 'Must not be after "to"' });
      if (errors.length) throw new HttpError(400, 'validation_failed', 'One or more query parameters are invalid.', { errors });
      // Retention: hourly rows for 30 days, daily rows for 400 days.
      const limitDays = granularity === 'hour' ? HOURLY_RETENTION_DAYS : DAILY_RETENTION_DAYS;
      from = Math.max(from, Date.now() - limitDays * DAY);
      return { granularity, rows: buildRows(ctx.tenantId, from, to, granularity, q.domain) };
    },
    { tenant: true },
  );

  r.get('/api/v1/stats/recent-events', (ctx) => recentEvents(ctx.tenantId, Math.max(1, parseInt(ctx.query.limit, 10) || 50)), { tenant: true });
}
