// Suppression list: cursor pagination, add (idempotent), remove.
import { EMAIL_RE, HttpError, daysAgo, paginate, rng, validate } from '../lib.mjs';

function seed() {
  const rand = rng(77);
  const reasons = ['bounce', 'bounce', 'complaint', 'manual'];
  const first = ['anna', 'ben', 'carla', 'dev', 'erin', 'finn', 'gus', 'hana', 'ivan', 'jules', 'kim', 'lee'];
  const doms = ['gmail.example', 'outlook.example', 'corp.example', 'mail.test', 'isp.example'];
  const out = [];
  for (let i = 0; i < 60; i++) {
    out.push({ address: `${first[i % first.length]}${i}@${rand.pick(doms)}`, reason: rand.pick(reasons), createdAt: daysAgo(rand.int(0, 120)) });
  }
  out.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
  return out;
}

const list = (ctx) => ctx.tenantData('suppressions', seed);

export function register(r) {
  r.get('/api/v1/suppressions', (ctx) => paginate(list(ctx), ctx.query, 25), { tenant: true });

  r.post(
    '/api/v1/suppressions',
    (ctx) => {
      const address = String(ctx.body?.address ?? '').trim().toLowerCase();
      const reason = String(ctx.body?.reason ?? 'manual');
      validate((fail) => {
        if (!address) fail('address', 'An email address is required.');
        else if (!EMAIL_RE.test(address)) fail('address', 'Enter a valid email address.');
        if (!['manual', 'bounce', 'complaint'].includes(reason)) fail('reason', 'Reason must be manual, bounce or complaint.');
      });
      const items = list(ctx);
      const existing = items.find((s) => s.address === address);
      if (existing) return existing;
      const s = { address, reason, createdAt: new Date().toISOString() };
      items.unshift(s);
      return { status: 201, body: s };
    },
    { tenant: true },
  );

  r.delete(
    '/api/v1/suppressions/:address',
    (ctx) => {
      const items = list(ctx);
      const i = items.findIndex((s) => s.address === ctx.params.address.toLowerCase());
      if (i < 0) throw new HttpError(404, 'not_found', 'That address is not on the suppression list.');
      items.splice(i, 1);
      return undefined;
    },
    { tenant: true },
  );
}
