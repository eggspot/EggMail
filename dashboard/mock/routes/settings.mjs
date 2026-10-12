// Tenant settings (GET/PUT /api/v1/settings). Global settings (/admin/settings) are mocked elsewhere.
import { HttpError } from '../lib.mjs';

function seed() {
  return [
    { key: 'Content:StoreAttachments', value: false, type: 'boolean', description: 'Store attachments of sent messages so they can be resent. Off by default; stored attachments increase disk use.' },
    { key: 'Content:RetentionDays', value: 7, type: 'number', description: 'Days message content is kept (6 to 30; there is no unlimited value).' },
    { key: 'Retention:MetadataDays', value: 30, type: 'number', description: 'Days delivery events are kept. 0 keeps them forever.' },
    { key: 'Webhooks:AllowedHosts', value: '', type: 'string', description: 'Comma separated internal hosts webhooks may call (SSRF allowlist).' },
    { key: 'Tls:RequireOutbound', value: 'may', type: 'enum', options: ['none', 'may', 'encrypt', 'verify'], description: 'Outbound TLS policy: none, may (opportunistic), encrypt or verify.' },
    { key: 'Smtp:MaxRecipients', value: 50, type: 'number', description: 'Maximum recipients per message.', locked: true },
  ];
}

const items = (ctx) => ctx.tenantData('settings', seed);

function check(item, value, fail) {
  if (item.type === 'number') {
    const n = Number(value);
    if (value === '' || value === null || !Number.isInteger(n) || n < 0) return fail(item.key, 'Enter a whole number, 0 or greater.');
    if (item.key === 'Content:RetentionDays' && (n < 6 || n > 30)) fail(item.key, 'Content retention must be between 6 and 30 days.');
  } else if (item.type === 'boolean') {
    if (typeof value !== 'boolean') fail(item.key, 'Must be true or false.');
  } else if (item.type === 'enum') {
    if (!item.options.includes(value)) fail(item.key, `Must be one of: ${item.options.join(', ')}.`);
  }
}

export function register(r) {
  r.get('/api/v1/settings', (ctx) => ({ items: items(ctx) }), { tenant: true });
  r.put(
    '/api/v1/settings',
    (ctx) => {
      const values = ctx.body?.values;
      if (!values || typeof values !== 'object') throw new HttpError(400, 'validation_failed', 'values is required.', { errors: [{ field: 'values', message: 'required' }] });
      const list = items(ctx);
      const errors = [];
      const fail = (field, message) => errors.push({ field, message });
      for (const [k, v] of Object.entries(values)) {
        const it = list.find((i) => i.key === k);
        if (!it) fail(k, 'Unknown setting.');
        else if (it.locked) fail(k, 'This setting is locked by deployment configuration.');
        else check(it, v, fail);
      }
      if (errors.length) throw new HttpError(400, 'validation_failed', 'One or more settings are invalid.', { errors });
      for (const [k, v] of Object.entries(values)) {
        const it = list.find((i) => i.key === k);
        it.value = it.type === 'number' ? Number(v) : v;
      }
      return { items: list };
    },
    { tenant: true },
  );
}
