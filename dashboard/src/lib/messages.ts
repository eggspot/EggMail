import type { SendMessageRequest, StatsRow } from '../api/types';

export const MESSAGE_STATUSES = ['queued', 'delivered', 'deferred', 'bounced', 'expired', 'suppressed', 'cancelled', 'complained'] as const;

// ---- addresses and send form ----

const EMAIL_RE = /^[^\s@<>,;]+@[^\s@<>,;]+\.[^\s@<>,;]+$/;

export function isEmailAddress(value: string): boolean {
  return EMAIL_RE.test(value.trim());
}

/** Accepts `a@b.c` or `Display Name <a@b.c>`. */
export function isMailbox(value: string): boolean {
  const v = value.trim();
  const m = /^(?:.*?)<([^<>]+)>$/.exec(v);
  return isEmailAddress(m ? m[1] : v);
}

/** Splits a recipient field on commas, semicolons, whitespace and new lines. */
export function splitAddresses(text: string): string[] {
  return text
    .split(/[\s,;]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function parseHeaderLines(text: string): { headers: Record<string, string>; errors: string[] } {
  const headers: Record<string, string> = {};
  const errors: string[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\r$/, '');
    if (!line.trim()) continue;
    const i = line.indexOf(':');
    const name = i > 0 ? line.slice(0, i).trim() : '';
    if (!name || !/^[A-Za-z0-9-]+$/.test(name)) {
      errors.push(`"${line.slice(0, 40)}" is not in the form Name: value`);
      continue;
    }
    headers[name] = line.slice(i + 1).trim();
  }
  return { headers, errors };
}

export interface AttachmentInput {
  filename: string;
  content_type: string;
  /** Base64 content. */
  content: string;
  /** Decoded size in bytes. */
  size: number;
}

export interface SendFormValues {
  from: string;
  to: string;
  cc: string;
  bcc: string;
  replyTo: string;
  subject: string;
  text: string;
  html: string;
  tags: string;
  headers: string;
  storeAttachments: boolean;
  attachments: AttachmentInput[];
}

export const emptySendForm: SendFormValues = {
  from: '',
  to: '',
  cc: '',
  bcc: '',
  replyTo: '',
  subject: '',
  text: '',
  html: '',
  tags: '',
  headers: '',
  storeAttachments: false,
  attachments: [],
};

export interface SendValidation {
  errors: Record<string, string>;
  request?: SendMessageRequest;
}

export function validateSendForm(v: SendFormValues, limits: { maxMessageBytes: number; maxRecipients: number }): SendValidation {
  const errors: Record<string, string> = {};
  if (!v.from.trim()) errors.from = 'Enter the sender address.';
  else if (!isMailbox(v.from)) errors.from = 'Enter a valid address such as sender@example.com or Name <sender@example.com>.';

  const lists = { to: splitAddresses(v.to), cc: splitAddresses(v.cc), bcc: splitAddresses(v.bcc) };
  for (const key of ['to', 'cc', 'bcc'] as const) {
    const bad = lists[key].filter((a) => !isEmailAddress(a));
    if (bad.length) errors[key] = `Not a valid email address: ${bad.slice(0, 3).join(', ')}${bad.length > 3 ? ' ...' : ''}`;
  }
  if (!lists.to.length && !errors.to) errors.to = 'Enter at least one recipient.';
  const total = lists.to.length + lists.cc.length + lists.bcc.length;
  if (total > limits.maxRecipients && !errors.to) errors.to = `At most ${limits.maxRecipients} recipients in total (you entered ${total}).`;
  if (v.replyTo.trim() && !isMailbox(v.replyTo)) errors.reply_to = 'Enter a valid reply-to address.';
  if (!v.subject.trim()) errors.subject = 'Enter a subject.';
  else if (/[\r\n]/.test(v.subject)) errors.subject = 'The subject must be a single line.';
  if (!v.text.trim() && !v.html.trim()) errors.text = 'Enter a text body, an HTML body, or both.';

  const { headers, errors: headerErrors } = parseHeaderLines(v.headers);
  if (headerErrors.length) errors.headers = headerErrors[0];

  const attachmentBytes = v.attachments.reduce((n, a) => n + a.size, 0);
  const estimated = attachmentBytes * (4 / 3) + v.text.length + v.html.length + 2000;
  if (estimated > limits.maxMessageBytes) errors.attachments = `The message would exceed the server limit of ${Math.floor(limits.maxMessageBytes / 1048576)} MiB.`;

  if (Object.keys(errors).length) return { errors };

  const request: SendMessageRequest = { from: v.from.trim(), to: lists.to, subject: v.subject.trim() };
  if (lists.cc.length) request.cc = lists.cc;
  if (lists.bcc.length) request.bcc = lists.bcc;
  if (v.replyTo.trim()) request.reply_to = v.replyTo.trim();
  if (v.text.trim()) request.text = v.text;
  if (v.html.trim()) request.html = v.html;
  const tags = v.tags.split(/[,\n]/).map((t) => t.trim()).filter(Boolean);
  if (tags.length) request.tags = tags;
  if (Object.keys(headers).length) request.headers = headers;
  if (v.attachments.length) {
    request.attachments = v.attachments.map((a) => ({ filename: a.filename, content_type: a.content_type, content: a.content }));
    if (v.storeAttachments) request.store_attachments = true;
  }
  return { errors, request };
}

/** Maps a server field path such as `to[1]` or `attachments[0].content` to the form field it belongs to. */
export function formFieldFor(serverField: string): string {
  return serverField.replace(/\[\d+\].*$/, '').replace(/\..*$/, '');
}

export function newIdempotencyKey(): string {
  const c = globalThis.crypto;
  if (c?.randomUUID) return c.randomUUID();
  const bytes = new Uint8Array(16);
  if (c?.getRandomValues) c.getRandomValues(bytes);
  else for (let i = 0; i < 16; i++) bytes[i] = Math.floor(Math.random() * 256);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// ---- statistics helpers ----

export interface Totals {
  accepted: number;
  delivered: number;
  deferred: number;
  bounced: number;
  expired: number;
  complained: number;
  suppressed: number;
  rejected: number;
}

export const emptyTotals = (): Totals => ({ accepted: 0, delivered: 0, deferred: 0, bounced: 0, expired: 0, complained: 0, suppressed: 0, rejected: 0 });

export function addRow(t: Totals, r: StatsRow): Totals {
  t.accepted += r.accepted;
  t.delivered += r.delivered;
  t.deferred += r.deferred;
  t.bounced += r.hardBounce + r.softBounce;
  t.expired += r.expired;
  t.complained += r.complained;
  t.suppressed += r.suppressed;
  t.rejected += r.rejected;
  return t;
}

export function totalsOf(rows: StatsRow[]): Totals {
  const t = emptyTotals();
  for (const r of rows) addRow(t, r);
  return t;
}

export interface DomainRow extends Totals {
  domain: string;
}

export function byRecipientDomain(rows: StatsRow[]): DomainRow[] {
  const map = new Map<string, DomainRow>();
  for (const r of rows) {
    const key = r.recipientDomain || '(unknown)';
    let row = map.get(key);
    if (!row) map.set(key, (row = { domain: key, ...emptyTotals() }));
    addRow(row, r);
  }
  return [...map.values()];
}

export interface BucketPoint {
  period: string;
  delivered: number;
  deferred: number;
  bounced: number;
}

const STEP = { hour: 3_600_000, day: 86_400_000 } as const;

const COUNTERS = ['accepted', 'delivered', 'deferred', 'hardBounce', 'softBounce', 'expired', 'complained', 'rejected', 'suppressed'] as const;

/**
 * The server rolls hourly rows up into daily rows only for days that are over, so a daily query never contains today (and perhaps
 * not yesterday). This adds the days that have no daily row yet by summing the given hourly rows per UTC day, series by series.
 */
export function mergeUnrolledDays(daily: StatsRow[], hourly: StatsRow[]): StatsRow[] {
  const day = STEP.day;
  const rolled = new Set(daily.map((r) => Math.floor(Date.parse(r.period) / day)));
  const sums = new Map<string, StatsRow>();
  for (const h of hourly) {
    const t = Date.parse(h.period);
    if (Number.isNaN(t)) continue;
    const dayIndex = Math.floor(t / day);
    if (rolled.has(dayIndex)) continue;
    const key = `${dayIndex}|${h.sendingDomain ?? ''}|${h.recipientDomain ?? ''}`;
    let row = sums.get(key);
    if (!row) {
      row = { period: new Date(dayIndex * day).toISOString(), sendingDomain: h.sendingDomain, recipientDomain: h.recipientDomain, accepted: 0, delivered: 0, deferred: 0, hardBounce: 0, softBounce: 0, expired: 0, complained: 0, rejected: 0, suppressed: 0 };
      sums.set(key, row);
    }
    for (const c of COUNTERS) row[c] += h[c];
  }
  return [...daily, ...sums.values()];
}

/** Sums rows per period and fills periods without traffic with zeros so the time axis is continuous. */
export function bucketRows(rows: StatsRow[], granularity: 'hour' | 'day', fromMs: number, toMs: number): BucketPoint[] {
  const step = STEP[granularity];
  const map = new Map<number, BucketPoint>();
  for (const r of rows) {
    const t = Date.parse(r.period);
    if (Number.isNaN(t)) continue;
    const key = Math.floor(t / step) * step;
    let p = map.get(key);
    if (!p) map.set(key, (p = { period: new Date(key).toISOString(), delivered: 0, deferred: 0, bounced: 0 }));
    p.delivered += r.delivered;
    p.deferred += r.deferred;
    p.bounced += r.hardBounce + r.softBounce;
  }
  const out: BucketPoint[] = [];
  const start = Math.floor(fromMs / step) * step;
  const end = Math.floor(toMs / step) * step;
  const count = Math.floor((end - start) / step) + 1;
  if (count > 0 && count <= 1000) {
    for (let t = start; t <= end; t += step) out.push(map.get(t) ?? { period: new Date(t).toISOString(), delivered: 0, deferred: 0, bounced: 0 });
    return out;
  }
  return [...map.entries()].sort((a, b) => a[0] - b[0]).map(([, p]) => p);
}
