import crypto from 'node:crypto';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

// Received mail in the real server's queue file. The SMTP receive path (a listener of the Inbound role) is a separate piece; these specs are about
// the dashboard and the API reading received mail, so messages are placed where the receive path puts them: one row and one body per recipient.
// The values are written the way the storage writes them (ids as upper-case text, times as Unix milliseconds, enums as their numbers), and the
// columns are checked against the file first, so a schema change fails here with its name instead of as a puzzling empty page.

const VERDICT = { none: 0, pass: 1, fail: 2, softfail: 3, neutral: 4, temperror: 5, permerror: 6, policy: 7 };
const ACTION = { webhook: 0, forward: 1, store: 2, discard: 3 };
const STATE = { pending: 0, done: 1, failed: 2 };

const COLUMNS = [
  'id', 'tenant_id', 'domain_id', 'domain', 'received_at', 'remote_address', 'helo', 'tls_used', 'envelope_from', 'envelope_to', 'subject', 'size', 'spf', 'spf_domain', 'spf_helo',
  'dkim', 'dkim_domain', 'dmarc', 'dmarc_policy', 'arc', 'disposition', 'route_id', 'action_kind', 'action_state', 'action_attempts', 'retry_generation', 'action_next_attempt_at',
  'action_finished_at', 'action_last_error', 'action_note', 'forward_message_id', 'has_raw', 'lease_owner', 'lease_until', 'transfer_switch_id',
];

/** A UUIDv7 for the given time: ids sort by time, and the list shows newest first. */
export function uuidv7(at = Date.now()) {
  const bytes = crypto.randomBytes(16);
  bytes.writeUIntBE(at, 0, 6);
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** The compact (32 hex digits) form the API uses for an id. */
export const compact = (id) => id.replaceAll('-', '').toLowerCase();

const upper = (id) => id.toUpperCase();

/**
 * Stores one received message. `raw` is the message as a string with CRLF line ends. Returns its compact id.
 * `route` is the compact id of the route it arrived under; `action` is { kind, state, attempts, error, note } as the receive path and the runner would leave it.
 */
export function seedInboundMessage(stack, { tenantId, domainId, domain, to, from = 'alice@sender.test', subject = 'Hello', raw, route = null, action = {}, auth = {}, flagged = false, receivedAt = Date.now(), remote = '203.0.113.9' }) {
  const id = uuidv7(receivedAt);
  const db = new DatabaseSync(path.join(stack.dataDir, 'queue.db'));
  try {
    db.exec('PRAGMA busy_timeout = 15000');
    const found = db.prepare("SELECT name FROM pragma_table_info('inbound_message')").all().map((r) => r.name);
    const missing = COLUMNS.filter((c) => !found.includes(c));
    const extra = found.filter((c) => !COLUMNS.includes(c));
    if (missing.length || extra.length) throw new Error(`inbound_message changed: missing ${missing.join(', ')}; unexpected ${extra.join(', ')}`);

    const kind = action.kind ?? 'store';
    const state = action.state ?? (kind === 'webhook' || kind === 'forward' ? 'pending' : 'done');
    const asId = (v) => (v ? upper(v.length === 32 ? `${v.slice(0, 8)}-${v.slice(8, 12)}-${v.slice(12, 16)}-${v.slice(16, 20)}-${v.slice(20)}` : v) : null);
    const bytes = Buffer.from(raw, 'utf8');
    const values = {
      id: upper(id),
      tenant_id: asId(tenantId),
      domain_id: asId(domainId),
      domain,
      received_at: receivedAt,
      remote_address: remote,
      helo: 'mail.sender.test',
      tls_used: 1,
      envelope_from: from.toLowerCase(),
      envelope_to: to.toLowerCase(),
      subject,
      size: bytes.length,
      spf: VERDICT[auth.spf ?? 'pass'],
      spf_domain: 'sender.test',
      spf_helo: VERDICT[auth.spfHelo ?? 'none'],
      dkim: VERDICT[auth.dkim ?? 'pass'],
      dkim_domain: 'sender.test',
      dmarc: VERDICT[auth.dmarc ?? 'pass'],
      dmarc_policy: auth.policy ?? 'reject',
      arc: VERDICT[auth.arc ?? 'none'],
      disposition: flagged ? 1 : 0,
      route_id: asId(route),
      action_kind: ACTION[kind],
      action_state: STATE[state],
      action_attempts: action.attempts ?? 0,
      retry_generation: 0,
      // A message waiting for its action is due in the future unless the spec says otherwise, so the runner of the live server does not pick it up and change it.
      action_next_attempt_at: state === 'pending' ? (action.dueAt ?? Date.now() + 3_600_000) : null,
      action_finished_at: state === 'pending' ? null : Date.now(),
      action_last_error: action.error ?? null,
      action_note: action.note ?? null,
      forward_message_id: null,
      has_raw: 1,
      lease_owner: null,
      lease_until: 0,
      transfer_switch_id: null,
    };
    db.prepare(`INSERT INTO inbound_message (${COLUMNS.join(', ')}) VALUES (${COLUMNS.map(() => '?').join(', ')})`).run(...COLUMNS.map((c) => values[c]));
    db.prepare('INSERT INTO inbound_message_raw (message_id, tenant_id, raw) VALUES (?, ?, ?)').run(upper(id), asId(tenantId), bytes);
  } finally {
    db.close();
  }
  return compact(id);
}

/** A message with a text part, an HTML part that tries everything, and one attachment. */
export function sampleMessage({ from = 'Alice <alice@sender.test>', to = 'support@example.test', subject = 'Quarterly report', text = 'Hello,\r\nthe report is attached.\r\n', html = '<p>Hello, <b>the report</b> is attached.</p>' } = {}) {
  return [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    'Message-ID: <e2e-1@sender.test>',
    'Date: Fri, 16 Oct 2026 07:00:00 +0000',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="b1"',
    '',
    '--b1',
    'Content-Type: multipart/alternative; boundary="b2"',
    '',
    '--b2',
    'Content-Type: text/plain; charset=utf-8',
    '',
    text,
    '--b2',
    'Content-Type: text/html; charset=utf-8',
    '',
    html,
    '--b2--',
    '--b1',
    'Content-Type: application/pdf; name="report.pdf"',
    'Content-Disposition: attachment; filename="report.pdf"',
    'Content-Transfer-Encoding: base64',
    '',
    Buffer.from('%PDF-1.4 e2e attachment').toString('base64'),
    '--b1--',
    '',
  ].join('\r\n');
}
