// Pure helpers of the inbound pages: labels, the settings and route forms and their validation. The server validates everything again (docs/api.md);
// these checks give the message next to the field before the request is made, and mirror its rules (InboundRules in Mta.Storage).
import type {
  DmarcActionWord,
  InboundActionKindWord,
  InboundActionStateWord,
  InboundMatchKindWord,
  InboundRoute,
  InboundRouteInput,
  InboundSettings,
  InboundSettingsPatch,
  InboundVerdictWord,
  InboundWebhookFormatWord,
} from '../api/types';
import type { Tone } from '../components/ui';

export const DMARC_ACTIONS: { value: DmarcActionWord; label: string; help: string }[] = [
  { value: 'record_only', label: 'Record only', help: 'Accept every message and record the DMARC verdict. Nothing is ever refused because of the sender\'s policy.' },
  { value: 'flag', label: 'Flag', help: 'Accept every message; one that fails a quarantine or reject policy is stored flagged (header X-EggMail-Dmarc: flagged, "DMARC flagged" in the list and in webhooks). Nothing is moved or dropped.' },
  { value: 'reject', label: 'Reject', help: 'Refuse a message that fails a reject policy during the SMTP conversation (550 5.7.1), so the sender is told. A quarantine failure is flagged as above.' },
];

export const ACTION_KINDS: { value: InboundActionKindWord; label: string; help: string }[] = [
  { value: 'store', label: 'Store', help: 'Keep the message for reading in the dashboard and through the API until the retention ends.' },
  { value: 'webhook', label: 'Webhook', help: 'POST every message to one of your webhook endpoints (signed), as JSON or as the raw message.' },
  { value: 'forward', label: 'Forward', help: 'Send a copy to other addresses through the outbound queue (SRS envelope, your sending limits apply).' },
  { value: 'discard', label: 'Discard', help: 'Accept and drop the message; only a record that it arrived is kept.' },
];

export const MATCH_KINDS: { value: InboundMatchKindWord; label: string }[] = [
  { value: 'catch_all', label: 'Every address' },
  { value: 'address', label: 'One address' },
  { value: 'wildcard', label: 'Pattern with *' },
];

export const VERDICTS: InboundVerdictWord[] = ['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror', 'policy'];

export function actionLabel(kind: InboundActionKindWord | null | undefined): string {
  return ACTION_KINDS.find((a) => a.value === kind)?.label ?? String(kind ?? '-');
}

export function verdictTone(result: InboundVerdictWord): Tone {
  switch (result) {
    case 'pass':
      return 'ok';
    case 'fail':
    case 'permerror':
      return 'bad';
    case 'softfail':
    case 'temperror':
      return 'warn';
    default:
      return 'neutral';
  }
}

export function stateTone(state: InboundActionStateWord): Tone {
  return state === 'done' ? 'ok' : state === 'failed' ? 'bad' : 'info';
}

/** What a code in `action.lastError` (or `action.note`) means, in the tenant's words. Unknown codes are shown as they are. */
export function explainActionCode(code: string | null | undefined): string | null {
  if (!code) return null;
  const known: Record<string, string> = {
    inbound_disabled: 'Inbound mail is switched off on this server, so the action was not carried out. It is tried again until the attempts are used up.',
    tenant_suspended: 'The tenant is suspended, so the action was not carried out.',
    endpoint_disabled: 'The webhook endpoint is disabled. Enable it again (Webhooks page) and the message is delivered at the next attempt, or use Retry.',
    endpoint_missing: 'The webhook endpoint of the route no longer exists.',
    endpoint_not_of_tenant: 'The route names a webhook endpoint that is not yours.',
    route_deleted: 'The route that received this message was deleted before its action could run.',
    body_missing: 'The stored message is gone, so the action cannot run.',
    attempts_exhausted: 'The attempts were used up (the server stopped in the middle of them).',
    too_large_for_raw_webhook: 'The message is too large for the raw webhook format. Use the JSON format or download the message.',
    secret_unreadable: 'The signing secret of the webhook endpoint cannot be read. Rotate the secret.',
    loop_detected: 'The message had already been forwarded by this server three times; it is not forwarded again.',
    forward_target_is_local: 'A forward address belongs to a domain this server receives for, which would loop. Edit the route.',
    invalid_forward_target: 'A forward address of the route is not valid.',
    unauthenticated_local_sender: 'The message claims to be from your own domain but failed DMARC, so it is not forwarded (it could be a spoof that a forward would make look genuine).',
    forward_unavailable: 'Forwarding is not available on this server right now.',
    forward_backlog_full: 'Too many forwarded messages of yours are already waiting to be delivered. This one is kept and tried again; it goes out when the queue has room.',
    forward_key_conflict: 'Another message already holds the reference this forward needs, so nothing was sent. Contact the operator.',
    dmarc_unsettled: 'The sender check (DMARC) could not be completed when the message arrived, and it claims to be from your own domain, so it is not forwarded. The result is the one recorded on arrival, so trying again does not change it.',
    srs_failed: 'The sender address of the message could not be rewritten for forwarding, so it was not forwarded.',
    all_targets_suppressed: 'Every forward address is on your suppression list, so nothing was sent.',
    route_is_now_store: 'The route was changed to "store" while this message waited, so nothing was delivered. The message is kept until the retention ends.',
    route_is_now_discard: 'The route was changed to "discard" while this message waited, so nothing was delivered. The message is kept until the retention ends.',
  };
  if (known[code]) return known[code];
  if (code === 'webhook_gone') return 'The receiver answered 410 Gone; the endpoint was switched off.';
  if (code === 'webhook_timeout') return 'The receiver did not answer in time.';
  if (code === 'webhook_ssrf_blocked') return 'The endpoint resolves to an internal address that is not allowed. An administrator can allow your network.';
  if (code === 'webhook_connect_failed') return 'Could not connect to the receiver.';
  if (code === 'webhook_throttled') return 'The receiver asked to slow down (429, 502 or 504).';
  if (code === 'webhook_redirect_not_followed') return 'The receiver answered with a redirect, which is not followed.';
  const http = /^webhook_http_(\d{3})$/.exec(code);
  if (http) return `The receiver answered HTTP ${http[1]}.`;
  return null;
}

export function canRetry(m: { hasRaw: boolean; action: { kind: InboundActionKindWord; currentKind?: InboundActionKindWord | null; state: InboundActionStateWord } }): boolean {
  const kind = m.action.currentKind ?? m.action.kind;
  return m.hasRaw && (kind === 'webhook' || kind === 'forward') && m.action.state !== 'pending';
}

/* ---------- settings form ---------- */

export interface SettingsForm {
  enabled: boolean;
  dmarcAction: DmarcActionWord;
  /** Text fields: '' is "the server value". Sizes are in MiB. */
  maxMessageMiB: string;
  maxMessagesPerMinute: string;
  maxMessagesPerMinutePerRemote: string;
  maxStoredMiB: string;
  /** '' is the server value; '0' keeps messages forever. */
  retentionDays: string;
}

const MIB = 1024 * 1024;

/**
 * The size in MiB as shown in the form: six decimals, so the number of bytes comes back exactly for any size that is a whole number of bytes up to a gigabyte
 * (25000000 bytes shows as 23.841858, 1024 bytes as 0.000977) and a value the tenant did not touch can be recognized by its text.
 */
function mibText(bytes: number | null): string {
  if (bytes === null) return '';
  if (bytes === 0) return '0';
  const mib = bytes / MIB;
  return Number.isInteger(mib) ? String(mib) : mib.toFixed(6).replace(/0+$/, '').replace(/\.$/, '');
}

export function settingsToForm(s: InboundSettings): SettingsForm {
  return {
    enabled: s.enabled,
    dmarcAction: s.dmarcAction,
    maxMessageMiB: mibText(s.maxMessageBytes),
    maxMessagesPerMinute: s.maxMessagesPerMinute === null ? '' : String(s.maxMessagesPerMinute),
    maxMessagesPerMinutePerRemote: s.maxMessagesPerMinutePerRemote === null ? '' : String(s.maxMessagesPerMinutePerRemote),
    maxStoredMiB: mibText(s.maxStoredBytes),
    retentionDays: s.retentionDays === null ? '' : String(s.retentionDays),
  };
}

function parseWhole(text: string): number | null | undefined {
  const t = text.trim();
  if (t === '') return null;
  if (!/^\d+$/.test(t)) return undefined;
  const n = Number(t);
  return Number.isSafeInteger(n) ? n : undefined;
}

function parseMiB(text: string): number | null | undefined {
  const t = text.trim();
  if (t === '') return null;
  if (!/^\d+(\.\d{1,6})?$/.test(t)) return undefined;
  return Math.round(Number(t) * MIB);
}

export type SettingsErrors = Partial<Record<keyof SettingsForm, string>>;

/** Ranges of docs/api.md; the operator's ceilings are checked by the server (a tenant can only lower them) and reported next to the field. */
export function validateSettings(f: SettingsForm): SettingsErrors {
  const errors: SettingsErrors = {};
  const size = parseMiB(f.maxMessageMiB);
  if (size === undefined || (size !== null && (size < 1024 || size > 1024 * MIB))) errors.maxMessageMiB = 'Enter a size in MiB between 0.001 and 1024, or leave it empty for the server value.';
  const perMinute = parseWhole(f.maxMessagesPerMinute);
  if (perMinute === undefined || (perMinute !== null && (perMinute < 1 || perMinute > 100000))) errors.maxMessagesPerMinute = 'Enter a whole number from 1 to 100000, or leave it empty.';
  const perRemote = parseWhole(f.maxMessagesPerMinutePerRemote);
  if (perRemote === undefined || (perRemote !== null && (perRemote < 1 || perRemote > 10000))) errors.maxMessagesPerMinutePerRemote = 'Enter a whole number from 1 to 10000, or leave it empty.';
  const stored = parseMiB(f.maxStoredMiB);
  if (stored === undefined || (stored !== null && stored !== 0 && (stored < MIB || stored > 2 ** 50))) errors.maxStoredMiB = 'Enter 0 (unlimited) or a size of at least 1 MiB, or leave it empty for the server value.';
  const days = parseWhole(f.retentionDays);
  if (days === undefined || (days !== null && days > 36500)) errors.retentionDays = 'Enter a number of days from 0 (keep forever) to 36500, or leave it empty for the server value.';
  return errors;
}

/**
 * The members that differ from what is stored, as a PATCH body. Only these are sent, so a ceiling the operator lowered later never blocks a change of something else.
 * A number is sent only when its text in the form differs from the text of the stored value: the form shows sizes in MiB, which cannot be an exact copy of every byte count, and a value
 * the tenant did not touch must never be written back as a rounded one.
 */
export function settingsPatch(original: InboundSettings, f: SettingsForm): InboundSettingsPatch {
  const unchanged = settingsToForm(original);
  const patch: InboundSettingsPatch = {};
  if (f.enabled !== original.enabled) patch.enabled = f.enabled;
  if (f.dmarcAction !== original.dmarcAction) patch.dmarcAction = f.dmarcAction;
  if (f.maxMessageMiB.trim() !== unchanged.maxMessageMiB) {
    const size = parseMiB(f.maxMessageMiB);
    if (size !== undefined) patch.maxMessageBytes = size;
  }

  if (f.maxMessagesPerMinute.trim() !== unchanged.maxMessagesPerMinute) {
    const perMinute = parseWhole(f.maxMessagesPerMinute);
    if (perMinute !== undefined) patch.maxMessagesPerMinute = perMinute;
  }

  if (f.maxMessagesPerMinutePerRemote.trim() !== unchanged.maxMessagesPerMinutePerRemote) {
    const perRemote = parseWhole(f.maxMessagesPerMinutePerRemote);
    if (perRemote !== undefined) patch.maxMessagesPerMinutePerRemote = perRemote;
  }

  if (f.maxStoredMiB.trim() !== unchanged.maxStoredMiB) {
    const stored = parseMiB(f.maxStoredMiB);
    if (stored !== undefined) patch.maxStoredBytes = stored;
  }

  if (f.retentionDays.trim() !== unchanged.retentionDays) {
    const days = parseWhole(f.retentionDays);
    if (days !== undefined) patch.retentionDays = days;
  }

  return patch;
}

/** The text that says what applies when a limit is left empty. */
export function effectiveText(kind: 'bytes' | 'count' | 'storedBytes' | 'days', value: number): string {
  switch (kind) {
    case 'bytes':
      return `${mibText(value)} MiB`;
    case 'storedBytes':
      return value === 0 ? 'unlimited' : `${mibText(value)} MiB`;
    case 'days':
      return value === 0 ? 'forever' : `${value} day${value === 1 ? '' : 's'}`;
    default:
      return String(value);
  }
}

/* ---------- route form ---------- */

export interface RouteForm {
  name: string;
  order: string;
  enabled: boolean;
  matchKind: InboundMatchKindWord;
  localPart: string;
  plusAddressing: boolean;
  actionKind: InboundActionKindWord;
  webhookEndpointId: string;
  webhookFormat: InboundWebhookFormatWord;
  /** One address per line (commas and spaces also separate). */
  forwardTo: string;
}

export const emptyRouteForm: RouteForm = {
  name: '',
  order: '100',
  enabled: true,
  matchKind: 'address',
  localPart: '',
  plusAddressing: false,
  actionKind: 'store',
  webhookEndpointId: '',
  webhookFormat: 'json',
  forwardTo: '',
};

export function routeToForm(r: InboundRoute): RouteForm {
  return {
    name: r.name,
    order: String(r.order),
    enabled: r.enabled,
    matchKind: r.match.kind,
    localPart: r.match.localPart ?? '',
    plusAddressing: r.match.plusAddressing ?? false,
    actionKind: r.action.kind,
    webhookEndpointId: r.action.webhookEndpointId ?? '',
    webhookFormat: r.action.webhookFormat ?? 'json',
    forwardTo: (r.action.forwardTo ?? []).join('\n'),
  };
}

export function splitAddresses(text: string): string[] {
  return text
    .split(/[\s,;]+/)
    .map((a) => a.trim())
    .filter(Boolean);
}

// Like InboundRules.ValidateRoute: ASCII letters, digits and the RFC 5322 specials, and any character from U+0080 up (internationalized local parts).
const ATOM = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.\u0080-\uffff-]+$/;
// The server accepts internationalized addresses (UTF-8 local part, IDN domain): letters and digits of any script are fine here, the server decides the rest.
const EMAIL = /^[^\s@,;<>()"]{1,64}@(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?\.)+[\p{L}\p{N}][\p{L}\p{N}-]*[\p{L}\p{N}]$/u;
// Control characters (the server refuses them in a name), the same test as InboundRules.ContainsControl.
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

export type RouteErrors = Partial<Record<'name' | 'order' | 'localPart' | 'webhookEndpointId' | 'forwardTo', string>>;

export function validateRoute(f: RouteForm): RouteErrors {
  const errors: RouteErrors = {};
  if (f.name.length > 100 || CONTROL.test(f.name)) errors.name = 'At most 100 characters, no control characters.';
  if (!/^\d{1,7}$/.test(f.order.trim()) || Number(f.order.trim()) > 1_000_000) errors.order = 'Enter a whole number from 0 to 1000000; the lowest number is checked first.';
  const local = f.localPart.trim();
  if (f.matchKind === 'address') {
    if (!local) errors.localPart = 'Enter the part before the @ (for example support).';
    else if (local.includes('*') || local.includes('@') || local.length > 64 || !ATOM.test(local)) errors.localPart = 'Use the part before the @ only, without * and without spaces (at most 64 characters).';
  } else if (f.matchKind === 'wildcard') {
    const stars = (local.match(/\*/g) ?? []).length;
    if (!local) errors.localPart = 'Enter a pattern such as billing-*.';
    else if (stars < 1 || stars > 3) errors.localPart = 'The pattern needs one to three * characters.';
    else if (local.replace(/\*/g, '').length === 0) errors.localPart = 'The pattern needs something besides *; use "Every address" to match everything.';
    else if (local.includes('@') || local.length > 64 || !ATOM.test(local)) errors.localPart = 'Use the part before the @ only (letters, digits and . _ - + characters, * for any text).';
  }
  if (f.actionKind === 'webhook' && !f.webhookEndpointId) errors.webhookEndpointId = 'Choose a webhook endpoint. Create one on the Webhooks page first if the list is empty.';
  if (f.actionKind === 'forward') {
    const list = splitAddresses(f.forwardTo);
    const bad = list.findIndex((a) => !EMAIL.test(a));
    if (list.length === 0) errors.forwardTo = 'Enter one to ten addresses to forward to.';
    else if (list.length > 10) errors.forwardTo = 'At most ten addresses.';
    else if (bad >= 0) errors.forwardTo = `"${list[bad]}" is not a valid address.`;
    else if (new Set(list.map((a) => a.toLowerCase())).size !== list.length) errors.forwardTo = 'An address is listed twice.';
  }
  return errors;
}

/** The request for a route; a `match` or an `action` always goes out complete (the server replaces the whole member). */
export function routeRequest(f: RouteForm): InboundRouteInput {
  const match: InboundRouteInput['match'] = { kind: f.matchKind };
  if (f.matchKind !== 'catch_all') {
    match.localPart = f.localPart.trim().toLowerCase();
    match.plusAddressing = f.plusAddressing;
  }
  const action: InboundRouteInput['action'] = { kind: f.actionKind };
  if (f.actionKind === 'webhook') {
    action.webhookEndpointId = f.webhookEndpointId;
    action.webhookFormat = f.webhookFormat;
  } else if (f.actionKind === 'forward') {
    action.forwardTo = splitAddresses(f.forwardTo);
  }
  return { name: f.name.trim(), order: Number(f.order.trim()), enabled: f.enabled, match, action };
}

/** "support", "billing-*" or "every address", with the plus-addressing note. */
export function describeMatch(r: Pick<InboundRoute, 'match'>): string {
  if (r.match.kind === 'catch_all') return 'every address';
  const text = r.match.localPart ?? '';
  return r.match.plusAddressing ? `${text} (also ${text}+anything)` : text;
}

export function describeAction(r: Pick<InboundRoute, 'action'>, endpointUrl?: string): string {
  switch (r.action.kind) {
    case 'webhook':
      return `webhook${endpointUrl ? ` to ${endpointUrl}` : ''} (${r.action.webhookFormat === 'raw_mime' ? 'raw message' : 'JSON'})`;
    case 'forward':
      return `forward to ${(r.action.forwardTo ?? []).join(', ')}`;
    case 'store':
      return 'store';
    default:
      return 'discard';
  }
}
