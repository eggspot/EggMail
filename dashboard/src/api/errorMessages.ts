import { ApiError } from './client';

/** Friendly texts for the stable problem+json `code` values (docs/api.md, design 5.2). */
const MESSAGES: Record<string, string> = {
  unauthorized: 'You are not signed in, or your session has expired. Please sign in again.',
  forbidden: 'You do not have permission to do that.',
  tenant_disabled: 'This tenant is suspended, so it cannot be used right now. An administrator can activate it again.',
  not_found: 'That item was not found. It may have been deleted.',
  validation_failed: 'Some of the values are not valid. Check the highlighted fields.',
  rate_limited: 'Too many requests. Please wait a moment and try again.',
  domain_not_verified: 'The sending domain is not verified yet. Publish the DNS records and verify the domain first.',
  recipient_suppressed: 'The recipient is on the suppression list, so the message was not sent to it.',
  payload_too_large: 'The message is larger than the server accepts.',
  idempotency_conflict: 'This request was already sent with different content. Reload and try again.',
  history_not_recorded: 'Per-message history is not recorded on this server (History mode is statistics only).',
  body_expired: 'The message content has expired and was removed. Metadata and events are still available.',
  message_not_found: 'That message was not found. It may be older than the event retention period.',
  attachments_not_stored: 'This message had attachments that were not stored, so it cannot be resent.',
  not_ready: 'The server is not ready yet (storage unavailable). Try again in a few seconds.',
  network_error: 'Cannot reach the server. Check your connection.',
  bad_response: 'The server sent a response the dashboard could not understand.',
  server_error: 'The server hit an unexpected error.',
  csrf_invalid: 'Your session security token is out of date. Reload the page and try again.',
};

export function friendlyMessage(err: unknown): string {
  if (err instanceof ApiError) {
    const base = MESSAGES[err.code];
    if (err.code === 'rate_limited' && err.retryAfter) return `${base} Retry in ${err.retryAfter} s.`;
    if (err.code === 'validation_failed' && err.fieldErrors.length) {
      return `${base} ${err.fieldErrors.map((f) => `${f.field}: ${f.message}`).join('; ')}`;
    }
    if (base) return base;
    return err.detail || err.title || `Request failed (HTTP ${err.status}).`;
  }
  if (err instanceof Error) return err.message;
  return 'Something went wrong.';
}

/** Server-side detail (if any) to show under the friendly text, with the request id for support. */
export function errorFootnote(err: unknown): string {
  if (!(err instanceof ApiError)) return '';
  const parts: string[] = [];
  // not_ready is also how the server refuses a step it cannot do on this instance, with the reason in the detail.
  if (err.detail && (!MESSAGES[err.code] || err.code === 'not_ready')) parts.push(err.detail);
  if (err.requestId) parts.push(`request id ${err.requestId}`);
  return parts.join(' - ');
}

export function isCode(err: unknown, ...codes: string[]): err is ApiError {
  return err instanceof ApiError && codes.includes(err.code);
}

/** Field-level validation messages keyed by field name (empty object when not a validation error). */
export function fieldErrors(err: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (err instanceof ApiError) for (const f of err.fieldErrors) out[f.field] = f.message;
  return out;
}
