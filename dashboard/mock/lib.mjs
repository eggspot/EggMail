// Helpers shared by the mock API server and its route modules. No dependencies.
import { randomBytes } from 'node:crypto';

/** Thrown by route handlers to answer with a problem+json error. */
export class HttpError extends Error {
  constructor(status, code, detail, extra = {}, headers = {}) {
    super(detail || code);
    this.status = status;
    this.code = code;
    this.detail = detail;
    this.extra = extra;
    this.headers = headers;
  }
}

const TITLES = {
  unauthorized: 'Unauthorized',
  forbidden: 'Forbidden',
  not_found: 'Not found',
  validation_failed: 'Validation failed',
  rate_limited: 'Too many requests',
  domain_not_verified: 'Domain not verified',
  recipient_suppressed: 'Recipient suppressed',
  payload_too_large: 'Payload too large',
  idempotency_conflict: 'Idempotency conflict',
  history_not_recorded: 'Per-message history is not recorded',
  body_expired: 'Message body expired',
  message_not_found: 'Message not found',
  attachments_not_stored: 'Attachments were not stored',
  not_ready: 'Not ready',
};

/** Builds the RFC 9457 body for an error. */
export function problemBody(status, code, detail, extra = {}, requestId = 'req_' + randomBytes(4).toString('hex')) {
  return {
    type: `https://eggmail.example/problems/${code}`,
    title: TITLES[code] || code,
    status,
    detail,
    code,
    request_id: requestId,
    ...extra,
  };
}

/** 32 lower-case hex digits, time-ordered like a UUIDv7 without hyphens. */
export function newId(at = Date.now()) {
  const ts = at.toString(16).padStart(12, '0').slice(-12);
  return ts + '7' + randomBytes(9).toString('hex').slice(1, 4) + '8' + randomBytes(8).toString('hex').slice(1, 4) + randomBytes(6).toString('hex');
}

export const iso = (d = new Date()) => new Date(d).toISOString();
export const minutesAgo = (m, from = Date.now()) => iso(from - m * 60_000);
export const hoursAgo = (h, from = Date.now()) => iso(from - h * 3_600_000);
export const daysAgo = (d, from = Date.now()) => iso(from - d * 86_400_000);
export const daysFromNow = (d, from = Date.now()) => iso(from + d * 86_400_000);

/** Small deterministic PRNG so fixtures are stable between runs. */
export function rng(seed = 1) {
  let s = seed >>> 0 || 1;
  const next = () => {
    s ^= s << 13;
    s >>>= 0;
    s ^= s >>> 17;
    s ^= s << 5;
    s >>>= 0;
    return s / 0xffffffff;
  };
  next.int = (min, max) => Math.floor(next() * (max - min + 1)) + min;
  next.pick = (arr) => arr[Math.floor(next() * arr.length)];
  return next;
}

/** Validation helper: collects field errors and throws validation_failed when any exist. */
export function validate(check) {
  const errors = [];
  check((field, message) => errors.push({ field, message }));
  if (errors.length) throw new HttpError(400, 'validation_failed', 'One or more fields are invalid.', { errors });
}

export const EMAIL_RE = /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/;

/** Cursor pagination over an array: cursor is the base64 offset. */
export function paginate(items, query, defaultLimit = 25) {
  const limit = Math.min(Math.max(parseInt(query.limit, 10) || defaultLimit, 1), 200);
  const offset = query.cursor ? parseInt(Buffer.from(String(query.cursor), 'base64url').toString(), 10) || 0 : 0;
  const slice = items.slice(offset, offset + limit);
  const end = offset + limit;
  return { items: slice, next_cursor: end < items.length ? Buffer.from(String(end)).toString('base64url') : null };
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
