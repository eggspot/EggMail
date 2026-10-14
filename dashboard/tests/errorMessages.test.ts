import { describe, expect, it } from 'vitest';
import { ApiError } from '../src/api/client';
import { errorFootnote, fieldErrors, friendlyMessage, isCode } from '../src/api/errorMessages';

const err = (status: number, code?: string, extra: Record<string, unknown> = {}, retryAfter?: number) => new ApiError({ status, code, ...extra }, retryAfter);

describe('error messages', () => {
  it.each([
    ['unauthorized', 401],
    ['forbidden', 403],
    ['not_found', 404],
    ['validation_failed', 400],
    ['rate_limited', 429],
    ['domain_not_verified', 400],
    ['recipient_suppressed', 400],
    ['payload_too_large', 413],
    ['idempotency_conflict', 409],
    ['history_not_recorded', 410],
    ['body_expired', 410],
    ['message_not_found', 404],
    ['attachments_not_stored', 409],
    ['not_ready', 503],
  ])('has a friendly message for the stable code %s', (code, status) => {
    const text = friendlyMessage(err(status, code));
    expect(text.length).toBeGreaterThan(20);
    expect(text).not.toContain(code); // no raw codes in user text
  });

  it('appends Retry-After to rate limit messages', () => {
    expect(friendlyMessage(err(429, 'rate_limited', {}, 12))).toContain('12 s');
  });

  it('lists field errors for validation_failed', () => {
    const e = err(400, 'validation_failed', { errors: [{ field: 'url', message: 'must be https' }] });
    expect(friendlyMessage(e)).toContain('url: must be https');
    expect(fieldErrors(e)).toEqual({ url: 'must be https' });
  });

  it('falls back to server detail for unknown codes and to generic text otherwise', () => {
    expect(friendlyMessage(err(418, 'teapot', { detail: 'I am a teapot' }))).toBe('I am a teapot');
    expect(friendlyMessage(err(418, 'teapot'))).toContain('418');
    expect(friendlyMessage(new Error('boom'))).toBe('boom');
    expect(friendlyMessage('x')).toBe('Something went wrong.');
  });

  it('includes the request id in the footnote', () => {
    expect(errorFootnote(err(500, 'server_error', { request_id: 'req_1' }))).toContain('req_1');
    expect(errorFootnote(new Error('x'))).toBe('');
  });

  it('adds the detail of a not_ready answer, which is also how a step is refused on this instance', () => {
    expect(errorFootnote(err(503, 'not_ready', { detail: "Finalize with 'mta migrate-storage finalize' instead." }))).toContain('mta migrate-storage finalize');
    expect(errorFootnote(err(404, 'not_found', { detail: 'raw detail' }))).not.toContain('raw detail'); // friendly text stands alone for the others
  });

  it('isCode narrows by code', () => {
    expect(isCode(err(410, 'body_expired'), 'body_expired', 'history_not_recorded')).toBe(true);
    expect(isCode(err(404, 'not_found'), 'body_expired')).toBe(false);
    expect(isCode(new Error('x'), 'body_expired')).toBe(false);
  });
});
