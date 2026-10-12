// @vitest-environment node
import { afterEach, describe, expect, it } from 'vitest';
import { startMock } from './mockClient.mjs';
import { ATTACH_ID, DUPLICATE_ID, EXPIRED_ID, HTML_ID, RAW_ID, RECOMPOSE_ID } from '../mock/routes/messages.mjs';

let mock;
afterEach(async () => {
  await mock?.close();
});

const validSend = (over = {}) => ({ from: 'Acme <noreply@example.com>', to: ['a@x.test'], subject: 'Hello', text: 'hi', ...over });

describe('mock messages: history full', () => {
  it('lists, filters and paginates with cursors', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const first = await mock.get('/api/v1/messages?limit=10');
    expect(first.status).toBe(200);
    expect(first.data.items).toHaveLength(10);
    expect(first.data.next_cursor).toBeTruthy();
    const second = await mock.get(`/api/v1/messages?limit=10&cursor=${first.data.next_cursor}`);
    expect(second.data.items[0].id).not.toBe(first.data.items[0].id);
    const bounced = await mock.get('/api/v1/messages?status=bounced&limit=200');
    expect(bounced.data.items.length).toBeGreaterThan(0);
    expect(bounced.data.items.every((m) => m.status === 'bounced')).toBe(true);
    const bySubject = await mock.get('/api/v1/messages?subject=sandbox%20test');
    expect(bySubject.data.items.map((m) => m.id)).toContain(HTML_ID);
    const future = await mock.get(`/api/v1/messages?from=${encodeURIComponent(new Date(Date.now() + 86400000).toISOString())}`);
    expect(future.data.items).toHaveLength(0);
  });

  it('returns detail, events with TLS details, and the possible_duplicate fixture', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const d = await mock.get(`/api/v1/messages/${DUPLICATE_ID}`);
    expect(d.data.content.state).toBe('available');
    const ev = await mock.get(`/api/v1/messages/${DUPLICATE_ID}/events`);
    expect(ev.data.map((e) => e.type)).toEqual(expect.arrayContaining(['aborted_by_switch', 'possible_duplicate', 'delivered']));
    expect(ev.data.find((e) => e.type === 'delivered').tls.version).toMatch(/TLS/);
  });

  it('marks old messages body_expired and answers 410 body_expired for content and resend', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const d = await mock.get(`/api/v1/messages/${EXPIRED_ID}`);
    expect(d.status).toBe(200);
    expect(d.data.content.state).toBe('body_expired');
    const c = await mock.get(`/api/v1/messages/${EXPIRED_ID}/content`);
    expect(c.status).toBe(410);
    expect(c.data.code).toBe('body_expired');
    expect(c.data.retention_days).toBe(7);
    expect(c.data.expired_at).toBeTruthy();
    const r = await mock.post(`/api/v1/messages/${EXPIRED_ID}/resend`);
    expect(r.status).toBe(410);
    expect(r.data.code).toBe('body_expired');
  });

  it('answers 404 message_not_found for unknown ids', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const r = await mock.get('/api/v1/messages/ffffffffffffffffffffffffffffffff');
    expect(r.status).toBe(404);
    expect(r.data.code).toBe('message_not_found');
  });

  it('resend: 409 for unstored attachments, recomposed true/false otherwise, and the copy shows in the list', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const a = await mock.post(`/api/v1/messages/${ATTACH_ID}/resend`);
    expect(a.status).toBe(409);
    expect(a.data.code).toBe('attachments_not_stored');
    const rc = await mock.post(`/api/v1/messages/${RECOMPOSE_ID}/resend`);
    expect(rc.status).toBe(202);
    expect(rc.data.recomposed).toBe(true);
    const raw = await mock.post(`/api/v1/messages/${RAW_ID}/resend`);
    expect(raw.status).toBe(202);
    expect(raw.data.recomposed).toBe(false);
    const created = await mock.get(`/api/v1/messages/${rc.data.id}`);
    expect(created.data.status).toBe('queued');
  });

  it('requires X-Tenant-Id for admins and scopes data per tenant', async () => {
    mock = await startMock();
    await mock.login('admin', '');
    mock.setTenant('');
    const none = await mock.get('/api/v1/messages');
    expect(none.status).toBe(400);
    expect(none.data.code).toBe('validation_failed');
    mock.setTenant('t_globex');
    const globex = await mock.get('/api/v1/messages?limit=200');
    expect(globex.data.items.length).toBeLessThan(20);
  });
});

describe('mock messages: sending', () => {
  it('accepts a valid send with 202 and records it', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const res = await mock.post('/api/v1/messages', validSend({ to: ['a@x.test', 'b@x.test'], cc: ['c@x.test'] }));
    expect(res.status).toBe(202);
    expect(res.data).toMatchObject({ status: 'queued', recipients: 3 });
    const d = await mock.get(`/api/v1/messages/${res.data.id}`);
    expect(d.data.recipients).toHaveLength(3);
  });

  it('records suppressed recipients as suppressed without failing', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const res = await mock.post('/api/v1/messages', validSend({ to: ['x@suppressed.test'] }));
    expect(res.status).toBe(202);
    const d = await mock.get(`/api/v1/messages/${res.data.id}`);
    expect(d.data.status).toBe('suppressed');
  });

  it('returns validation_failed with field errors', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const res = await mock.post('/api/v1/messages', { from: 'nope', to: ['bad'], bogus: 1 });
    expect(res.status).toBe(400);
    expect(res.data.code).toBe('validation_failed');
    const fields = res.data.errors.map((e) => e.field);
    expect(fields).toEqual(expect.arrayContaining(['from', 'to[0]', 'subject', 'bogus']));
  });

  it('rejects unverified sending domains with domain_not_verified', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const res = await mock.post('/api/v1/messages', validSend({ from: 'x@unknown-domain.test' }));
    expect(res.status).toBe(403);
    expect(res.data.code).toBe('domain_not_verified');
  });

  it('handles Idempotency-Key: same body replays, different body conflicts', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const h = { 'Idempotency-Key': 'key-1' };
    const a = await mock.post('/api/v1/messages', validSend(), h);
    const b = await mock.post('/api/v1/messages', validSend(), h);
    expect(b.status).toBe(202);
    expect(b.data.id).toBe(a.data.id);
    const c = await mock.post('/api/v1/messages', validSend({ subject: 'Different' }), h);
    expect(c.status).toBe(409);
    expect(c.data.code).toBe('idempotency_conflict');
  });

  it('rate limits after 20 sends per minute with Retry-After', async () => {
    mock = await startMock();
    await mock.login('tenant');
    let last;
    for (let i = 0; i < 21; i++) last = await mock.post('/api/v1/messages', validSend({ subject: 's' + i }));
    expect(last.status).toBe(429);
    expect(last.data.code).toBe('rate_limited');
    expect(Number(last.headers.get('retry-after'))).toBeGreaterThan(0);
  });

  it('accepts a raw message', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const raw = Buffer.from('From: noreply@example.com\r\nSubject: Raw one\r\n\r\nBody here\r\n').toString('base64');
    const res = await mock.post('/api/v1/messages/raw', { from: 'noreply@example.com', to: ['a@x.test'], raw });
    expect(res.status).toBe(202);
    const d = await mock.get(`/api/v1/messages/${res.data.id}`);
    expect(d.data.subject).toBe('Raw one');
    const bad = await mock.post('/api/v1/messages/raw', { from: 'noreply@example.com', to: ['a@x.test'], raw: '***' });
    expect(bad.status).toBe(400);
  });
});

describe('mock messages: history statsonly', () => {
  it('answers 410 history_not_recorded for every per-message endpoint but still accepts sends', async () => {
    mock = await startMock({ history: 'statsonly' });
    await mock.login('tenant');
    for (const path of ['/api/v1/messages', `/api/v1/messages/${RAW_ID}`, `/api/v1/messages/${RAW_ID}/events`, `/api/v1/messages/${RAW_ID}/content`]) {
      const r = await mock.get(path);
      expect(r.status, path).toBe(410);
      expect(r.data.code).toBe('history_not_recorded');
      expect(r.data.history_mode).toBe('StatsOnly');
    }
    expect((await mock.post(`/api/v1/messages/${RAW_ID}/resend`)).status).toBe(410);
    const sent = await mock.post('/api/v1/messages', validSend());
    expect(sent.status).toBe(202);
    expect(sent.data.id).toBeTruthy();
  });
});

describe('mock stats', () => {
  it('returns hourly rows for the last 24 hours and daily rows summing the hours', async () => {
    mock = await startMock({ history: 'statsonly' });
    await mock.login('tenant');
    const to = new Date();
    const from = new Date(to.getTime() - 3 * 86400000);
    const q = (g) => `/api/v1/stats?granularity=${g}&from=${from.toISOString()}&to=${to.toISOString()}`;
    const hourly = await mock.get(q('hour'));
    const daily = await mock.get(q('day'));
    expect(hourly.status).toBe(200);
    expect(hourly.data.granularity).toBe('hour');
    expect(hourly.data.rows.length).toBeGreaterThan(24);
    const sum = (rows) => rows.reduce((a, r) => a + r.accepted, 0);
    expect(sum(daily.data.rows)).toBe(sum(hourly.data.rows));
    expect(hourly.data.rows[0]).toEqual(expect.objectContaining({ period: expect.any(String), sendingDomain: expect.any(String), recipientDomain: expect.any(String), hardBounce: expect.any(Number) }));
  });

  it('filters by sending domain, validates parameters and returns the recent events ring', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const d = await mock.get('/api/v1/stats?domain=mail.example.com');
    expect(d.data.rows.every((r) => r.sendingDomain === 'mail.example.com')).toBe(true);
    const bad = await mock.get('/api/v1/stats?granularity=week');
    expect(bad.status).toBe(400);
    expect(bad.data.errors[0].field).toBe('granularity');
    const ring = await mock.get('/api/v1/stats/recent-events?limit=5');
    expect(ring.data).toHaveLength(5);
    expect(ring.data[0]).toEqual(expect.objectContaining({ at: expect.any(String), type: expect.any(String), recipientDomain: expect.any(String) }));
    expect(JSON.stringify(ring.data)).not.toContain('@');
  });
});
