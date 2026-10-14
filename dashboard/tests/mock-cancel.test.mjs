// @vitest-environment node
import { afterEach, describe, expect, it } from 'vitest';
import { startMock } from './mockClient.mjs';
import { INFLIGHT_ID, RAW_ID, WAITING_ID } from '../mock/routes/messages.mjs';

let mock;
afterEach(async () => {
  await mock?.close();
});

describe('mock messages: cancel', () => {
  it('cancels the named waiting recipients, records the events and updates the status', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const r = await mock.post(`/api/v1/messages/${WAITING_ID}/cancel`, { recipients: ['AYO7@outlook.com', 'stranger@x.test'] });
    expect(r.status).toBe(200);
    expect(r.data).toMatchObject({ id: WAITING_ID, cancelled: ['ayo7@outlook.com'], inFlight: [], notPending: ['stranger@x.test'] });
    const ev = await mock.get(`/api/v1/messages/${WAITING_ID}/events`);
    expect(ev.data.filter((e) => e.type === 'cancelled').map((e) => e.recipient)).toEqual(['ayo7@outlook.com']);
    expect((await mock.get(`/api/v1/messages/${WAITING_ID}`)).data.status).toBe('deferred');

    const rest = await mock.post(`/api/v1/messages/${WAITING_ID}/cancel`);
    expect(rest.status).toBe(200);
    expect(rest.data.cancelled).toEqual(['noor2@gmail.com']);
    expect(rest.data.status).toBe('cancelled');
    const again = await mock.post(`/api/v1/messages/${WAITING_ID}/cancel`);
    expect(again.status).toBe(409);
    expect(again.data.code).toBe('conflict');
  });

  it('leaves a recipient whose delivery is running and reports it in flight', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const r = await mock.post(`/api/v1/messages/${INFLIGHT_ID}/cancel`);
    expect(r.status).toBe(200);
    expect(r.data.cancelled).toEqual(['ivan8@gmail.com']);
    expect(r.data.inFlight).toEqual(['inflight1@gmail.com']);
    const only = await mock.post(`/api/v1/messages/${INFLIGHT_ID}/cancel`);
    expect(only.status).toBe(409);
    expect(only.data.in_flight).toEqual(['inflight1@gmail.com']);
  });

  it('validates the body and answers 404 for unknown messages, 409 for finished ones', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const empty = await mock.post(`/api/v1/messages/${WAITING_ID}/cancel`, { recipients: [] });
    expect(empty.status).toBe(400);
    const bad = await mock.post(`/api/v1/messages/${WAITING_ID}/cancel`, { recipients: ['nope'] });
    expect(bad.status).toBe(400);
    expect(bad.data.errors[0].field).toBe('recipients[0]');
    expect((await mock.post(`/api/v1/messages/${WAITING_ID}/cancel`, { all: true })).status).toBe(400);
    expect((await mock.post('/api/v1/messages/ffffffffffffffffffffffffffffffff/cancel')).data.code).toBe('message_not_found');
    expect((await mock.post(`/api/v1/messages/${RAW_ID}/cancel`)).status).toBe(409);
  });
});
