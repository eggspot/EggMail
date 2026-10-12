// @vitest-environment node
import { afterEach, describe, expect, it } from 'vitest';
import { startMock } from './mockClient.mjs';

let mock;
afterEach(async () => {
  await mock?.close();
});

describe('mock webhooks', () => {
  it('returns the signing secret only on create and rotate', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const created = await mock.post('/api/v1/webhooks', { url: 'https://example.com/hook', event_types: ['message.delivered'] });
    expect(created.status).toBe(201);
    expect(created.data.secret).toMatch(/^whsec_/);
    const got = await mock.get(`/api/v1/webhooks/${created.data.id}`);
    expect(got.data.secret).toBeUndefined();
    const list = await mock.get('/api/v1/webhooks');
    expect(JSON.stringify(list.data)).not.toContain('whsec_');
    const rotated = await mock.post(`/api/v1/webhooks/${created.data.id}/rotate-secret`);
    expect(rotated.data.secret).toMatch(/^whsec_/);
    expect(rotated.data.secret).not.toBe(created.data.secret);
  });

  it('rejects http and internal addresses with a url field error', async () => {
    mock = await startMock();
    await mock.login('tenant');
    for (const url of ['http://example.com/h', 'https://127.0.0.1/h', 'https://169.254.169.254/latest', 'https://localhost/h', 'https://10.1.2.3/h', 'nonsense']) {
      const r = await mock.post('/api/v1/webhooks', { url, event_types: ['message.delivered'] });
      expect(r.status, url).toBe(400);
      expect(r.data.errors[0].field).toBe('url');
    }
    const noEvents = await mock.post('/api/v1/webhooks', { url: 'https://example.com/h', event_types: [] });
    expect(noEvents.data.errors[0].field).toBe('event_types');
  });

  it('records test events and supports replay', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const w = (await mock.get('/api/v1/webhooks')).data[0];
    const test = await mock.post(`/api/v1/webhooks/${w.id}/test`);
    expect(test.status).toBe(200);
    const attempts = (await mock.get(`/api/v1/webhooks/${w.id}/attempts?limit=50`)).data;
    expect(attempts[0].eventType).toBe('webhook.test');
    expect(attempts.some((a) => a.status === null && a.errorClass === 'timeout')).toBe(true);
    const replay = await mock.post(`/api/v1/webhook-events/${attempts[1].outboxId}/replay`);
    expect(replay.status).toBe(202);
    expect((await mock.post('/api/v1/webhook-events/nope/replay')).status).toBe(404);
  });

  it('patches enabled', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const off = (await mock.get('/api/v1/webhooks')).data.find((w) => !w.enabled);
    const r = await mock.patch(`/api/v1/webhooks/${off.id}`, { enabled: true });
    expect(r.data.enabled).toBe(true);
    expect(r.data.disabledReason).toBeNull();
  });
});

describe('mock suppressions', () => {
  it('paginates with a cursor, adds idempotently and removes', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const p1 = (await mock.get('/api/v1/suppressions?limit=25')).data;
    expect(p1.items).toHaveLength(25);
    expect(p1.next_cursor).toBeTruthy();
    const p2 = (await mock.get(`/api/v1/suppressions?limit=25&cursor=${p1.next_cursor}`)).data;
    expect(p2.items[0].address).not.toBe(p1.items[0].address);
    const add = await mock.post('/api/v1/suppressions', { address: 'Someone@Example.com', reason: 'manual' });
    expect(add.status).toBe(201);
    expect((await mock.post('/api/v1/suppressions', { address: 'someone@example.com' })).status).toBe(200);
    expect((await mock.del('/api/v1/suppressions/someone%40example.com')).status).toBe(204);
    expect((await mock.del('/api/v1/suppressions/someone%40example.com')).status).toBe(404);
    expect((await mock.post('/api/v1/suppressions', { address: 'bad' })).data.errors[0].field).toBe('address');
  });
});

describe('mock credentials', () => {
  it('shows API key and SMTP password only once', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const k = await mock.post('/api/v1/api-keys', { name: 'ci', scopes: ['send'] });
    expect(k.data.key).toMatch(/^egk_/);
    const list = (await mock.get('/api/v1/api-keys')).data;
    expect(JSON.stringify(list)).not.toContain(k.data.key);
    expect(list.find((x) => x.id === k.data.id).prefix).toBe(k.data.key.slice(0, 10));
    expect((await mock.post('/api/v1/api-keys', { name: 'x', scopes: [] })).data.errors[0].field).toBe('scopes');
    const s = await mock.post('/api/v1/smtp-credentials', { username: 'mailer-2' });
    expect(s.data.password).toBeTruthy();
    expect(JSON.stringify((await mock.get('/api/v1/smtp-credentials')).data)).not.toContain(s.data.password);
    expect((await mock.post('/api/v1/smtp-credentials', { username: 'mailer-2' })).status).toBe(400);
    expect((await mock.del(`/api/v1/api-keys/${k.data.id}`)).status).toBe(204);
  });
});

describe('mock settings', () => {
  it('validates ranges and rejects locked keys', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const list = (await mock.get('/api/v1/settings')).data.items;
    expect(list.some((i) => i.locked)).toBe(true);
    const bad = await mock.put('/api/v1/settings', { values: { 'Content:RetentionDays': 3 } });
    expect(bad.status).toBe(400);
    expect(bad.data.errors[0].field).toBe('Content:RetentionDays');
    const locked = await mock.put('/api/v1/settings', { values: { 'Smtp:MaxRecipients': 10 } });
    expect(locked.data.errors[0].message).toMatch(/locked/);
    const ok = await mock.put('/api/v1/settings', { values: { 'Content:RetentionDays': 14, 'Tls:RequireOutbound': 'encrypt' } });
    expect(ok.data.items.find((i) => i.key === 'Content:RetentionDays').value).toBe(14);
  });
});
