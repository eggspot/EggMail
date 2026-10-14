// @vitest-environment node
import { afterEach, describe, expect, it } from 'vitest';
import { startMock } from './mockClient.mjs';

let mock;
afterEach(async () => {
  await mock?.close();
});

describe('mock domains', () => {
  it('lists the four seeded states for a tenant and requires X-Tenant-Id for admins', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const res = await mock.get('/api/v1/domains');
    expect(res.data.map((d) => d.status).sort()).toEqual(['failed', 'pending', 'temporary_failure', 'verified']);
    const paused = res.data.find((d) => d.status === 'failed');
    expect(paused.sendingPaused).toBe(true);
    await mock.login('admin');
    mock.setTenant('');
    expect((await mock.get('/api/v1/domains')).status).toBe(400);
  });

  it('returns DNS records with a long dkim TXT value under an underscore host', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const d = (await mock.get('/api/v1/domains')).data.find((x) => x.name === 'example.com');
    const dkim = d.records.find((r) => r.purpose === 'dkim');
    expect(dkim.host).toBe('eggmail1._domainkey.example.com');
    expect(dkim.value.length).toBeGreaterThan(255);
    expect(d.records.map((r) => r.purpose).sort()).toEqual(['dkim', 'dmarc', 'return_path', 'spf']);
  });

  it('validates names on create (format and duplicates) with field errors', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const bad = await mock.post('/api/v1/domains', { name: 'not a domain' });
    expect(bad.status).toBe(400);
    expect(bad.data.code).toBe('validation_failed');
    expect(bad.data.errors[0].field).toBe('name');
    const dup = await mock.post('/api/v1/domains', { name: 'example.com' });
    expect(dup.data.errors[0].message).toMatch(/already exists/);
    const ok = await mock.post('/api/v1/domains', { name: 'New.Example.io' });
    expect(ok.status).toBe(201);
    expect(ok.data.name).toBe('new.example.io');
    expect(ok.data.status).toBe('pending');
  });

  it('rate limits verify to once per 30 s with Retry-After', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const d = (await mock.get('/api/v1/domains')).data.find((x) => x.name === 'newsletter.example.net');
    const first = await mock.post(`/api/v1/domains/${d.id}/verify`);
    expect(first.status).toBe(200);
    expect(first.data.status).toBe('verifying');
    const second = await mock.post(`/api/v1/domains/${d.id}/verify`);
    expect(second.status).toBe(429);
    expect(second.data.code).toBe('rate_limited');
    expect(Number(second.headers.get('retry-after'))).toBeGreaterThan(0);
  });

  it('rotates the DKIM selector to N+1 and keeps the old record', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const d = (await mock.get('/api/v1/domains')).data.find((x) => x.name === 'example.com');
    const res = await mock.post(`/api/v1/domains/${d.id}/dkim/rotate`);
    expect(res.data.dkim.selector).toBe('eggmail2');
    // The new key does not sign yet; the old one keeps signing.
    expect(res.data.dkim.active).toBe(false);
    expect(res.data.dkimKeys.map((k) => [k.selector, k.active])).toEqual([['eggmail1', true], ['eggmail2', false]]);
    const hosts = res.data.records.filter((r) => r.purpose === 'dkim').map((r) => r.host);
    expect(hosts).toContain('eggmail1._domainkey.example.com');
    expect(hosts).toContain('eggmail2._domainkey.example.com');
    // One rotation at a time.
    expect((await mock.post(`/api/v1/domains/${d.id}/dkim/rotate`)).status).toBe(409);
  });

  it('cancels a pending rotation and 404s when none is pending', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const d = (await mock.get('/api/v1/domains')).data.find((x) => x.name === 'example.com');
    expect((await mock.del(`/api/v1/domains/${d.id}/dkim/rotate`)).status).toBe(404);
    await mock.post(`/api/v1/domains/${d.id}/dkim/rotate`);
    const res = await mock.del(`/api/v1/domains/${d.id}/dkim/rotate`);
    expect(res.status).toBe(200);
    expect(res.data.dkimKeys.map((k) => k.selector)).toEqual(['eggmail1']);
    expect(res.data.dkim.selector).toBe('eggmail1');
    expect(res.data.records.filter((r) => r.purpose === 'dkim').map((r) => r.host)).toEqual(['eggmail1._domainkey.example.com']);
  });

  it('deletes and then 404s', async () => {
    mock = await startMock();
    await mock.login('tenant');
    const d = (await mock.get('/api/v1/domains')).data[0];
    expect((await mock.del(`/api/v1/domains/${d.id}`)).status).toBe(204);
    expect((await mock.get(`/api/v1/domains/${d.id}`)).status).toBe(404);
  });
});
