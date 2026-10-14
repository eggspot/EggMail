// @vitest-environment node
import { afterEach, describe, expect, it } from 'vitest';
import { startMock } from './mockClient.mjs';

let mock;
afterEach(async () => {
  await mock?.close();
});

const route = (over = {}) => ({ name: 'backup', host: 'smtp.relay.example', tlsMode: 'verify', userName: 'u', password: 'p', domains: ['partner.example'], ...over });

describe('relay routes in the mock', () => {
  it('is admin only', async () => {
    mock = await startMock();
    await mock.login('tenant');
    for (const p of ['/api/v1/admin/relay-routes', '/api/v1/admin/tls-policies']) expect((await mock.get(p)).status).toBe(403);
  });

  it('creates, reads, patches and deletes, and never returns the password', async () => {
    mock = await startMock();
    await mock.login('admin');
    const created = await mock.post('/api/v1/admin/relay-routes', route());
    expect(created.status).toBe(201);
    expect(created.data).toMatchObject({ name: 'backup', port: 587, tlsMode: 'verify', userName: 'u', hasPassword: true, priority: 100, enabled: true, domains: ['partner.example'], warnings: [] });
    expect(JSON.stringify(created.data)).not.toContain('"password"');
    const id = created.data.id;
    expect((await mock.get(`/api/v1/admin/relay-routes/${id}`)).data.name).toBe('backup');
    const patched = await mock.patch(`/api/v1/admin/relay-routes/${id}`, { port: 2525, password: 'again', domains: ['*.Corp.Example.', 'a.example', 'a.example'] });
    expect(patched.data).toMatchObject({ port: 2525, domains: ['*.corp.example', 'a.example'], hasPassword: true });
    expect((await mock.patch(`/api/v1/admin/relay-routes/${id}`, { removeCredentials: true })).data).toMatchObject({ userName: null, hasPassword: false });
    expect((await mock.del(`/api/v1/admin/relay-routes/${id}`)).status).toBe(204);
    expect((await mock.get(`/api/v1/admin/relay-routes/${id}`)).status).toBe(404);
  });

  it('refuses addresses as hosts and asks for the password again when the route moves', async () => {
    mock = await startMock();
    await mock.login('admin');
    for (const host of ['192.0.2.25', '[2001:db8::25]', '127.1', '1']) {
      const r = await mock.post('/api/v1/admin/relay-routes', route({ host }));
      expect(r.data.errors.map((e) => e.field)).toEqual(['host']);
    }
    const id = (await mock.post('/api/v1/admin/relay-routes', route())).data.id;
    for (const change of [{ host: 'other.relay.example' }, { port: 2525 }, { tlsMode: 'required' }]) {
      const r = await mock.patch(`/api/v1/admin/relay-routes/${id}`, change);
      expect(r.status).toBe(400);
      expect(r.data.errors.map((e) => e.field)).toEqual(['password']);
    }
    expect((await mock.patch(`/api/v1/admin/relay-routes/${id}`, { port: 2525, password: 'again' })).data.port).toBe(2525);
    expect((await mock.patch(`/api/v1/admin/relay-routes/${id}`, { priority: 5 })).status).toBe(200);
  });

  it('validates like the server', async () => {
    mock = await startMock();
    await mock.login('admin');
    const fields = async (body) => (await mock.post('/api/v1/admin/relay-routes', body)).data.errors?.map((e) => e.field).sort();
    expect(await fields(route({ name: 'direct' }))).toEqual(['name']);
    expect(await fields(route({ port: 0 }))).toEqual(['port']);
    expect(await fields(route({ host: 'a b' }))).toEqual(['host']);
    expect(await fields(route({ tlsMode: 'plain' }))).toEqual(['tlsMode']);
    expect(await fields(route({ domains: [] }))).toEqual(['domains']);
    expect(await fields(route({ domains: ['ok.example', 'a*b'] }))).toEqual(['domains[1]']);
    expect(await fields(route({ tlsMode: 'none' }))).toEqual(['tlsMode']);
    expect(await fields(route({ password: undefined }))).toEqual(['password']);
    expect((await mock.post('/api/v1/admin/relay-routes', route({ name: 'OFFICE-RELAY' }))).data.errors[0].field).toBe('name'); // the seeded name, in any case
  });
});

describe('tls policies in the mock', () => {
  it('creates, normalizes, refuses duplicates, patches and deletes', async () => {
    mock = await startMock();
    await mock.login('admin');
    const created = await mock.post('/api/v1/admin/tls-policies', { domainPattern: ' *.Partner.Example. ', level: 'encrypt' });
    expect(created.status).toBe(201);
    expect(created.data).toMatchObject({ domainPattern: '*.partner.example', level: 'encrypt' });
    expect(created.data.warnings[0]).toContain('not partner.example itself');
    const dup = await mock.post('/api/v1/admin/tls-policies', { domainPattern: '*.partner.example', level: 'may' });
    expect(dup.data.errors[0].field).toBe('domainPattern');
    expect((await mock.post('/api/v1/admin/tls-policies', { domainPattern: 'a.example', level: 'required' })).data.errors[0].field).toBe('level');
    expect((await mock.post('/api/v1/admin/tls-policies', { domainPattern: '10.0.0.1', level: 'may' })).status).toBe(400);
    const refused = await mock.post('/api/v1/admin/tls-policies', { domainPattern: '*', level: 'none' });
    expect(refused.data.errors.map((e) => e.field)).toEqual(['acknowledgeInsecure']);
    const none = await mock.post('/api/v1/admin/tls-policies', { domainPattern: '*', level: 'none', acknowledgeInsecure: true });
    expect(none.data.warnings).toHaveLength(1);
    expect((await mock.patch(`/api/v1/admin/tls-policies/${none.data.id}`, { level: 'verify' })).status).toBe(200);
    expect((await mock.patch(`/api/v1/admin/tls-policies/${none.data.id}`, { level: 'none' })).data.errors[0].field).toBe('acknowledgeInsecure');
    expect((await mock.patch(`/api/v1/admin/tls-policies/${created.data.id}`, { level: 'verify' })).data.level).toBe('verify');
    expect((await mock.get('/api/v1/admin/tls-policies')).data.find((p) => p.id === created.data.id).warnings[0]).toContain('not partner.example itself');
    expect((await mock.del(`/api/v1/admin/tls-policies/${created.data.id}`)).status).toBe(204);
    expect((await mock.del(`/api/v1/admin/tls-policies/${created.data.id}`)).status).toBe(404);
  });
});
