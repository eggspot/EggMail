// @vitest-environment node
import { afterEach, describe, expect, it } from 'vitest';
import { startMock } from './mockClient.mjs';

let mock;
afterEach(async () => {
  await mock?.close();
});

async function signedIn(user = 'admin') {
  mock = await startMock();
  await mock.login(user);
  return mock;
}

async function signInAs(userName, password) {
  const res = await fetch(`${mock.base}/api/v1/session`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ user: userName, password }) });
  const cookie = (res.headers.get('set-cookie') || '').split(';')[0];
  return { status: res.status, cookie };
}

const meStatus = async (cookie) => (await fetch(`${mock.base}/api/v1/me`, { headers: { Cookie: cookie } })).status;

describe('mock user management', () => {
  it('is admin only', async () => {
    await signedIn('tenant');
    expect((await mock.get('/api/v1/admin/users')).status).toBe(403);
    expect((await mock.post('/api/v1/admin/users', { userName: 'x', role: 'admin' })).status).toBe(403);
  });

  it('creates users with a generated password that works, and never lists it', async () => {
    await signedIn();
    const created = await mock.post('/api/v1/admin/users', { userName: ' Carol ', role: 'tenant', tenantId: 't_acme' });
    expect(created.status).toBe(201);
    expect(created.data.userName).toBe('carol');
    expect(created.data.password.length).toBeGreaterThanOrEqual(10);
    const login = await signInAs('CAROL', created.data.password);
    expect(login.status).toBe(200);
    const list = await mock.get('/api/v1/admin/users');
    expect(JSON.stringify(list.data)).not.toContain(created.data.password);
    expect(list.data.map((u) => u.userName)).toEqual(['admin', 'carol', 'tenant']);
  });

  it('validates names, roles, tenants and passwords', async () => {
    await signedIn();
    const bad = async (body, field) => {
      const r = await mock.post('/api/v1/admin/users', body);
      expect(r.status, JSON.stringify(body)).toBe(400);
      expect(r.data.errors.map((e) => e.field)).toContain(field);
    };
    await bad({ userName: '', role: 'admin' }, 'userName');
    await bad({ userName: 'TENANT', role: 'admin' }, 'userName');
    await bad({ userName: 'x', role: 'root' }, 'role');
    await bad({ userName: 'x', role: 'tenant' }, 'tenantId');
    await bad({ userName: 'x', role: 'tenant', tenantId: 't_initech' }, 'tenantId'); // suspended
    await bad({ userName: 'x', role: 'admin', tenantId: 't_acme' }, 'tenantId');
    await bad({ userName: 'x', role: 'admin', password: 'short' }, 'password');
  });

  it('ends sessions when a user is disabled, and blocks sign-in until enabled', async () => {
    await signedIn();
    const jane = (await mock.post('/api/v1/admin/users', { userName: 'jane', role: 'tenant', tenantId: 't_acme', password: 'jane-password-1' })).data;
    const s = await signInAs('jane', 'jane-password-1');
    expect(await meStatus(s.cookie)).toBe(200);
    expect((await mock.patch(`/api/v1/admin/users/${jane.id}`, { enabled: false })).data.enabled).toBe(false);
    expect(await meStatus(s.cookie)).toBe(401);
    expect((await signInAs('jane', 'jane-password-1')).status).toBe(401);
    await mock.patch(`/api/v1/admin/users/${jane.id}`, { enabled: true });
    expect((await signInAs('jane', 'jane-password-1')).status).toBe(200);
  });

  it('protects the last enabled administrator', async () => {
    await signedIn();
    const admin = (await mock.get('/api/v1/admin/users')).data.find((u) => u.userName === 'admin');
    for (const r of [await mock.patch(`/api/v1/admin/users/${admin.id}`, { enabled: false }), await mock.patch(`/api/v1/admin/users/${admin.id}`, { role: 'tenant', tenantId: 't_acme' }), await mock.del(`/api/v1/admin/users/${admin.id}`)]) {
      expect(r.status).toBe(409);
      expect(r.data.reason).toBe('last_admin');
    }
    const second = (await mock.post('/api/v1/admin/users', { userName: 'second', role: 'admin', password: 'second-password' })).data;
    expect((await mock.patch(`/api/v1/admin/users/${admin.id}`, { enabled: false })).status).toBe(200);
    expect((await mock.del(`/api/v1/admin/users/${second.id}`)).status).toBe(401); // the admin session ended with the disable
  });

  it('resets a password (not your own) and ends the user sessions', async () => {
    await signedIn();
    const tenantUser = (await mock.get('/api/v1/admin/users')).data.find((u) => u.userName === 'tenant');
    const s = await signInAs('tenant', 'eggmail');
    const reset = await mock.post(`/api/v1/admin/users/${tenantUser.id}/reset-password`, {});
    expect(reset.status).toBe(200);
    expect(await meStatus(s.cookie)).toBe(401);
    expect((await signInAs('tenant', 'eggmail')).status).toBe(401);
    expect((await signInAs('tenant', reset.data.password)).status).toBe(200);
    const admin = (await mock.get('/api/v1/admin/users')).data.find((u) => u.userName === 'admin');
    expect((await mock.post(`/api/v1/admin/users/${admin.id}/reset-password`, {})).status).toBe(409);
  });

  it('changes your own password, keeps this session and ends the others', async () => {
    await signedIn('tenant');
    const other = await signInAs('tenant', 'eggmail');
    const wrong = await mock.post('/api/v1/me/password', { currentPassword: 'nope-nope-nope', newPassword: 'a brand new password' });
    expect(wrong.status).toBe(400);
    expect(wrong.data.errors[0].field).toBe('currentPassword');
    expect((await mock.post('/api/v1/me/password', { currentPassword: 'eggmail', newPassword: 'short' })).status).toBe(400);
    expect((await mock.post('/api/v1/me/password', { currentPassword: 'eggmail', newPassword: 'a brand new password' })).status).toBe(204);
    expect((await mock.get('/api/v1/me')).status).toBe(200);
    expect(await meStatus(other.cookie)).toBe(401);
    expect((await signInAs('tenant', 'a brand new password')).status).toBe(200);
  });

  it('locks the password form after repeated failures', async () => {
    await signedIn('tenant');
    for (let i = 0; i < 5; i++) await mock.post('/api/v1/me/password', { currentPassword: 'wrong-wrong-1', newPassword: 'a brand new password' });
    const locked = await mock.post('/api/v1/me/password', { currentPassword: 'eggmail', newPassword: 'a brand new password' });
    expect(locked.status).toBe(429);
    expect(locked.headers.get('retry-after')).toBeTruthy();
  });
});
