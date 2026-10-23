// @vitest-environment node
import { afterEach, describe, expect, it } from 'vitest';
import { startMock } from './mockClient.mjs';

let mock;
afterEach(async () => {
  await mock?.close();
});

const PASS = 'correct horse battery';
const pgTarget = { host: 'db.internal', port: 5432, database: 'eggmail' };

async function admin(options = {}) {
  mock = await startMock({ switchStepMs: 15, ...options });
  await mock.login('admin');
  return mock;
}

const body = (over = {}) => ({ to: 'postgres', target: pgTarget, include: ['history'], mode: 'drain', ...over });

async function waitForState(want, timeoutMs = 3000) {
  const t0 = Date.now();
  for (;;) {
    const r = await mock.get('/api/v1/admin/storage/switch');
    if (r.data.state === want) return r.data;
    if (Date.now() - t0 > timeoutMs) throw new Error(`timeout waiting for ${want}, last ${r.data.state}`);
    await new Promise((r2) => setTimeout(r2, 10));
  }
}

async function startSwitch(over = {}) {
  const b = body(over);
  return mock.post('/api/v1/admin/storage/switch/start', { ...b, exportPassphrase: PASS, confirmation: `switch to ${b.to}` });
}

describe('admin access', () => {
  it('forbids the tenant role on every admin endpoint', async () => {
    mock = await startMock();
    await mock.login('tenant');
    for (const p of ['/api/v1/admin/tenants', '/api/v1/admin/status', '/api/v1/admin/settings', '/api/v1/admin/certificates', '/api/v1/admin/storage/switch']) {
      const r = await mock.get(p);
      expect(r.status, p).toBe(403);
      expect(r.data.code).toBe('forbidden');
    }
    expect((await mock.post('/api/v1/admin/storage/switch/start', {})).status).toBe(403);
  });
});

describe('tenants', () => {
  it('lists, creates, validates, renames and suspends', async () => {
    await admin();
    const list = await mock.get('/api/v1/admin/tenants');
    expect(list.data.map((t) => t.id)).toContain('t_acme');

    const created = await mock.post('/api/v1/admin/tenants', { name: 'Wayne Enterprises' });
    expect(created.status).toBe(201);
    expect(created.data.status).toBe('active');

    const dup = await mock.post('/api/v1/admin/tenants', { name: 'wayne enterprises' });
    expect(dup.status).toBe(400);
    expect(dup.data.code).toBe('validation_failed');
    expect(dup.data.errors[0].field).toBe('name');
    expect((await mock.post('/api/v1/admin/tenants', { name: '  ' })).status).toBe(400);

    const patched = await mock.patch(`/api/v1/admin/tenants/${created.data.id}`, { status: 'suspended', name: 'Wayne Corp' });
    expect(patched.data).toMatchObject({ status: 'suspended', name: 'Wayne Corp' });
    expect((await mock.patch(`/api/v1/admin/tenants/${created.data.id}`, { status: 'bogus' })).status).toBe(400);
    expect((await mock.patch('/api/v1/admin/tenants/nope', { name: 'x' })).status).toBe(404);
  });
});

describe('status, settings, certificates', () => {
  it('reports status from the runtime options with writer pressure on sqlite and pool pressure on postgres', async () => {
    await admin({ backend: 'sqlite', history: 'statsonly', warnings: ['sqlite_sync_off'] });
    const s = (await mock.get('/api/v1/admin/status')).data;
    expect(s.backend).toBe('sqlite');
    expect(s.historyMode).toBe('statsonly');
    expect(s.pressure.advisory).toBe(true);
    expect(s.storage.warnings[0].code).toBe('sqlite_sync_off');
    expect(s.switch.state).toBe('none');
    await mock.post('/__mock/config', { backend: 'postgres', warnings: [] });
    const p = (await mock.get('/api/v1/admin/status')).data;
    expect(p.pressure.writerQueueDepth).toBeUndefined();
    expect(p.pressure.poolMaxSize).toBe(50);
    expect(p.pressure.advisory).toBe(false);
    expect(p.storage.warnings).toEqual([]);
  });

  it('validates global settings and rejects locked ones', async () => {
    await admin();
    const items = (await mock.get('/api/v1/admin/settings')).data.items;
    expect(items.find((i) => i.key === 'Smtp:MaxMessageSize').locked).toBe(true);
    const ok = await mock.put('/api/v1/admin/settings', { values: { 'Retention:MetadataDays': 0 } });
    expect(ok.data.items.find((i) => i.key === 'Retention:MetadataDays').value).toBe(0);
    const bad = await mock.put('/api/v1/admin/settings', { values: { 'Smtp:MaxMessageSize': 1, 'Stats:HourlyRetentionDays': -1, 'History:Mode': 'Nope', Unknown: 1 } });
    expect(bad.status).toBe(400);
    expect(bad.data.errors.map((e) => e.field).sort()).toEqual(['History:Mode', 'Smtp:MaxMessageSize', 'Stats:HourlyRetentionDays', 'Unknown']);
  });

  it('lists, uploads and validates certificates and requests ACME', async () => {
    await admin();
    const certs = (await mock.get('/api/v1/admin/certificates')).data;
    expect(certs.length).toBeGreaterThanOrEqual(2);
    expect((await mock.post('/api/v1/admin/certificates', {})).status).toBe(400);
    const pem = '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----';
    const noKey = await mock.post('/api/v1/admin/certificates', { certificatePem: pem });
    expect(noKey.data.errors[0].field).toBe('privateKeyPem');
    const good = await mock.post('/api/v1/admin/certificates', { certificatePem: pem, privateKeyPem: '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----' });
    expect(good.status).toBe(201);
    expect(good.data.source).toBe('upload');
    expect((await mock.post('/api/v1/admin/certificates', { pfxBase64: '***' })).status).toBe(400);

    const acme = await mock.post('/api/v1/admin/certificates/acme', { domains: ['mail.example.org'] });
    expect(acme.status).toBe(202);
    expect(acme.data.status).toBe('pending');
    expect((await mock.post('/api/v1/admin/certificates/acme', { domains: ['not a host'] })).status).toBe(400);
    expect((await mock.post('/api/v1/admin/maintenance/run')).status).toBe(202);
  });
});

describe('storage switch machine', () => {
  it('runs the full drain happy path: preflight, start, verify, confirm, activate, finalize', async () => {
    await admin({ backend: 'sqlite' });
    const pre = await mock.post('/api/v1/admin/storage/switch/preflight', body());
    expect(pre.status).toBe(200);
    expect(pre.data.ok).toBe(true);
    expect(pre.data.estimate.unverified).toBe(true);
    expect(pre.data.notCarried.length).toBeGreaterThan(0);
    expect((await mock.get('/api/v1/admin/storage/switch')).data.state).toBe('none');

    const started = await startSwitch();
    expect(started.status).toBe(202);
    expect(started.data.state).toBe('draining');
    expect(started.data.progress.percent).toBeLessThan(100);

    // too early to confirm or activate
    expect((await mock.post('/api/v1/admin/storage/switch/confirm')).status).toBe(409);
    expect((await mock.post('/api/v1/admin/storage/switch/activate')).status).toBe(409);

    const verified = await waitForState('verified');
    expect(verified.verifyReport.ok).toBe(true);
    expect(verified.verifyReport.tables.every((t) => t.expected === t.actual)).toBe(true);

    // nothing advances by itself: still verified after waiting
    await new Promise((r) => setTimeout(r, 120));
    expect((await mock.get('/api/v1/admin/storage/switch')).data.state).toBe('verified');
    expect((await mock.get('/api/v1/capabilities')).data.backend).toBe('sqlite');

    expect((await mock.post('/api/v1/admin/storage/switch/finalize')).status).toBe(409);
    expect((await mock.post('/api/v1/admin/storage/switch/confirm')).data.state).toBe('confirmed');
    expect((await mock.get('/api/v1/capabilities')).data.backend).toBe('sqlite');
    const active = await mock.post('/api/v1/admin/storage/switch/activate');
    expect(active.data.state).toBe('active');
    expect((await mock.get('/api/v1/capabilities')).data.backend).toBe('postgres');

    // rollback is refused after activation
    const rb = await mock.post('/api/v1/admin/storage/switch/rollback');
    expect(rb.status).toBe(409);
    expect(rb.data.switch_state).toBe('active');
    expect((await mock.post('/api/v1/admin/storage/switch/finalize')).data.state).toBe('finalized');
    expect((await mock.get('/api/v1/admin/status')).data.switch.state).toBe('finalized');
  });

  it('passes through fenced, exporting and importing on the way (quiesce)', async () => {
    await admin();
    const started = await startSwitch({ mode: 'quiesce', include: ['queue', 'history'] });
    expect(started.data.state).toBe('quiescing');
    const seen = new Set();
    const t0 = Date.now();
    for (;;) {
      const s = (await mock.get('/api/v1/admin/storage/switch')).data.state;
      seen.add(s);
      if (s === 'verified' || Date.now() - t0 > 3000) break;
      await new Promise((r) => setTimeout(r, 5));
    }
    expect([...seen]).toContain('fenced');
    expect([...seen]).toContain('verified');
    const v = (await mock.get('/api/v1/admin/storage/switch')).data;
    expect(v.verifyReport.tables.some((t) => t.table === 'queue.deliveries' && t.expected > 0)).toBe(true);
  });

  it('can roll back before activation and then start again', async () => {
    await admin();
    await startSwitch();
    await waitForState('verified');
    await mock.post('/api/v1/admin/storage/switch/confirm');
    const rb = await mock.post('/api/v1/admin/storage/switch/rollback');
    expect(rb.data.state).toBe('rolled_back');
    expect((await mock.get('/api/v1/capabilities')).data.backend).toBe('sqlite');
    expect((await startSwitch()).status).toBe(202);
  });

  it('refuses a second start while a switch is in flight', async () => {
    await admin();
    await startSwitch();
    const again = await startSwitch();
    expect(again.status).toBe(409);
  });

  it('validates the preflight request', async () => {
    await admin({ backend: 'sqlite' });
    const sameBackend = await mock.post('/api/v1/admin/storage/switch/preflight', body({ to: 'sqlite', target: { path: '/data' } }));
    expect(sameBackend.status).toBe(400);
    expect(sameBackend.data.errors[0].field).toBe('to');
    const drainQueue = await mock.post('/api/v1/admin/storage/switch/preflight', body({ include: ['queue'], mode: 'drain' }));
    expect(drainQueue.data.errors[0].field).toBe('include');
    const noTarget = await mock.post('/api/v1/admin/storage/switch/preflight', body({ target: {} }));
    expect(noTarget.data.errors[0].field).toBe('target');
  });

  it('requires the passphrase and the typed confirmation to start', async () => {
    await admin();
    const b = body();
    const short = await mock.post('/api/v1/admin/storage/switch/start', { ...b, exportPassphrase: 'short', confirmation: 'switch to postgres' });
    expect(short.data.errors.map((e) => e.field)).toContain('exportPassphrase');
    const wrong = await mock.post('/api/v1/admin/storage/switch/start', { ...b, exportPassphrase: PASS, confirmation: 'yes' });
    expect(wrong.data.errors.map((e) => e.field)).toContain('confirmation');
    expect((await mock.get('/api/v1/admin/storage/switch')).data.state).toBe('none');
  });

  it('injects failures: unreachable target and failing verification', async () => {
    await admin();
    const bad = await mock.post('/api/v1/admin/storage/switch/preflight', body({ target: { host: 'unreachable.test', database: 'x' } }));
    expect(bad.data.ok).toBe(false);
    expect(bad.data.checks.some((c) => !c.ok && c.severity === 'error')).toBe(true);
    expect((await startSwitch({ target: { host: 'unreachable.test', database: 'x' } })).status).toBe(400);

    await startSwitch({ target: { host: 'db', database: 'fail-verify' } });
    const v = await waitForState('verified');
    expect(v.verifyReport.ok).toBe(false);
    expect(v.verifyReport.checksumsOk).toBe(false);
    const confirm = await mock.post('/api/v1/admin/storage/switch/confirm');
    expect(confirm.status).toBe(409);
    expect((await mock.post('/api/v1/admin/storage/switch/rollback')).data.state).toBe('rolled_back');
  });

  it('produces the cutover patch at activation for orchestrator-managed deployments, and the bootstrap note otherwise', async () => {
    await admin();
    await startSwitch({ target: { ...pgTarget, orchestrated: true } });
    await waitForState('verified');
    await mock.post('/api/v1/admin/storage/switch/confirm');
    expect((await mock.get('/api/v1/admin/storage/switch')).data.cutoverPatch).toBeNull(); // not before the activation
    await mock.post('/api/v1/admin/storage/switch/activate');
    const s = (await mock.get('/api/v1/admin/storage/switch')).data;
    expect(s.orchestratorManaged).toBe(true);
    expect(s.cutoverPatch.kind).toBe('patch');
    expect(s.cutoverPatch.text).toContain('Storage__Backend=Postgres');
    expect(s.cutoverPatch.text).not.toMatch(/password=/i);

    await mock.close(); // an activated switch moves the mock to the other backend; start again from a fresh server
    await admin();
    await startSwitch();
    await waitForState('verified');
    await mock.post('/api/v1/admin/storage/switch/confirm');
    await mock.post('/api/v1/admin/storage/switch/activate');
    const plain = (await mock.get('/api/v1/admin/storage/switch')).data;
    expect(plain.orchestratorManaged).toBe(false);
    expect(plain.cutoverPatch.kind).toBe('bootstrap');
    expect(plain.cutoverPatch.text).toContain('bootstrap file');
  });

  it('is SQLite to PostgreSQL and back (symmetric)', async () => {
    await admin({ backend: 'postgres', warnings: [] });
    const r = await startSwitch({ to: 'sqlite', target: { path: '/data' } });
    expect(r.status).toBe(202);
    expect(r.data.direction).toEqual({ from: 'postgres', to: 'sqlite' });
    const pre = await mock.post('/api/v1/admin/storage/switch/preflight', body({ to: 'sqlite', target: { path: '/data' } }));
    expect(pre.data.checks.some((c) => c.severity === 'warning' && /synchronous=OFF/.test(c.message))).toBe(true);
  });
});

describe('mock maintenance and ACME state', () => {
  it('reports no maintenance run until one was started, then its jobs', async () => {
    await admin();
    const before = (await mock.get('/api/v1/admin/maintenance')).data;
    expect(before).toMatchObject({ running: false, finishedAt: null, reports: [] });
    expect((await mock.post('/api/v1/admin/maintenance/run')).status).toBe(202);
    const after = (await mock.get('/api/v1/admin/maintenance')).data;
    expect(after.finishedAt).not.toBeNull();
    expect(after.reports.length).toBeGreaterThan(0);
  });

  it('lists the ACME renewal state and marks it pending after a request', async () => {
    await admin();
    expect((await mock.get('/api/v1/admin/certificates/acme')).data[0]).toMatchObject({ certificateName: 'default', status: 'renewed' });
    expect((await mock.post('/api/v1/admin/certificates/acme', { domains: ['mail.example.com'] })).status).toBe(202);
    expect((await mock.get('/api/v1/admin/certificates/acme')).data[0].status).toBe('pending');
  });
});

