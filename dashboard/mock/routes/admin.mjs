// Admin endpoints: tenants, status, global settings, certificates, maintenance and the storage-switch machine.
// The switch machine is time driven (Date.now()) so manual QA is quick and tests can shorten it with the
// `switchStepMs` option. Nothing here ever starts, advances past "verified", activates or finalizes on its own.
import { HttpError, daysFromNow, daysAgo, minutesAgo, newId, iso, validate } from '../lib.mjs';
import { WARNING_TEXT } from '../app.mjs';

const DEFAULT_STEP_MS = 1500;
const SWITCH_STATES_RUNNING = ['draining', 'quiescing', 'fenced', 'exporting', 'importing'];

function sharedStore(state) {
  const s = state.shared;
  if (!s.admin) {
    s.admin = {
      certs: [
        { id: newId(), subject: 'CN=mail.example.com', issuer: "CN=Let's Encrypt R11", san: ['mail.example.com', 'smtp.example.com'], notBefore: daysAgo(81), notAfter: daysFromNow(9), source: 'acme', active: true, thumbprint: 'A1B2C3D4E5F60718293A4B5C6D7E8F9001122334' },
        { id: newId(), subject: 'CN=eggmail-selfsigned', issuer: 'CN=eggmail-selfsigned', san: ['localhost'], notBefore: daysAgo(30), notAfter: daysFromNow(335), source: 'self_signed', active: false, thumbprint: 'FFEEDDCCBBAA99887766554433221100AABBCCDD' },
      ],
      settings: initialSettings(),
      switch: null,
      maintenanceRuns: 0,
    };
  }
  return s.admin;
}

function initialSettings() {
  return [
    { key: 'History:Mode', value: 'Full', type: 'enum', options: ['StatsOnly', 'Full'], description: 'How much per-message history is recorded.', locked: false },
    { key: 'Retention:MetadataDays', value: 30, type: 'number', description: 'Days to keep message events. 0 keeps them forever.', locked: false },
    { key: 'Webhooks:OutboxRetentionDays', value: 7, type: 'number', description: 'Days to keep finished webhook outbox rows. 0 keeps them forever.', locked: false },
    { key: 'Stats:HourlyRetentionDays', value: 30, type: 'number', description: 'Days to keep hourly statistics. 0 keeps them forever.', locked: false },
    { key: 'Stats:DailyRetentionDays', value: 400, type: 'number', description: 'Days to keep daily statistics. 0 keeps them forever.', locked: false },
    { key: 'Queue:MaxLifetime', value: 5, type: 'number', description: 'Days a message may stay queued.', locked: false },
    { key: 'Smtp:MaxMessageSize', value: 26214400, type: 'number', description: 'Maximum message size in bytes.', locked: true },
    { key: 'Sqlite:SyncMode', value: 'Off', type: 'enum', options: ['Off', 'Normal', 'Full'], description: 'SQLite synchronous mode for the data files.', locked: true },
  ];
}

// ---------- switch machine ----------

function stepMs(state) {
  return Number(state.options.switchStepMs) > 0 ? Number(state.options.switchStepMs) : DEFAULT_STEP_MS;
}

function currentBackend(state) {
  return state.options.backend;
}

function computeState(state, sw) {
  if (!sw) return 'none';
  if (sw.manual) return sw.manual;
  const phases = [sw.mode === 'quiesce' ? 'quiescing' : 'draining', 'fenced', 'exporting', 'importing'];
  const elapsed = Date.now() - sw.startedAt;
  const idx = Math.floor(elapsed / stepMs(state));
  return idx >= phases.length ? 'verified' : phases[idx];
}

function verifyReportFor(sw) {
  const failing = sw.target?.database === 'fail-verify';
  const tables = [
    { table: 'config.tenants', expected: 3, actual: 3 },
    { table: 'config.domains', expected: 4, actual: 4 },
    { table: 'config.suppressions', expected: 120, actual: 120 },
    { table: 'stats.hourly', expected: 21600, actual: 21600 },
    { table: 'queue.deliveries', expected: sw.include.includes('queue') ? 17 : 0, actual: sw.include.includes('queue') ? 17 : 0 },
  ];
  if (sw.include.includes('history')) tables.push({ table: 'history.events', expected: 184000, actual: failing ? 183990 : 184000 });
  return { ok: !failing, tables, checksumsOk: !failing, checkedAt: iso() };
}

function switchStatus(state) {
  const store = sharedStore(state);
  const sw = store.switch;
  if (!sw) return { state: 'none' };
  const st = computeState(state, sw);
  const elapsed = Date.now() - sw.startedAt;
  const total = stepMs(state) * 4;
  const running = SWITCH_STATES_RUNNING.includes(st);
  const out = {
    switchId: sw.switchId,
    state: st,
    direction: { from: sw.from, to: sw.to },
    mode: sw.mode,
    include: sw.include,
    orchestratorManaged: sw.orchestratorManaged,
    startedAt: iso(sw.startedAt),
    updatedAt: iso(),
    error: null,
  };
  if (running) {
    const percent = Math.min(99, Math.floor((elapsed / total) * 100));
    out.progress = { phase: st, percent, rowsDone: Math.floor((percent / 100) * 205000), rowsTotal: 205000 };
  } else if (st === 'verified' || st === 'confirmed' || st === 'active' || st === 'finalized') {
    out.progress = { phase: 'done', percent: 100, rowsDone: 205000, rowsTotal: 205000 };
    out.verifyReport = verifyReportFor(sw);
  }
  if (st === 'confirmed' && sw.orchestratorManaged) {
    out.cutoverPatch = {
      kind: 'environment',
      text: sw.to === 'postgres'
        ? 'Storage__Backend=Postgres\nStorage__Postgres__ConnectionString=<from secret eggmail-pg-connection>\n'
        : 'Storage__Backend=Sqlite\nStorage__Sqlite__DataDirectory=' + (sw.target?.path || '/data') + '\n',
    };
  } else {
    out.cutoverPatch = null;
  }
  return out;
}

function requireState(state, allowed, action) {
  const sw = sharedStore(state).switch;
  const st = computeState(state, sw);
  if (!allowed.includes(st)) {
    throw new HttpError(409, 'validation_failed', `Cannot ${action}: the switch is in state "${st}".`, { switch_state: st });
  }
  return sw;
}

function validateSwitchRequest(b, state) {
  validate((fail) => {
    if (b?.to !== 'postgres' && b?.to !== 'sqlite') fail('to', 'must be "postgres" or "sqlite"');
    else if (b.to === currentBackend(state)) fail('to', `the server already uses ${b.to}`);
    if (b?.mode !== 'drain' && b?.mode !== 'quiesce') fail('mode', 'must be "drain" or "quiesce"');
    if (!Array.isArray(b?.include) || b.include.some((x) => x !== 'queue' && x !== 'history')) fail('include', 'must be a list of "queue" and/or "history"');
    else if (b.mode === 'drain' && b.include.includes('queue')) fail('include', 'queued mail only moves with mode "quiesce"; a drain empties the queue first');
    const t = b?.target;
    if (!t || typeof t !== 'object') fail('target', 'required');
    else if (b.to === 'postgres' && !t.connectionName && !(t.host && t.database)) fail('target', 'give a connection name, or host and database');
    else if (b.to === 'sqlite' && !t.path) fail('target.path', 'required');
  });
}

function preflight(b, state) {
  validateSwitchRequest(b, state);
  const unreachable = b.target.host === 'unreachable.test';
  const history = b.include.includes('history');
  const checks = [
    { name: 'Target reachable', ok: !unreachable, severity: unreachable ? 'error' : 'info', message: unreachable ? 'Could not connect to unreachable.test:5432 (timeout).' : 'Connected to the target.' },
    { name: 'Target is empty', ok: true, severity: 'info', message: 'No EggMail tables found; nothing will be merged.' },
    { name: 'Schema and migrations', ok: true, severity: 'info', message: 'Schema is current.' },
    { name: 'Target key protection', ok: true, severity: 'info', message: 'Secrets can be re-protected under the target Data Protection key ring.' },
    { name: 'Bundle format', ok: true, severity: 'info', message: 'Bundle format 1.0 is compatible.' },
    { name: 'Disk space', ok: true, severity: 'info', message: 'Enough free space for the bundle (about 1.2 GiB).' },
  ];
  if (b.to === 'sqlite') {
    checks.push({ name: 'SQLite sync mode', ok: true, severity: 'warning', message: 'The target would run with synchronous=OFF: process-crash-safe, not power-loss-safe. Set Sqlite:SyncMode=Normal or Full for power-loss safety.' });
  }
  const notCarried = ['The deployment configuration (ports, connection strings, Storage:Backend, sync modes, key-protection certificate) stays with your deployment.', 'In-flight ACME orders and DNS-01 challenge state are not moved; the target restarts any pending order.'];
  if (!history) notCarried.push('Per-message history stays in the read-only source (you chose to skip it); it can be backfilled after activation.');
  return {
    ok: !unreachable,
    checks,
    counts: { queuedMessages: 17, historyRows: history ? 184000 : 0, historyBytes: history ? 14_500_000_000 : 0, statsRows: 21600 },
    estimate: { seconds: history ? 5400 : 120, bytes: history ? 14_700_000_000 : 40_000_000, unverified: true },
    notCarried,
    orchestratorManaged: process.env.MOCK_ORCHESTRATED === '1' || b.target.orchestrated === true,
  };
}

// ---------- registration ----------

export function register(r, state) {
  // ---- tenants ----
  r.get('/api/v1/admin/tenants', () => state.tenants);
  r.post('/api/v1/admin/tenants', (ctx) => {
    const name = typeof ctx.body?.name === 'string' ? ctx.body.name.trim() : '';
    validate((fail) => {
      if (!name) fail('name', 'required');
      else if (name.length > 80) fail('name', 'at most 80 characters');
      else if (state.tenants.some((t) => t.name.toLowerCase() === name.toLowerCase())) fail('name', 'a tenant with this name already exists');
    });
    const tenant = { id: 't_' + newId().slice(-8), name, status: 'active', createdAt: iso() };
    state.tenants.push(tenant);
    return { status: 201, body: tenant };
  });
  r.patch('/api/v1/admin/tenants/:id', (ctx) => {
    const t = state.tenants.find((x) => x.id === ctx.params.id);
    if (!t) throw new HttpError(404, 'not_found', 'Tenant not found.');
    const b = ctx.body || {};
    validate((fail) => {
      if (b.name !== undefined && (typeof b.name !== 'string' || !b.name.trim())) fail('name', 'required');
      else if (b.name !== undefined && state.tenants.some((x) => x.id !== t.id && x.name.toLowerCase() === b.name.trim().toLowerCase())) fail('name', 'a tenant with this name already exists');
      if (b.status !== undefined && b.status !== 'active' && b.status !== 'suspended') fail('status', 'must be "active" or "suspended"');
    });
    if (b.name !== undefined) t.name = b.name.trim();
    if (b.status !== undefined) t.status = b.status;
    return t;
  });

  // ---- status ----
  r.get('/api/v1/admin/status', () => {
    const o = state.options;
    const store = sharedStore(state);
    const sqlite = o.backend === 'sqlite';
    return {
      version: '0.1.0',
      backend: o.backend,
      historyMode: o.history,
      uptimeSeconds: Math.floor((Date.now() - state.startedAt) / 1000) + 86_400 * 3,
      queue: { depth: sqlite ? 1240 : 42, deferred: 17, oldestDueAt: minutesAgo(sqlite ? 12 : 1) },
      storage: {
        healthy: !o.notReady,
        detail: o.notReady ? 'Storage backend unavailable' : sqlite ? 'SQLite files open; integrity check passed at startup.' : 'PostgreSQL connection pool healthy (12/50).',
        warnings: o.warnings.map((code) => ({ code, message: WARNING_TEXT[code] || code })),
      },
      certificates: store.certs.filter((c) => c.active || c.source === 'acme').map((c) => ({ subject: c.subject, notAfter: c.notAfter, source: c.source })),
      pressure: sqlite
        ? { writerQueueDepth: 1240, writerQueueOverThresholdSeconds: 410, commitP99Ms: 118, advisory: true }
        : { writerQueueDepth: 12, writerQueueOverThresholdSeconds: 0, commitP99Ms: 9, advisory: false },
      switch: { state: computeState(state, store.switch) },
    };
  });

  // ---- global settings ----
  r.get('/api/v1/admin/settings', () => ({ items: sharedStore(state).settings }));
  r.put('/api/v1/admin/settings', (ctx) => {
    const values = ctx.body?.values;
    const store = sharedStore(state);
    validate((fail) => {
      if (!values || typeof values !== 'object') return fail('values', 'required');
      for (const [key, v] of Object.entries(values)) {
        const item = store.settings.find((s) => s.key === key);
        if (!item) fail(key, 'unknown setting');
        else if (item.locked) fail(key, 'locked by deployment configuration');
        else if (item.type === 'number') {
          if (typeof v !== 'number' || !Number.isInteger(v) || v < 0) fail(key, 'must be a whole number, 0 or more');
        } else if (item.type === 'enum' && !item.options.includes(v)) fail(key, `must be one of ${item.options.join(', ')}`);
      }
    });
    for (const [key, v] of Object.entries(values)) store.settings.find((s) => s.key === key).value = v;
    return { items: store.settings };
  });

  // ---- certificates ----
  r.get('/api/v1/admin/certificates', () => sharedStore(state).certs);
  r.post('/api/v1/admin/certificates', (ctx) => {
    const b = ctx.body || {};
    validate((fail) => {
      const pem = typeof b.certificatePem === 'string' && b.certificatePem.trim();
      const pfx = typeof b.pfxBase64 === 'string' && b.pfxBase64.trim();
      if (!pem && !pfx) return fail('certificatePem', 'give a PEM certificate or a PFX file');
      if (pem) {
        if (!/-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----/.test(b.certificatePem)) fail('certificatePem', 'not a PEM certificate');
        if (!/-----BEGIN (RSA |EC )?PRIVATE KEY-----[\s\S]+-----END (RSA |EC )?PRIVATE KEY-----/.test(b.privateKeyPem || '')) fail('privateKeyPem', 'a PEM private key is required');
      } else if (!/^[A-Za-z0-9+/=\s]+$/.test(b.pfxBase64)) fail('pfxBase64', 'not valid base64');
    });
    const store = sharedStore(state);
    const cert = {
      id: newId(), subject: 'CN=uploaded.example.com', issuer: 'CN=Example CA', san: ['uploaded.example.com'], notBefore: iso(), notAfter: daysFromNow(365), source: 'upload', active: false,
      thumbprint: newId().toUpperCase().slice(0, 40),
    };
    store.certs.push(cert);
    return { status: 201, body: cert };
  });
  r.post('/api/v1/admin/certificates/acme', (ctx) => {
    const domains = ctx.body?.domains;
    validate((fail) => {
      if (!Array.isArray(domains) || !domains.length) return fail('domains', 'give at least one domain');
      for (const d of domains) if (typeof d !== 'string' || !/^([a-z0-9-]+\.)+[a-z]{2,}$/i.test(d)) fail('domains', `"${d}" is not a valid host name`);
    });
    return { status: 202, body: { status: 'pending', message: `Certificate requested for ${domains.join(', ')} using DNS-01. Check back in a few minutes.` } };
  });
  r.post('/api/v1/admin/maintenance/run', () => {
    sharedStore(state).maintenanceRuns += 1;
    return { status: 202, body: { status: 'started' } };
  });

  // ---- storage switch (never automatic) ----
  r.post('/api/v1/admin/storage/switch/preflight', (ctx) => preflight(ctx.body, state));
  r.post('/api/v1/admin/storage/switch/start', (ctx) => {
    const b = ctx.body || {};
    const store = sharedStore(state);
    const existing = computeState(state, store.switch);
    if (store.switch && !['none', 'finalized', 'rolled_back'].includes(existing)) {
      throw new HttpError(409, 'validation_failed', `A switch is already in progress (state "${existing}").`, { switch_state: existing });
    }
    const report = preflight(b, state);
    validate((fail) => {
      if (typeof b.exportPassphrase !== 'string' || b.exportPassphrase.length < 12) fail('exportPassphrase', 'at least 12 characters');
      if (b.confirmation !== `switch to ${b.to}`) fail('confirmation', `type "switch to ${b.to}" to confirm`);
      if (!report.ok) fail('target', 'preflight failed; fix the reported problems first');
    });
    store.switch = {
      switchId: newId(), from: currentBackend(state), to: b.to, mode: b.mode, include: b.include, target: b.target,
      orchestratorManaged: report.orchestratorManaged, startedAt: Date.now(), manual: null,
    };
    return { status: 202, body: switchStatus(state) };
  });
  r.get('/api/v1/admin/storage/switch', () => switchStatus(state));
  r.post('/api/v1/admin/storage/switch/confirm', () => {
    const sw = requireState(state, ['verified'], 'confirm');
    if (!verifyReportFor(sw).ok) throw new HttpError(409, 'validation_failed', 'Verification failed; roll back instead of confirming.', { switch_state: 'verified' });
    sw.manual = 'confirmed';
    return switchStatus(state);
  });
  r.post('/api/v1/admin/storage/switch/activate', () => {
    const sw = requireState(state, ['confirmed'], 'activate');
    sw.manual = 'active';
    // For bootstrap-managed deployments the tool writes the pointer and restarts; the mock just flips it.
    state.options.backend = sw.to;
    if (sw.to === 'postgres') state.options.warnings = state.options.warnings.filter((w) => w !== 'sqlite_sync_off');
    return switchStatus(state);
  });
  r.post('/api/v1/admin/storage/switch/rollback', () => {
    const sw = requireState(state, ['draining', 'quiescing', 'fenced', 'exporting', 'importing', 'verified', 'confirmed', 'failed'], 'roll back');
    sw.manual = 'rolled_back';
    return switchStatus(state);
  });
  r.post('/api/v1/admin/storage/switch/finalize', () => {
    const sw = requireState(state, ['active'], 'finalize');
    sw.manual = 'finalized';
    return switchStatus(state);
  });
}
