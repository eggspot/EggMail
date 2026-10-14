// Dashboard user management (docs/api.md, "Users"): admin-only /api/v1/admin/users and the signed-in user's own password change.
// Mirrors the host's rules: case-insensitive unique names, password policy, last-admin protection, sessions ended on disable / role change /
// reset / delete, generated passwords returned once, password hashes (here: the plain mock password) never listed.
import { randomBytes } from 'node:crypto';
import { HttpError, iso, newId, validate } from '../lib.mjs';

const MIN_PASSWORD = 10;
const MAX_PASSWORD = 1024;

const publicUser = (u, generatedPassword) => {
  const out = { id: u.id, userName: u.userName, role: u.role, enabled: u.enabled, createdAt: u.createdAt };
  if (u.tenantId) out.tenantId = u.tenantId;
  if (generatedPassword) out.password = generatedPassword;
  return out;
};

const generatePassword = () => randomBytes(18).toString('base64url');

function endSessions(state, userId, exceptSid) {
  for (const [sid, s] of state.sessions) if (s.userId === userId && sid !== exceptSid) state.sessions.delete(sid);
}

const enabledAdmins = (state) => state.accounts.filter((a) => a.role === 'admin' && a.enabled);

function refuseLastAdmin(state, user) {
  if (user.role === 'admin' && user.enabled && enabledAdmins(state).every((a) => a.id === user.id)) {
    throw new HttpError(409, 'conflict', 'This is the only enabled administrator. Create or enable another administrator first.', { reason: 'last_admin' });
  }
}

function find(state, id) {
  const u = state.accounts.find((a) => a.id === id);
  if (!u) throw new HttpError(404, 'not_found', 'User not found.');
  return u;
}

function passwordProblem(p) {
  if (typeof p !== 'string') return 'A password is required.';
  if (p.length < MIN_PASSWORD) return `The password must have at least ${MIN_PASSWORD} characters.`;
  if (p.length > MAX_PASSWORD) return `The password must have at most ${MAX_PASSWORD} characters.`;
  return null;
}

function checkActiveTenant(state, id, fail, field = 'tenantId') {
  const t = state.tenants.find((x) => x.id === id);
  if (typeof id !== 'string' || !id) fail(field, 'A tenant user needs a tenant id.');
  else if (!t) fail(field, 'Unknown tenant.');
  else if (t.status !== 'active') fail(field, 'The tenant is suspended.');
}

export function register(r, state) {
  r.get('/api/v1/admin/users', () => [...state.accounts].sort((a, b) => a.userName.localeCompare(b.userName)).map((u) => publicUser(u)));

  r.get('/api/v1/admin/users/:id', (ctx) => publicUser(find(state, ctx.params.id)));

  r.post('/api/v1/admin/users', (ctx) => {
    const b = ctx.body || {};
    const name = typeof b.userName === 'string' ? b.userName.trim().toLowerCase() : '';
    let generated = null;
    validate((fail) => {
      // eslint-disable-next-line no-control-regex
      if (!name || name.length > 256 || /[\u0000-\u001f\u007f]/.test(name)) fail('userName', 'A user name of 1 to 256 characters without control characters is required.');
      else if (state.accounts.some((a) => a.userName === name)) fail('userName', 'A user with this name already exists.');
      if (b.role !== 'admin' && b.role !== 'tenant') fail('role', 'Must be "admin" or "tenant".');
      else if (b.role === 'tenant') checkActiveTenant(state, b.tenantId, fail);
      else if (b.tenantId) fail('tenantId', 'An administrator does not belong to a tenant.');
      if (b.password === undefined || b.password === null) generated = generatePassword();
      else if (passwordProblem(b.password)) fail('password', passwordProblem(b.password));
    });
    const user = { id: newId(), userName: name, password: generated ?? b.password, role: b.role, tenantId: b.role === 'tenant' ? b.tenantId : null, enabled: true, createdAt: iso() };
    state.accounts.push(user);
    return { status: 201, body: publicUser(user, generated), headers: { Location: `/api/v1/admin/users/${user.id}` } };
  });

  r.patch('/api/v1/admin/users/:id', (ctx) => {
    const u = find(state, ctx.params.id);
    const b = ctx.body || {};
    if (b.enabled === undefined && b.role === undefined && b.tenantId === undefined) {
      throw new HttpError(400, 'validation_failed', 'One or more fields are invalid.', { errors: [{ field: '$', message: 'Send at least one of enabled, role or tenantId.' }] });
    }
    const role = b.role ?? u.role;
    let tenantId = u.tenantId;
    validate((fail) => {
      if (b.role !== undefined && b.role !== 'admin' && b.role !== 'tenant') fail('role', 'Must be "admin" or "tenant".');
      if (b.enabled !== undefined && typeof b.enabled !== 'boolean') fail('enabled', 'Must be true or false.');
      if (role === 'admin') {
        if (b.tenantId) fail('tenantId', 'An administrator does not belong to a tenant.');
        tenantId = null;
      } else if (b.tenantId !== undefined || u.role !== 'tenant') {
        checkActiveTenant(state, b.tenantId, fail);
        tenantId = b.tenantId;
      }
    });
    const enabled = b.enabled ?? u.enabled;
    if (u.role === 'admin' && u.enabled && !(role === 'admin' && enabled)) refuseLastAdmin(state, u);
    const end = enabled === false || role !== u.role || tenantId !== u.tenantId;
    Object.assign(u, { role, tenantId, enabled });
    if (end) endSessions(state, u.id);
    return publicUser(u);
  });

  r.delete('/api/v1/admin/users/:id', (ctx) => {
    const u = find(state, ctx.params.id);
    refuseLastAdmin(state, u);
    endSessions(state, u.id);
    state.accounts.splice(state.accounts.indexOf(u), 1);
    return undefined;
  });

  r.post('/api/v1/admin/users/:id/reset-password', (ctx) => {
    const u = find(state, ctx.params.id);
    if (u.id === ctx.session.userId) throw new HttpError(409, 'conflict', 'Use the change-password form (POST /me/password) for your own password.');
    const b = ctx.body || {};
    const generated = b.password === undefined || b.password === null ? generatePassword() : null;
    validate((fail) => {
      if (!generated && passwordProblem(b.password)) fail('password', passwordProblem(b.password));
    });
    u.password = generated ?? b.password;
    endSessions(state, u.id);
    return publicUser(u, generated);
  });

  r.post('/api/v1/me/password', (ctx) => {
    const b = ctx.body || {};
    const u = state.accounts.find((a) => a.id === ctx.session.userId);
    validate((fail) => {
      if (typeof b.currentPassword !== 'string' || !b.currentPassword) fail('currentPassword', 'The current password is required.');
      const problem = passwordProblem(b.newPassword);
      if (problem) fail('newPassword', problem);
      else if (b.newPassword === b.currentPassword) fail('newPassword', 'The new password must differ from the current one.');
    });
    const key = 'pw:' + u.userName;
    const fails = state.loginFailures.get(key);
    if (fails && fails.count >= 5 && fails.until > Date.now()) {
      throw new HttpError(429, 'rate_limited', 'Too many failed password attempts. Try again later.', {}, { 'Retry-After': String(Math.ceil((fails.until - Date.now()) / 1000)) });
    }
    if (u.password !== b.currentPassword) {
      const f = fails && fails.until > Date.now() ? fails : { count: 0, until: Date.now() + 60_000 };
      f.count += 1;
      state.loginFailures.set(key, f);
      throw new HttpError(400, 'validation_failed', 'One or more fields are invalid.', { errors: [{ field: 'currentPassword', message: 'The current password is not correct.' }] });
    }
    state.loginFailures.delete(key);
    u.password = b.newPassword;
    endSessions(state, u.id, ctx.sid);
    return undefined;
  });
}
