// Admin relay routes and per-domain TLS policies (docs/api.md). Server-wide records; the admin guard of the mock covers /api/v1/admin/*.
// The password of a relay route is write-only: the mock keeps only whether one is set, like the server's response shape.
import { HttpError, newId, validate } from '../lib.mjs';

const TLS_MODES = ['none', 'starttls', 'required', 'verify', 'implicit'];
const LEVELS = ['none', 'may', 'encrypt', 'verify'];
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const HOST_RE = /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*$/;
const MAX_ROUTES = 50;
const hostError = (value) => {
  const host = String(value ?? '').trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (host.includes(':') || /^\d+$/.test(host.split('.').at(-1) ?? '')) return 'Use a host name such as smtp.relay.example, not an IP address: the address is looked up in DNS.';
  if (!host || host.includes('*') || !HOST_RE.test(host)) return 'Enter a host name such as smtp.relay.example.';
  return null;
};
const MAX_POLICIES = 500;
const ACK_TEXT = 'Level none for "*" turns TLS off for every destination and skips MTA-STS and DANE: set acknowledgeInsecure to true if that is meant.';

function store(state) {
  const s = state.shared;
  if (!s.routing) {
    s.routing = {
      routes: [
        { id: newId(), name: 'office-relay', host: 'smtp.relay.example', port: 587, tlsMode: 'verify', userName: 'relay-user', hasPassword: true, priority: 100, enabled: true, domains: ['partner.example'] },
      ],
      policies: [{ id: newId(), domainPattern: '*.bank.example', level: 'verify' }],
    };
  }
  return s.routing;
}

function normalizePattern(value) {
  const v = String(value ?? '').trim().toLowerCase().replace(/\.$/, '');
  if (v === '*') return '*';
  const suffix = v.startsWith('*.') ? v.slice(2) : v;
  if (!suffix || suffix.includes('*') || /^\d+(\.\d+){3}$/.test(suffix) || !HOST_RE.test(suffix)) return null;
  return v;
}

function routeView(r) {
  const warnings = [];
  if (r.tlsMode === 'required' && r.userName) warnings.push('The certificate of this relay is not validated, so the password could be given to an impostor. Use tlsMode verify or implicit.');
  if (r.tlsMode === 'none') warnings.push('Mail goes to this relay in plaintext.');
  else if (r.tlsMode === 'starttls') warnings.push('TLS is only used when the relay offers it, and its certificate is not validated.');
  if (r.domains.includes('*')) warnings.push('Matches every recipient domain: this relay is used whenever direct delivery cannot connect.');
  for (const d of r.domains) if (d.startsWith('*.') && !r.domains.includes(d.slice(2))) warnings.push(`${d} covers the subdomains of ${d.slice(2)} only, not ${d.slice(2)} itself; list ${d.slice(2)} as well to carry it.`);
  return { ...r, warnings };
}

function policyView(p, all = []) {
  const warnings = [];
  if (p.domainPattern.startsWith('*.') && !all.some((o) => o.domainPattern === p.domainPattern.slice(2))) warnings.push(`${p.domainPattern} covers the subdomains of ${p.domainPattern.slice(2)} only, not ${p.domainPattern.slice(2)} itself, which has no policy of its own; add one for it too.`);
  if (p.level === 'none') warnings.push('Level none turns TLS off for these destinations and MTA-STS and DANE are not consulted: mail can go in plaintext even where the destination publishes an enforcing policy.');
  if (p.domainPattern === '*' && (p.level === 'encrypt' || p.level === 'verify')) {
    warnings.push(p.level === 'verify'
      ? 'Applies to every destination: mail to servers without STARTTLS or without a valid certificate for their MX name is deferred and eventually bounces.'
      : 'Applies to every destination: mail to servers without STARTTLS is deferred and eventually bounces.');
  }
  return { ...p, warnings };
}

function checkDomains(fail, domains) {
  if (!Array.isArray(domains) || domains.length === 0) return [];
  const out = [];
  domains.forEach((d, i) => {
    const p = normalizePattern(d);
    if (p === null) fail(`domains[${i}]`, 'Use a domain name, "*.suffix" for every subdomain at any depth (not the domain itself), or "*" for every domain.');
    else if (!out.includes(p)) out.push(p);
  });
  return out;
}

export function register(r, state) {
  // ---- relay routes ----
  r.get('/api/v1/admin/relay-routes', () => store(state).routes.map(routeView));
  r.get('/api/v1/admin/relay-routes/:id', (ctx) => {
    const route = store(state).routes.find((x) => x.id === ctx.params.id);
    if (!route) throw new HttpError(404, 'not_found', 'Relay route not found.');
    return routeView(route);
  });
  r.post('/api/v1/admin/relay-routes', (ctx) => {
    const b = ctx.body || {};
    const s = store(state);
    let domains = [];
    validate((fail) => {
      if (s.routes.length >= MAX_ROUTES) fail('name', `At most ${MAX_ROUTES} relay routes.`);
      const tlsMode = String(b.tlsMode ?? 'verify').toLowerCase();
      if (!TLS_MODES.includes(tlsMode)) fail('tlsMode', `Must be one of: ${TLS_MODES.join(', ')}.`);
      const name = String(b.name ?? '').trim();
      if (!NAME_RE.test(name)) fail('name', 'Use 1 to 64 letters, digits, dot, dash or underscore, starting with a letter or digit.');
      else if (name.toLowerCase() === 'direct') fail('name', '"direct" is the name of direct delivery.');
      else if (s.routes.some((x) => x.name.toLowerCase() === name.toLowerCase())) fail('name', 'A relay route with this name already exists.');
      const hostProblem = hostError(b.host);
      if (hostProblem) fail('host', hostProblem);
      const port = b.port ?? (tlsMode === 'implicit' ? 465 : 587);
      if (!Number.isInteger(port) || port < 1 || port > 65535) fail('port', 'Must be between 1 and 65535.');
      const priority = b.priority ?? 100;
      if (!Number.isInteger(priority) || priority < 0 || priority > 1000) fail('priority', 'Must be between 0 and 1000 (lower numbers are tried first).');
      if (!Array.isArray(b.domains) || b.domains.length === 0) fail('domains', 'Name at least one recipient domain: a relay is only used for the domains it lists. Use "*" for all of them.');
      else domains = checkDomains(fail, b.domains);
      if (b.password && !b.userName) fail('userName', 'A password needs a user name.');
      if (b.userName && !b.password) fail('password', 'A password is required with a user name.');
      if (b.userName && tlsMode === 'none') fail('tlsMode', 'Credentials need TLS: with tlsMode none the password would be sent in plaintext.');
    });
    const tlsMode = String(b.tlsMode ?? 'verify').toLowerCase();
    const route = {
      id: newId(), name: String(b.name).trim(), host: String(b.host).trim().toLowerCase().replace(/\.$/, ''), port: b.port ?? (tlsMode === 'implicit' ? 465 : 587), tlsMode,
      userName: b.userName ? String(b.userName) : null, hasPassword: !!b.userName, priority: b.priority ?? 100, enabled: b.enabled ?? true, domains,
    };
    s.routes.push(route);
    return { status: 201, body: routeView(route) };
  });
  r.patch('/api/v1/admin/relay-routes/:id', (ctx) => {
    const s = store(state);
    const route = s.routes.find((x) => x.id === ctx.params.id);
    if (!route) throw new HttpError(404, 'not_found', 'Relay route not found.');
    const b = ctx.body || {};
    const next = { ...route };
    let failures = 0;
    const errorsSoFar = () => failures > 0;
    validate((rawFail) => {
      const fail = (field, message) => {
        failures += 1;
        rawFail(field, message);
      };
      if (b.tlsMode !== undefined) {
        const m = String(b.tlsMode).toLowerCase();
        if (!TLS_MODES.includes(m)) fail('tlsMode', `Must be one of: ${TLS_MODES.join(', ')}.`);
        else next.tlsMode = m;
      }
      if (b.name !== undefined) {
        const name = String(b.name).trim();
        if (!NAME_RE.test(name)) fail('name', 'Use 1 to 64 letters, digits, dot, dash or underscore, starting with a letter or digit.');
        else if (name.toLowerCase() === 'direct') fail('name', '"direct" is the name of direct delivery.');
        else if (s.routes.some((x) => x.id !== route.id && x.name.toLowerCase() === name.toLowerCase())) fail('name', 'A relay route with this name already exists.');
        else next.name = name;
      }
      if (b.host !== undefined) {
        const hostProblem = hostError(b.host);
        if (hostProblem) fail('host', hostProblem);
        else next.host = String(b.host).trim().toLowerCase().replace(/\.$/, '');
      }
      if (b.port !== undefined) {
        if (!Number.isInteger(b.port) || b.port < 1 || b.port > 65535) fail('port', 'Must be between 1 and 65535.');
        else next.port = b.port;
      }
      if (b.priority !== undefined) {
        if (!Number.isInteger(b.priority) || b.priority < 0 || b.priority > 1000) fail('priority', 'Must be between 0 and 1000 (lower numbers are tried first).');
        else next.priority = b.priority;
      }
      if (b.enabled !== undefined) next.enabled = !!b.enabled;
      if (b.domains !== undefined) {
        if (!Array.isArray(b.domains) || b.domains.length === 0) fail('domains', 'Name at least one recipient domain: a relay is only used for the domains it lists. Use "*" for all of them.');
        else next.domains = checkDomains(fail, b.domains);
      }
      if (b.removeCredentials === true) {
        if (b.userName !== undefined || b.password !== undefined) fail('removeCredentials', 'Cannot be combined with userName or password.');
        next.userName = null;
        next.hasPassword = false;
      } else if (b.userName !== undefined || b.password !== undefined) {
        const user = b.userName ?? route.userName;
        const changed = b.userName !== undefined && b.userName !== route.userName;
        if (!user) fail('userName', 'A password needs a user name.');
        else if (!b.password && (!route.hasPassword || changed)) fail('password', 'A password is required with a user name.');
        else {
          next.userName = user;
          next.hasPassword = true;
        }
      }
      if (next.userName && next.tlsMode === 'none') fail('tlsMode', 'Credentials need TLS: with tlsMode none the password would be sent in plaintext.');
      const moved = next.host !== route.host || next.port !== route.port || next.tlsMode !== route.tlsMode;
      if (moved && next.userName && next.hasPassword && !b.password && b.removeCredentials !== true && !errorsSoFar()) {
        fail('password', 'Changing the host, port or TLS mode of a route with a stored login needs the password again (or removeCredentials), so a stored secret is never sent somewhere you did not choose for it.');
      }
    });
    Object.assign(route, next);
    return routeView(route);
  });
  r.delete('/api/v1/admin/relay-routes/:id', (ctx) => {
    const s = store(state);
    const i = s.routes.findIndex((x) => x.id === ctx.params.id);
    if (i < 0) throw new HttpError(404, 'not_found', 'Relay route not found.');
    s.routes.splice(i, 1);
    return undefined;
  });

  // ---- TLS policies ----
  r.get('/api/v1/admin/tls-policies', () => store(state).policies.map((p, _i, all) => policyView(p, all)));
  r.get('/api/v1/admin/tls-policies/:id', (ctx) => {
    const p = store(state).policies.find((x) => x.id === ctx.params.id);
    if (!p) throw new HttpError(404, 'not_found', 'TLS policy not found.');
    return policyView(p, store(state).policies);
  });
  r.post('/api/v1/admin/tls-policies', (ctx) => {
    const b = ctx.body || {};
    const s = store(state);
    let pattern = '';
    validate((fail) => {
      if (s.policies.length >= MAX_POLICIES) fail('domainPattern', `At most ${MAX_POLICIES} TLS policies.`);
      const p = normalizePattern(b.domainPattern);
      if (p === null) fail('domainPattern', 'Use a domain name, "*.suffix" for every subdomain at any depth (not the domain itself), or "*" for every destination.');
      else if (s.policies.some((x) => x.domainPattern === p)) fail('domainPattern', 'A policy for this pattern already exists.');
      else pattern = p;
      if (!LEVELS.includes(String(b.level ?? '').toLowerCase())) fail('level', `Must be one of: ${LEVELS.join(', ')}.`);
      if (pattern === '*' && String(b.level).toLowerCase() === 'none' && b.acknowledgeInsecure !== true) fail('acknowledgeInsecure', ACK_TEXT);
    });
    const policy = { id: newId(), domainPattern: pattern, level: String(b.level).toLowerCase() };
    s.policies.push(policy);
    return { status: 201, body: policyView(policy, s.policies) };
  });
  r.patch('/api/v1/admin/tls-policies/:id', (ctx) => {
    const s = store(state);
    const policy = s.policies.find((x) => x.id === ctx.params.id);
    if (!policy) throw new HttpError(404, 'not_found', 'TLS policy not found.');
    const b = ctx.body || {};
    const next = { ...policy };
    validate((fail) => {
      if (b.domainPattern !== undefined) {
        const p = normalizePattern(b.domainPattern);
        if (p === null) fail('domainPattern', 'Use a domain name, "*.suffix" for every subdomain at any depth (not the domain itself), or "*" for every destination.');
        else if (s.policies.some((x) => x.id !== policy.id && x.domainPattern === p)) fail('domainPattern', 'A policy for this pattern already exists.');
        else next.domainPattern = p;
      }
      if (b.level !== undefined) {
        if (!LEVELS.includes(String(b.level).toLowerCase())) fail('level', `Must be one of: ${LEVELS.join(', ')}.`);
        else next.level = String(b.level).toLowerCase();
      }
      if ((b.domainPattern !== undefined || b.level !== undefined) && next.domainPattern === '*' && next.level === 'none' && b.acknowledgeInsecure !== true) fail('acknowledgeInsecure', ACK_TEXT);
    });
    Object.assign(policy, next);
    return policyView(policy, s.policies);
  });
  r.delete('/api/v1/admin/tls-policies/:id', (ctx) => {
    const s = store(state);
    const i = s.policies.findIndex((x) => x.id === ctx.params.id);
    if (i < 0) throw new HttpError(404, 'not_found', 'TLS policy not found.');
    s.policies.splice(i, 1);
    return undefined;
  });
}
