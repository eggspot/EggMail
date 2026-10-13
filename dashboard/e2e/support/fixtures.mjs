import { test as base, expect } from '@playwright/test';
import { ApiClient } from './apiClient.mjs';
import { ADMIN_PASSWORD, ADMIN_USER, startStack } from './stack.mjs';

export { expect, ADMIN_PASSWORD, ADMIN_USER };

let counter = 0;
/** A short unique token for names (tenants, domains, users), so specs never collide on the shared server. */
export const unique = (prefix = 'e2e') => `${prefix}${Date.now().toString(36)}${(counter++).toString(36)}`;

/** Publishes the records a domain asks for into the fake DNS. `except` lists purposes to leave out, `wrongDkim` publishes a different key. */
export function publishDomainRecords(dns, domain, { except = [], wrongDkim = false, only } = {}) {
  for (const record of domain.records) {
    if (except.includes(record.purpose) || (only && !only.includes(record.purpose))) continue;
    if (record.type === 'CNAME') dns.setCname(record.host, record.value);
    else if (record.purpose === 'dkim' && wrongDkim) dns.setTxt(record.host, 'v=DKIM1; k=rsa; p=' + 'A'.repeat(380));
    else dns.setTxt(record.host, record.value);
  }
}

/** Registers a domain for the tenant, publishes its required DNS records and verifies it, so mail can be sent from it. */
export async function createVerifiedDomain(admin, stack, tenant, prefix = 'send') {
  const domain = await admin.ok('POST', '/api/v1/domains', { name: `${unique(prefix)}.mail.test` }, { tenantId: tenant.id });
  publishDomainRecords(stack.dns, domain, { except: ['spf', 'dmarc'] });
  const verified = await admin.ok('POST', `/api/v1/domains/${domain.id}/verify`, undefined, { tenantId: tenant.id });
  if (verified.status !== 'verified') throw new Error(`the domain did not verify: ${JSON.stringify(verified)}`);
  return verified;
}

/** A recipient domain whose MX is the SMTP sink on loopback. */
export function createRecipientDomain(stack, prefix = 'rcpt') {
  const name = `${unique(prefix)}.recipients.test`;
  stack.dns.setMx(name, `mx.${name}`);
  stack.dns.setA(`mx.${name}`, '127.0.0.1');
  return name;
}

/** Sends through the HTTP API with a bearer key and returns `{ status, body }`. */
export async function sendViaApi(stack, key, message) {
  const response = await fetch(`${stack.baseURL}/api/v1/messages`, {
    method: 'POST',
    headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' },
    body: JSON.stringify(message),
  });
  return { status: response.status, body: await response.json() };
}

export const test = base.extend({
  // One real server (and its fakes) per worker.
  stack: [
    async ({}, use) => {
      const stack = await startStack();
      await use(stack);
      await stack.stop();
    },
    { scope: 'worker', timeout: 180_000 },
  ],

  baseURL: async ({ stack }, use) => {
    await use(stack.baseURL);
  },

  // An API client signed in as the administrator, for set-up and for checks that bypass the UI.
  admin: [
    async ({ stack }, use) => {
      await use(await new ApiClient(stack.baseURL).signIn(ADMIN_USER, ADMIN_PASSWORD));
    },
    { scope: 'worker' },
  ],

  // A fresh tenant per test, created through the API.
  tenant: async ({ admin }, use) => {
    const name = unique('Tenant ');
    const tenant = await admin.ok('POST', '/api/v1/admin/tenants', { name });
    await use(tenant);
  },

  // Console messages a test expects on purpose (RegExp list): for example the browser reporting that it blocked a hostile message's
  // remote image. Everything else still fails the test.
  allowProblems: async ({}, use) => {
    await use([]);
  },

  // Fails a test on page errors, console errors and any Content-Security-Policy violation. Failed requests that a test provokes
  // on purpose (401, 403, 404, 409, 429 ...) show up as "Failed to load resource" console lines and are not counted.
  problems: [
    async ({ page, allowProblems }, use) => {
      const problems = [];
      page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`));
      page.on('console', (m) => {
        const text = m.text();
        if (m.type() !== 'error' && m.type() !== 'warning') return;
        if (/Failed to load resource: the server responded with a status of [45]\d\d/.test(text)) return;
        // A message that carries a <script> proves the sandbox: the browser reports that it refused to run it.
        if (/Blocked script execution in 'about:srcdoc' because the document's frame is sandboxed/.test(text)) return;
        problems.push(`console.${m.type()}: ${text}`);
      });
      await page.addInitScript(() => {
        window.__cspViolations = [];
        document.addEventListener('securitypolicyviolation', (e) => window.__cspViolations.push(`${e.violatedDirective} blocked ${e.blockedURI || e.sample}`));
      });
      await use(problems);
      const violations = await page.evaluate(() => window.__cspViolations ?? []).catch(() => []);
      const unexpected = [...problems, ...violations.map((v) => `CSP violation: ${v}`)].filter((p) => !allowProblems.some((re) => re.test(p)));
      expect(unexpected, 'console errors, page errors and CSP violations').toEqual([]);
    },
    { auto: true },
  ],

  // The page signed in as the administrator, acting on the test's tenant.
  adminPage: async ({ page, context, stack, admin, tenant }, use) => {
    await context.addCookies([{ name: 'eggmail_session', value: admin.sessionCookieValue, url: stack.baseURL, httpOnly: true, sameSite: 'Strict' }]);
    await page.addInitScript((id) => {
      try {
        if (window === window.top && !sessionStorage.getItem('eggmail.tenant')) sessionStorage.setItem('eggmail.tenant', id);
      } catch { /* sandboxed frames have no storage */ }
    }, tenant.id);
    await use(page);
  },
});

/** Signs in through the form. */
export async function signInThroughForm(page, baseURL, user = ADMIN_USER, password = ADMIN_PASSWORD) {
  await page.goto(`${baseURL}/`);
  await page.getByLabel('User').fill(user);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
}
