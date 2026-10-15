import fs from 'node:fs';
import https from 'node:https';
import { expect, test } from '@playwright/test';
import { ApiClient } from './support/apiClient.mjs';
import { createRecipientDomain, createVerifiedDomain, unique } from './support/fixtures.mjs';
import { provisionPostgres } from './support/postgres.mjs';
import { submit } from './support/smtpClient.mjs';
import { NOTICE_BEGIN, startZeroConfigStack } from './support/zeroConfigStack.mjs';

// "Anyone uses the image, starts it, and has SMTP working with very simple configuration." These tests start the real, published host with NOTHING
// configured (see support/zeroConfigStack.mjs for the three harness settings a test machine needs) and prove it is usable: healthy, TLS on every
// port with the self-signed certificate, the dashboard reachable, the one-time administrator password from the log signs in, and mail submitted over
// SMTP (STARTTLS and implicit TLS) and through the API reaches the recipients' server. deploy/smoke/image.sh makes the same checks on the Docker image.

test.use({ ignoreHTTPSErrors: true });

/** GET over HTTPS accepting the self-signed certificate. */
function httpsGet(url) {
  return new Promise((resolve, reject) => {
    https
      .get(url, { rejectUnauthorized: false }, (response) => {
        const chunks = [];
        response.on('data', (c) => chunks.push(c));
        response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString('utf8'), headers: response.headers }));
      })
      .on('error', reject);
  });
}

function messageText({ from, to, subject }) {
  return `From: ${from}\r\nTo: ${to}\r\nSubject: ${subject}\r\nDate: ${new Date().toUTCString()}\r\nMessage-ID: <${unique('m')}@zero.test>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSent by the zero-configuration end-to-end test.\r\n`;
}

test.describe('a start with nothing configured', () => {
  test.describe.configure({ mode: 'serial' });
  let stack;
  let password;

  test.beforeAll(async () => {
    test.setTimeout(180_000);
    stack = await startZeroConfigStack();
    password = stack.oneTimePassword();
  });

  test.afterAll(async () => {
    await stack?.stop();
  });

  test('the process is healthy and made everything it needs: data directory, databases, certificate, administrator', async () => {
    expect((await fetch(`${stack.baseURL}/healthz`)).status).toBe(200);
    expect((await fetch(`${stack.baseURL}/readyz`)).status).toBe(200);
    const check = stack.cli('--healthcheck');
    expect(check.status, check.output).toBe(0);

    // The data directory did not exist: the server created it and the databases in it.
    expect(fs.readdirSync(stack.dataDir)).toEqual(expect.arrayContaining(['config.db', 'queue.db', 'history.db', 'stats.db']));

    // The self-signed certificate is announced in the log (a warning, at the start) and as a warning of the API.
    expect(stack.log()).toMatch(/Serving a SELF-SIGNED certificate/);
    const capabilities = await (await fetch(`${stack.baseURL}/api/v1/capabilities`)).json();
    expect(capabilities.warnings.map((w) => w.code)).toContain('self_signed_certificate');

    // The administrator password was generated and printed once, delimited, and it is not part of any structured log line.
    expect(password, 'the log has no one-time password notice').toMatch(/^[A-Za-z0-9_-]{20,}$/);
    expect(stack.log().split(password)).toHaveLength(2);
    expect(stack.log()).not.toMatch(/configuration error/);
  });

  test('STARTTLS and implicit TLS answer with the self-signed certificate on every submission port', async () => {
    const starttls = await submit({ port: stack.ports.submission, mode: 'starttls', send: false });
    expect(starttls.greeting.lines[0]).toMatch(/^220 /);
    expect(starttls.certificate.selfSigned).toBe(true);
    expect(['TLSv1.2', 'TLSv1.3']).toContain(starttls.certificate.protocol);
    expect(starttls.certificate.subjectAltName).toContain('DNS:');

    const alternate = await submit({ port: stack.ports.alternate, mode: 'starttls', send: false });
    expect(alternate.certificate.selfSigned).toBe(true);

    const implicit = await submit({ port: stack.ports.submissions, mode: 'implicit', send: false });
    expect(implicit.certificate.selfSigned).toBe(true);
    expect(implicit.certificate.subject).toBe(starttls.certificate.subject);
    expect(implicit.ehlo.lines.join(' ')).toMatch(/AUTH/);
  });

  test('the dashboard answers over HTTPS with the persistent self-signed banner, and the one-time password signs in', async ({ page }) => {
    const root = await httpsGet(`${stack.httpsURL}/`);
    expect(root.status).toBe(200);
    expect(root.headers['strict-transport-security']).toBeTruthy();
    expect((await httpsGet(`${stack.httpsURL}/healthz`)).status).toBe(200);

    await page.goto(`${stack.httpsURL}/`);
    await expect(page.getByRole('heading', { name: 'EggMail' })).toBeVisible();
    await expect(page.locator('[data-warning="self_signed_certificate"]')).toBeVisible(); // the banner is on the sign-in page too

    await page.getByLabel('User').fill('admin');
    await page.getByLabel('Password').fill(`${password}x`);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.getByRole('alert').filter({ hasText: 'The user name or password is not correct.' })).toBeVisible();

    await page.getByLabel('Password').fill(password);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
    await expect(page.locator('.user')).toContainText('admin (admin)');
    await expect(page.locator('[data-warning="self_signed_certificate"]')).toBeVisible(); // and on every page after sign-in
  });

  test('mail submitted over SMTP AUTH (STARTTLS and implicit TLS) and through the API is delivered to the recipients server, DKIM signed', async () => {
    const admin = await new ApiClient(stack.baseURL).signIn('admin', password);
    const tenant = await admin.ok('POST', '/api/v1/admin/tenants', { name: unique('Zero ') });
    const domain = await createVerifiedDomain(admin, stack, tenant, 'zero');   // the DKIM key was generated when the domain was added
    const recipientDomain = createRecipientDomain(stack);
    const username = `sender@${domain.name}`;
    const credential = await admin.ok('POST', '/api/v1/smtp-credentials', { username }, { tenantId: tenant.id });
    const apiKey = (await admin.ok('POST', '/api/v1/api-keys', { name: unique('zero '), scopes: ['send', 'read'] }, { tenantId: tenant.id })).key;

    const subjects = { starttls: unique('Zero STARTTLS '), implicit: unique('Zero implicit TLS '), api: unique('Zero API ') };
    const to = `alice@${recipientDomain}`;
    for (const [mode, port] of [['starttls', stack.ports.submission], ['implicit', stack.ports.submissions]]) {
      const sent = await submit({ port, mode, user: username, password: credential.password, from: username, to: [to], data: messageText({ from: username, to, subject: subjects[mode] }) });
      expect(sent.accepted.code).toBe(250);
      expect(sent.certificate.selfSigned).toBe(true);
    }

    const response = await fetch(`${stack.baseURL}/api/v1/messages`, {
      method: 'POST',
      headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' },
      body: JSON.stringify({ from: `Zero <hello@${domain.name}>`, to: [to], subject: subjects.api, text: 'Sent through the API by the zero-configuration test.' }),
    });
    expect(response.status).toBe(202);

    for (const subject of Object.values(subjects)) {
      await expect.poll(() => stack.sink.received.some((m) => m.data.includes(`Subject: ${subject}`)), { timeout: 60_000, message: `"${subject}" reached the sink` }).toBe(true);
      const received = stack.sink.received.find((m) => m.data.includes(`Subject: ${subject}`));
      expect(received.data).toMatch(new RegExp(`^DKIM-Signature:[^]*?\\bd=${domain.name.replaceAll('.', '\\.')};`, 'm'));
    }
  });

  test('a restart prints no password again, keeps the account and the data, and the server is healthy again', async () => {
    const admin = await new ApiClient(stack.baseURL).signIn('admin', password);
    const tenantsBefore = (await admin.ok('GET', '/api/v1/admin/tenants')).map((t) => t.name);

    await stack.restart();

    expect(stack.currentRunLog()).not.toContain(NOTICE_BEGIN);
    expect(stack.oneTimePassword()).toBe(password); // still exactly one notice in the whole log
    expect(stack.currentRunLog()).toMatch(/Serving a SELF-SIGNED certificate/);   // said again at every start while it is all there is
    const again = await new ApiClient(stack.baseURL).signIn('admin', password);
    expect((await again.ok('GET', '/api/v1/admin/tenants')).map((t) => t.name)).toEqual(tenantsBefore);
    expect(stack.cli('--healthcheck').status).toBe(0);
  });
});

test.describe('the simple environment variables', () => {
  test.describe.configure({ mode: 'serial' });
  let stack;

  test.beforeAll(async () => {
    test.setTimeout(180_000);
    stack = await startZeroConfigStack({
      name: 'simple',
      variables: {
        EGGMAIL_HOSTNAME: 'mail.zero.example',
        EGGMAIL_ADMIN_USER: 'owner',
        EGGMAIL_ADMIN_PASSWORD: 'chosen-by-the-operator-1',
        EGGMAIL_RELAY: 'smtp.relay.example:587',
      },
    });
  });

  test.afterAll(async () => {
    await stack?.stop();
  });

  test('the host name, the chosen administrator and the relay are used, and no password is generated or printed', async () => {
    expect(stack.oneTimePassword()).toBeNull();
    expect(stack.log()).not.toContain('chosen-by-the-operator-1');

    const starttls = await submit({ port: stack.ports.submission, mode: 'starttls', send: false });
    expect(starttls.greeting.lines[0]).toContain('mail.zero.example');           // the SMTP greeting names the configured host
    expect(starttls.certificate.subject).toBe('mail.zero.example');               // so does the first-run certificate
    expect(starttls.certificate.subjectAltName).toContain('DNS:mail.zero.example');
    expect(stack.log()).not.toMatch(/No host name is configured/);

    const admin = await new ApiClient(stack.baseURL).signIn('owner', 'chosen-by-the-operator-1');
    const routes = await admin.ok('GET', '/api/v1/admin/relay-routes');
    expect(routes).toHaveLength(1);
    expect(routes[0]).toMatchObject({ name: 'configuration-relay', host: 'smtp.relay.example', port: 587, tlsMode: 'verify', hasPassword: false, domains: ['*'] });
  });
});

test.describe('PostgreSQL with one extra variable', () => {
  // The server from EGGMAIL_TEST_POSTGRES (CI) or a throwaway local cluster; without either the test is skipped, with the reason (not in CI).
  let postgres = null;

  test.beforeAll(async () => {
    postgres = await provisionPostgres();
    if (!postgres && process.env.CI) throw new Error('CI provides EGGMAIL_TEST_POSTGRES, but psql or the server is not usable.');
  });

  test.afterAll(async () => {
    await postgres?.stop();
  });

  test('EGGMAIL_DATABASE alone selects PostgreSQL: generated administrator, working mail, nothing printed again after a restart', async () => {
    test.skip(!postgres, 'No PostgreSQL available: set EGGMAIL_TEST_POSTGRES or install initdb, postgres and psql (EGGMAIL_TEST_PG_BIN).');
    test.setTimeout(240_000);
    const stack = await startZeroConfigStack({ name: 'pg', variables: { EGGMAIL_DATABASE: postgres.createDatabase() } });
    try {
      const password = stack.oneTimePassword();
      expect(password).toMatch(/^[A-Za-z0-9_-]{20,}$/);
      const capabilities = await (await fetch(`${stack.baseURL}/api/v1/capabilities`)).json();
      expect(capabilities.backend).toBe('postgres');
      expect(capabilities.warnings.map((w) => w.code)).toEqual(expect.arrayContaining(['postgres_single_role', 'self_signed_certificate']));
      expect(fs.existsSync(stack.dataDir) ? fs.readdirSync(stack.dataDir).filter((f) => f.endsWith('.db')) : []).toEqual([]); // no SQLite files: the data is in PostgreSQL

      const admin = await new ApiClient(stack.baseURL).signIn('admin', password);
      const tenant = await admin.ok('POST', '/api/v1/admin/tenants', { name: unique('Pg ') });
      const domain = await createVerifiedDomain(admin, stack, tenant, 'pg');
      const apiKey = (await admin.ok('POST', '/api/v1/api-keys', { name: 'pg', scopes: ['send'] }, { tenantId: tenant.id })).key;
      const subject = unique('Zero PostgreSQL ');
      const to = `alice@${createRecipientDomain(stack)}`;
      const response = await fetch(`${stack.baseURL}/api/v1/messages`, {
        method: 'POST',
        headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' },
        body: JSON.stringify({ from: `Zero <hello@${domain.name}>`, to: [to], subject, text: 'PostgreSQL by one variable.' }),
      });
      expect(response.status).toBe(202);
      await expect.poll(() => stack.sink.received.some((m) => m.data.includes(`Subject: ${subject}`)), { timeout: 60_000 }).toBe(true);

      await stack.restart();
      expect(stack.currentRunLog()).not.toContain(NOTICE_BEGIN);
      expect(stack.oneTimePassword()).toBe(password);
      await new ApiClient(stack.baseURL).signIn('admin', password);
    } finally {
      await stack.stop();
    }
  });
});

test.describe('a combination that cannot work stops the start with a message that says what to set', () => {
  test('an ACME contact without a host name', async () => {
    const attempt = startZeroConfigStack({ name: 'refused', variables: { EGGMAIL_ACME_EMAIL: 'ops@example.com' } });
    await expect(attempt).rejects.toThrow(/EGGMAIL_ACME_EMAIL needs EGGMAIL_HOSTNAME/);
  });

  test('a database value that is not a connection string', async () => {
    const attempt = startZeroConfigStack({ name: 'refused', variables: { EGGMAIL_DATABASE: 'not a connection string' } });
    await expect(attempt).rejects.toThrow(/EGGMAIL_DATABASE: /);
  });
});
