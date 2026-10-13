import fs from 'node:fs';
import path from 'node:path';
import { ApiClient } from './support/apiClient.mjs';
import { test as base, expect, ADMIN_PASSWORD, ADMIN_USER, createRecipientDomain, createVerifiedDomain, sendViaApi, signInThroughForm, unique } from './support/fixtures.mjs';
import { provisionPostgres } from './support/postgres.mjs';
import { startStack } from './support/stack.mjs';

const PASSPHRASE = 'e2e-bundle-passphrase-123';

// The API only switches between backends (SQLite and PostgreSQL), so the target of these tests is a real PostgreSQL: the server from
// EGGMAIL_TEST_POSTGRES (CI) or a throwaway local cluster. Without either the whole file is skipped, with the reason.
let postgres = null;
let skipReason = '';
base.beforeAll(async () => {
  postgres = await provisionPostgres();
  // In CI a missing PostgreSQL is a broken job, not a reason to skip the switch tests.
  if (!postgres && process.env.CI) throw new Error('CI provides EGGMAIL_TEST_POSTGRES, but psql or the server is not usable.');
  if (!postgres) skipReason = 'No PostgreSQL available: set EGGMAIL_TEST_POSTGRES or install initdb, postgres and psql (EGGMAIL_TEST_PG_BIN).';
});
base.afterAll(async () => {
  await postgres?.stop();
});

// The switch fences the server it runs on, so every test gets a server (and a database) of its own instead of the shared one.
const test = base.extend({
  extraServerArgs: [[], { option: true }],
  ownStack: async ({ extraServerArgs }, use, testInfo) => {
    testInfo.skip(!postgres, skipReason);
    const connectionString = postgres.createDatabase();
    const stack = await startStack({ name: 'switch', switchConnections: { pg: connectionString }, extraArgs: extraServerArgs });
    stack.postgresConnectionString = connectionString;
    await use(stack);
    await stack.stop();
  },
});

/** Data that a switch must carry: a tenant with a verified domain, a suppression, an API key and a delivered message. */
async function seed(stack) {
  const admin = await new ApiClient(stack.baseURL).signIn(ADMIN_USER, ADMIN_PASSWORD);
  const tenant = await admin.ok('POST', '/api/v1/admin/tenants', { name: unique('Switch tenant ') });
  const domain = await createVerifiedDomain(admin, stack, tenant);
  const recipientDomain = createRecipientDomain(stack);
  const key = (await admin.ok('POST', '/api/v1/api-keys', { name: 'carried key', scopes: ['send', 'read'] }, { tenantId: tenant.id })).key;
  const webhook = await admin.ok('POST', '/api/v1/webhooks', { url: 'https://hooks.example.test/carried', event_types: ['message.delivered'] }, { tenantId: tenant.id }).catch(() => null);
  await admin.ok('POST', '/api/v1/suppressions', { address: `carried@${recipientDomain}`, reason: 'manual' }, { tenantId: tenant.id });
  const subject = unique('Carried message ');
  const sent = await sendViaApi(stack, key, { from: `hello@${domain.name}`, to: [`someone@${recipientDomain}`], subject, text: 'before the switch' });
  expect(sent.status).toBe(202);
  await expect.poll(async () => (await admin.ok('GET', `/api/v1/messages?subject=${encodeURIComponent(subject)}`, undefined, { tenantId: tenant.id })).items[0]?.status, { timeout: 60_000 }).toBe('delivered');
  return { admin, tenant, domain, key, subject, recipientDomain, webhook };
}

/** Runs the wizard from the first step to the verification report. */
async function startSwitchToPostgres(page, baseURL) {
  await page.goto(`${baseURL}/admin/storage`);
  await expect(page.getByRole('heading', { name: 'Storage switch', exact: true })).toBeVisible();
  await expect(page.getByTestId('direction')).toContainText('SQLite to PostgreSQL');

  await page.getByLabel('Connection name').fill('pg');
  await page.getByLabel('Passphrase', { exact: true }).fill(PASSPHRASE);
  await page.getByLabel('Repeat passphrase').fill(PASSPHRASE);
  await page.getByRole('button', { name: 'Run preflight checks' }).click();

  await expect(page.getByText('Preflight passed')).toBeVisible();
  await expect(page.getByRole('table', { name: 'Preflight checks' }).getByRole('row')).not.toHaveCount(1);
  await page.getByRole('button', { name: 'Continue' }).click();

  await page.getByLabel('Type "switch to postgres" to confirm').fill('switch to postgres');
  await page.getByRole('button', { name: 'Start switch' }).click();
  await expect(page.getByText('verification passed')).toBeVisible({ timeout: 180_000 });
}

const signInCookie = async (context, stack) => {
  const admin = await new ApiClient(stack.baseURL).signIn(ADMIN_USER, ADMIN_PASSWORD);
  await context.addCookies([{ name: 'eggmail_session', value: admin.sessionCookieValue, url: stack.baseURL, httpOnly: true, sameSite: 'Strict' }]);
  return admin;
};

test.describe('storage switch wizard (SQLite to PostgreSQL)', () => {
  test.setTimeout(420_000);

  test('the wizard refuses bad input and starts nothing without the typed phrase', async ({ ownStack: stack, page, context }) => {
    const admin = await signInCookie(context, stack);
    await page.goto(`${stack.baseURL}/admin/storage`);

    // Client-side validation: nothing is sent.
    await page.getByRole('button', { name: 'Run preflight checks' }).click();
    await expect(page.getByText('Enter a host, or a connection name instead.')).toBeVisible();
    await expect(page.getByText('Use at least 12 characters.')).toBeVisible();

    // A connection name the deployment does not define is refused by the server, with its message.
    await page.getByLabel('Connection name').fill('no-such-connection');
    await page.getByLabel('Passphrase', { exact: true }).fill(PASSPHRASE);
    await page.getByLabel('Repeat passphrase').fill(PASSPHRASE);
    await page.getByRole('button', { name: 'Run preflight checks' }).click();
    await expect(page.getByRole('alert').filter({ hasText: 'Preflight could not run' })).toContainText('no-such-connection');
    expect((await admin.ok('GET', '/api/v1/admin/storage/switch')).state).toBe('none');

    // With a good target the Start button stays disabled until the phrase is typed exactly.
    await page.getByLabel('Connection name').fill('pg');
    await page.getByRole('button', { name: 'Run preflight checks' }).click();
    await page.getByRole('button', { name: 'Continue' }).click();
    await expect(page.getByRole('button', { name: 'Start switch' })).toBeDisabled();
    await page.getByLabel('Type "switch to postgres" to confirm').fill('switch to sqlite');
    await expect(page.getByRole('button', { name: 'Start switch' })).toBeDisabled();
    await page.getByRole('button', { name: 'Back' }).click();
    await page.getByRole('button', { name: 'Back' }).click();
    await expect(page.getByRole('heading', { name: '1. Choose the switch' })).toBeVisible();
    expect((await admin.ok('GET', '/api/v1/admin/storage/switch')).state).toBe('none');
  });

  test('rolling back after verification resumes the source with all of its data', async ({ ownStack: stack, page, context }) => {
    const data = await seed(stack);
    await context.addCookies([{ name: 'eggmail_session', value: data.admin.sessionCookieValue, url: stack.baseURL, httpOnly: true, sameSite: 'Strict' }]);
    await startSwitchToPostgres(page, stack.baseURL);

    // The report lists the tables with expected and actual counts.
    const report = page.getByRole('table', { name: /Row counts per table/ });
    await expect(report.getByRole('row').filter({ hasText: 'match' }).first()).toBeVisible();
    await expect(report.getByText('differs')).toHaveCount(0);
    await expect(page.getByText('checksums match')).toBeVisible();
    // The source is fenced while the switch is open: it no longer accepts mail.
    const refused = await sendViaApi(stack, data.key, { from: `hello@${data.domain.name}`, to: [`late@${data.recipientDomain}`], subject: 'during the switch', text: 'x' });
    expect([503, 421]).toContain(refused.status);

    await page.getByRole('button', { name: 'Roll back' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Roll back' }).click();
    await expect(page.getByText('The last switch was rolled back')).toBeVisible();

    // The source works again, with everything it had.
    const after = await sendViaApi(stack, data.key, { from: `hello@${data.domain.name}`, to: [`again@${data.recipientDomain}`], subject: unique('After rollback '), text: 'x' });
    expect(after.status).toBe(202);
    const messages = await data.admin.ok('GET', `/api/v1/messages?subject=${encodeURIComponent(data.subject)}`, undefined, { tenantId: data.tenant.id });
    expect(messages.items).toHaveLength(1);
    const suppressions = await data.admin.ok('GET', '/api/v1/suppressions', undefined, { tenantId: data.tenant.id });
    expect(suppressions.items.map((s) => s.address)).toContain(`carried@${data.recipientDomain}`);
    expect((await data.admin.ok('GET', '/api/v1/admin/storage/switch')).state).toBe('rolled_back');
  });

  test('a full switch: verify, confirm, activate (bootstrap file), restart on PostgreSQL, finalize; the data came along', async ({ ownStack: stack, page, context }) => {
    const data = await seed(stack);
    await context.addCookies([{ name: 'eggmail_session', value: data.admin.sessionCookieValue, url: stack.baseURL, httpOnly: true, sameSite: 'Strict' }]);
    await startSwitchToPostgres(page, stack.baseURL);

    await page.getByRole('button', { name: 'Confirm the verified target' }).click();
    await expect(page.getByRole('heading', { name: '6. Activate the target' })).toBeVisible();

    // Nothing in the deployment supplies the storage pointer (only the data directory is given), so activation writes the bootstrap file.
    await expect(page.getByText('Bootstrap-file deployment')).toBeVisible();
    await expect(page.getByText('Orchestrator-managed deployment')).toHaveCount(0);
    await page.getByRole('button', { name: 'Activate the target' }).click();
    await expect(page.getByRole('heading', { name: '7. Finalize' })).toBeVisible();
    await expect(page.getByText('Rollback is no longer available')).toBeVisible();
    await expect(page.getByTestId('activation-note')).toContainText('bootstrap');
    const bootstrap = path.join(stack.dataDir, 'bootstrap.json');
    expect(fs.existsSync(bootstrap)).toBe(true);
    expect(JSON.parse(fs.readFileSync(bootstrap, 'utf8')).Storage.Backend).toBe('Postgres');
    // The passphrase of the bundle is never written next to it.
    expect(fs.readFileSync(bootstrap, 'utf8')).not.toContain(PASSPHRASE);

    // The operator restarts the application: it comes up on PostgreSQL, and the target becomes active.
    await stack.restart();
    await page.context().clearCookies();
    await signInThroughForm(page, stack.baseURL);
    await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
    await expect(page.getByTestId('backend-info')).toContainText('storage: postgres');
    await page.goto(`${stack.baseURL}/admin/storage`);
    await expect(page.getByRole('heading', { name: '7. Finalize' })).toBeVisible();

    // Everything arrived: tenant, domain, key, suppression and the message history; new mail is accepted and delivered.
    const moved = await new ApiClient(stack.baseURL).signIn(ADMIN_USER, ADMIN_PASSWORD);
    expect((await moved.ok('GET', '/api/v1/admin/tenants')).map((t) => t.id)).toContain(data.tenant.id);
    expect((await moved.ok('GET', '/api/v1/domains', undefined, { tenantId: data.tenant.id })).map((d) => d.name)).toContain(data.domain.name);
    expect((await moved.ok('GET', '/api/v1/suppressions', undefined, { tenantId: data.tenant.id })).items.map((s) => s.address)).toContain(`carried@${data.recipientDomain}`);
    const history = await moved.ok('GET', `/api/v1/messages?subject=${encodeURIComponent(data.subject)}`, undefined, { tenantId: data.tenant.id });
    expect(history.items).toHaveLength(1);
    expect(history.items[0].status).toBe('delivered');
    const fresh = unique('After the switch ');
    expect((await sendViaApi(stack, data.key, { from: `hello@${data.domain.name}`, to: [`new@${data.recipientDomain}`], subject: fresh, text: 'x' })).status).toBe(202);
    await expect.poll(async () => (await moved.ok('GET', `/api/v1/messages?subject=${encodeURIComponent(fresh)}`, undefined, { tenantId: data.tenant.id })).items[0]?.status, { timeout: 60_000 }).toBe('delivered');

    // The restarted server does not know where the old store was, and says what to do instead of "storage unavailable".
    await expect(page.getByText('The source (SQLite) is fenced and read-only.')).toBeVisible();
    await page.getByRole('button', { name: 'Finalize the switch' }).click();
    await expect(page.getByRole('alert')).toContainText('mta migrate-storage finalize');

    // With the former source described (SwitchSource:*) finalize works from the dashboard. It is a separate, explicit click, and
    // EggMail never deletes the old data.
    await stack.restart(`--SwitchSource:Sqlite:DataDirectory=${stack.dataDir}`);
    await page.reload();
    await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
    await page.getByRole('button', { name: 'Finalize the switch' }).click();
    await expect(page.getByText('Switch finalized')).toBeVisible();
    expect(fs.existsSync(path.join(stack.dataDir, 'config.db'))).toBe(true);
    await page.getByRole('button', { name: 'Plan another switch' }).click();
    await expect(page.getByRole('heading', { name: '1. Choose the switch' })).toBeVisible();
  });

  test.describe('a deployment that pins the storage pointer', () => {
    test.use({ extraServerArgs: ['--Storage:Backend=Sqlite'] });

    test('gets a cutover patch to apply instead of a rewritten bootstrap file, without any secret in it', async ({ ownStack: stack, page, context }) => {
      await signInCookie(context, stack);
      await startSwitchToPostgres(page, stack.baseURL);
      await page.getByRole('button', { name: 'Confirm the verified target' }).click();

      // The page says so before activation, because the server knows the pointer is supplied by the command line.
      await expect(page.getByText('Orchestrator-managed deployment')).toBeVisible();
      await expect(page.getByText('Bootstrap-file deployment')).toHaveCount(0);
      await page.getByRole('button', { name: 'Activate the target' }).click();
      await expect(page.getByRole('heading', { name: '7. Finalize' })).toBeVisible();
      const patch = page.getByTestId('cutover-patch');
      await expect(patch).toBeVisible();
      await expect(patch).toContainText('Postgres');
      await expect(patch).not.toContainText(PASSPHRASE);
      // The connection string is referenced by secret name, never printed (the password itself may be a common word, so look for the string).
      await expect(patch).not.toContainText(stack.postgresConnectionString);
      await expect(patch).not.toContainText(/Password=/i);
      expect(fs.existsSync(path.join(stack.dataDir, 'bootstrap.json'))).toBe(false);
    });
  });
});
