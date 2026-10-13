import { ApiClient } from './support/apiClient.mjs';
import { test as base, expect, ADMIN_PASSWORD, ADMIN_USER, signInThroughForm, unique } from './support/fixtures.mjs';
import { startStack } from './support/stack.mjs';

const ALICE = { user: 'alice', password: 'alice-long-password-1', tenantName: 'Alice Corp' };
const BOB = { user: 'bob', password: 'bob-long-password-22', tenantName: 'Bob Ltd' };

// A server with two tenant accounts. `mta admin create --role tenant` needs the tenant to exist and the data directory to be free,
// so the stack starts the server, creates the tenants, stops it, creates the accounts and starts it again.
const test = base.extend({
  accounts: [
    async ({}, use) => {
      const stack = await startStack({ name: 'tenant-users', tenantUsers: [ALICE, BOB] });
      await use(stack);
      await stack.stop();
    },
    { scope: 'worker', timeout: 240_000 },
  ],
});

test.describe('a tenant account', () => {
  test('sees only its own tenant: no administration, no tenant picker, no global settings', async ({ accounts: stack, page }) => {
    await page.goto(`${stack.baseURL}/`);
    await signInThroughForm(page, stack.baseURL, ALICE.user, ALICE.password);
    await expect(page.locator('.user')).toContainText('alice (tenant)');
    await expect(page.getByLabel('Acting on tenant')).toHaveCount(0);

    const nav = page.getByRole('navigation', { name: 'Main' });
    await expect(nav.getByRole('link', { name: 'Domains' })).toBeVisible();
    for (const admin of ['Tenants', 'Server status', 'Certificates', 'Storage switch']) await expect(nav.getByRole('link', { name: admin })).toHaveCount(0);

    // Typing an administrator URL gives an explanation, not data or an error banner.
    for (const route of ['/admin/tenants', '/admin/status', '/admin/certificates', '/admin/storage']) {
      await page.goto(`${stack.baseURL}${route}`);
      await expect(page.getByText('Administrators only')).toBeVisible();
    }

    // The server refuses the same requests on its own.
    const me = await new ApiClient(stack.baseURL).signIn(ALICE.user, ALICE.password);
    for (const path of ['/api/v1/admin/tenants', '/api/v1/admin/status', '/api/v1/admin/settings', '/api/v1/admin/storage/switch', '/api/v1/admin/certificates']) {
      const r = await me.request('GET', path);
      expect([r.status, r.body?.code]).toEqual([403, 'forbidden']);
    }

    // Settings: the tenant's own, and the administrator-only ones cannot be changed by the tenant.
    await page.goto(`${stack.baseURL}/settings`);
    await expect(page.getByRole('form', { name: 'Tenant settings' })).toBeVisible();
    await expect(page.getByRole('form', { name: 'Global settings' })).toHaveCount(0);
    const allowlist = page.getByLabel('Webhooks:AllowedNetworks');
    await expect(allowlist).toHaveAttribute('readonly', '');
    await expect(page.locator('.setting').filter({ has: allowlist })).toContainText('Only an administrator can change this.');
    // The server refuses the change on its own, whatever the page offers.
    const refused = await me.request('PUT', '/api/v1/settings', { values: { 'Webhooks:AllowedNetworks': '10.0.0.0/8' } });
    expect(refused.status).toBeGreaterThanOrEqual(400);
    expect(refused.status).toBeLessThan(500);
    await page.reload();
    await expect(page.getByLabel('Webhooks:AllowedNetworks')).toHaveValue('');
  });

  test('works with its own data, and cannot see or touch another tenant', async ({ accounts: stack, browser }) => {
    const aliceContext = await browser.newContext();
    const alicePage = await aliceContext.newPage();
    await signInThroughForm(alicePage, stack.baseURL, ALICE.user, ALICE.password);
    await expect(alicePage.getByRole('button', { name: 'Sign out' })).toBeVisible();

    const domainName = `${unique('alice')}.mail.test`;
    await alicePage.goto(`${stack.baseURL}/domains`);
    await alicePage.getByLabel('Domain name').fill(domainName);
    await alicePage.getByRole('button', { name: 'Add domain' }).click();
    await expect(alicePage.getByRole('heading', { name: domainName, exact: true })).toBeVisible();
    const domainId = /\/domains\/([0-9a-f]{32})$/.exec(alicePage.url())[1];

    const aliceKeyName = unique('alice key ');
    await alicePage.goto(`${stack.baseURL}/credentials`);
    await alicePage.getByLabel('Key name').fill(aliceKeyName);
    await alicePage.getByRole('button', { name: 'Create API key' }).click();
    await alicePage.getByRole('alertdialog').getByRole('button', { name: 'I have saved it' }).click();
    await expect(alicePage.getByRole('row').filter({ hasText: aliceKeyName })).toBeVisible();

    // Bob has nothing of Alice's, in the dashboard and in the API (not even the fact that it exists).
    const bobContext = await browser.newContext();
    const bobPage = await bobContext.newPage();
    await signInThroughForm(bobPage, stack.baseURL, BOB.user, BOB.password);
    await expect(bobPage.getByRole('button', { name: 'Sign out' })).toBeVisible();
    await bobPage.goto(`${stack.baseURL}/domains`);
    await expect(bobPage.getByText('No domains yet')).toBeVisible();
    await bobPage.goto(`${stack.baseURL}/domains/${domainId}`);
    await expect(bobPage.getByText('Domain not found')).toBeVisible();
    await bobPage.goto(`${stack.baseURL}/credentials`);
    await expect(bobPage.getByRole('row').filter({ hasText: aliceKeyName })).toHaveCount(0);

    const bob = await new ApiClient(stack.baseURL).signIn(BOB.user, BOB.password);
    expect((await bob.request('GET', `/api/v1/domains/${domainId}`)).status).toBe(404);
    expect((await bob.request('DELETE', `/api/v1/domains/${domainId}`)).status).toBe(404);
    const admin = await new ApiClient(stack.baseURL).signIn(ADMIN_USER, ADMIN_PASSWORD);
    const aliceTenant = (await admin.ok('GET', '/api/v1/admin/tenants')).find((t) => t.name === ALICE.tenantName);
    // Naming Alice's tenant in X-Tenant-Id does not get Bob anywhere.
    expect((await bob.request('GET', '/api/v1/domains', undefined, { tenantId: aliceTenant.id })).status).toBe(403);

    await aliceContext.close();
    await bobContext.close();
  });

  test('a suspended tenant is told why, and everything works again once it is activated', async ({ accounts: stack, browser }) => {
    const admin = await new ApiClient(stack.baseURL).signIn(ADMIN_USER, ADMIN_PASSWORD);
    const bobTenant = (await admin.ok('GET', '/api/v1/admin/tenants')).find((t) => t.name === BOB.tenantName);
    const context = await browser.newContext();
    const page = await context.newPage();
    await signInThroughForm(page, stack.baseURL, BOB.user, BOB.password);
    await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();

    await admin.ok('PATCH', `/api/v1/admin/tenants/${bobTenant.id}`, { status: 'suspended' });
    await page.goto(`${stack.baseURL}/domains`);
    await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
    await expect(page.getByRole('status').filter({ hasText: 'tenant is suspended' })).toBeVisible();
    // Signing in again says the same.
    await page.getByLabel('User').fill(BOB.user);
    await page.getByLabel('Password').fill(BOB.password);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.locator('main .notice-bad')).toBeVisible(); // refused while suspended

    await admin.ok('PATCH', `/api/v1/admin/tenants/${bobTenant.id}`, { status: 'active' });
    await page.getByLabel('Password').fill(BOB.password);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
    await page.goto(`${stack.baseURL}/domains`);
    await expect(page.getByRole('heading', { name: 'Add a domain' })).toBeVisible();
    await context.close();
  });
});
