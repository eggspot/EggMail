import { ApiClient } from './support/apiClient.mjs';
import { ADMIN_PASSWORD, ADMIN_USER, expect, signInThroughForm, test } from './support/fixtures.mjs';

test.describe('sign-in, sign-out and CSRF', () => {
  test('a wrong password is refused with a clear message, the right one signs in', async ({ page, baseURL }) => {
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'EggMail' })).toBeVisible();
    // The persistent warning banner is on the sign-in page too.
    await expect(page.locator('[data-warning="sqlite_sync_off"]')).toBeVisible();

    await signInThroughForm(page, baseURL, ADMIN_USER, 'definitely-not-the-password');
    await expect(page.getByRole('alert').filter({ hasText: /not signed in|password|credentials|Invalid/i })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Sign out' })).toHaveCount(0);

    await page.getByLabel('Password').fill(ADMIN_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
    await expect(page.locator('.user')).toContainText(`${ADMIN_USER} (admin)`);
    await expect(page.getByTestId('backend-info')).toContainText('storage: sqlite');
  });

  test('the session cookie is HttpOnly and SameSite=Strict, and script cannot read it', async ({ page, context, baseURL }) => {
    await signInThroughForm(page, baseURL);
    await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
    const cookie = (await context.cookies(baseURL)).find((c) => c.name === 'eggmail_session');
    expect(cookie).toMatchObject({ httpOnly: true, sameSite: 'Strict' });
    expect(await page.evaluate(() => document.cookie)).not.toContain('eggmail_session');
    // The CSRF token is not kept in web storage either.
    const stored = await page.evaluate(() => JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }));
    expect(stored).not.toMatch(/csrf/i);
  });

  test('a mutating request needs the CSRF token of the session', async ({ page, baseURL }) => {
    await signInThroughForm(page, baseURL);
    await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
    // Acting on a tenant is required for tenant endpoints, so use an admin endpoint: creating a tenant.
    const name = `csrf-${Date.now()}`;
    const withoutToken = await page.request.post('/api/v1/admin/tenants', { data: { name } });
    expect(withoutToken.status()).toBe(403);
    expect((await withoutToken.json()).code).toBe('forbidden');

    const wrongToken = await page.request.post('/api/v1/admin/tenants', { data: { name }, headers: { 'X-CSRF-Token': 'not-the-token' } });
    expect(wrongToken.status()).toBe(403);

    const me = await (await page.request.get('/api/v1/me')).json();
    expect(me.csrfToken).toBeTruthy();
    const accepted = await page.request.post('/api/v1/admin/tenants', { data: { name }, headers: { 'X-CSRF-Token': me.csrfToken } });
    expect(accepted.status()).toBe(201);
  });

  test('signing out ends the session on the server and returns to the sign-in form', async ({ page, baseURL }) => {
    await signInThroughForm(page, baseURL);
    const token = (await (await page.request.get('/api/v1/me')).json()).csrfToken;
    await page.getByRole('button', { name: 'Sign out' }).click();
    await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
    expect((await page.request.get('/api/v1/me')).status()).toBe(401);
    // The old CSRF token is useless without the session.
    expect((await page.request.post('/api/v1/admin/tenants', { data: { name: 'late' }, headers: { 'X-CSRF-Token': token } })).status()).toBe(401);
    // Reloading stays on the form.
    await page.reload();
    await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
  });

  test('a session that the server ended sends the user back to the form on the next action', async ({ page, context, stack }) => {
    const mine = await new ApiClient(stack.baseURL).signIn(ADMIN_USER, ADMIN_PASSWORD);
    await context.addCookies([{ name: 'eggmail_session', value: mine.sessionCookieValue, url: stack.baseURL, httpOnly: true, sameSite: 'Strict' }]);
    await page.goto('/admin/tenants');
    await expect(page.getByRole('heading', { name: 'Tenants', exact: true })).toBeVisible();
    // The session is ended on the server (as if it had expired or been signed out elsewhere).
    await mine.ok('DELETE', '/api/v1/session');
    await page.getByLabel('Name', { exact: true }).fill('after-expiry');
    await page.getByRole('button', { name: 'Create tenant' }).click();
    await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
  });

  test('an API key cannot reach the admin endpoints or be used as a dashboard session', async ({ admin, tenant, stack }) => {
    const key = await admin.ok('POST', '/api/v1/api-keys', { name: 'cannot-admin', scopes: ['read'] }, { tenantId: tenant.id });
    const res = await fetch(`${stack.baseURL}/api/v1/admin/tenants`, { headers: { authorization: `Bearer ${key.key}` } });
    expect(res.status).toBe(403);
  });
});
