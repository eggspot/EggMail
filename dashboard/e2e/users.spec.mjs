import { ApiClient } from './support/apiClient.mjs';
import { ADMIN_USER, expect, signInThroughForm, test, unique } from './support/fixtures.mjs';

const PASSWORD = 'first-long-password-1';
const NEXT_PASSWORD = 'second-long-password-2';

const userRow = (page, name) => page.getByRole('row').filter({ has: page.getByRole('rowheader', { name, exact: false }) });

/** A tenant user created through the API (set-up), with a known password. */
async function createTenantUser(admin, tenant, prefix = 'user') {
  const userName = unique(prefix);
  const user = await admin.ok('POST', '/api/v1/admin/users', { userName, role: 'tenant', tenantId: tenant.id, password: PASSWORD });
  return { userName, id: user.id };
}

test.describe('user management', () => {
  test('an administrator creates a user in the dashboard; the user signs in with the generated password', async ({ adminPage: page, browser, stack, tenant }) => {
    await page.goto('/admin/users');
    await expect(page.getByRole('heading', { name: 'Users', exact: true })).toBeVisible();
    const userName = unique('created');

    // Validation happens before anything is sent.
    await page.getByRole('button', { name: 'Create user' }).click();
    await expect(page.getByText('Enter a user name.')).toBeVisible();
    await expect(page.getByText('Choose the tenant this user belongs to.')).toBeVisible();

    await page.getByLabel('User name').fill(userName);
    await page.getByLabel('Tenant', { exact: true }).selectOption({ label: tenant.name });
    await page.getByRole('button', { name: 'Create user' }).click();
    await expect(page.getByText(`User ${userName} created.`)).toBeVisible();
    const generated = (await page.getByTestId('secret-value').textContent()).trim();
    expect(generated.length).toBeGreaterThanOrEqual(10);
    await page.getByRole('button', { name: 'I have saved it' }).click();
    await expect(page.getByTestId('secret-value')).toHaveCount(0);

    const row = userRow(page, userName);
    await expect(row).toContainText('tenant user');
    await expect(row).toContainText(tenant.name);
    await expect(row).toContainText('enabled');
    // The password is not part of the page any more, and a reload does not bring it back.
    await page.reload();
    await expect(page.getByText(generated)).toHaveCount(0);

    // A taken name is refused under the field (names are not case sensitive).
    await page.getByLabel('User name').fill(userName.toUpperCase());
    await page.getByLabel('Tenant', { exact: true }).selectOption({ label: tenant.name });
    await page.getByRole('button', { name: 'Create user' }).click();
    await expect(page.getByText('A user with this name already exists.')).toBeVisible();

    // The new user signs in with the generated password and sees only its tenant.
    const context = await browser.newContext();
    const userPage = await context.newPage();
    await signInThroughForm(userPage, stack.baseURL, userName, generated);
    await expect(userPage.locator('.user')).toContainText(`${userName} (tenant)`);
    const nav = userPage.getByRole('navigation', { name: 'Main' });
    await expect(nav.getByRole('link', { name: 'Account' })).toBeVisible();
    await expect(nav.getByRole('link', { name: 'Users' })).toHaveCount(0);
    await userPage.goto(`${stack.baseURL}/admin/users`);
    await expect(userPage.getByText('Administrators only')).toBeVisible();
    await context.close();
  });

  test('disabling a user ends the session at once and blocks sign-in until the user is enabled again', async ({ adminPage: page, browser, stack, admin, tenant }) => {
    const { userName } = await createTenantUser(admin, tenant, 'disable');
    const context = await browser.newContext();
    const userPage = await context.newPage();
    await signInThroughForm(userPage, stack.baseURL, userName, PASSWORD);
    await expect(userPage.getByRole('button', { name: 'Sign out' })).toBeVisible();
    await userPage.goto(`${stack.baseURL}/domains`);
    await expect(userPage.getByRole('heading', { name: 'Add a domain' })).toBeVisible();

    await page.goto('/admin/users');
    await userRow(page, userName).getByRole('button', { name: `Disable ${userName}` }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Disable' }).click();
    await expect(page.getByText(`${userName} is disabled and was signed out everywhere.`)).toBeVisible();
    await expect(userRow(page, userName)).toContainText('disabled');

    // The user's open page is rejected on its next request and returns to the form.
    await userPage.goto(`${stack.baseURL}/domains`);
    await expect(userPage.getByRole('button', { name: 'Sign in' })).toBeVisible();
    // The same account cannot sign in: the message is the one for a wrong password, so it does not reveal the account.
    await userPage.getByLabel('User').fill(userName);
    await userPage.getByLabel('Password').fill(PASSWORD);
    await userPage.getByRole('button', { name: 'Sign in' }).click();
    await expect(userPage.getByRole('alert').filter({ hasText: 'The user name or password is not correct.' })).toBeVisible();

    await userRow(page, userName).getByRole('button', { name: `Enable ${userName}` }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Enable' }).click();
    await expect(page.getByText(`${userName} can sign in again.`)).toBeVisible();
    await userPage.getByLabel('Password').fill(PASSWORD);
    await userPage.getByRole('button', { name: 'Sign in' }).click();
    await expect(userPage.getByRole('button', { name: 'Sign out' })).toBeVisible();
    await context.close();
  });

  test('an administrator resets a password: the generated one works, the old one and open sessions do not', async ({ adminPage: page, browser, stack, admin, tenant }) => {
    const { userName } = await createTenantUser(admin, tenant, 'reset');
    const context = await browser.newContext();
    const userPage = await context.newPage();
    await signInThroughForm(userPage, stack.baseURL, userName, PASSWORD);
    await expect(userPage.getByRole('button', { name: 'Sign out' })).toBeVisible();

    await page.goto('/admin/users');
    await userRow(page, userName).getByRole('button', { name: `Reset password of ${userName}` }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Reset password' }).click();
    const generated = (await page.getByTestId('secret-value').textContent()).trim();
    await expect(page.getByText(`The password of ${userName} was reset`)).toBeVisible();

    await userPage.goto(`${stack.baseURL}/domains`);
    await expect(userPage.getByRole('button', { name: 'Sign in' })).toBeVisible();
    // (That the old password no longer works is covered by the API tests; failed sign-ins here would count towards the shared server's lockout.)
    await userPage.getByLabel('User').fill(userName);
    await userPage.getByLabel('Password').fill(generated);
    await userPage.getByRole('button', { name: 'Sign in' }).click();
    await expect(userPage.getByRole('button', { name: 'Sign out' })).toBeVisible();

    // Your own row offers no reset: the account page is the place for that.
    await expect(userRow(page, ADMIN_USER).first().getByRole('button', { name: `Reset password of ${ADMIN_USER}` })).toBeDisabled();
    await context.close();
  });

  test('changing the role moves a user between a tenant and the administrators and signs them out', async ({ adminPage: page, admin, stack, tenant }) => {
    const { userName } = await createTenantUser(admin, tenant, 'role');
    const user = await new ApiClient(stack.baseURL).signIn(userName, PASSWORD);
    expect((await user.request('GET', '/api/v1/domains', undefined, { tenantId: tenant.id })).status).toBe(200);

    await page.goto('/admin/users');
    await userRow(page, userName).getByRole('button', { name: `Change role of ${userName}` }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('Role').selectOption('admin');
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByText(`${userName} is now an administrator.`)).toBeVisible();
    await expect(userRow(page, userName)).toContainText('administrator');

    expect((await user.request('GET', '/api/v1/me')).status).toBe(401); // the old session ended
    const promoted = await new ApiClient(stack.baseURL).signIn(userName, PASSWORD);
    expect((await promoted.request('GET', '/api/v1/admin/tenants')).status).toBe(200);

    // Back to a tenant user, and this administrator may be removed again because another administrator exists.
    await userRow(page, userName).getByRole('button', { name: `Change role of ${userName}` }).click();
    await dialog.getByLabel('Role').selectOption('tenant');
    await dialog.getByLabel('Tenant', { exact: true }).selectOption({ label: tenant.name });
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expect(userRow(page, userName)).toContainText('tenant user');
    expect((await promoted.request('GET', '/api/v1/admin/tenants')).status).toBe(401);
  });

  test('the last enabled administrator cannot be disabled or deleted, and the page says why', async ({ adminPage: page, admin }) => {
    const admins = (await admin.ok('GET', '/api/v1/admin/users')).filter((u) => u.role === 'admin' && u.enabled);
    expect(admins.map((u) => u.userName)).toEqual([ADMIN_USER]); // the shared server has exactly one

    await page.goto('/admin/users');
    const row = userRow(page, ADMIN_USER).first();
    await row.getByRole('button', { name: `Disable ${ADMIN_USER}` }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByRole('button', { name: 'Disable' }).click();
    await expect(dialog.getByRole('alert')).toContainText('only enabled administrator');
    await dialog.getByRole('button', { name: 'Cancel' }).click();

    await row.getByRole('button', { name: `Delete ${ADMIN_USER}` }).click();
    await dialog.getByRole('button', { name: 'Delete user' }).click();
    await expect(dialog.getByRole('alert')).toContainText('only enabled administrator');
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(row).toContainText('enabled');
    expect((await admin.request('GET', '/api/v1/me')).status).toBe(200); // still signed in

    // A second administrator makes removing a different one possible: create, disable and delete it.
    const second = unique('second');
    await page.getByLabel('User name').fill(second);
    await page.getByLabel('Role', { exact: true }).selectOption('admin');
    await page.getByLabel('Password (optional)').fill(PASSWORD);
    await page.getByRole('button', { name: 'Create user' }).click();
    await expect(page.getByText(`User ${second} created.`)).toBeVisible();
    await userRow(page, second).getByRole('button', { name: `Disable ${second}` }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Disable' }).click();
    await expect(page.getByText(`${second} is disabled`)).toBeVisible();
    await userRow(page, second).getByRole('button', { name: `Delete ${second}` }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Delete user' }).click();
    await expect(page.getByText(`${second} was deleted.`)).toBeVisible();
    await expect(userRow(page, second)).toHaveCount(0);
  });

  test('the API refuses user management to tenant users and API keys, and needs the CSRF token', async ({ admin, stack, tenant, page }) => {
    const { userName } = await createTenantUser(admin, tenant, 'denied');
    const user = await new ApiClient(stack.baseURL).signIn(userName, PASSWORD);
    for (const [method, path, body] of [
      ['GET', '/api/v1/admin/users'],
      ['POST', '/api/v1/admin/users', { userName: unique('evil'), role: 'admin', password: PASSWORD }],
      ['POST', '/api/v1/admin/users/ffffffffffffffffffffffffffffffff/reset-password', {}],
    ]) {
      const r = await user.request(method, path, body);
      expect([r.status, r.body?.code]).toEqual([403, 'forbidden']);
    }
    const key = await admin.ok('POST', '/api/v1/api-keys', { name: 'no-users', scopes: ['read', 'keys'] }, { tenantId: tenant.id });
    expect((await admin.request('GET', '/api/v1/admin/users', undefined, { bearer: key.key })).status).toBe(403);
    expect((await admin.request('POST', '/api/v1/me/password', { currentPassword: PASSWORD, newPassword: NEXT_PASSWORD }, { bearer: key.key })).status).toBe(403);

    // Cookie mutations without the token are refused, with it they are accepted.
    await signInThroughForm(page, stack.baseURL);
    await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
    const noToken = await page.request.post('/api/v1/admin/users', { data: { userName: unique('csrf'), role: 'admin' } });
    expect([noToken.status(), (await noToken.json()).code]).toEqual([403, 'forbidden']);
    expect((await user.request('GET', '/api/v1/me')).status).toBe(200);
  });
});

test.describe('changing your own password', () => {
  test('the account page changes the password; other sessions end and the new password signs in', async ({ admin, browser, stack, tenant }) => {
    const { userName } = await createTenantUser(admin, tenant, 'own');
    const mine = await browser.newContext();
    const page = await mine.newPage();
    await signInThroughForm(page, stack.baseURL, userName, PASSWORD);
    const otherContext = await browser.newContext();
    const other = await otherContext.newPage();
    await signInThroughForm(other, stack.baseURL, userName, PASSWORD);
    await expect(other.getByRole('button', { name: 'Sign out' })).toBeVisible();

    await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Account' }).click();
    await expect(page.getByRole('heading', { name: 'Account', exact: true })).toBeVisible();

    // A wrong current password is refused under the field.
    await page.getByLabel('Current password').fill('this-is-not-it-at-all');
    await page.getByLabel('New password', { exact: true }).fill(NEXT_PASSWORD);
    await page.getByLabel('New password again').fill(NEXT_PASSWORD);
    await page.getByRole('button', { name: 'Change password' }).click();
    await expect(page.getByText('The current password is not correct.')).toBeVisible();
    // A short password and a mismatch are caught on the page.
    await page.getByLabel('Current password').fill(PASSWORD);
    await page.getByLabel('New password', { exact: true }).fill('short');
    await page.getByRole('button', { name: 'Change password' }).click();
    await expect(page.getByText('Use at least 10 characters.')).toBeVisible();
    await page.getByLabel('New password', { exact: true }).fill(NEXT_PASSWORD);
    await page.getByLabel('New password again').fill(NEXT_PASSWORD + 'x');
    await page.getByRole('button', { name: 'Change password' }).click();
    await expect(page.getByText('The two new passwords are not the same.')).toBeVisible();

    await page.getByLabel('New password again').fill(NEXT_PASSWORD);
    await page.getByRole('button', { name: 'Change password' }).click();
    await expect(page.getByText('Password changed. Your other sessions were signed out.')).toBeVisible();
    // This session goes on working.
    await page.goto(`${stack.baseURL}/domains`);
    await expect(page.getByRole('heading', { name: 'Add a domain' })).toBeVisible();

    // The other session ended with the change; the old password is dead, the new one works.
    await other.goto(`${stack.baseURL}/domains`);
    await expect(other.getByRole('button', { name: 'Sign in' })).toBeVisible();
    await other.getByLabel('User').fill(userName);
    await other.getByLabel('Password').fill(PASSWORD);
    await other.getByRole('button', { name: 'Sign in' }).click();
    await expect(other.getByRole('alert').filter({ hasText: 'The user name or password is not correct.' })).toBeVisible();
    await other.getByLabel('Password').fill(NEXT_PASSWORD);
    await other.getByRole('button', { name: 'Sign in' }).click();
    await expect(other.getByRole('button', { name: 'Sign out' })).toBeVisible();
    await mine.close();
    await otherContext.close();
  });
});
