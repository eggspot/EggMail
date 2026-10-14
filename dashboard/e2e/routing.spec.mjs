import { createRecipientDomain, createVerifiedDomain, expect, sendViaApi, test, unique } from './support/fixtures.mjs';

// Relay routes and per-domain TLS policies against the real server. The relay password must never come back from the API; a TLS policy
// must change the next delivery at once (the API tells the delivery engine of the same process to reload).

const row = (page, text) => page.getByRole('row').filter({ hasText: text });

/** Re-reads the tenant's messages until the one with this subject has the wanted status. */
async function waitForMessageStatus(admin, tenant, subject, status) {
  await expect
    .poll(
      async () => {
        const list = await admin.ok('GET', `/api/v1/messages?subject=${encodeURIComponent(subject)}`, undefined, { tenantId: tenant.id });
        return list.items[0]?.status;
      },
      { timeout: 60_000, intervals: [250, 500, 1000] },
    )
    .toBe(status);
}

test.describe('relay routes', () => {
  test('an administrator adds, edits, disables and deletes a relay route; the password is never shown again', async ({ adminPage: page, admin }) => {
    const name = unique('relay-');
    const domain = `${unique('via')}.partners.test`;
    await page.goto('/admin/relay-routes');
    await expect(page.getByRole('heading', { name: 'Relay routes', exact: true })).toBeVisible();

    await page.getByLabel('Name', { exact: true }).fill(name);
    await page.getByLabel('Host', { exact: true }).fill('smtp.relay.test');
    await page.getByLabel('User name').fill('relay-user');
    await page.getByLabel('Password', { exact: true }).fill('correct-horse-relay-secret');
    await page.getByLabel('Recipient domains').fill(`${domain}\n*.${domain}`);
    await page.getByRole('button', { name: 'Add relay route' }).click();
    await expect(page.getByText(`Relay route ${name} added.`)).toBeVisible();

    const created = row(page, name);
    await expect(created).toContainText('smtp.relay.test:587');
    await expect(created).toContainText('verify');
    await expect(created).toContainText('relay-user (password set)');
    await expect(created).toContainText(domain);
    await expect(page.getByLabel('Password', { exact: true })).toHaveValue('');

    // The server never returns the password: not on create, not on list, and not in the page.
    const listed = await admin.request('GET', '/api/v1/admin/relay-routes');
    expect(listed.status).toBe(200);
    const stored = listed.body.find((r) => r.name === name);
    expect(stored).toMatchObject({ host: 'smtp.relay.test', port: 587, tlsMode: 'verify', userName: 'relay-user', hasPassword: true, enabled: true });
    expect(JSON.stringify(listed.body)).not.toContain('correct-horse-relay-secret');
    expect(JSON.stringify(stored)).not.toMatch(/password"\s*:\s*"/i);
    await expect(page.locator('body')).not.toContainText('correct-horse-relay-secret');

    // Edit the port; the stored password stays.
    await created.getByRole('button', { name: `Edit ${name}` }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByLabel('Password', { exact: true })).toHaveAttribute('placeholder', 'unchanged');
    await dialog.getByLabel('Port').fill('2525');
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByText(`Relay route ${name} saved.`)).toBeVisible();
    await expect(row(page, name)).toContainText(':2525');
    expect((await admin.ok('GET', `/api/v1/admin/relay-routes/${stored.id}`)).hasPassword).toBe(true);

    // Disable, then remove the credentials.
    await row(page, name).getByRole('button', { name: `Disable ${name}` }).click();
    await expect(page.getByText(`${name} is now disabled.`)).toBeVisible();
    await expect(row(page, name)).toContainText('Disabled');
    await row(page, name).getByRole('button', { name: `Edit ${name}` }).click();
    await page.getByRole('dialog').getByLabel('Remove the stored user name and password').check();
    await page.getByRole('dialog').getByRole('button', { name: 'Save' }).click();
    await expect(page.getByText(`Relay route ${name} saved.`)).toBeVisible();
    expect(await admin.ok('GET', `/api/v1/admin/relay-routes/${stored.id}`)).toMatchObject({ userName: null, hasPassword: false, enabled: false });

    // Deleting needs a confirmation.
    await row(page, name).getByRole('button', { name: `Delete ${name}` }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();
    await expect(row(page, name)).toHaveCount(1);
    await row(page, name).getByRole('button', { name: `Delete ${name}` }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Delete route' }).click();
    await expect(page.getByText(`Relay route ${name} deleted.`)).toBeVisible();
    await expect(row(page, name)).toHaveCount(0);
    expect((await admin.request('GET', `/api/v1/admin/relay-routes/${stored.id}`)).status).toBe(404);
  });

  test('the form shows what the server refuses next to the field, and nothing is created', async ({ adminPage: page, admin }) => {
    const before = (await admin.ok('GET', '/api/v1/admin/relay-routes')).length;
    await page.goto('/admin/relay-routes');
    await page.getByLabel('Name', { exact: true }).fill('direct');
    await page.getByLabel('Host', { exact: true }).fill('not a host');
    await page.getByLabel('Port').fill('70000');
    await page.getByLabel('Recipient domains').fill('ok.example\na*b.example');
    await page.getByRole('button', { name: 'Add relay route' }).click();
    await expect(page.getByText('"direct" is the name of direct delivery.')).toBeVisible();
    await expect(page.getByText('Enter a host name such as smtp.relay.example')).toBeVisible();
    await expect(page.getByText('Must be between 1 and 65535.')).toBeVisible();
    await expect(page.getByText(/Entry 2: Use a domain name/)).toBeVisible();
    expect((await admin.ok('GET', '/api/v1/admin/relay-routes')).length).toBe(before);

    // Credentials need TLS: the server refuses a password over tlsMode none.
    await page.reload();
    await page.getByLabel('Name', { exact: true }).fill(unique('plain-'));
    await page.getByLabel('Host', { exact: true }).fill('smtp.relay.test');
    await page.getByLabel('TLS', { exact: true }).selectOption('none');
    await page.getByLabel('User name').fill('u');
    await page.getByLabel('Password', { exact: true }).fill('p');
    await page.getByLabel('Recipient domains').fill('x.partners.test');
    await page.getByRole('button', { name: 'Add relay route' }).click();
    await expect(page.getByText(/Credentials need TLS/)).toBeVisible();
    expect((await admin.ok('GET', '/api/v1/admin/relay-routes')).length).toBe(before);
  });

  test('the endpoints refuse callers without a session and tenant API keys', async ({ stack, admin, tenant }) => {
    const { ApiClient } = await import('./support/apiClient.mjs');
    const anonymous = new ApiClient(stack.baseURL);
    const key = (await admin.ok('POST', '/api/v1/api-keys', { name: 'k', scopes: ['send', 'read', 'keys'] }, { tenantId: tenant.id })).key;
    for (const path of ['/api/v1/admin/relay-routes', '/api/v1/admin/tls-policies']) {
      expect((await anonymous.request('GET', path)).status).toBe(401);
      expect((await anonymous.request('POST', path, {})).status).toBe(401);
      expect((await anonymous.request('GET', path, undefined, { bearer: key })).status).toBe(403);
      expect((await anonymous.request('POST', path, {}, { bearer: key })).status).toBe(403);
    }
  });
});

test.describe('TLS policies', () => {
  test('a policy for a destination takes effect for the very next delivery', async ({ adminPage: page, admin, tenant, stack }) => {
    const sender = await createVerifiedDomain(admin, stack, tenant);
    const destination = createRecipientDomain(stack); // its mail server (the SMTP sink) offers no STARTTLS
    const key = (await admin.ok('POST', '/api/v1/api-keys', { name: 'sender', scopes: ['send', 'read'] }, { tenantId: tenant.id })).key;
    const send = (subject) => sendViaApi(stack, key, { from: `news@${sender.name}`, to: [`user@${destination}`], subject, text: 'hello' });
    const accepted = () => stack.sink.received.filter((m) => m.to.some((t) => t.endsWith('@' + destination))).length;

    // Without a policy the default (TLS when offered) delivers in plaintext.
    const plain = unique('plain ');
    expect((await send(plain)).status).toBe(202);
    await waitForMessageStatus(admin, tenant, plain, 'delivered');
    expect(accepted()).toBe(1);

    // encrypt: the sink cannot do TLS, so nothing may be sent and the message waits.
    await page.goto('/admin/tls-policies');
    await page.getByLabel('Recipient domain').fill(destination);
    await page.getByLabel('TLS level').selectOption('encrypt');
    await page.getByRole('button', { name: 'Add policy' }).click();
    await expect(page.getByText(`Policy for ${destination} added.`)).toBeVisible();
    await expect(row(page, destination)).toContainText('encrypt');
    const strict = unique('strict ');
    expect((await send(strict)).status).toBe(202);
    await waitForMessageStatus(admin, tenant, strict, 'deferred');
    expect(accepted()).toBe(1);

    // A second policy for the same pattern is refused with a message at the field.
    await page.getByLabel('Recipient domain').fill(destination.toUpperCase());
    await page.getByRole('button', { name: 'Add policy' }).click();
    await expect(page.getByText('A policy for this pattern already exists.')).toBeVisible();

    // Back to may: the next message is delivered again, with no restart and no wait for the 30 s reload.
    await row(page, destination).getByRole('button', { name: `Edit ${destination}` }).click();
    await page.getByRole('dialog').getByLabel('TLS level').selectOption('may');
    await page.getByRole('dialog').getByRole('button', { name: 'Save' }).click();
    await expect(page.getByText(`Policy for ${destination} saved.`)).toBeVisible();
    const relaxed = unique('relaxed ');
    expect((await send(relaxed)).status).toBe(202);
    await waitForMessageStatus(admin, tenant, relaxed, 'delivered');
    expect(accepted()).toBe(2);

    await row(page, destination).getByRole('button', { name: `Delete ${destination}` }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Delete policy' }).click();
    await expect(page.getByText(`Policy for ${destination} deleted.`)).toBeVisible();
    await expect(row(page, destination)).toHaveCount(0);
  });

  test('level none and a catch-all strict policy are flagged before and after saving', async ({ adminPage: page, admin }) => {
    const pattern = `${unique('legacy')}.example`;
    await page.goto('/admin/tls-policies');
    await page.getByLabel('Recipient domain').fill(pattern);
    await page.getByLabel('TLS level').selectOption('none');
    await expect(page.getByText(/turns TLS off for these destinations/).first()).toBeVisible();
    await page.getByRole('button', { name: 'Add policy' }).click();
    await expect(page.getByText(`Policy for ${pattern} added.`)).toBeVisible();
    await expect(row(page, pattern)).toContainText('MTA-STS and DANE are not consulted');

    await page.getByLabel('Recipient domain').fill('*');
    await page.getByLabel('TLS level').selectOption('verify');
    await expect(page.getByText(/applies to every destination/i)).toBeVisible();

    const id = (await admin.ok('GET', '/api/v1/admin/tls-policies')).find((p) => p.domainPattern === pattern).id;
    await admin.ok('DELETE', `/api/v1/admin/tls-policies/${id}`);
  });
});
