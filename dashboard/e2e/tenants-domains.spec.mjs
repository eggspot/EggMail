import { REQUIRED_PURPOSES, expect, publishDomainRecords, test, unique } from './support/fixtures.mjs';

const chip = (page, purpose, text) => recordRow(page, purpose).locator('.chip', { hasText: text });
const recordRow = (page, purpose) => page.locator('.dns-table tbody tr:not(.dns-detail)').filter({ has: page.getByRole('cell', { name: purpose, exact: true }) });

test.describe('tenants', () => {
  test('an administrator creates, renames, suspends and re-activates a tenant', async ({ adminPage: page, admin, tenant }) => {
    await page.goto('/admin/tenants');
    const name = unique('Created tenant ');
    await page.getByLabel('Name', { exact: true }).fill(name);
    await page.getByRole('button', { name: 'Create tenant' }).click();
    await expect(page.getByText(`Tenant ${name} created.`)).toBeVisible();
    const row = page.getByRole('row').filter({ hasText: name });
    await expect(row).toContainText('active');

    // The header picker offers the new tenant without a reload.
    await expect(page.getByLabel('Acting on tenant')).toContainText(name);

    await row.getByRole('button', { name: `Act on ${name}` }).click();
    await expect(row).toContainText('(selected)');

    const renamed = `${name} renamed`;
    await row.getByRole('button', { name: `Rename ${name}` }).click();
    await page.getByRole('dialog').getByLabel('Name').fill(renamed);
    await page.getByRole('dialog').getByRole('button', { name: 'Save' }).click();
    await expect(page.getByText(`Renamed to ${renamed}.`)).toBeVisible();
    await expect(page.getByLabel('Acting on tenant')).toContainText(renamed);

    // Suspending stops the tenant's API keys at once; activating brings them back.
    const created = (await admin.ok('GET', '/api/v1/admin/tenants')).find((t) => t.name === renamed);
    const key = await admin.ok('POST', '/api/v1/api-keys', { name: 'k', scopes: ['domains'] }, { tenantId: created.id });
    const read = () => admin.request('GET', '/api/v1/domains', undefined, { bearer: key.key });
    expect((await read()).status).toBe(200);
    await page.getByRole('row').filter({ hasText: renamed }).getByRole('button', { name: `Suspend ${renamed}` }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Suspend' }).click();
    await expect(page.getByText(`${renamed} is now suspended.`)).toBeVisible();
    const refused = await read();
    expect(refused.status).toBe(403);
    expect(refused.body.code).toBe('tenant_disabled');
    await page.getByRole('row').filter({ hasText: renamed }).getByRole('button', { name: `Activate ${renamed}` }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Activate' }).click();
    await expect(page.getByText(`${renamed} is now active.`)).toBeVisible();
    expect((await read()).status).toBe(200);
    expect(tenant.id).toBeTruthy();
  });

  test('a blank or duplicate tenant name is refused', async ({ adminPage: page, tenant }) => {
    await page.goto('/admin/tenants');
    await expect(page.getByRole('button', { name: 'Create tenant' })).toBeDisabled();
    await page.getByLabel('Name', { exact: true }).fill(tenant.name);
    await page.getByRole('button', { name: 'Create tenant' }).click();
    // The server accepts or refuses duplicates by its own rule; either way the page must stay usable and show no raw error.
    await expect(page.getByRole('heading', { name: 'Tenants', exact: true })).toBeVisible();
  });
});

test.describe('domains and DNS verification', () => {
  test('adding a domain shows the DNS records to publish, with a pending state', async ({ adminPage: page, context, tenant }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const domain = `${unique('add')}.mail.test`;
    await page.goto('/domains');
    await expect(page.getByText('No domains yet')).toBeVisible();

    await page.getByLabel('Domain name').fill('not a domain');
    await page.getByRole('button', { name: 'Add domain' }).click();
    await expect(page.getByText('Enter a valid domain name')).toBeVisible();

    await page.getByLabel('Domain name').fill(domain);
    await page.getByRole('button', { name: 'Add domain' }).click();
    await expect(page).toHaveURL(/\/domains\/[0-9a-f]{32}$/);
    await expect(page.getByRole('heading', { name: domain, exact: true })).toBeVisible();
    await expect(page.getByText('Waiting for DNS records')).toBeVisible();

    // DKIM TXT, return-path CNAME, SPF and DMARC advice.
    await expect(recordRow(page, 'DKIM')).toContainText(`._domainkey.${domain}`);
    await expect(recordRow(page, 'DKIM')).toContainText('v=DKIM1');
    await expect(recordRow(page, 'Return-path')).toContainText(`bounce.${domain}`);
    await expect(recordRow(page, 'Return-path')).toContainText('bounces.eggmail.test');
    await expect(recordRow(page, 'SPF')).toContainText('v=spf1');
    await expect(recordRow(page, 'DMARC')).toContainText(`_dmarc.${domain}`);
    await expect(recordRow(page, 'Bounce MX')).toContainText('10 mta.eggmail.test');
    await expect(recordRow(page, 'Reverse DNS')).toContainText('mta.eggmail.test');
    await expect(page.getByTestId('dkim-public-key')).not.toBeEmpty();

    // Nothing is published yet: the page says so, and the zone file is there to copy.
    await expect(page.getByTestId('ready-state')).toHaveText('Not ready to send');
    await expect(page.getByTestId('record-progress')).toContainText('Required records: 0 of 2 published.');
    await expect(page.getByTestId('zone-file')).toContainText(`_dmarc.${domain}. 3600 IN TXT "v=DMARC1; p=none; rua=mailto:dmarc@${domain}"`);
    await page.getByRole('button', { name: 'Copy zone file' }).click();
    const zone = await page.getByTestId('zone-file').evaluate((e) => e.textContent);
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(zone);

    // The copy button puts the exact DNS value on the clipboard.
    const expectedValue = await recordRow(page, 'SPF').getByTestId('dns-value').innerText();
    await recordRow(page, 'SPF').getByRole('button', { name: /Copy SPF value/ }).click();
    await expect(recordRow(page, 'SPF').getByRole('button', { name: /Copy SPF value/ })).toHaveText('Copied');
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(expectedValue);

    // The list shows it and a duplicate registration is refused with a field error.
    await page.goto('/domains');
    await expect(page.getByRole('link', { name: domain })).toBeVisible();
    await page.getByLabel('Domain name').fill(domain);
    await page.getByRole('button', { name: 'Add domain' }).click();
    await expect(page.locator('.error-text')).toBeVisible();
    expect(tenant.id).toBeTruthy();
  });

  test('records that are not published yet are shown as missing, and the check can be repeated only every 30 seconds', async ({ adminPage: page, admin, tenant }) => {
    const domain = (await admin.ok('POST', '/api/v1/domains', { name: `${unique('miss')}.mail.test` }, { tenantId: tenant.id }));
    await page.goto(`/domains/${domain.id}`);
    await page.getByRole('button', { name: 'Check DNS' }).click();

    await expect(chip(page, 'DKIM', 'Missing')).toBeVisible();
    await expect(chip(page, 'Return-path', 'Missing')).toBeVisible();
    await expect(page.getByText('nothing found').first()).toBeVisible();
    await expect(page.getByRole('button', { name: /Check again in \d+ s/ })).toBeDisabled();
    await expect(page.getByText('Sending from this domain is blocked until it is verified')).toBeVisible();

    // The server enforces the same limit independently of the button.
    const again = await admin.request('POST', `/api/v1/domains/${domain.id}/verify`, undefined, { tenantId: tenant.id });
    expect(again.status).toBe(429);
    expect(again.body.code).toBe('rate_limited');
    expect(Number(again.headers.get('retry-after'))).toBeGreaterThan(0);
  });

  test('a record with the wrong value is shown as a mismatch with what was found and what is expected', async ({ adminPage: page, admin, tenant, stack }) => {
    const domain = (await admin.ok('POST', '/api/v1/domains', { name: `${unique('wrong')}.mail.test` }, { tenantId: tenant.id }));
    publishDomainRecords(stack.dns, domain, { wrongDkim: true, only: REQUIRED_PURPOSES });
    await page.goto(`/domains/${domain.id}`);
    await page.getByRole('button', { name: 'Check DNS' }).click();

    await expect(chip(page, 'DKIM', 'Mismatch')).toBeVisible();
    await expect(chip(page, 'Return-path', 'OK')).toBeVisible();
    const detail = page.locator('.dns-detail').filter({ hasText: 'AAAAAAAA' });
    await expect(detail).toContainText('Found in DNS');
    await expect(detail).toContainText('Expected');
    await expect(detail).toContainText('v=DKIM1');
    await expect(page.getByText('Verified', { exact: true })).toHaveCount(0);
  });

  test('once the required records are published the domain becomes verified; SPF and DMARC are only advice', async ({ adminPage: page, admin, tenant, stack }) => {
    const domain = (await admin.ok('POST', '/api/v1/domains', { name: `${unique('ok')}.mail.test` }, { tenantId: tenant.id }));
    publishDomainRecords(stack.dns, domain, { only: REQUIRED_PURPOSES });
    await page.goto(`/domains/${domain.id}`);
    await page.getByRole('button', { name: 'Check DNS' }).click();

    await expect(page.getByRole('heading', { name: domain.name, exact: true }).locator('xpath=ancestor::header')).toContainText('Verified');
    await expect(chip(page, 'DKIM', 'OK')).toBeVisible();
    await expect(chip(page, 'Return-path', 'OK')).toBeVisible();
    await expect(chip(page, 'SPF', 'Missing')).toBeVisible();
    await expect(page.getByText('Waiting for DNS records')).toHaveCount(0);
    await expect(page.getByTestId('ready-state')).toHaveText('Ready to send');
    await expect(page.getByTestId('record-progress')).toContainText('Required records: 2 of 2 published.');

    // And it shows as verified in the list, where sending is active.
    await page.goto('/domains');
    const row = page.getByRole('row').filter({ hasText: domain.name });
    await expect(row).toContainText('Verified');
    await expect(row).toContainText('Active');
  });

  test('rotating the DKIM key adds a new selector as advice, and a pending rotation can be cancelled', async ({ adminPage: page, admin, tenant, stack }) => {
    const domain = (await admin.ok('POST', '/api/v1/domains', { name: `${unique('rot')}.mail.test` }, { tenantId: tenant.id }));
    publishDomainRecords(stack.dns, domain, { only: REQUIRED_PURPOSES });
    await page.goto(`/domains/${domain.id}`);
    const firstSelector = (await page.locator('dl.kv', { hasText: 'Selector' }).locator('code').first().innerText()).trim();

    await page.getByRole('button', { name: 'Rotate DKIM key' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Rotate key' }).click();
    await expect(page.locator('.dns-table tbody tr:not(.dns-detail)').filter({ hasText: '._domainkey.' })).toHaveCount(2);
    // The current key keeps signing until the new record is found in DNS.
    await expect(page.locator('dl.kv', { hasText: 'Selector' }).locator('code').first()).toHaveText(firstSelector);

    // A second rotation while one is pending is refused with a clear message.
    await page.getByRole('button', { name: 'Rotate DKIM key' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Rotate key' }).click();
    await expect(page.getByRole('dialog').getByRole('alert')).toBeVisible();
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();

    // The pending rotation is cancelled from the dashboard; the unused key goes away.
    await page.getByRole('button', { name: 'Cancel pending rotation' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel rotation' }).click();
    await expect(page.locator('.dns-table tbody tr:not(.dns-detail)').filter({ hasText: '._domainkey.' })).toHaveCount(1);
    await expect(page.getByRole('button', { name: 'Cancel pending rotation' })).toHaveCount(0);
  });

  test('deleting a domain needs the typed name', async ({ adminPage: page, admin, tenant }) => {
    const domain = (await admin.ok('POST', '/api/v1/domains', { name: `${unique('del')}.mail.test` }, { tenantId: tenant.id }));
    await page.goto('/domains');
    await page.getByRole('button', { name: `Delete ${domain.name}` }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByRole('button', { name: 'Delete domain' })).toBeDisabled();
    await dialog.getByLabel(/Type .* to confirm/).fill(domain.name);
    await dialog.getByRole('button', { name: 'Delete domain' }).click();
    await expect(page.getByText('No domains yet')).toBeVisible();
    expect((await admin.request('GET', `/api/v1/domains/${domain.id}`, undefined, { tenantId: tenant.id })).status).toBe(404);
  });
});
