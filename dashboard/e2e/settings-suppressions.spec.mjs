import { createRecipientDomain, createVerifiedDomain, expect, sendViaApi, test, unique } from './support/fixtures.mjs';

test.describe('settings', () => {
  test('tenant settings: an administrator edits the webhook allowlist; invalid values and locked settings are handled', async ({ adminPage: page }) => {
    await page.goto('/settings');
    const tenantCard = page.getByRole('form', { name: 'Tenant settings' });
    const allowlist = tenantCard.getByLabel('Webhooks:AllowedNetworks');
    await expect(allowlist).toHaveValue('');

    // Locked settings come from the deployment and cannot be edited.
    await expect(tenantCard.getByLabel('Smtp:MaxRecipients')).toHaveAttribute('readonly', '');
    await expect(tenantCard.getByLabel('Content:StoreAttachments')).toBeDisabled();
    await expect(tenantCard.getByText('Locked by deployment configuration').first()).toBeVisible();
    await expect(tenantCard.getByRole('button', { name: 'Save settings' })).toBeDisabled();

    // The server's validation message lands on the field.
    await allowlist.fill('not-a-network');
    await expect(page.getByText('1 unsaved change')).toBeVisible();
    await tenantCard.getByRole('button', { name: 'Save settings' }).click();
    await expect(tenantCard.locator('.field-error')).toContainText('Webhooks:AllowedNetworks');
    await expect(tenantCard.locator('.error-text')).toBeVisible();

    await allowlist.fill('127.0.0.0/8');
    await tenantCard.getByRole('button', { name: 'Save settings' }).click();
    await expect(tenantCard.getByText('Saved 1 setting.')).toBeVisible();
    await page.reload();
    await expect(page.getByRole('form', { name: 'Tenant settings' }).getByLabel('Webhooks:AllowedNetworks')).toHaveValue('127.0.0.0/8');
  });

  test('global settings: values are edited, validated, flagged when they need a restart, and persist', async ({ adminPage: page }) => {
    await page.goto('/settings');
    const card = page.getByRole('form', { name: 'Global settings' });
    const metadata = card.getByLabel('Retention:MetadataDays');
    await expect(metadata).toHaveValue('30');
    await expect(card.getByText('Takes effect the next time the server starts').first()).toBeVisible();

    // The 6 to 30 day content window has no unlimited value.
    const content = card.getByLabel('Content:RetentionDays');
    await content.fill('5');
    await card.getByRole('button', { name: 'Save settings' }).click();
    await expect(card.getByText('Content retention must be between 6 and 30 days')).toBeVisible();
    await content.fill('7');

    // Zero keeps data forever and says what that means.
    await metadata.fill('0');
    await expect(card.getByText('0 keeps data forever')).toBeVisible();
    await metadata.fill('31');
    await card.getByRole('button', { name: 'Save settings' }).click();
    await expect(card.getByText('Saved 1 setting.')).toBeVisible();

    await page.reload();
    const reloaded = page.getByRole('form', { name: 'Global settings' });
    await expect(reloaded.getByLabel('Retention:MetadataDays')).toHaveValue('31');
    await reloaded.getByLabel('Retention:MetadataDays').fill('30');
    await reloaded.getByRole('button', { name: 'Save settings' }).click();
    await expect(reloaded.getByText('Saved 1 setting.')).toBeVisible();

    // Deployment-only values are read-only.
    await expect(reloaded.getByLabel('Smtp:MaxMessageSize')).toHaveAttribute('readonly', '');
  });
});

test.describe('suppressions', () => {
  test('an address is added, filtered and removed', async ({ adminPage: page }) => {
    await page.goto('/suppressions');
    await expect(page.getByText('The suppression list is empty')).toBeVisible();

    // Validation.
    await page.getByRole('button', { name: 'Add to suppression list' }).click();
    await expect(page.getByText('Enter an email address.')).toBeVisible();
    await page.getByLabel('Email address').fill('nonsense');
    await page.getByRole('button', { name: 'Add to suppression list' }).click();
    await expect(page.getByText('Enter a valid email address.')).toBeVisible();

    const address = `Block.Me+${unique('')}@Example.COM`;
    await page.getByLabel('Email address').fill(address);
    await page.getByRole('button', { name: 'Add to suppression list' }).click();
    const lowered = address.toLowerCase();
    await expect(page.getByText(`${lowered} is on the suppression list.`)).toBeVisible();
    const row = page.getByRole('row').filter({ hasText: lowered });
    await expect(row).toContainText('manual');

    // Another reason, then a filter over the loaded entries.
    const other = `complainer-${unique('')}@example.org`;
    await page.getByLabel('Email address').fill(other);
    await page.getByLabel('Reason').selectOption('complaint');
    await page.getByRole('button', { name: 'Add to suppression list' }).click();
    await expect(page.getByRole('row').filter({ hasText: other })).toContainText('complaint');
    await page.getByLabel('Filter loaded addresses').fill('complainer');
    await expect(page.getByRole('row').filter({ hasText: lowered })).toHaveCount(0);
    await expect(page.getByRole('row').filter({ hasText: other })).toHaveCount(1);
    await page.getByLabel('Filter loaded addresses').fill('zzz-nothing');
    await expect(page.getByText('No loaded address matches the filter.')).toBeVisible();
    await page.getByLabel('Filter loaded addresses').fill('');

    // Removing asks first; cancelling keeps the entry.
    await page.getByRole('button', { name: `Remove ${lowered}` }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();
    await expect(page.getByRole('row').filter({ hasText: lowered })).toHaveCount(1);
    await page.getByRole('button', { name: `Remove ${lowered}` }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Remove address' }).click();
    await expect(page.getByText(`${lowered} was removed.`)).toBeVisible();
    await expect(page.getByRole('row').filter({ hasText: lowered })).toHaveCount(0);

    await page.reload();
    await expect(page.getByRole('row').filter({ hasText: lowered })).toHaveCount(0);
    await expect(page.getByRole('row').filter({ hasText: other })).toHaveCount(1);
  });

  test('the list is paged: more entries load on request', async ({ adminPage: page, admin, tenant }) => {
    for (let i = 0; i < 55; i++) {
      await admin.ok('POST', '/api/v1/suppressions', { address: `bulk${String(i).padStart(3, '0')}@paging.test` }, { tenantId: tenant.id });
    }
    await page.goto('/suppressions');
    await expect(page.getByRole('row').filter({ hasText: '@paging.test' })).toHaveCount(50);
    await page.getByRole('button', { name: 'Load more' }).click();
    await expect(page.getByRole('row').filter({ hasText: '@paging.test' })).toHaveCount(55);
    await expect(page.getByRole('button', { name: 'Load more' })).toHaveCount(0);
  });

  test('mail to a suppressed address is recorded as suppressed and not delivered', async ({ adminPage: page, admin, tenant, stack }) => {
    const domain = await createVerifiedDomain(admin, stack, tenant);
    const recipientDomain = createRecipientDomain(stack);
    const blocked = `blocked@${recipientDomain}`;
    await page.goto('/suppressions');
    await page.getByLabel('Email address').fill(blocked);
    await page.getByRole('button', { name: 'Add to suppression list' }).click();
    await expect(page.getByText(`${blocked} is on the suppression list.`)).toBeVisible();

    const key = (await admin.ok('POST', '/api/v1/api-keys', { name: 'supp', scopes: ['send'] }, { tenantId: tenant.id })).key;
    const subject = unique('Suppressed ');
    const before = stack.sink.received.length;
    expect((await sendViaApi(stack, key, { from: `hello@${domain.name}`, to: [blocked], subject, text: 'x' })).status).toBe(202);

    await page.goto('/messages');
    await expect(async () => {
      await page.getByRole('button', { name: 'Search' }).click();
      await expect(page.getByRole('row').filter({ hasText: subject })).toContainText('suppressed', { timeout: 2_000 });
    }).toPass({ timeout: 30_000 });
    expect(stack.sink.received.length).toBe(before);
  });
});
