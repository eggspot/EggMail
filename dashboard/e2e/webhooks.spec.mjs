import crypto from 'node:crypto';
import { test as base, expect, unique } from './support/fixtures.mjs';

// The receiver is shared by the worker, and a delivery that failed in one test is retried later, possibly during another test:
// every lookup is therefore limited to the unique URL (path and query) of the test's own endpoint, and a test that makes the
// receiver fail cannot leave it failing for the next one.
const test = base.extend({
  receiverReset: [
    async ({ stack }, use) => {
      await use();
      stack.webhooks.respondWith(200);
    },
    { auto: true },
  ],
});
const receivedAt = (stack, url) => {
  const target = new URL(url);
  return stack.webhooks.requests.filter((r) => r.url === target.pathname + target.search);
};

/** Standard Webhooks: HMAC-SHA256 over "<id>.<timestamp>.<body>" with the base64 part of the whsec_ secret as key. */
function signatureFor(secret, request) {
  const key = Buffer.from(secret.replace(/^whsec_/, ''), 'base64');
  const signed = `${request.headers['webhook-id']}.${request.headers['webhook-timestamp']}.${request.body}`;
  return `v1,${crypto.createHmac('sha256', key).update(signed).digest('base64')}`;
}

const endpointCard = (page, url) => page.locator('section.card').filter({ has: page.getByRole('heading', { name: url, exact: true }) });

test.describe('webhooks', () => {
  test('internal addresses are refused until an administrator allows them; then an endpoint is created and tested with a verifiable signature', async ({ adminPage: page, admin, tenant, stack }) => {
    const url = `${stack.webhooks.url}?t=${unique('')}`;
    stack.webhooks.respondWith(200);

    // The SSRF guard refuses loopback, with the message on the URL field.
    await page.goto('/webhooks');
    await page.getByLabel('Endpoint URL').fill(url);
    await page.getByRole('button', { name: 'Create endpoint' }).click();
    await expect(page.locator('.field-error').filter({ hasText: 'Endpoint URL' })).toBeVisible();
    await expect(page.locator('.error-text')).toBeVisible();

    // Only an administrator can lift the guard for a tenant.
    await admin.ok('PUT', '/api/v1/settings', { values: { 'Webhooks:AllowedNetworks': '127.0.0.0/8' } }, { tenantId: tenant.id });
    await page.getByRole('button', { name: 'Create endpoint' }).click();
    const secretDialog = page.getByRole('alertdialog');
    const secret = (await secretDialog.getByTestId('secret-value').innerText()).trim();
    expect(secret).toMatch(/^whsec_/);
    await secretDialog.getByRole('button', { name: 'I have saved it' }).click();
    const card = endpointCard(page, url);
    await expect(card).toContainText('Enabled');
    await expect(card).toContainText('message.delivered');

    // A test event reaches the receiver, signed with the secret that was shown.
    await card.getByRole('button', { name: 'Send test event' }).click();
    await expect(card.getByText('Test event sent.')).toBeVisible();
    await expect.poll(() => receivedAt(stack, url).length, { timeout: 30_000 }).toBeGreaterThan(0);
    const request = receivedAt(stack, url).at(-1);
    expect(request.method).toBe('POST');
    expect(JSON.parse(request.body).type).toBe('webhook.test');
    expect(request.headers['webhook-signature'].split(' ')).toContain(signatureFor(secret, request));

    const attempts = card.locator('[id^="attempts-"]');
    await expect(attempts.getByRole('row').nth(1)).toContainText('200', { timeout: 30_000 });
  });

  test('a failing receiver shows in the attempts log; a finished delivery can be replayed, one waiting for a retry cannot', async ({ adminPage: page, admin, tenant, stack }) => {
    await admin.ok('PUT', '/api/v1/settings', { values: { 'Webhooks:AllowedNetworks': '127.0.0.0/8' } }, { tenantId: tenant.id });
    const url = `${stack.webhooks.url}?fail=${unique('')}`;
    await admin.ok('POST', '/api/v1/webhooks', { url, event_types: ['message.delivered'] }, { tenantId: tenant.id });

    await page.goto('/webhooks');
    const card = endpointCard(page, url);
    const attemptRows = card.locator('[id^="attempts-"]').getByRole('row');

    // A 500 is recorded as a failed attempt (and the delivery waits for its retry).
    stack.webhooks.respondWith(500);
    await card.getByRole('button', { name: 'Send test event' }).click();
    const failed = attemptRows.filter({ hasText: '500' });
    await expect(failed.first()).toBeVisible({ timeout: 30_000 });
    await expect(failed.first().locator('.chip')).toHaveClass(/chip-bad/);
    await expect(failed.first()).toContainText('http_500');
    await failed.first().getByRole('button', { name: /^Replay/ }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Replay delivery' }).click();
    await expect(page.getByRole('dialog').getByRole('alert')).toContainText('still waiting for its next retry');
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();

    // A delivery that succeeded can be replayed: the receiver gets the same event again.
    stack.webhooks.respondWith(200);
    await card.getByRole('button', { name: 'Send test event' }).click();
    const ok = attemptRows.filter({ hasText: '200' });
    await expect(ok.first()).toBeVisible({ timeout: 30_000 });
    const before = receivedAt(stack, url).length;
    await ok.first().getByRole('button', { name: /^Replay/ }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Replay delivery' }).click();
    await expect(page.getByText('Delivery re-queued.')).toBeVisible();
    await expect.poll(() => receivedAt(stack, url).length, { timeout: 30_000 }).toBeGreaterThan(before);
    // The replay is a new attempt in the log (the earlier failed delivery may also be retried meanwhile and succeed now).
    await expect.poll(() => attemptRows.filter({ hasText: '200' }).count(), { timeout: 30_000 }).toBeGreaterThanOrEqual(2);
  });

  test('an endpoint is edited, disabled, re-enabled and deleted; test events to a disabled endpoint are refused', async ({ adminPage: page, admin, tenant, stack }) => {
    await admin.ok('PUT', '/api/v1/settings', { values: { 'Webhooks:AllowedNetworks': '127.0.0.0/8' } }, { tenantId: tenant.id });
    const url = `${stack.webhooks.url}?edit=${unique('')}`;
    await admin.ok('POST', '/api/v1/webhooks', { url, event_types: ['message.delivered'] }, { tenantId: tenant.id });

    await page.goto('/webhooks');
    let card = endpointCard(page, url);
    await card.getByRole('button', { name: 'Edit' }).click();
    await card.getByLabel('message.bounced').check();
    await card.getByLabel('message.delivered').uncheck();
    await card.getByRole('button', { name: 'Save changes' }).click();
    await expect(card).toContainText('message.bounced');
    await expect(card).not.toContainText('message.delivered');

    // Editing to an internal address outside the allowlist is refused.
    await card.getByRole('button', { name: 'Edit' }).click();
    await card.getByLabel('Endpoint URL').fill('https://169.254.169.254/latest');
    await card.getByRole('button', { name: 'Save changes' }).click();
    await expect(card.locator('.error-text')).toBeVisible();
    await card.getByRole('button', { name: 'Cancel' }).click();

    await card.getByRole('button', { name: 'Disable' }).click();
    await expect(card).toContainText('Disabled');
    await card.getByRole('button', { name: 'Send test event' }).click();
    await expect(card.getByRole('alert')).toBeVisible();
    await card.getByRole('button', { name: 'Enable' }).click();
    await expect(card).toContainText('Enabled');

    await card.getByRole('button', { name: 'Delete' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Delete endpoint' }).click();
    card = endpointCard(page, url);
    await expect(card).toHaveCount(0);
  });

  test('rotating the secret shows the new one once; both secrets sign until the previous one is removed', async ({ adminPage: page, admin, tenant, stack }) => {
    await admin.ok('PUT', '/api/v1/settings', { values: { 'Webhooks:AllowedNetworks': '127.0.0.0/8' } }, { tenantId: tenant.id });
    const url = `${stack.webhooks.url}?rotate=${unique('')}`;
    const created = await admin.ok('POST', '/api/v1/webhooks', { url, event_types: ['message.delivered'] }, { tenantId: tenant.id });
    stack.webhooks.respondWith(200);

    await page.goto('/webhooks');
    const card = endpointCard(page, url);
    await card.getByRole('button', { name: 'Rotate secret' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Rotate secret' }).click();
    const secretDialog = page.getByRole('alertdialog');
    const newSecret = (await secretDialog.getByTestId('secret-value').innerText()).trim();
    expect(newSecret).toMatch(/^whsec_/);
    expect(newSecret).not.toBe(created.secret);
    await secretDialog.getByRole('button', { name: 'I have saved it' }).click();
    await expect(card.getByText('Secret rotation in progress')).toBeVisible();

    // Deliveries carry a signature for the new and the previous secret.
    await card.getByRole('button', { name: 'Send test event' }).click();
    await expect.poll(() => receivedAt(stack, url).length, { timeout: 30_000 }).toBeGreaterThan(0);
    const both = receivedAt(stack, url).at(-1);
    const signatures = both.headers['webhook-signature'].split(' ');
    expect(signatures).toContain(signatureFor(newSecret, both));
    expect(signatures).toContain(signatureFor(created.secret, both));

    // After the previous secret is removed only the new one signs.
    await card.getByRole('button', { name: 'Remove previous secret' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Remove previous secret' }).click();
    await expect(card.getByText('Secret rotation in progress')).toHaveCount(0);
    const beforeRemoval = receivedAt(stack, url).length;
    await card.getByRole('button', { name: 'Send test event' }).click();
    await expect.poll(() => receivedAt(stack, url).length, { timeout: 30_000 }).toBeGreaterThan(beforeRemoval);
    const only = receivedAt(stack, url).at(-1);
    expect(only.headers['webhook-signature'].split(' ')).toEqual([signatureFor(newSecret, only)]);
  });

  test('a delivered message produces a signed message.delivered event', async ({ adminPage: page, admin, tenant, stack }) => {
    const { createRecipientDomain, createVerifiedDomain, sendViaApi } = await import('./support/fixtures.mjs');
    await admin.ok('PUT', '/api/v1/settings', { values: { 'Webhooks:AllowedNetworks': '127.0.0.0/8' } }, { tenantId: tenant.id });
    const url = `${stack.webhooks.url}?events=${unique('')}`;
    const hook = await admin.ok('POST', '/api/v1/webhooks', { url, event_types: ['message.delivered'] }, { tenantId: tenant.id });
    stack.webhooks.respondWith(200);
    const domain = await createVerifiedDomain(admin, stack, tenant);
    const recipientDomain = createRecipientDomain(stack);
    const key = (await admin.ok('POST', '/api/v1/api-keys', { name: 'hook-send', scopes: ['send'] }, { tenantId: tenant.id })).key;
    const subject = unique('Webhook ');
    const sent = await sendViaApi(stack, key, { from: `hello@${domain.name}`, to: [`erin@${recipientDomain}`], subject, text: 'x' });
    expect(sent.status).toBe(202);

    await expect.poll(() => receivedAt(stack, url).some((r) => JSON.parse(r.body).type === 'message.delivered'), { timeout: 60_000 }).toBe(true);
    const request = receivedAt(stack, url).find((r) => JSON.parse(r.body).type === 'message.delivered');
    expect(request.headers['webhook-signature'].split(' ')).toContain(signatureFor(hook.secret, request));
    expect(request.body).toContain(sent.body.id);

    await page.goto('/webhooks');
    const card = endpointCard(page, url);
    await card.getByRole('button', { name: 'Show attempts' }).click();
    await expect(card.locator('[id^="attempts-"]').getByRole('row').nth(1)).toContainText('200');
  });
});
