import { createRecipientDomain, createVerifiedDomain, expect, sendViaApi, test, unique } from './support/fixtures.mjs';

/** Creates an API key through the dashboard and returns the one-time secret that was shown. */
async function createKeyThroughUi(page, name) {
  await page.goto('/credentials');
  await page.getByLabel('Key name').fill(name);
  await page.getByRole('button', { name: 'Create API key' }).click();
  return (await page.getByTestId('secret-value').innerText()).trim();
}

const search = async (page) => page.getByRole('button', { name: 'Search' }).click();
const messageRow = (page, subject) => page.getByRole('row').filter({ has: page.getByRole('link', { name: subject }) });

/** Re-runs the search until the message shows the wanted status (delivery is asynchronous). */
async function waitForStatus(page, subject, status) {
  await expect(async () => {
    await search(page);
    await expect(messageRow(page, subject)).toContainText(status, { timeout: 2_000 });
  }).toPass({ timeout: 60_000, intervals: [500, 1000, 2000] });
}

test.describe('API keys', () => {
  test('a key is created, shown once, listed with its scopes and revoked', async ({ adminPage: page, admin, tenant, stack }) => {
    const name = unique('key ');
    await page.goto('/credentials');
    await expect(page.getByText('No API keys')).toBeVisible();

    // Validation first: no name, no scopes.
    await page.getByRole('button', { name: 'Create API key' }).click();
    await expect(page.getByText('Give the key a name')).toBeVisible();

    await page.getByLabel('Key name').fill(name);
    await page.getByLabel('send mail').uncheck();
    await page.getByRole('button', { name: 'Create API key' }).click();
    await expect(page.getByText('Select at least one scope.')).toBeVisible();
    await page.getByLabel('send mail').check();
    await page.getByLabel('read messages and statistics').check();
    await page.getByRole('button', { name: 'Create API key' }).click();

    const secretDialog = page.getByRole('alertdialog');
    const secret = (await secretDialog.getByTestId('secret-value').innerText()).trim();
    expect(secret).toMatch(/^egm_[A-Za-z0-9_-]{8}_[A-Za-z0-9_-]{43}$/);
    await expect(secretDialog).toContainText('shown only once');

    // The key works against the API...
    const me = await fetch(`${stack.baseURL}/api/v1/me`, { headers: { authorization: `Bearer ${secret}` } });
    expect(me.status).toBe(200);
    expect(await me.json()).toMatchObject({ authenticatedBy: 'api_key', tenantId: tenant.id });

    // ...is listed with its prefix and scopes, and the secret is gone once acknowledged and after a reload.
    await secretDialog.getByRole('button', { name: 'I have saved it' }).click();
    await expect(page.getByRole('alertdialog')).toHaveCount(0);
    const row = page.getByRole('row').filter({ hasText: name });
    await expect(row).toContainText(secret.slice(0, 12));
    await expect(row.locator('.chip')).toHaveText(['send', 'read']);
    await expect(row).not.toContainText(secret.slice(13));
    await page.reload();
    await expect(page.getByText(secret)).toHaveCount(0);

    // Revoking needs a confirmation and stops the key at once.
    await row.getByRole('button', { name: `Revoke API key ${name}` }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Revoke key' }).click();
    await expect(page.getByRole('row').filter({ hasText: name })).toHaveCount(0);
    expect((await fetch(`${stack.baseURL}/api/v1/me`, { headers: { authorization: `Bearer ${secret}` } })).status).toBe(401);
    expect(admin).toBeTruthy();
  });

  test('an SMTP credential is created with a one-time password and revoked', async ({ adminPage: page }) => {
    const username = unique('smtp-user-');
    await page.goto('/credentials');
    await page.getByLabel('Username').fill(username);
    await page.getByRole('button', { name: 'Create SMTP credential' }).click();
    const secretDialog = page.getByRole('alertdialog');
    expect((await secretDialog.getByTestId('secret-value').innerText()).trim().length).toBeGreaterThanOrEqual(16);
    await secretDialog.getByRole('button', { name: 'I have saved it' }).click();
    const row = page.getByRole('row').filter({ hasText: username });
    await expect(row).toBeVisible();
    await row.getByRole('button', { name: `Revoke SMTP credential ${username}` }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Revoke credential' }).click();
    await expect(page.getByRole('row').filter({ hasText: username })).toHaveCount(0);
  });
});

test.describe('sending and the message list', () => {
  test('a message sent through the API is delivered and can be found, opened and resent in the dashboard', async ({ adminPage: page, admin, tenant, stack }) => {
    const domain = await createVerifiedDomain(admin, stack, tenant);
    const recipientDomain = createRecipientDomain(stack);
    const key = await createKeyThroughUi(page, unique('sender '));
    const subject = unique('Hello from the API ');

    const sent = await sendViaApi(stack, key, {
      from: `Sender <hello@${domain.name}>`,
      to: [`alice@${recipientDomain}`],
      subject,
      text: 'Plain text body of the e2e message.',
      html: '<h1>HTML heading</h1><p>HTML paragraph</p>',
      tags: ['e2e'],
    });
    expect(sent.status).toBe(202);
    expect(sent.body).toMatchObject({ status: 'queued', recipients: 1 });

    // It is in the list, becomes delivered, and the sink really received it.
    await page.goto('/messages');
    await waitForStatus(page, subject, 'delivered');
    const row = messageRow(page, subject);
    await expect(row).toContainText(`hello@${domain.name}`);
    await expect(row).toContainText(`alice@${recipientDomain}`);
    await expect.poll(() => stack.sink.received.some((m) => m.data.includes(`Subject: ${subject}`))).toBe(true);
    const received = stack.sink.received.find((m) => m.data.includes(`Subject: ${subject}`));
    expect(received.to).toEqual([`alice@${recipientDomain}`]);
    expect(received.data).toMatch(new RegExp(`^DKIM-Signature:[^]*?\\bd=${domain.name.replaceAll('.', '\\.')};`, 'm')); // signed at delivery with the domain's key

    // Detail page: status, events with the MX host, text view, sandboxed HTML view.
    await row.getByRole('link', { name: subject }).click();
    await expect(page.getByRole('heading', { name: subject, exact: true })).toBeVisible();
    await expect(page.locator('dl.kv').first()).toContainText('delivered');
    const timeline = page.getByRole('list', { name: 'Delivery events' });
    await expect(timeline.locator('[data-event-type="queued"]')).toBeVisible();
    await expect(timeline.locator('[data-event-type="delivered"]')).toContainText(`alice@${recipientDomain}`);
    await expect(timeline.locator('[data-event-type="delivered"]')).toContainText('mx.');
    await expect(page.getByTestId('text-view')).toHaveText('Plain text body of the e2e message.');

    await page.getByRole('tab', { name: /HTML/ }).click();
    const frame = page.frameLocator('iframe[title^="Message HTML"]');
    await expect(frame.getByRole('heading', { name: 'HTML heading' })).toBeVisible();
    // The frame is sandboxed without any flag.
    await expect(page.locator('iframe[title^="Message HTML"]')).toHaveAttribute('sandbox', '');

    // Resend queues a new message with the same content.
    const countBefore = stack.sink.received.length;
    await page.getByRole('button', { name: 'Resend', exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Resend message' }).click();
    await expect(page.getByText('Resend queued')).toBeVisible();
    await page.getByRole('link', { name: /^[0-9a-f]{32}$/ }).click();
    await expect(page.getByRole('heading', { name: subject, exact: true })).toBeVisible();
    await expect.poll(() => stack.sink.received.length).toBeGreaterThan(countBefore);
  });

  test('a recipient the remote server refuses ends as bounced, with the SMTP reply in the events, and the list filters work', async ({ adminPage: page, admin, tenant, stack }) => {
    const domain = await createVerifiedDomain(admin, stack, tenant);
    const recipientDomain = createRecipientDomain(stack);
    const key = (await admin.ok('POST', '/api/v1/api-keys', { name: 'bounce', scopes: ['send'] }, { tenantId: tenant.id })).key;
    const bounceSubject = unique('Will bounce ');
    const okSubject = unique('Will arrive ');
    for (const [subject, local] of [[bounceSubject, 'reject-me'], [okSubject, 'bob']]) {
      const r = await sendViaApi(stack, key, { from: `hello@${domain.name}`, to: [`${local}@${recipientDomain}`], subject, text: 'body' });
      expect(r.status).toBe(202);
    }

    await page.goto('/messages');
    await waitForStatus(page, bounceSubject, 'bounced');
    await waitForStatus(page, okSubject, 'delivered');

    await messageRow(page, bounceSubject).getByRole('link').click();
    const bounced = page.getByRole('list', { name: 'Delivery events' }).locator('[data-event-type="bounced"]');
    await expect(bounced).toContainText('550');
    await expect(bounced).toContainText('user unknown');

    // Filters: status, recipient, subject; clearing restores everything.
    await page.goto('/messages');
    await page.getByLabel('Status').selectOption('bounced');
    await search(page);
    await expect(messageRow(page, bounceSubject)).toBeVisible();
    await expect(messageRow(page, okSubject)).toHaveCount(0);
    await page.getByLabel('Status').selectOption('');
    await page.getByLabel('Recipient').fill(`bob@${recipientDomain}`);
    await search(page);
    await expect(messageRow(page, okSubject)).toBeVisible();
    await expect(messageRow(page, bounceSubject)).toHaveCount(0);
    await page.getByLabel('Recipient').fill('');
    await page.getByLabel('Subject contains').fill('no such subject at all');
    await search(page);
    await expect(page.getByText('No messages match')).toBeVisible();
    await page.getByRole('button', { name: 'Clear' }).click();
    await expect(messageRow(page, okSubject)).toBeVisible();
  });

  test('a message to many recipients shows how many there are, though the list carries only the first few', async ({ adminPage: page, admin, tenant, stack }) => {
    const domain = await createVerifiedDomain(admin, stack, tenant);
    const recipientDomain = createRecipientDomain(stack);
    const key = (await admin.ok('POST', '/api/v1/api-keys', { name: 'many', scopes: ['send'] }, { tenantId: tenant.id })).key;
    const subject = unique('Seven recipients ');
    const to = Array.from({ length: 7 }, (_, i) => `person${i}@${recipientDomain}`);
    expect((await sendViaApi(stack, key, { from: `hello@${domain.name}`, to, subject, text: 'x' })).body.recipients).toBe(7);

    await page.goto('/messages');
    await expect(async () => {
      await search(page);
      await expect(messageRow(page, subject)).toContainText('+6 more', { timeout: 2_000 });
    }).toPass({ timeout: 30_000 });
    await messageRow(page, subject).getByRole('link', { name: subject }).click();
    await expect(page.locator('dl.kv').first()).toContainText(`person6@${recipientDomain}`); // the detail lists everyone
  });

  test('the send page sends a message with an attachment through the API and links to it', async ({ adminPage: page, admin, tenant, stack }) => {
    const domain = await createVerifiedDomain(admin, stack, tenant);
    const recipientDomain = createRecipientDomain(stack);
    const subject = unique('From the form ');

    await page.goto('/send');
    await page.getByLabel('From', { exact: true }).fill(`Form Sender <form@${domain.name}>`);
    await page.getByLabel('To', { exact: true }).fill(`carol@${recipientDomain}, dave@${recipientDomain}`);
    await page.getByLabel('Subject').fill(subject);
    await page.getByLabel('Text body').fill('Sent from the dashboard.');
    await page.getByLabel('Tags (optional)').fill('e2e, form');
    await page.getByLabel('Attachments (optional)').setInputFiles({ name: 'note.txt', mimeType: 'text/plain', buffer: Buffer.from('attachment content') });
    await expect(page.getByRole('list', { name: 'Selected attachments' })).toContainText('note.txt');
    await page.getByRole('button', { name: 'Send message' }).click();

    const result = page.getByTestId('send-result');
    await expect(result).toContainText('Message accepted');
    await expect(result).toContainText('2 recipients');
    await result.getByRole('link').click();
    await expect(page.getByRole('heading', { name: subject, exact: true })).toBeVisible();
    await page.getByRole('tab', { name: /Attachments \(1\)/ }).click();
    await expect(page.getByRole('cell', { name: 'note.txt' })).toBeVisible();
    await expect(page.getByText('Attachment contents were not stored')).toBeVisible();
    await expect.poll(() => stack.sink.received.filter((m) => m.data.includes(`Subject: ${subject}`)).length).toBeGreaterThan(0);
    const received = stack.sink.received.find((m) => m.data.includes(`Subject: ${subject}`));
    expect(received.data).toContain('note.txt');
  });

  test('sending from a domain that is not verified is refused with a pointer to the domains page', async ({ adminPage: page, admin, tenant }) => {
    const domain = await admin.ok('POST', '/api/v1/domains', { name: `${unique('unverified')}.mail.test` }, { tenantId: tenant.id });
    await page.goto('/send');
    await page.getByLabel('From', { exact: true }).fill(`x@${domain.name}`);
    await page.getByLabel('To', { exact: true }).fill('someone@recipients.test');
    await page.getByLabel('Subject').fill('never sent');
    await page.getByLabel('Text body').fill('body');
    await page.getByRole('button', { name: 'Send message' }).click();
    await expect(page.getByText('The From domain is not verified')).toBeVisible();
    await page.getByRole('link', { name: 'Open the domains page' }).click();
    await expect(page.getByRole('heading', { name: 'Domains', exact: true })).toBeVisible();
  });

  test('client-side validation points at the field', async ({ adminPage: page }) => {
    await page.goto('/send');
    await page.getByRole('button', { name: 'Send message' }).click();
    await expect(page.locator('[aria-invalid="true"]').first()).toBeFocused();
  });
});
