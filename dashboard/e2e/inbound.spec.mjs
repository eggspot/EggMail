import { createVerifiedDomain, expect, publishDomainRecords, test, unique } from './support/fixtures.mjs';
import { sampleMessage, seedInboundMessage } from './support/inboundSeed.mjs';

// Inbound mail in the real dashboard against a real server: turning a domain on, the MX guidance and its check, routes, and reading received mail
// (including hostile mail under the strict CSP). Mail is placed in the queue file the way the receive path leaves it (support/inboundSeed.mjs), so the
// specs are about what the tenant sees and does; the route actions run in the real server (the retry below is a real webhook delivery).

const SERVER_HOST = 'mta.eggmail.test';

async function enabledDomain(admin, stack, tenant, prefix = 'inb') {
  const domain = await createVerifiedDomain(admin, stack, tenant, prefix);
  await admin.ok('PATCH', `/api/v1/domains/${domain.id}/inbound`, { enabled: true }, { tenantId: tenant.id });
  return domain;
}

const rowOf = (page, text) => page.getByRole('row').filter({ hasText: text });

test.describe('inbound mail', () => {
  test('a domain is turned on, the MX is explained and checked, and the page is shown only while the server accepts inbound mail', async ({ adminPage: page, admin, tenant, stack }) => {
    const domain = await createVerifiedDomain(admin, stack, tenant, 'inb');
    const verifiedAt = Date.now();

    // The navigation has the page because the server accepts inbound mail.
    await page.goto(`/domains/${domain.id}`);
    await expect(page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Inbound mail' })).toBeVisible();
    await page.getByRole('link', { name: 'Open the inbound settings' }).click();

    await expect(page.getByRole('heading', { name: `Inbound mail: ${domain.name}` })).toBeVisible();
    await page.getByLabel('Receive mail for this domain').check();
    await page.getByLabel('When a message fails DMARC').selectOption('flag');
    await page.getByLabel('Keep received mail (days)').fill('14');
    await page.getByRole('button', { name: 'Save settings' }).click();
    await expect(page.getByText('Settings saved.')).toBeVisible();
    await expect(page.getByText('Receiving', { exact: true })).toBeVisible();

    // What applies: the typed value shows in the stored settings of the API.
    const stored = await admin.ok('GET', `/api/v1/domains/${domain.id}/inbound`, undefined, { tenantId: tenant.id });
    expect(stored).toMatchObject({ enabled: true, dmarcAction: 'flag', retentionDays: 14 });

    // The MX to publish, with the host of this server.
    await expect(page.getByTestId('mx-host')).toHaveText(domain.name);
    await expect(page.getByTestId('mx-value')).toHaveText(`10 ${SERVER_HOST}`);
    await expect(page.getByText(/port 25 must be reachable/)).toBeVisible();

    // The domain page lists the record, and "Check DNS" sees it once it is published.
    await page.goto(`/domains/${domain.id}`);
    const mxRow = page.locator('.dns-table tbody tr').filter({ hasText: 'Inbound MX' });
    await expect(mxRow).toBeVisible();
    await expect(mxRow).toContainText(`10 ${SERVER_HOST}`);
    publishDomainRecords(stack.dns, await admin.ok('GET', `/api/v1/domains/${domain.id}`, undefined, { tenantId: tenant.id }), { only: ['inbound_mx'] });
    // A check is limited to once per 30 seconds per domain, and the domain was verified a moment ago.
    await page.waitForTimeout(Math.max(0, 31_000 - (Date.now() - verifiedAt)));
    await page.getByRole('button', { name: /Check DNS/ }).click();
    await expect(mxRow).toContainText('OK', { timeout: 30_000 });
  });

  test('routes are added, tried, reordered, disabled and deleted; a forward needs valid addresses', async ({ adminPage: page, admin, tenant, stack }) => {
    const domain = await enabledDomain(admin, stack, tenant);
    await page.goto(`/domains/${domain.id}/inbound`);
    await expect(page.getByText('No routes yet')).toBeVisible();

    // A catch-all that stores, last.
    await page.getByRole('button', { name: 'Add route' }).first().click();
    let dialog = page.getByRole('dialog');
    await dialog.getByLabel('Name', { exact: true }).fill('Everything');
    await dialog.getByLabel('Matches').selectOption('catch_all');
    await dialog.getByLabel('Order').fill('1000');
    await dialog.getByRole('button', { name: 'Add route' }).click();
    await expect(rowOf(page, 'Everything')).toBeVisible();

    // An address route that discards, first. The client checks the fields before asking.
    await page.getByRole('button', { name: 'Add route' }).first().click();
    dialog = page.getByRole('dialog');
    await dialog.getByLabel('Name', { exact: true }).fill('Spam trap');
    await dialog.getByLabel('Address (before the @)').fill('has space');
    await dialog.getByLabel('Then').selectOption('discard');
    await dialog.getByRole('button', { name: 'Add route' }).click();
    await expect(dialog.getByText(/Use the part before the @ only/)).toBeVisible();
    await dialog.getByLabel('Address (before the @)').fill('Trap');
    await dialog.getByLabel('Order').fill('10');
    await dialog.getByRole('button', { name: 'Add route' }).click();
    await expect(rowOf(page, 'Spam trap')).toBeVisible();

    // The server's check shows next to the field: a forward must not stay on a domain the server receives for.
    await page.getByRole('button', { name: 'Add route' }).first().click();
    dialog = page.getByRole('dialog');
    await dialog.getByLabel('Name', { exact: true }).fill('Loop');
    await dialog.getByLabel('Matches').selectOption('catch_all');
    await dialog.getByLabel('Then').selectOption('forward');
    await dialog.getByLabel('Forward to').fill('not an address');
    await dialog.getByRole('button', { name: 'Add route' }).click();
    await expect(dialog.getByText(/is not a valid address/)).toBeVisible();
    await dialog.getByLabel('Forward to').fill(`someone@${domain.name}`);
    await dialog.getByRole('button', { name: 'Add route' }).click();
    await expect(dialog.getByRole('alert')).toContainText('route was not saved');
    await dialog.getByRole('button', { name: 'Cancel' }).click();

    // Evaluation order: the trap (10) before the catch-all (1000).
    const names = await page.locator('table tbody tr td:nth-child(2)').allInnerTexts();
    expect(names.indexOf('Spam trap')).toBeLessThan(names.indexOf('Everything'));

    // Try an address: the trap takes it; another address falls through to the catch-all.
    await page.getByLabel('Address', { exact: true }).fill('TRAP');
    await page.getByRole('button', { name: 'Test' }).click();
    await expect(page.getByTestId('probe-result')).toContainText('Spam trap');
    await page.getByLabel('Address', { exact: true }).fill('trap+x');   // plus addressing was not asked for
    await page.getByRole('button', { name: 'Test' }).click();
    await expect(page.getByTestId('probe-result')).toContainText('Everything');
    await page.getByLabel('Address', { exact: true }).fill('anyone');
    await page.getByRole('button', { name: 'Test' }).click();
    await expect(page.getByTestId('probe-result')).toContainText('Everything');

    // Disable, edit and delete.
    await page.getByRole('button', { name: 'Disable route Spam trap' }).click();
    await expect(rowOf(page, 'Spam trap')).toContainText('Disabled');
    await page.getByRole('button', { name: 'Edit route Everything' }).click();
    dialog = page.getByRole('dialog');
    await dialog.getByLabel('Then').selectOption('store');
    await dialog.getByRole('button', { name: 'Save route' }).click();
    await expect(rowOf(page, 'Everything')).toContainText('store');
    await page.getByRole('button', { name: 'Delete route Spam trap' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Delete route' }).click();
    await expect(rowOf(page, 'Spam trap')).toHaveCount(0);
    const routes = await admin.ok('GET', `/api/v1/domains/${domain.id}/inbound/routes`, undefined, { tenantId: tenant.id });
    expect(routes.map((r) => r.name)).toEqual(['Everything']);
  });

  test('received mail is listed, searched and read: checks, headers, the text, the sandboxed HTML, an attachment and the whole message', async ({ adminPage: page, admin, tenant, stack }) => {
    const domain = await enabledDomain(admin, stack, tenant);
    const route = await admin.ok('POST', `/api/v1/domains/${domain.id}/inbound/routes`, { name: 'Keep', match: { kind: 'catch_all' }, action: { kind: 'store' } }, { tenantId: tenant.id });
    const subject = unique('Report ');
    const to = `support@${domain.name}`;
    const id = seedInboundMessage(stack, { tenantId: tenant.id, domainId: domain.id, domain: domain.name, to, subject, route: route.id, raw: sampleMessage({ to, subject }), auth: { dmarc: 'fail' }, flagged: true });
    seedInboundMessage(stack, { tenantId: tenant.id, domainId: domain.id, domain: domain.name, to: `other@${domain.name}`, from: 'bob@elsewhere.test', subject: unique('Other '), route: route.id, raw: sampleMessage({ subject: 'Other' }) });

    await page.goto('/inbound');
    await expect(page.getByTestId('inbound-usage')).toContainText('2');
    const row = rowOf(page, subject);
    await expect(row).toContainText('DMARC flagged');
    await expect(row).toContainText('DMARC fail');
    await expect(row).toContainText('Store: done');

    // Search by recipient narrows the list.
    await page.getByLabel('Recipient').fill(to);
    await page.getByRole('button', { name: 'Search' }).click();
    await expect(rowOf(page, subject)).toBeVisible();
    await expect(rowOf(page, 'Other')).toHaveCount(0);

    await page.getByRole('link', { name: subject }).click();
    await expect(page).toHaveURL(new RegExp(`/inbound/messages/${id}$`));
    await expect(page.getByText("Flagged: failed the sender's DMARC policy")).toBeVisible();
    await expect(page.getByTestId('text-view')).toContainText('the report is attached');
    await expect(page.getByText('203.0.113.9 (said mail.sender.test)')).toBeVisible();

    // The HTML only renders in the empty sandbox.
    await page.getByRole('tab', { name: 'HTML (sandboxed)' }).click();
    const frame = page.locator('iframe.html-frame');
    await expect(frame).toHaveAttribute('sandbox', '');
    await expect(page.frameLocator('iframe.html-frame').locator('body')).toContainText('the report is attached');

    await page.getByRole('tab', { name: /Headers/ }).click();
    await expect(page.getByRole('row').filter({ hasText: 'Message-ID' })).toContainText('<e2e-1@sender.test>');

    // The attachment is saved, not opened; so is the whole message.
    await page.getByRole('tab', { name: /Attachments/ }).click();
    const [attachment] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Download report.pdf' }).click()]);
    expect(attachment.suggestedFilename()).toBe('report.pdf');
    const [whole] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Download message (.eml)' }).click()]);
    expect(whole.suggestedFilename()).toBe(`${id}.eml`);
  });

  test('hostile mail is shown as text, never as markup, and its HTML cannot reach the page', async ({ adminPage: page, admin, tenant, stack, allowProblems }) => {
    // The browser reports (as a console error) that it refused the remote image of the sandboxed message: that is the protection working.
    allowProblems.push(/Refused to load the image|tracker\.invalid|Content Security Policy/);
    const domain = await enabledDomain(admin, stack, tenant);
    const subject = '<img src=x onerror=window.__pwned=1> <script>window.__pwned=2</script>';
    const to = `support@${domain.name}`;
    const html = '<script>parent.__pwned=3</script><img src="https://tracker.invalid/p.gif"><a href="javascript:parent.__pwned=4">x</a><form action="https://evil.invalid"><input name=a></form>hostile html';
    const id = seedInboundMessage(stack, {
      tenantId: tenant.id, domainId: domain.id, domain: domain.name, to, from: '"><script>window.__pwned=5</script>@sender.test', subject,
      raw: sampleMessage({ to, subject, text: '<b>not bold</b> <img src=x onerror=window.__pwned=6>', html }),
    });

    await page.goto('/inbound');
    await expect(page.getByRole('link', { name: subject })).toBeVisible();
    await page.goto(`/inbound/messages/${id}`);
    await expect(page.getByRole('heading', { name: subject })).toBeVisible();
    await expect(page.getByTestId('text-view')).toHaveText(/<b>not bold<\/b> <img src=x onerror=window.__pwned=6>/);
    await page.getByRole('tab', { name: 'HTML (sandboxed)' }).click();
    await expect(page.frameLocator('iframe.html-frame').locator('body')).toContainText('hostile html');

    // Nothing of the message became an element of the page, and no script of it ran anywhere.
    await expect(page.locator('main img, main script, main form')).toHaveCount(0);
    expect(await page.evaluate(() => window.__pwned)).toBeUndefined();
    await page.getByRole('tab', { name: /Headers/ }).click();
    await expect(page.getByRole('table', { name: 'Header fields of the stored message' })).toContainText('<script>');
  });

  test('a failed webhook action is explained and retried: the receiver gets the message as a new, signed event', async ({ adminPage: page, admin, tenant, stack }) => {
    await admin.ok('PUT', '/api/v1/settings', { values: { 'Webhooks:AllowedNetworks': '127.0.0.0/8' } }, { tenantId: tenant.id });
    const domain = await enabledDomain(admin, stack, tenant);
    const url = `${stack.webhooks.url}?inbound=${unique('')}`;
    stack.webhooks.respondWith(200);
    const endpoint = await admin.ok('POST', '/api/v1/webhooks', { url, event_types: ['inbound.action.failed'] }, { tenantId: tenant.id });
    const route = await admin.ok('POST', `/api/v1/domains/${domain.id}/inbound/routes`, { name: 'Hook', match: { kind: 'catch_all' }, action: { kind: 'webhook', webhookEndpointId: endpoint.id, webhookFormat: 'json' } }, { tenantId: tenant.id });
    const to = `support@${domain.name}`;
    const subject = unique('Retry ');
    const id = seedInboundMessage(stack, {
      tenantId: tenant.id, domainId: domain.id, domain: domain.name, to, subject, route: route.id, raw: sampleMessage({ to, subject }),
      action: { kind: 'webhook', state: 'failed', attempts: 8, error: 'webhook_http_503' },
    });
    const received = () => stack.webhooks.requests.filter((r) => r.url === new URL(url).pathname + new URL(url).search && r.body.includes(id));

    await page.goto(`/inbound/messages/${id}`);
    await expect(page.getByText('The action failed')).toBeVisible();
    await expect(page.getByText('The receiver answered HTTP 503.')).toBeVisible();
    await page.getByRole('button', { name: 'Retry the action' }).click();

    // The real runner of the server picks it up and posts it; the page, reloaded, shows it done.
    await expect.poll(() => received().length, { timeout: 60_000 }).toBeGreaterThan(0);
    const request = received().at(-1);
    expect(request.headers['webhook-id']).toBe(`evt_${id}-1`);   // a manual retry is a new event
    const payload = JSON.parse(request.body);
    expect(payload.type).toBe('inbound.message.received');
    expect(payload.data.inbound_id).toBe(id);
    expect(payload.data.attachments[0].url).toBe(`/api/v1/inbound/messages/${id}/attachments/0`);
    await expect(async () => {
      await page.reload();
      await expect(page.getByRole('cell', { name: 'done' }).or(page.locator('dd .chip', { hasText: 'done' }))).toBeVisible({ timeout: 2_000 });
    }).toPass({ timeout: 30_000 });
  });

  test('messages are deleted one by one, and by filter only after typing the word', async ({ adminPage: page, admin, tenant, stack }) => {
    const domain = await enabledDomain(admin, stack, tenant);
    const to = `support@${domain.name}`;
    const first = seedInboundMessage(stack, { tenantId: tenant.id, domainId: domain.id, domain: domain.name, to, from: 'erase-me@sender.test', subject: unique('Gone1 '), raw: sampleMessage({ to }) });
    seedInboundMessage(stack, { tenantId: tenant.id, domainId: domain.id, domain: domain.name, to, from: 'erase-me@sender.test', subject: unique('Gone2 '), raw: sampleMessage({ to }) });
    seedInboundMessage(stack, { tenantId: tenant.id, domainId: domain.id, domain: domain.name, to, from: 'keep-me@sender.test', subject: unique('Stay '), raw: sampleMessage({ to }) });

    await page.goto('/inbound');
    await expect(page.getByRole('button', { name: 'Delete matching messages' })).toHaveCount(0);   // no filter: no way to empty everything
    await page.getByLabel('Sender').fill('erase-me@sender.test');
    await page.getByRole('button', { name: 'Search' }).click();
    await expect(page.getByRole('link', { name: /Gone/ })).toHaveCount(2);
    await page.getByRole('button', { name: 'Delete matching messages' }).click();
    const confirm = page.getByRole('dialog').getByRole('button', { name: 'Delete messages' });
    await expect(confirm).toBeDisabled();
    await page.getByLabel('Type "delete" to confirm').fill('delete');
    await confirm.click();
    await expect(page.getByText('2 messages were deleted.')).toBeVisible();
    await expect(page.getByRole('link', { name: /Gone/ })).toHaveCount(0);

    // The other sender's message is still there, and one message can be deleted from its own page.
    await page.getByRole('button', { name: 'Clear' }).click();
    await expect(page.getByRole('link', { name: /Stay/ })).toBeVisible();
    await page.getByRole('link', { name: /Stay/ }).click();
    await page.getByRole('button', { name: 'Delete', exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Delete message' }).click();
    await expect(page).toHaveURL(/\/inbound$/);
    await expect(page.getByText('No received messages')).toBeVisible();
    expect((await admin.request('GET', `/api/v1/inbound/messages/${first}`, undefined, { tenantId: tenant.id })).status).toBe(404);
  });

  test("another tenant's mail is not served", async ({ adminPage: page, admin, tenant, stack }) => {
    const domain = await enabledDomain(admin, stack, tenant);
    const to = `support@${domain.name}`;
    const id = seedInboundMessage(stack, { tenantId: tenant.id, domainId: domain.id, domain: domain.name, to, subject: unique('Mine '), raw: sampleMessage({ to }) });
    const other = await admin.ok('POST', '/api/v1/admin/tenants', { name: unique('Other ') });

    // Acting as another tenant, the message is a plain 404 (never 403) and the list is empty.
    const asOther = await admin.request('GET', `/api/v1/inbound/messages/${id}`, undefined, { tenantId: other.id });
    expect(asOther.status).toBe(404);
    const list = await admin.ok('GET', '/api/v1/inbound/messages', undefined, { tenantId: other.id });
    expect(list.items).toEqual([]);
    await page.goto(`/inbound/messages/${id}`);
    await expect(page.getByRole('heading', { name: /Mine/ })).toBeVisible();
  });
});
