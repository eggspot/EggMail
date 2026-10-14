import { createRecipientDomain, createVerifiedDomain, expect, sendViaApi, test, unique } from './support/fixtures.mjs';

const search = async (page) => page.getByRole('button', { name: 'Search' }).click();
const messageRow = (page, subject) => page.getByRole('row').filter({ has: page.getByRole('link', { name: subject }) });

/** Re-runs the search until the message shows the wanted status (delivery is asynchronous). */
async function waitForStatus(page, subject, status) {
  await expect(async () => {
    await search(page);
    await expect(messageRow(page, subject)).toContainText(status, { timeout: 2_000 });
  }).toPass({ timeout: 60_000, intervals: [500, 1000, 2000] });
}

/** A sender key and a domain for a fresh tenant; recipients "defer..." are answered 451 by the sink and stay in the queue for a long time. */
async function setUp(admin, tenant, stack) {
  const domain = await createVerifiedDomain(admin, stack, tenant);
  const recipientDomain = createRecipientDomain(stack);
  const key = (await admin.ok('POST', '/api/v1/api-keys', { name: unique('cancel '), scopes: ['send', 'read'] }, { tenantId: tenant.id })).key;
  return { domain, recipientDomain, key };
}

test.describe('cancelling a queued message', () => {
  test('a deferred message is cancelled from its detail page and is never sent', async ({ adminPage: page, admin, tenant, stack }) => {
    const { domain, recipientDomain, key } = await setUp(admin, tenant, stack);
    const subject = unique('Cancel me ');
    const sent = await sendViaApi(stack, key, { from: `hello@${domain.name}`, to: [`defer1@${recipientDomain}`], subject, text: 'never delivered' });
    expect(sent.status).toBe(202);

    await page.goto('/messages');
    await waitForStatus(page, subject, 'deferred');
    await messageRow(page, subject).getByRole('link', { name: subject }).click();
    await expect(page.getByRole('heading', { name: subject, exact: true })).toBeVisible();

    // The button is offered, the dialog asks first, and dismissing it changes nothing.
    await page.getByRole('button', { name: 'Cancel delivery', exact: true }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText(`defer1@${recipientDomain}`);
    await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.locator('dl.kv').first()).toContainText('deferred');

    await page.getByRole('button', { name: 'Cancel delivery', exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel delivery to 1 recipient' }).click();

    await expect(page.getByTestId('cancel-result')).toContainText('Delivery cancelled for 1 recipient');
    await expect(page.locator('dl.kv').first()).toContainText('cancelled');
    const timeline = page.getByRole('list', { name: 'Delivery events' });
    await expect(timeline.locator('[data-event-type="cancelled"]')).toContainText(`defer1@${recipientDomain}`);
    await expect(page.getByRole('button', { name: 'Cancel delivery', exact: true })).toHaveCount(0); // nothing left to cancel

    // The server agrees: a second cancel is a conflict, the list shows the status, and the sink never saw the message.
    const again = await admin.request('POST', `/api/v1/messages/${new URL(page.url()).pathname.split('/').pop()}/cancel`, undefined, { tenantId: tenant.id });
    expect(again.status).toBe(409);
    await page.goto('/messages');
    await page.getByLabel('Status').selectOption('cancelled');
    await search(page);
    await expect(messageRow(page, subject)).toBeVisible();
    expect(stack.sink.received.some((m) => m.data.includes(`Subject: ${subject}`))).toBe(false);
  });

  test('one recipient of several is cancelled and the others keep waiting', async ({ adminPage: page, admin, tenant, stack }) => {
    const { domain, recipientDomain, key } = await setUp(admin, tenant, stack);
    const subject = unique('Cancel one ');
    const keep = `defer-keep@${recipientDomain}`;
    const drop = `defer-drop@${recipientDomain}`;
    expect((await sendViaApi(stack, key, { from: `hello@${domain.name}`, to: [keep, drop], subject, text: 'x' })).status).toBe(202);

    await page.goto('/messages');
    await waitForStatus(page, subject, 'deferred');
    await messageRow(page, subject).getByRole('link', { name: subject }).click();

    await page.getByRole('button', { name: 'Cancel delivery', exact: true }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByRole('checkbox')).toHaveCount(2);
    await dialog.getByRole('checkbox', { name: keep }).uncheck();
    await dialog.getByRole('button', { name: 'Cancel delivery to 1 recipient' }).click();

    await expect(page.getByTestId('cancel-result')).toContainText(drop);
    const timeline = page.getByRole('list', { name: 'Delivery events' });
    await expect(timeline.locator('[data-event-type="cancelled"]')).toHaveCount(1);
    await expect(timeline.locator('[data-event-type="cancelled"]')).toContainText(drop);
    // The message is still waiting for the other recipient, which can be cancelled in turn.
    await expect(page.locator('dl.kv').first()).toContainText('deferred');
    await page.getByRole('button', { name: 'Cancel delivery', exact: true }).click();
    const second = page.getByRole('dialog');
    await expect(second).toContainText(keep);
    await expect(second.getByRole('checkbox')).toHaveCount(0);
    await second.getByRole('button', { name: 'Cancel delivery to 1 recipient' }).click();
    await expect(page.locator('dl.kv').first()).toContainText('cancelled');
  });

  test('a key without the send scope cannot cancel, and a key of another tenant finds no such message', async ({ admin, tenant, stack }) => {
    const { domain, recipientDomain, key } = await setUp(admin, tenant, stack);
    const sent = await sendViaApi(stack, key, { from: `hello@${domain.name}`, to: [`defer-iso@${recipientDomain}`], subject: unique('Isolated '), text: 'x' });
    expect(sent.status).toBe(202);
    const id = sent.body.id;

    const readOnly = (await admin.ok('POST', '/api/v1/api-keys', { name: 'read only', scopes: ['read'] }, { tenantId: tenant.id })).key;
    const denied = await fetch(`${stack.baseURL}/api/v1/messages/${id}/cancel`, { method: 'POST', headers: { authorization: `Bearer ${readOnly}` } });
    expect(denied.status).toBe(403);

    const other = await admin.ok('POST', '/api/v1/admin/tenants', { name: unique('Other ') });
    const otherKey = (await admin.ok('POST', '/api/v1/api-keys', { name: 'other', scopes: ['send', 'read'] }, { tenantId: other.id })).key;
    const foreign = await fetch(`${stack.baseURL}/api/v1/messages/${id}/cancel`, { method: 'POST', headers: { authorization: `Bearer ${otherKey}` } });
    expect(foreign.status).toBe(404);
    expect((await foreign.json()).code).toBe('message_not_found');
  });
});
