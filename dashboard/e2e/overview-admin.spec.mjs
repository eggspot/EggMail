import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRecipientDomain, createVerifiedDomain, expect, sendViaApi, test, unique } from './support/fixtures.mjs';

/** A fresh self-signed certificate and key (PEM) from the openssl command line. */
function makeCertificate(commonName) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eggmail-e2e-cert-'));
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '30', '-subj', `/CN=${commonName}`, '-addext', `subjectAltName=DNS:${commonName}`,
      '-keyout', path.join(dir, 'key.pem'), '-out', path.join(dir, 'cert.pem')], { stdio: 'ignore' });
    return { certificate: fs.readFileSync(path.join(dir, 'cert.pem'), 'utf8'), key: fs.readFileSync(path.join(dir, 'key.pem'), 'utf8') };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test.describe('overview and statistics', () => {
  test('delivered and bounced mail shows in the counters, the recent events and the per-domain table', async ({ adminPage: page, admin, tenant, stack }) => {
    const domain = await createVerifiedDomain(admin, stack, tenant);
    const recipientDomain = createRecipientDomain(stack, 'stats');
    const key = (await admin.ok('POST', '/api/v1/api-keys', { name: 'stats', scopes: ['send', 'read'] }, { tenantId: tenant.id })).key;
    for (const local of ['one', 'two', 'reject-three']) {
      const r = await sendViaApi(stack, key, { from: `hello@${domain.name}`, to: [`${local}@${recipientDomain}`], subject: unique('Stats '), text: 'x' });
      expect(r.status).toBe(202);
    }

    const counter = (label) => page.locator('.stat').filter({ has: page.locator('.stat-label', { hasText: new RegExp(`^${label}$`) }) }).locator('.stat-value');
    await page.goto('/');
    await expect(async () => {
      await page.reload();
      await expect(counter('Accepted')).toHaveText('3', { timeout: 2_000 });
      await expect(counter('Delivered')).toHaveText('2', { timeout: 2_000 });
      await expect(counter('Bounced')).toHaveText('1', { timeout: 2_000 });
    }).toPass({ timeout: 60_000, intervals: [1000, 2000] });
    const recent = page.getByRole('table', { name: 'Recent delivery events, newest first' });
    await expect(recent.getByRole('row').filter({ hasText: 'delivered' })).toHaveCount(2);
    await expect(recent.getByRole('row').filter({ hasText: 'bounced' })).toHaveCount(1);
    await expect(recent).toContainText(recipientDomain);
    // The server's ring of recent events records no sending domain, so the dashboard has no such column.
    await expect(recent.getByRole('columnheader', { name: 'Sending domain' })).toHaveCount(0);
    await expect(page.getByRole('img', { name: /Messages per hour/ })).toBeVisible();

    // Statistics: the same numbers by recipient domain, filterable by sending domain.
    await page.goto('/statistics');
    const byDomain = page.getByRole('table', { name: 'Statistics by recipient domain' });
    const row = byDomain.getByRole('row').filter({ hasText: recipientDomain });
    await expect(row).toBeVisible();
    // Cells after the row header: accepted, delivered, deferred, bounced, complaints, delivery rate.
    await expect(row.getByRole('cell').nth(0)).toHaveText('3');
    await expect(row.getByRole('cell').nth(1)).toHaveText('2');
    await expect(row.getByRole('cell').nth(3)).toHaveText('1');
    await page.getByLabel('Sending domain').selectOption(domain.name);
    await expect(byDomain.getByRole('row').filter({ hasText: recipientDomain })).toBeVisible();
    await page.getByLabel('Period').selectOption('400d');
    await expect(page.getByLabel('Hourly')).toBeDisabled();
    await expect(byDomain.getByRole('row').filter({ hasText: recipientDomain })).toBeVisible();
  });
});

test.describe('server administration', () => {
  test('the status page shows the server, queue, storage health and certificates, and runs maintenance', async ({ adminPage: page }) => {
    await page.goto('/admin/status');
    await expect(page.getByRole('heading', { name: 'Server status', exact: true })).toBeVisible();
    const server = page.locator('section.card').filter({ has: page.getByRole('heading', { name: 'Server', exact: true }) });
    await expect(server).toContainText('0.1.0');
    await expect(server).toContainText('sqlite');
    await expect(page.locator('section.card').filter({ has: page.getByRole('heading', { name: 'Storage health' }) })).toContainText('healthy');
    await expect(page.getByRole('table', { name: 'Certificate expiry' })).toContainText('CN=mta.eggmail.test');
    await expect(page.getByText(/No maintenance run since the server started|finished/)).toBeVisible();

    await page.getByRole('button', { name: 'Run maintenance now' }).click();
    await expect(page.getByText(/Maintenance run started|Maintenance is already running/)).toBeVisible();
    await expect(page.getByRole('table', { name: 'Maintenance jobs of the last run' })).toBeVisible({ timeout: 60_000 });
    await expect(page.locator('.chip', { hasText: 'finished' })).toBeVisible();
  });

  test('certificates: a PEM upload is installed and becomes the active one; a wrong key, a duplicate and ACME without configuration are refused clearly', async ({ adminPage: page }) => {
    const first = makeCertificate(`${unique('up')}.certs.test`);
    const other = makeCertificate(`${unique('other')}.certs.test`);
    await page.goto('/admin/certificates');
    await expect(page.getByText('A self-signed certificate is in use')).toBeVisible();
    await expect(page.getByText('No certificate was requested through ACME yet.')).toBeVisible();

    // Client-side checks first.
    await page.getByRole('button', { name: 'Upload certificate' }).click();
    await expect(page.getByText('Paste a PEM certificate')).toBeVisible();

    // A key that does not belong to the certificate is refused by the server.
    await page.getByLabel('Certificate chain (PEM)').fill(first.certificate);
    await page.getByLabel('Private key (PEM)').fill(other.key);
    await page.getByRole('button', { name: 'Upload certificate' }).click();
    await expect(page.getByRole('alert').first()).toBeVisible();

    await page.getByLabel('Private key (PEM)').fill(first.key);
    await page.getByRole('button', { name: 'Upload certificate' }).click();
    await expect(page.getByText(/^Uploaded CN=.*certs\.test/)).toBeVisible();
    const installed = page.getByRole('table', { name: 'Installed certificates' });
    const row = installed.getByRole('row').filter({ hasText: '.certs.test' });
    await expect(row).toContainText('uploaded');
    await expect(row).toContainText('active');
    await expect(page.getByText('A self-signed certificate is in use')).toHaveCount(0);
    // The private key does not stay in the form.
    await expect(page.getByLabel('Private key (PEM)')).toHaveValue('');

    // Uploading the same certificate twice is a conflict.
    await page.getByLabel('Certificate chain (PEM)').fill(first.certificate);
    await page.getByLabel('Private key (PEM)').fill(first.key);
    await page.getByRole('button', { name: 'Upload certificate' }).click();
    await expect(page.getByRole('alert').first()).toBeVisible();

    // ACME is not configured on this server: a clear refusal, not a crash.
    await page.getByLabel('Host names').fill('mail.certs.test');
    await page.getByRole('button', { name: 'Request certificate' }).click();
    await expect(page.getByRole('alert').filter({ hasText: /not ready|ACME|configured/i }).first()).toBeVisible();
  });

  test('the sidebar and pages differ by role, and an unknown route has a way back', async ({ adminPage: page }) => {
    await page.goto('/');
    const nav = page.getByRole('navigation', { name: 'Main' });
    for (const name of ['Overview', 'Messages', 'Send test', 'Domains', 'Webhooks', 'Suppressions', 'API keys and SMTP', 'Statistics', 'Settings', 'Tenants', 'Server status', 'Certificates', 'Storage switch']) {
      await expect(nav.getByRole('link', { name })).toBeVisible();
    }
    await page.goto('/no/such/page');
    await expect(page.getByText('Page not found')).toBeVisible();
    await page.getByRole('link', { name: 'Go to the overview' }).click();
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
  });
});
