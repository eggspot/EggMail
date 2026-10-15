import { createHash, generateKeyPairSync } from 'node:crypto';
import http from 'node:http';
import { ADMIN_PASSWORD, ADMIN_USER, attachServerLogOnFailure, expect, publishDomainRecords, signInThroughForm, test as base, unique } from './support/fixtures.mjs';
import { ApiClient } from './support/apiClient.mjs';
import { startStack } from './support/stack.mjs';

// Besides the shared server, this spec starts a second one with Domains:Bootstrap and MTA-STS serving on, with its own fake DNS.
const test = base.extend({
  boot: [
    async ({}, use) => {
      const stack = await startStack({
        name: 'bootstrap',
        extraArgs: ['--Domains:Bootstrap=boot1.mail.test, boot2.mail.test', '--Domains:MtaStsMode=Testing', '--Domains:DmarcReportAddress=reports@{domain}', '--Delivery:PublicSendingIp=192.0.2.10'],
      });
      await use(stack);
      await stack.stop();
    },
    { scope: 'worker', timeout: 240_000 },
  ],
  bootLog: [
    async ({ boot }, use, testInfo) => {
      await use();
      await attachServerLogOnFailure(testInfo, boot, 'bootstrap-server.log');
    },
    { auto: true },
  ],
});

const recordRow = (page, purpose) => page.locator('.dns-table tbody tr:not(.dns-detail)').filter({ has: page.getByRole('cell', { name: purpose, exact: true }) });
const chip = (page, purpose, text) => recordRow(page, purpose).locator('.chip', { hasText: text });

/** A real RSA-2048 public key (base64 SubjectPublicKeyInfo) that is not the domain's. */
function otherDkimValue() {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return `v=DKIM1; k=rsa; p=${publicKey.export({ type: 'spki', format: 'der' }).toString('base64')}`;
}

/** How many log entries (lines of the JSON console log) contain the text. */
const timesLogged = (log, text) => log.split('\n').filter((line) => line.includes(text)).length;

/** GET with a chosen Host header on the dashboard listener (fetch does not allow it). */
function getWithHost(stack, host, path) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: stack.httpPort, path, method: 'GET', headers: { host } }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => (body += c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

test.describe('adding a domain: the records, the check and the ready-to-send state', () => {
  test('every record published: each one is OK and the domain is ready to send', async ({ adminPage: page, admin, tenant, stack }) => {
    const domain = await admin.ok('POST', '/api/v1/domains', { name: `${unique('full')}.mail.test` }, { tenantId: tenant.id });
    expect(domain.records.map((r) => r.purpose)).toEqual(['dkim', 'return_path', 'spf', 'dmarc', 'tls_rpt', 'bounce_mx', 'ptr']);
    publishDomainRecords(stack.dns, domain);
    await page.goto(`/domains/${domain.id}`);
    await expect(page.getByTestId('ready-state')).toHaveText('Not ready to send');

    await page.getByRole('button', { name: 'Check DNS' }).click();

    await expect(page.getByTestId('ready-state')).toHaveText('Ready to send');
    for (const purpose of ['DKIM', 'Return-path', 'SPF', 'DMARC', 'TLS-RPT', 'Bounce MX', 'Reverse DNS']) await expect(chip(page, purpose, 'OK')).toBeVisible();
    await expect(page.getByTestId('record-progress')).toContainText('Required records: 2 of 2 published. Recommended records: 5 of 5 published.');
    await expect(page.getByRole('heading', { name: domain.name, exact: true }).locator('xpath=ancestor::header')).toContainText('Verified');
    // Each row says whether the record is required or only recommended.
    await expect(recordRow(page, 'DKIM').getByTestId('dns-level')).toHaveText('Required');
    await expect(recordRow(page, 'TLS-RPT').getByTestId('dns-level')).toHaveText('Recommended');
  });

  test('a record with another value shows mismatch, a malformed one invalid, with found next to expected', async ({ adminPage: page, admin, tenant, stack }) => {
    const domain = await admin.ok('POST', '/api/v1/domains', { name: `${unique('bad')}.mail.test` }, { tenantId: tenant.id });
    publishDomainRecords(stack.dns, domain, { only: ['return_path', 'bounce_mx'] });
    const otherKey = otherDkimValue();
    stack.dns.setTxt(domain.records[0].host, otherKey); // a DKIM key, but not ours
    stack.dns.setTxt(domain.name, 'v=spf1 include:_spf.elsewhere.test ~all'); // another sender: ours is missing from it
    stack.dns.setTxt(`_dmarc.${domain.name}`, 'v=DMARC1; p=sometimes'); // not a policy
    await page.goto(`/domains/${domain.id}`);
    await page.getByRole('button', { name: 'Check DNS' }).click();

    await expect(chip(page, 'DKIM', 'Mismatch')).toBeVisible();
    await expect(chip(page, 'SPF', 'Mismatch')).toBeVisible();
    await expect(chip(page, 'DMARC', 'Invalid')).toBeVisible();
    await expect(chip(page, 'TLS-RPT', 'Missing')).toBeVisible();
    await expect(chip(page, 'Return-path', 'OK')).toBeVisible();
    await expect(chip(page, 'Bounce MX', 'OK')).toBeVisible();
    await expect(page.getByTestId('ready-state')).toHaveText('Not ready to send'); // the DKIM key is not ours: sending stays blocked

    const spf = page.locator('.dns-detail').filter({ hasText: 'include:_spf.elsewhere.test' });
    await expect(spf).toContainText('Found in DNS');
    await expect(spf).toContainText('Expected');
    await expect(spf).toContainText('a:mta.eggmail.test');
    await expect(page.locator('.dns-detail').filter({ hasText: otherKey })).toContainText('Found in DNS');
    await expect(page.locator('.dns-detail').filter({ hasText: 'p=sometimes' })).toBeVisible();
    // The check is limited to once per 30 seconds per domain, and the button says when it can be used again.
    await expect(page.getByRole('button', { name: /Check again in \d+ s/ })).toBeDisabled();
  });

  test('the zone file is on the page, in the records endpoint and as plain text, and is the same everywhere', async ({ adminPage: page, admin, tenant, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const domain = await admin.ok('POST', '/api/v1/domains', { name: `${unique('zone')}.mail.test` }, { tenantId: tenant.id });
    await page.goto(`/domains/${domain.id}`);
    const onPage = await page.getByTestId('zone-file').evaluate((e) => e.textContent);

    const records = await admin.ok('GET', `/api/v1/domains/${domain.id}/records`, undefined, { tenantId: tenant.id });
    expect(records.zoneFile).toBe(onPage);
    expect(records.mtaStsPolicy).toBeNull(); // MTA-STS serving is off on this server
    expect(records.readyToSend).toBe(false);
    const plain = await admin.request('GET', `/api/v1/domains/${domain.id}/records?format=zone`, undefined, { tenantId: tenant.id });
    expect(plain.status).toBe(200);
    expect(plain.headers.get('content-type')).toContain('text/plain');
    expect(plain.body).toBe(onPage);

    // Every record of the table that belongs in the zone is a line of the zone file (the reverse DNS and the operator's bounce MX are comments); the long DKIM key is split in quoted strings of at most 255 characters.
    for (const r of records.records.filter((x) => x.type !== 'PTR' && x.type !== 'MX')) expect(onPage).toContain(`${r.host}. ${r.ttl} IN ${r.type} `);
    const dkim = onPage.split('\n').find((l) => l.includes('._domainkey.'));
    const strings = [...dkim.matchAll(/"([^"]*)"/g)].map((m) => m[1]);
    expect(strings.length).toBeGreaterThan(1);
    expect(Math.max(...strings.map((x) => x.length))).toBeLessThanOrEqual(255);
    expect(strings.join('')).toBe(domain.records[0].value);

    // Per-record copy buttons copy the exact host and value.
    await recordRow(page, 'SPF').getByRole('button', { name: /Copy SPF host/ }).click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(domain.name);
    await recordRow(page, 'TLS-RPT').getByRole('button', { name: /Copy TLS-RPT value/ }).click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(`v=TLSRPTv1; rua=mailto:tls-rpt@${domain.name}`);
  });
});

test.describe('domains from Domains:Bootstrap (EGGMAIL_DOMAINS) and the MTA-STS policy file', () => {
  test('the listed domains exist for a Default tenant, pending, and their records were printed to the log once', async ({ boot }) => {
    const admin = await new ApiClient(boot.baseURL).signIn(ADMIN_USER, ADMIN_PASSWORD);
    const tenants = await admin.ok('GET', '/api/v1/admin/tenants');
    expect(tenants.map((t) => t.name)).toEqual(['Default']);
    const domains = await admin.ok('GET', '/api/v1/domains', undefined, { tenantId: tenants[0].id });
    expect(domains.map((d) => [d.name, d.status]).sort()).toEqual([['boot1.mail.test', 'pending'], ['boot2.mail.test', 'pending']]);

    const log = boot.log();
    for (const name of ['boot1.mail.test', 'boot2.mail.test']) {
      expect(timesLogged(log, `DNS records to create for ${name}.`), `records of ${name} printed once`).toBe(1);
      expect(log).toContain(`_dmarc.${name}. 3600 IN TXT \\u0022v=DMARC1; p=none; rua=mailto:reports@${name}\\u0022`); // JSON console log: the encoder writes a quote as \\u0022
      expect(log).toContain(`mta-sts.${name}. 3600 IN CNAME mta.eggmail.test.`);
      expect(log).toContain(`bounce.${name}. 3600 IN CNAME bounces.eggmail.test.`);
    }
    expect(log).toContain('; MX bounces.eggmail.test -\\u003E 10 mta.eggmail.test (published once by whoever runs EggMail, not in this zone)'); // the JSON encoder writes > as \\u003E
    expect(log).toContain('v=spf1 ip4:192.0.2.10 ~all');
  });

  test('the server serves the MTA-STS policy of a registered domain on the dashboard listener, and the TXT id belongs to it', async ({ boot }) => {
    const policy = await getWithHost(boot, 'mta-sts.boot1.mail.test', '/.well-known/mta-sts.txt');
    expect(policy.status).toBe(200);
    expect(policy.headers['content-type']).toContain('text/plain');
    expect(policy.body).toBe('version: STSv1\r\nmode: testing\r\nmx: mta.eggmail.test\r\nmax_age: 604800\r\n');

    const admin = await new ApiClient(boot.baseURL).signIn(ADMIN_USER, ADMIN_PASSWORD);
    const tenant = (await admin.ok('GET', '/api/v1/admin/tenants'))[0];
    const domain = (await admin.ok('GET', '/api/v1/domains', undefined, { tenantId: tenant.id })).find((d) => d.name === 'boot1.mail.test');
    const txt = domain.records.find((r) => r.purpose === 'mta_sts');
    expect(txt.host).toBe('_mta-sts.boot1.mail.test');
    expect(txt.value).toBe(`v=STSv1; id=${createHash('sha256').update(policy.body).digest('hex').slice(0, 16)}`);

    expect((await getWithHost(boot, 'mta-sts.stranger.test', '/.well-known/mta-sts.txt')).status).toBe(404); // not ours
    expect((await getWithHost(boot, 'mta-sts.boot1.mail.test', '/')).status).toBe(404); // the dashboard is not offered under that name
    expect((await getWithHost(boot, 'mta-sts.boot1.mail.test', '/api/v1/domains')).status).toBe(404);
    expect((await getWithHost(boot, 'mta-sts.boot1.mail.test', '/index.html')).status).toBe(404); // not even the static files of the dashboard
    expect((await getWithHost(boot, 'mta.eggmail.test', '/index.html')).status).toBe(200);
    const dashboard = await getWithHost(boot, 'mta.eggmail.test', '/');
    expect(dashboard.status).toBe(200); // other names still reach the dashboard
    expect(dashboard.headers['content-type']).toContain('text/html');
  });

  test('the dashboard shows the bootstrapped domain with its records, the zone file and the MTA-STS policy; Check DNS makes it ready', async ({ boot, page }) => {
    await signInThroughForm(page, boot.baseURL);
    await expect(page.locator('.user')).toContainText(ADMIN_USER);
    await expect(page.getByLabel('Acting on tenant')).toContainText('Default'); // the first tenant of a fresh install is the acting tenant
    await page.goto(`${boot.baseURL}/domains`);
    await expect(page.getByRole('link', { name: 'boot1.mail.test' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'boot2.mail.test' })).toBeVisible();
    await page.getByRole('link', { name: 'boot1.mail.test' }).click();

    await expect(page.getByTestId('ready-state')).toHaveText('Not ready to send');
    await expect(page.getByTestId('mta-sts-url')).toHaveText('https://mta-sts.boot1.mail.test/.well-known/mta-sts.txt');
    await expect(page.getByTestId('mta-sts-policy')).toContainText('mx: mta.eggmail.test');
    await expect(recordRow(page, 'MTA-STS')).toContainText('_mta-sts.boot1.mail.test');
    await expect(recordRow(page, 'MTA-STS host')).toContainText('mta.eggmail.test');
    await expect(page.getByText(/must point at this server/)).toBeVisible();

    // Publish everything the page asks for (the reverse DNS of the configured sending IP included) and check.
    const admin = await new ApiClient(boot.baseURL).signIn(ADMIN_USER, ADMIN_PASSWORD);
    const tenant = (await admin.ok('GET', '/api/v1/admin/tenants'))[0];
    const domain = (await admin.ok('GET', '/api/v1/domains', undefined, { tenantId: tenant.id })).find((d) => d.name === 'boot1.mail.test');
    expect(domain.records.map((r) => r.purpose)).toEqual(['dkim', 'return_path', 'spf', 'dmarc', 'tls_rpt', 'mta_sts', 'mta_sts_host', 'bounce_mx', 'ptr']);
    const ptr = domain.records.find((r) => r.purpose === 'ptr');
    expect(ptr.host).toBe('10.2.0.192.in-addr.arpa');
    publishDomainRecords(boot.dns, { records: domain.records.filter((r) => r.purpose !== 'ptr') });
    boot.dns.setPtr(ptr.host, ptr.value);
    await page.getByRole('button', { name: 'Check DNS' }).click();

    await expect(page.getByTestId('ready-state')).toHaveText('Ready to send');
    for (const purpose of ['DKIM', 'Return-path', 'SPF', 'DMARC', 'TLS-RPT', 'MTA-STS', 'MTA-STS host', 'Bounce MX', 'Reverse DNS']) await expect(chip(page, purpose, 'OK')).toBeVisible();
    await expect(page.getByTestId('record-progress')).toContainText('Required records: 2 of 2 published. Recommended records: 7 of 7 published.');
  });

  test('a restart registers nothing twice and prints nothing again', async ({ boot }) => {
    await boot.restart();
    const admin = await new ApiClient(boot.baseURL).signIn(ADMIN_USER, ADMIN_PASSWORD);
    const tenants = await admin.ok('GET', '/api/v1/admin/tenants');
    expect(tenants).toHaveLength(1);
    const domains = await admin.ok('GET', '/api/v1/domains', undefined, { tenantId: tenants[0].id });
    expect(domains.map((d) => d.name).sort()).toEqual(['boot1.mail.test', 'boot2.mail.test']);
    const log = boot.log();
    expect(timesLogged(log, 'DNS records to create for boot1.mail.test.')).toBe(1);
    expect(timesLogged(log, 'DNS records to create for boot2.mail.test.')).toBe(1);
  });
});
