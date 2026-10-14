import { createRecipientDomain, createVerifiedDomain, expect, sendViaApi, test, unique } from './support/fixtures.mjs';

// Every page, every tab and the sandboxed message frame under the server's strict CSP. The `problems` fixture (auto) fails each test on
// any console error, page error or `securitypolicyviolation` event, so visiting the page is the assertion.

const PAGES = [
  ['/', 'Overview'],
  ['/messages', 'Messages'],
  ['/send', 'Send test message'],
  ['/domains', 'Domains'],
  ['/webhooks', 'Webhooks'],
  ['/suppressions', 'Suppressions'],
  ['/credentials', 'API keys and SMTP credentials'],
  ['/statistics', 'Statistics'],
  ['/settings', 'Settings'],
  ['/account', 'Account'],
  ['/admin/tenants', 'Tenants'],
  ['/admin/users', 'Users'],
  ['/admin/status', 'Server status'],
  ['/admin/certificates', 'Certificates'],
  ['/admin/storage', 'Storage switch'],
  ['/admin/relay-routes', 'Relay routes'],
  ['/admin/tls-policies', 'TLS policies'],
];

test.describe('strict content security policy', () => {
  test('the server sends the strict headers on the page, the assets and the API', async ({ stack }) => {
    const index = await fetch(`${stack.baseURL}/`);
    const csp = index.headers.get('content-security-policy');
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("style-src 'self'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toMatch(/unsafe-inline|unsafe-eval|\*/);
    expect(index.headers.get('x-content-type-options')).toBe('nosniff');
    expect(index.headers.get('referrer-policy')).toBe('no-referrer');
    expect(index.headers.get('x-frame-options')).toBe('DENY');

    // The single-page-app fallback answers any unknown path without a file extension with the same page and headers.
    const deep = await fetch(`${stack.baseURL}/domains/0123456789abcdef0123456789abcdef`);
    expect(deep.status).toBe(200);
    expect(deep.headers.get('content-type')).toContain('text/html');
    expect(deep.headers.get('content-security-policy')).toBe(csp);
    expect(deep.headers.get('cache-control')).toBe('no-cache');

    // Unknown API paths are API errors, never the HTML shell.
    const missing = await fetch(`${stack.baseURL}/api/v1/does-not-exist`);
    expect(missing.status).toBe(404);
    expect(missing.headers.get('content-type')).toContain('application/problem+json');
    expect(missing.headers.get('cache-control')).toContain('no-store');

    // The page has no inline script or style and loads only same-origin assets.
    const html = await (await fetch(`${stack.baseURL}/`)).text();
    expect(html).not.toMatch(/<script(?![^>]*\bsrc=)[^>]*>/i);
    expect(html).not.toMatch(/<style\b|\sstyle=/i);
    const assets = [...html.matchAll(/(?:src|href)="(\/[^"]+)"/g)].map((m) => m[1]).filter((p) => p.startsWith('/assets/'));
    expect(assets.length).toBeGreaterThan(0);
    for (const asset of assets) {
      const res = await fetch(`${stack.baseURL}${asset}`);
      expect(res.status, asset).toBe(200);
      expect(res.headers.get('cache-control') ?? '', asset).toMatch(/max-age=\d{6,}/); // content-hashed: cacheable for a long time
    }
  });

  test('every page of the administrator renders without a console error or a CSP violation', async ({ adminPage: page, admin, tenant, stack, allowProblems }) => {
    // The hostile message below is blocked by the policy on purpose, and the browser says so.
    allowProblems.push(/Applying inline style violates.*(style-src 'self'|default-src 'none')/, /Loading the image 'https:\/\/example\.invalid\/pixel\.gif' violates/);
    const domain = await createVerifiedDomain(admin, stack, tenant);
    const recipientDomain = createRecipientDomain(stack);
    const key = (await admin.ok('POST', '/api/v1/api-keys', { name: 'csp', scopes: ['send'] }, { tenantId: tenant.id })).key;
    const subject = unique('CSP ');
    await sendViaApi(stack, key, {
      from: `hello@${domain.name}`, to: [`someone@${recipientDomain}`], subject, text: 'plain',
      html: '<p style="color:red">styled</p><style>p{color:blue}</style><img src="https://example.invalid/pixel.gif"><script>alert(1)</script><a href="https://example.invalid/">link</a>',
    });
    await admin.ok('POST', '/api/v1/suppressions', { address: 'csp@example.test' }, { tenantId: tenant.id });

    for (const [route, heading] of PAGES) {
      await page.goto(route);
      await expect(page.getByRole('heading', { name: heading, exact: true }).first()).toBeVisible();
      await expect(page.locator('main [role="alert"]:not([data-warning])')).toHaveCount(0);
    }

    // Detail pages and tabs.
    await page.goto(`/domains/${domain.id}`);
    await expect(page.getByRole('heading', { name: domain.name, exact: true })).toBeVisible();
    await page.goto('/messages');
    await expect(async () => {
      await page.getByRole('button', { name: 'Search' }).click();
      await expect(page.getByRole('link', { name: subject })).toBeVisible({ timeout: 2_000 });
    }).toPass({ timeout: 30_000 });
    await page.getByRole('link', { name: subject }).click();
    await expect(page.getByRole('heading', { name: subject, exact: true })).toBeVisible();
    await page.getByRole('tab', { name: /HTML/ }).click();
    const frame = page.frameLocator('iframe[title^="Message HTML"]');
    await expect(frame.locator('body')).toContainText('styled');
    // Remote content, scripts and styling in a message are blocked by the frame and the page policy (the `problems` fixture allows
    // exactly the browser's own "blocked script" report for a sandboxed frame).
    await page.getByRole('tab', { name: /Attachments/ }).click();
    await page.getByRole('tab', { name: 'Text' }).click();
    await expect(page.getByTestId('text-view')).toHaveText('plain');
  });

  test('the sign-in page, the offline state and the theme toggle are clean too', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
    for (let i = 0; i < 3; i++) await page.getByRole('button', { name: /theme/i }).click();
    expect(await page.evaluate(() => document.documentElement.dataset.theme ?? 'system')).toBeTruthy();
    await page.goto('/this/path/does/not/exist');
    await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
  });
});
