import { defineConfig, devices } from '@playwright/test';

// Real-browser end-to-end tests: Chromium against a real `mta serve` (SQLite in a temp directory, loopback ports) serving the
// production dashboard build. The server and its fakes (DNS, recipients' SMTP, webhook receiver) are started by the tests'
// own fixtures (e2e/support). One worker: the specs share one server and create their own uniquely named data.
export default defineConfig({
  testDir: './e2e',
  testMatch: '**/*.spec.mjs',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: !!process.env.CI,
  timeout: 120_000,
  expect: { timeout: 15_000 },
  reporter: process.env.CI ? [['list'], ['html', { open: 'never', outputFolder: 'e2e-report' }]] : [['list']],
  outputDir: 'e2e-results',
  use: {
    ...devices['Desktop Chrome'],
    viewport: { width: 1280, height: 900 },
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
});
