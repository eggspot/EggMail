// Full-stack smoke test: the real App rendered in jsdom against the real mock API server (HTTP, cookies,
// CSRF). Every route must render without an error notice or a crashed page, for both roles and both
// history modes. Page-level behavior is covered by the per-page tests; this catches wiring problems.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/preact';
import { LocationProvider } from 'preact-iso';
import { App } from '../src/app';
import { startMock } from './mockClient.mjs';

type Mock = Awaited<ReturnType<typeof startMock>>;
let mock: Mock;

/** fetch that targets the mock server and keeps a cookie jar like a browser. */
function browserFetch(base: string) {
  let cookie = '';
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const headers = new Headers(init?.headers);
    if (cookie) headers.set('Cookie', cookie);
    const res = await fetch(new URL(url, base), { ...init, headers });
    const set = res.headers.get('set-cookie');
    if (set) cookie = set.split(';')[0].endsWith('=') ? '' : set.split(';')[0];
    return res;
  });
}

async function signIn(user: string) {
  const user_ = await screen.findByLabelText('User');
  const { fireEvent } = await import('@testing-library/preact');
  fireEvent.input(user_, { target: { value: user } });
  fireEvent.input(screen.getByLabelText('Password'), { target: { value: 'eggmail' } });
  fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
  await screen.findByRole('navigation', { name: 'Main' });
}

async function visit(path: string) {
  cleanup();
  window.history.pushState({}, '', path);
  render(
    <LocationProvider>
      <App />
    </LocationProvider>,
  );
}

const TENANT_ROUTES = ['/', '/messages', '/send', '/domains', '/webhooks', '/suppressions', '/credentials', '/statistics', '/settings'];
const ADMIN_ROUTES = ['/admin/tenants', '/admin/status', '/admin/certificates', '/admin/storage'];

describe('dashboard against the mock API', () => {
  beforeEach(() => {
    window.history.pushState({}, '', '/');
  });
  afterEach(async () => {
    await mock?.close();
  });

  for (const history of ['full', 'statsonly'] as const) {
    it(`renders every tenant page without errors (history=${history})`, async () => {
      mock = await startMock({ history });
      vi.stubGlobal('fetch', browserFetch(mock.base));
      render(
        <LocationProvider>
          <App />
        </LocationProvider>,
      );
      await signIn('tenant');
      expect(screen.queryByRole('link', { name: 'Storage switch' })).toBeNull();
      for (const path of TENANT_ROUTES) {
        window.history.pushState({}, '', path);
        window.dispatchEvent(new PopStateEvent('popstate'));
        await waitFor(() => expect(screen.getByRole('main').querySelector('h1')).toBeTruthy(), { timeout: 4000 });
        await waitFor(() => expect(screen.queryByText(/Loading/)).toBeNull(), { timeout: 4000 });
        expect(screen.queryByText('This page crashed'), path).toBeNull();
        expect(screen.getByRole('main').querySelector('.notice-bad'), `${path} shows an error`).toBeNull();
      }
      if (history === 'statsonly') {
        window.history.pushState({}, '', '/messages');
        window.dispatchEvent(new PopStateEvent('popstate'));
        expect(await screen.findByText(/history is not recorded/i)).toBeTruthy();
      }
    });
  }

  it('renders every admin page for the admin role and keeps the sqlite warning banner visible', async () => {
    mock = await startMock({ history: 'full', warnings: ['sqlite_sync_off'] });
    vi.stubGlobal('fetch', browserFetch(mock.base));
    await visit('/');
    await signIn('admin');
    expect(screen.getByLabelText('Acting on tenant')).toBeTruthy();
    for (const path of [...TENANT_ROUTES, ...ADMIN_ROUTES]) {
      window.history.pushState({}, '', path);
      window.dispatchEvent(new PopStateEvent('popstate'));
      await waitFor(() => expect(screen.getByRole('main').querySelector('h1')).toBeTruthy(), { timeout: 4000 });
      await waitFor(() => expect(screen.queryByText(/Loading/)).toBeNull(), { timeout: 4000 });
      expect(screen.queryByText('This page crashed'), path).toBeNull();
      expect(screen.getByRole('main').querySelector('.notice-bad'), `${path} shows an error`).toBeNull();
      expect(document.querySelector('[data-warning="sqlite_sync_off"]'), `${path} lacks the banner`).toBeTruthy();
    }
  });

  it('shows the not-ready screen when the server answers 503, then recovers', async () => {
    mock = await startMock({ notReady: true });
    vi.stubGlobal('fetch', browserFetch(mock.base));
    await visit('/');
    expect(await screen.findByRole('heading', { name: 'Server not available' })).toBeTruthy();
    await mock.post('/__mock/config', { notReady: false });
    const { fireEvent } = await import('@testing-library/preact');
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByLabelText('User')).toBeTruthy();
  });
});
