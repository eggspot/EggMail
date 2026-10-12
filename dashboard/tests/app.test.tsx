import { describe, expect, it } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { LocationProvider } from 'preact-iso';
import { Shell } from '../src/app';
import { AppProvider } from '../src/state/app';
import { api } from '../src/api/endpoints';
import { getCsrfToken } from '../src/api/client';
import { makeCapabilities, mockFetch, problem } from './helpers';

const tenants = [
  { id: 't_acme', name: 'Acme Corp', status: 'active' },
  { id: 't_globex', name: 'Globex', status: 'active' },
];

function mount() {
  return render(
    <LocationProvider>
      <AppProvider>
        <Shell />
      </AppProvider>
    </LocationProvider>,
  );
}

const tenantMe = { user: 'tenant', role: 'tenant', tenantId: 't_acme', csrfToken: 'csrf-t' };
const adminMe = { user: 'admin', role: 'admin', tenantId: null, csrfToken: 'csrf-a' };

describe('app shell', () => {
  it('shows the sign-in form when there is no session, with the server warning banner above it', async () => {
    mockFetch({
      'GET /api/v1/capabilities': makeCapabilities({ warnings: [{ code: 'sqlite_sync_off', message: 'sync off' }] }),
      'GET /api/v1/me': () => problem(401, 'unauthorized'),
    });
    mount();
    expect(await screen.findByRole('button', { name: 'Sign in' })).toBeTruthy();
    expect(screen.getByLabelText('User')).toBeTruthy();
    expect(screen.getByLabelText('Password')).toBeTruthy();
    expect(screen.getByRole('alert').getAttribute('data-warning')).toBe('sqlite_sync_off');
  });

  it('signs in, stores only the CSRF token in memory, and renders the navigation', async () => {
    // the first /me probe answers 401 (no session); after the POST it returns the CSRF token
    mockFetch({
      'GET /api/v1/capabilities': makeCapabilities(),
      'GET /api/v1/me': (() => {
        let n = 0;
        return () => (++n === 1 ? problem(401, 'unauthorized') : tenantMe);
      })(),
      'POST /api/v1/session': { user: 'tenant', role: 'tenant', tenantId: 't_acme' },
    });
    mount();
    fireEvent.input(await screen.findByLabelText('User'), { target: { value: 'tenant' } });
    fireEvent.input(screen.getByLabelText('Password'), { target: { value: 'eggmail' } });
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByRole('navigation', { name: 'Main' })).toBeTruthy();
    expect(getCsrfToken()).toBe('csrf-t');
    expect(window.localStorage.length).toBe(0);
    expect(JSON.stringify({ ...window.sessionStorage })).not.toContain('csrf');
    expect(screen.queryByRole('link', { name: 'Tenants' })).toBeNull(); // admin-only items hidden
    expect(screen.getByRole('link', { name: 'Domains' })).toBeTruthy();
  });

  it('shows a friendly message for a failed sign-in and clears the password', async () => {
    mockFetch({
      'GET /api/v1/capabilities': makeCapabilities(),
      'GET /api/v1/me': () => problem(401, 'unauthorized'),
      'POST /api/v1/session': () => problem(401, 'unauthorized', { detail: 'Invalid user or password.' }),
    });
    mount();
    fireEvent.input(await screen.findByLabelText('User'), { target: { value: 'x' } });
    fireEvent.input(screen.getByLabelText('Password'), { target: { value: 'wrong' } });
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    await waitFor(() => expect(screen.getByRole('alert').textContent).toMatch(/sign in again|session/i));
    expect((screen.getByLabelText('Password') as HTMLInputElement).value).toBe('');
  });

  it('shows the lockout wait on 429 during sign-in', async () => {
    mockFetch({
      'GET /api/v1/capabilities': makeCapabilities(),
      'GET /api/v1/me': () => problem(401, 'unauthorized'),
      'POST /api/v1/session': () => problem(429, 'rate_limited', {}, { 'Retry-After': '30' }),
    });
    mount();
    fireEvent.input(await screen.findByLabelText('User'), { target: { value: 'x' } });
    fireEvent.input(screen.getByLabelText('Password'), { target: { value: 'y' } });
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('30 s'));
  });

  it('shows the offline screen on 503 not_ready and recovers on retry', async () => {
    let ready = false;
    mockFetch({
      'GET /api/v1/capabilities': () => (ready ? makeCapabilities() : problem(503, 'not_ready', { detail: 'storage down' })),
      'GET /api/v1/me': () => (ready ? tenantMe : problem(503, 'not_ready')),
    });
    mount();
    expect(await screen.findByRole('heading', { name: 'Server not available' })).toBeTruthy();
    expect(document.body.textContent).toMatch(/not ready/i);
    ready = true;
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByRole('navigation', { name: 'Main' })).toBeTruthy();
  });

  it('shows the offline screen when the network is down', async () => {
    mockFetch({});
    // every request 404s in the stub, but a rejected fetch means the server is unreachable
    (globalThis.fetch as unknown as { mockRejectedValue: (e: unknown) => void }).mockRejectedValue(new TypeError('Failed to fetch'));
    mount();
    expect(await screen.findByRole('heading', { name: 'Server not available' })).toBeTruthy();
    expect(document.body.textContent).toMatch(/Cannot reach the server/);
  });

  it('loads tenants for admins, offers the admin pages and sends X-Tenant-Id for the chosen tenant', async () => {
    const { calls } = mockFetch({
      'GET /api/v1/capabilities': makeCapabilities(),
      'GET /api/v1/me': adminMe,
      'GET /api/v1/admin/tenants': tenants,
    });
    mount();
    const picker = (await screen.findByLabelText('Acting on tenant')) as HTMLSelectElement;
    expect(picker.value).toBe('t_acme');
    expect(screen.getByRole('link', { name: 'Storage switch' })).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Tenants' })).toBeTruthy();
    fireEvent.change(picker, { target: { value: 't_globex' } });
    await api.domains().catch(() => {});
    const last = calls.filter((c) => c.path === '/api/v1/domains').pop()!;
    expect(last.headers.get('X-Tenant-Id')).toBe('t_globex');
    expect(window.sessionStorage.getItem('eggmail.tenant')).toBe('t_globex');
  });

  it('returns to the sign-in form when any call answers 401 mid-session', async () => {
    mockFetch({
      'GET /api/v1/capabilities': makeCapabilities(),
      'GET /api/v1/me': tenantMe,
      'GET /api/v1/domains': () => problem(401, 'unauthorized'),
    });
    mount();
    await screen.findByRole('navigation', { name: 'Main' });
    await api.domains().catch(() => {});
    expect(await screen.findByRole('button', { name: 'Sign in' })).toBeTruthy();
    expect(getCsrfToken()).toBeNull();
  });

  it('signs out through DELETE /session with the CSRF token', async () => {
    const { calls } = mockFetch({
      'GET /api/v1/capabilities': makeCapabilities(),
      'GET /api/v1/me': tenantMe,
      'DELETE /api/v1/session': undefined,
    });
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Sign out' }));
    expect(await screen.findByRole('button', { name: 'Sign in' })).toBeTruthy();
    const del = calls.find((c) => c.method === 'DELETE')!;
    expect(del.headers.get('X-CSRF-Token')).toBe('csrf-t');
  });

  it('shows backend and history mode informationally and the persistent banner on signed-in pages', async () => {
    mockFetch({
      'GET /api/v1/capabilities': makeCapabilities({ backend: 'postgres', mode: 'statsonly', warnings: [{ code: 'sqlite_sync_off', message: 'sync off' }] }),
      'GET /api/v1/me': tenantMe,
    });
    mount();
    const info = await screen.findByTestId('backend-info');
    expect(info.textContent).toContain('storage: postgres');
    expect(info.textContent).toContain('history: statsonly');
    expect(screen.getByRole('alert').getAttribute('data-warning')).toBe('sqlite_sync_off');
  });

  it('offers a skip link and a focusable main landmark', async () => {
    mockFetch({ 'GET /api/v1/capabilities': makeCapabilities(), 'GET /api/v1/me': tenantMe });
    mount();
    await screen.findByRole('navigation', { name: 'Main' });
    expect(screen.getByRole('link', { name: 'Skip to content' }).getAttribute('href')).toBe('#main');
    const main = screen.getByRole('main');
    expect(main.getAttribute('tabindex')).toBe('-1');
    fireEvent.click(screen.getByRole('link', { name: 'Skip to content' }));
    expect(document.activeElement).toBe(main);
  });

  it('toggles the color theme through data-theme and remembers it', async () => {
    mockFetch({ 'GET /api/v1/capabilities': makeCapabilities(), 'GET /api/v1/me': tenantMe });
    mount();
    fireEvent.click(await screen.findByRole('button', { name: /Color theme: System theme/ }));
    await waitFor(() => expect(document.documentElement.getAttribute('data-theme')).toBe('light'));
    expect(window.localStorage.getItem('eggmail.theme')).toBe('light');
    fireEvent.click(await screen.findByRole('button', { name: /Color theme: Light theme/ }));
    await waitFor(() => expect(document.documentElement.getAttribute('data-theme')).toBe('dark'));
    fireEvent.click(await screen.findByRole('button', { name: /Color theme: Dark theme/ }));
    await waitFor(() => expect(document.documentElement.hasAttribute('data-theme')).toBe(false));
    expect(window.localStorage.getItem('eggmail.theme')).toBeNull();
  });

  it('opens the mobile menu with aria-expanded', async () => {
    mockFetch({ 'GET /api/v1/capabilities': makeCapabilities(), 'GET /api/v1/me': tenantMe });
    mount();
    const menu = await screen.findByRole('button', { name: 'Menu' });
    expect(menu.getAttribute('aria-expanded')).toBe('false');
    fireEvent.click(menu);
    await waitFor(() => expect(menu.getAttribute('aria-expanded')).toBe('true'));
    expect(document.getElementById('site-nav')?.className).toContain('open');
  });
});
