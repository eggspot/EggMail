import { describe, expect, it } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/preact';
import RelayRoutes, { parseDomains } from '../src/pages/admin/RelayRoutes';
import TlsPolicies from '../src/pages/admin/TlsPolicies';
import type { RelayRoute, TlsPolicy } from '../src/api/types';
import { json, mockFetch, problem, renderWithApp } from './helpers';
import type { RecordedCall } from './helpers';

const route: RelayRoute = {
  id: 'r1',
  name: 'office',
  host: 'smtp.relay.example',
  port: 587,
  tlsMode: 'verify',
  userName: 'relay-user',
  hasPassword: true,
  priority: 100,
  enabled: true,
  domains: ['partner.example', '*.corp.example'],
  warnings: [],
};
const weak: RelayRoute = { ...route, id: 'r2', name: 'weak', tlsMode: 'required', enabled: false, warnings: ['The certificate of this relay is not validated, so the password could be given to an impostor.'] };
const policy: TlsPolicy = { id: 'p1', domainPattern: '*.bank.example', level: 'verify', warnings: [] };
const none: TlsPolicy = { id: 'p2', domainPattern: 'legacy.example', level: 'none', warnings: ['Level none turns TLS off for these destinations and MTA-STS and DANE are not consulted.'] };

describe('Relay routes page', () => {
  it('lists routes with host, TLS mode, login (never a password), domains, state and warnings', async () => {
    mockFetch({ 'GET /api/v1/admin/relay-routes': [route, weak] });
    renderWithApp(<RelayRoutes />, { role: 'admin' });
    const table = await screen.findByRole('table', { name: 'Relay routes' });
    const row = within(table).getByRole('row', { name: /office/ });
    expect(row.textContent).toContain('smtp.relay.example:587');
    expect(row.textContent).toContain('verify');
    expect(row.textContent).toContain('relay-user (password set)');
    expect(row.textContent).toContain('partner.example');
    expect(row.textContent).toContain('*.corp.example');
    expect(row.textContent).toContain('Enabled');
    const weakRow = within(table).getByRole('row', { name: /weak/ });
    expect(weakRow.textContent).toContain('Disabled');
    expect(weakRow.textContent).toContain('impostor');
  });

  it('shows an empty state', async () => {
    mockFetch({ 'GET /api/v1/admin/relay-routes': [] });
    renderWithApp(<RelayRoutes />, { role: 'admin' });
    expect(await screen.findByText('No relay routes')).toBeTruthy();
  });

  it('parses the domains field', () => {
    expect(parseDomains('a.example, b.example\n*.c.example\n\n  d.example ')).toEqual(['a.example', 'b.example', '*.c.example', 'd.example']);
    expect(parseDomains('')).toEqual([]);
  });

  it('creates a route with its password in the request body only, and clears the form afterwards', async () => {
    let created: RelayRoute[] = [];
    const m = mockFetch({
      'GET /api/v1/admin/relay-routes': () => created,
      'POST /api/v1/admin/relay-routes': (c: RecordedCall) => {
        const b = c.body as Record<string, unknown>;
        const r: RelayRoute = { ...route, id: 'new', name: String(b.name), host: String(b.host), domains: b.domains as string[], warnings: [] };
        created = [r];
        return json(r, 201);
      },
    });
    renderWithApp(<RelayRoutes />, { role: 'admin' });
    await screen.findByText('No relay routes');
    const submit = screen.getByRole('button', { name: 'Add relay route' }) as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
    fireEvent.input(screen.getByLabelText('Name'), { target: { value: 'office' } });
    fireEvent.input(screen.getByLabelText('Host'), { target: { value: 'smtp.relay.example' } });
    fireEvent.input(screen.getByLabelText('User name'), { target: { value: 'relay-user' } });
    fireEvent.input(screen.getByLabelText('Password'), { target: { value: 'hunter2-secret' } });
    fireEvent.input(screen.getByLabelText('Recipient domains'), { target: { value: 'partner.example\n*.corp.example' } });
    fireEvent.click(submit);
    expect(await screen.findByText('Relay route office added.')).toBeTruthy();
    const body = m.callsTo('POST', '/api/v1/admin/relay-routes')[0].body as Record<string, unknown>;
    expect(body).toMatchObject({ name: 'office', host: 'smtp.relay.example', tlsMode: 'verify', userName: 'relay-user', password: 'hunter2-secret', domains: ['partner.example', '*.corp.example'], enabled: true });
    expect(body.port).toBeUndefined();
    // The password is not kept anywhere: not in the form state (the field is empty again), not in the markup the table was rendered into, not in web storage.
    expect(await screen.findByRole('table', { name: 'Relay routes' })).toBeTruthy();
    expect((screen.getByLabelText('Password') as HTMLInputElement).value).toBe('');
    expect(document.body.innerHTML).not.toContain('hunter2-secret');
    expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toContain('hunter2-secret');
    expect(m.callsTo('GET', '/api/v1/admin/relay-routes').every((c) => !JSON.stringify(c.body ?? '').includes('hunter2-secret'))).toBe(true);
  });

  it('shows field errors from the server next to the fields, including a domain entry', async () => {
    mockFetch({
      'GET /api/v1/admin/relay-routes': [],
      'POST /api/v1/admin/relay-routes': () =>
        problem(400, 'validation_failed', {
          errors: [
            { field: 'host', message: 'Enter a host name such as smtp.relay.example, or an IP address.' },
            { field: 'domains[1]', message: 'Use a domain name, "*.suffix" for every subdomain at any depth (not the domain itself), or "*" for every domain.' },
          ],
        }),
    });
    renderWithApp(<RelayRoutes />, { role: 'admin' });
    await screen.findByText('No relay routes');
    fireEvent.input(screen.getByLabelText('Name'), { target: { value: 'x' } });
    fireEvent.input(screen.getByLabelText('Host'), { target: { value: 'bad host' } });
    fireEvent.input(screen.getByLabelText('Recipient domains'), { target: { value: 'a.example\nb c' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add relay route' }));
    expect(await screen.findByText(/Enter a host name/)).toBeTruthy();
    expect(screen.getByText(/Entry 2: Use a domain name/)).toBeTruthy();
  });

  it('warns about a catch-all domain and about a password over an unchecked certificate', async () => {
    mockFetch({ 'GET /api/v1/admin/relay-routes': [] });
    renderWithApp(<RelayRoutes />, { role: 'admin' });
    await screen.findByText('No relay routes');
    fireEvent.input(screen.getByLabelText('Recipient domains'), { target: { value: '*' } });
    expect(screen.getByText(/every recipient domain through this relay/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText('TLS'), { target: { value: 'required' } });
    fireEvent.input(screen.getByLabelText('Password'), { target: { value: 'x' } });
    expect(screen.getByText(/certificate is not checked in this mode/)).toBeTruthy();
  });

  it('edits without sending the password unless a new one is typed, and can remove the credentials', async () => {
    const m = mockFetch({
      'GET /api/v1/admin/relay-routes': [route],
      'PATCH /api/v1/admin/relay-routes/:id': (c: RecordedCall) => json({ ...route, ...(c.body as object) }),
    });
    renderWithApp(<RelayRoutes />, { role: 'admin' });
    fireEvent.click(await screen.findByRole('button', { name: 'Edit office' }));
    const dialog = await screen.findByRole('dialog');
    expect((within(dialog).getByLabelText('Password') as HTMLInputElement).placeholder).toBe('unchanged');
    fireEvent.input(within(dialog).getByLabelText('Priority'), { target: { value: '7' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
    await screen.findByText('Relay route office saved.');
    const first = m.callsTo('PATCH', '/api/v1/admin/relay-routes/r1')[0].body as Record<string, unknown>;
    expect(first.priority).toBe(7);
    expect('password' in first).toBe(false);
    expect('userName' in first).toBe(false);
    expect('removeCredentials' in first).toBe(false);

    fireEvent.click(await screen.findByRole('button', { name: 'Edit office' }));
    const second = await screen.findByRole('dialog');
    fireEvent.click(within(second).getByLabelText('Remove the stored user name and password'));
    fireEvent.click(within(second).getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(m.callsTo('PATCH', '/api/v1/admin/relay-routes/r1')).toHaveLength(2));
    const removal = m.callsTo('PATCH', '/api/v1/admin/relay-routes/r1')[1].body as Record<string, unknown>;
    expect(removal.removeCredentials).toBe(true);
    expect('password' in removal).toBe(false);
  });

  it('sends a typed password together with the unchanged user name', async () => {
    const m = mockFetch({
      'GET /api/v1/admin/relay-routes': [route],
      'PATCH /api/v1/admin/relay-routes/:id': (c: RecordedCall) => json({ ...route, ...(c.body as object) }),
    });
    renderWithApp(<RelayRoutes />, { role: 'admin' });
    fireEvent.click(await screen.findByRole('button', { name: 'Edit office' }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.input(within(dialog).getByLabelText('Password'), { target: { value: 'new-secret' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(m.callsTo('PATCH', '/api/v1/admin/relay-routes/r1')).toHaveLength(1));
    expect(m.callsTo('PATCH', '/api/v1/admin/relay-routes/r1')[0].body).toMatchObject({ password: 'new-secret', userName: 'relay-user' });
  });

  it('enables and disables a route and deletes one after confirmation', async () => {
    let routes = [route];
    const m = mockFetch({
      'GET /api/v1/admin/relay-routes': () => routes,
      'PATCH /api/v1/admin/relay-routes/:id': (c: RecordedCall) => {
        routes = [{ ...route, ...(c.body as object) }];
        return json(routes[0]);
      },
      'DELETE /api/v1/admin/relay-routes/:id': () => {
        routes = [];
        return undefined;
      },
    });
    renderWithApp(<RelayRoutes />, { role: 'admin' });
    fireEvent.click(await screen.findByRole('button', { name: 'Disable office' }));
    expect(await screen.findByText('office is now disabled.')).toBeTruthy();
    expect(m.callsTo('PATCH', '/api/v1/admin/relay-routes/r1')[0].body).toEqual({ enabled: false });

    fireEvent.click(await screen.findByRole('button', { name: 'Delete office' }));
    expect(m.callsTo('DELETE', '/api/v1/admin/relay-routes/r1')).toHaveLength(0);
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Delete route' }));
    expect(await screen.findByText('Relay route office deleted.')).toBeTruthy();
    expect(await screen.findByText('No relay routes')).toBeTruthy();
  });

  it('asks for the password again before the host, port or TLS mode of a route with a login changes, and says so before the request', async () => {
    const m = mockFetch({
      'GET /api/v1/admin/relay-routes': [route],
      'PATCH /api/v1/admin/relay-routes/:id': (c: RecordedCall) => json({ ...route, ...(c.body as object) }),
    });
    renderWithApp(<RelayRoutes />, { role: 'admin' });
    fireEvent.click(await screen.findByRole('button', { name: 'Edit office' }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.input(within(dialog).getByLabelText('Port'), { target: { value: '2525' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
    expect(await within(dialog).findByText(/Type the password again/)).toBeTruthy();
    expect(m.callsTo('PATCH', '/api/v1/admin/relay-routes/r1')).toHaveLength(0);

    fireEvent.input(within(dialog).getByLabelText('Password'), { target: { value: 'typed-again' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(m.callsTo('PATCH', '/api/v1/admin/relay-routes/r1')).toHaveLength(1));
    expect(m.callsTo('PATCH', '/api/v1/admin/relay-routes/r1')[0].body).toMatchObject({ port: 2525, password: 'typed-again', userName: 'relay-user' });
  });

  it('does not let an emptied user name silently keep the login, and refuses TLS mode none with one', async () => {
    const m = mockFetch({ 'GET /api/v1/admin/relay-routes': [route], 'PATCH /api/v1/admin/relay-routes/:id': () => json(route) });
    renderWithApp(<RelayRoutes />, { role: 'admin' });
    fireEvent.click(await screen.findByRole('button', { name: 'Edit office' }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.input(within(dialog).getByLabelText('User name'), { target: { value: '' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
    expect(await within(dialog).findByText(/An empty field keeps the stored login/)).toBeTruthy();

    fireEvent.input(within(dialog).getByLabelText('User name'), { target: { value: 'relay-user' } });
    fireEvent.change(within(dialog).getByLabelText('TLS'), { target: { value: 'none' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
    expect(await within(dialog).findByText(/Not with a login/)).toBeTruthy();
    expect(m.callsTo('PATCH', '/api/v1/admin/relay-routes/r1')).toHaveLength(0);

    // Removing the login first makes mode none possible.
    fireEvent.click(within(dialog).getByLabelText('Remove the stored user name and password'));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(m.callsTo('PATCH', '/api/v1/admin/relay-routes/r1')).toHaveLength(1));
    expect(m.callsTo('PATCH', '/api/v1/admin/relay-routes/r1')[0].body).toMatchObject({ tlsMode: 'none', removeCredentials: true });
  });

  it('only busies the button of the route being switched', async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((r) => (release = r));
    mockFetch({
      'GET /api/v1/admin/relay-routes': [route, { ...route, id: 'r3', name: 'second' }],
      'PATCH /api/v1/admin/relay-routes/:id': async () => {
        await gate;
        return json(route);
      },
    });
    renderWithApp(<RelayRoutes />, { role: 'admin' });
    fireEvent.click(await screen.findByRole('button', { name: 'Disable office' }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Disable office' }).getAttribute('aria-busy')).toBe('true'));
    expect(screen.getByRole('button', { name: 'Disable second' }).getAttribute('aria-busy')).toBeNull();
    release();
  });

  it('shows a load error with a retry', async () => {
    mockFetch({ 'GET /api/v1/admin/relay-routes': () => problem(500, 'server_error') });
    renderWithApp(<RelayRoutes />, { role: 'admin' });
    expect(await screen.findByRole('button', { name: /retry|try again/i })).toBeTruthy();
  });
});

describe('TLS policies page', () => {
  it('lists policies with their level and warnings', async () => {
    mockFetch({ 'GET /api/v1/admin/tls-policies': [policy, none] });
    renderWithApp(<TlsPolicies />, { role: 'admin' });
    const table = await screen.findByRole('table', { name: 'TLS policies' });
    expect(within(table).getByRole('row', { name: /bank\.example/ }).textContent).toContain('verify');
    const noneRow = within(table).getByRole('row', { name: /legacy\.example/ });
    expect(noneRow.textContent).toContain('none');
    expect(noneRow.textContent).toContain('MTA-STS and DANE are not consulted');
  });

  it('explains how a level combines with MTA-STS and DANE', async () => {
    mockFetch({ 'GET /api/v1/admin/tls-policies': [] });
    renderWithApp(<TlsPolicies />, { role: 'admin' });
    expect(await screen.findByText('No policies')).toBeTruthy();
    expect(screen.getByText(/never overridden/)).toBeTruthy();
  });

  it('creates a policy and shows the server-side validation error for a duplicate', async () => {
    let calls = 0;
    const m = mockFetch({
      'GET /api/v1/admin/tls-policies': [],
      'POST /api/v1/admin/tls-policies': () => {
        calls += 1;
        return calls === 1
          ? json({ id: 'p9', domainPattern: 'a.example', level: 'encrypt', warnings: [] }, 201)
          : problem(400, 'validation_failed', { errors: [{ field: 'domainPattern', message: 'A policy for this pattern already exists.' }] });
      },
    });
    renderWithApp(<TlsPolicies />, { role: 'admin' });
    await screen.findByText('No policies');
    const submit = screen.getByRole('button', { name: 'Add policy' }) as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
    fireEvent.input(screen.getByLabelText('Recipient domain'), { target: { value: 'a.example' } });
    fireEvent.change(screen.getByLabelText('TLS level'), { target: { value: 'encrypt' } });
    fireEvent.click(submit);
    expect(await screen.findByText('Policy for a.example added.')).toBeTruthy();
    expect(m.callsTo('POST', '/api/v1/admin/tls-policies')[0].body).toEqual({ domainPattern: 'a.example', level: 'encrypt' });

    fireEvent.input(screen.getByLabelText('Recipient domain'), { target: { value: 'a.example' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add policy' }));
    expect(await screen.findByText('A policy for this pattern already exists.')).toBeTruthy();
  });

  it('warns before saving level none or a strict catch-all', async () => {
    mockFetch({ 'GET /api/v1/admin/tls-policies': [] });
    renderWithApp(<TlsPolicies />, { role: 'admin' });
    await screen.findByText('No policies');
    fireEvent.change(screen.getByLabelText('TLS level'), { target: { value: 'none' } });
    expect(screen.getByText(/turns TLS off for these destinations/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText('TLS level'), { target: { value: 'verify' } });
    fireEvent.input(screen.getByLabelText('Recipient domain'), { target: { value: '*' } });
    expect(screen.getByText(/applies to every destination/i)).toBeTruthy();
  });

  it('needs an explicit acknowledgement before level none is saved for every destination, and sends it', async () => {
    const m = mockFetch({
      'GET /api/v1/admin/tls-policies': [],
      'POST /api/v1/admin/tls-policies': (c: RecordedCall) => json({ id: 'p7', ...(c.body as object), warnings: [] }, 201),
    });
    renderWithApp(<TlsPolicies />, { role: 'admin' });
    await screen.findByText('No policies');
    fireEvent.input(screen.getByLabelText('Recipient domain'), { target: { value: '*' } });
    fireEvent.change(screen.getByLabelText('TLS level'), { target: { value: 'none' } });
    expect(screen.getByText('This turns TLS off for every destination')).toBeTruthy();
    const submit = screen.getByRole('button', { name: 'Add policy' }) as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
    fireEvent.click(screen.getByLabelText(/I understand that all mail will be sent without TLS/));
    expect(submit.disabled).toBe(false);
    fireEvent.click(submit);
    await screen.findByText('Policy for * added.');
    expect(m.callsTo('POST', '/api/v1/admin/tls-policies')[0].body).toEqual({ domainPattern: '*', level: 'none', acknowledgeInsecure: true });
  });

  it('sends no acknowledgement for anything else', async () => {
    const m = mockFetch({
      'GET /api/v1/admin/tls-policies': [],
      'POST /api/v1/admin/tls-policies': (c: RecordedCall) => json({ id: 'p8', ...(c.body as object), warnings: [] }, 201),
    });
    renderWithApp(<TlsPolicies />, { role: 'admin' });
    await screen.findByText('No policies');
    fireEvent.input(screen.getByLabelText('Recipient domain'), { target: { value: 'legacy.example' } });
    fireEvent.change(screen.getByLabelText('TLS level'), { target: { value: 'none' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add policy' }));
    await screen.findByText('Policy for legacy.example added.');
    expect(m.callsTo('POST', '/api/v1/admin/tls-policies')[0].body).toEqual({ domainPattern: 'legacy.example', level: 'none' });
  });

  it('edits the level and deletes after confirmation', async () => {
    let policies = [policy];
    const m = mockFetch({
      'GET /api/v1/admin/tls-policies': () => policies,
      'PATCH /api/v1/admin/tls-policies/:id': (c: RecordedCall) => {
        policies = [{ ...policy, ...(c.body as object) }];
        return json(policies[0]);
      },
      'DELETE /api/v1/admin/tls-policies/:id': () => {
        policies = [];
        return undefined;
      },
    });
    renderWithApp(<TlsPolicies />, { role: 'admin' });
    fireEvent.click(await screen.findByRole('button', { name: 'Edit *.bank.example' }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText('TLS level'), { target: { value: 'encrypt' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('Policy for *.bank.example saved.')).toBeTruthy();
    expect(m.callsTo('PATCH', '/api/v1/admin/tls-policies/p1')[0].body).toEqual({ domainPattern: '*.bank.example', level: 'encrypt' });

    fireEvent.click(await screen.findByRole('button', { name: 'Delete *.bank.example' }));
    expect(m.callsTo('DELETE', '/api/v1/admin/tls-policies/p1')).toHaveLength(0);
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Delete policy' }));
    expect(await screen.findByText('Policy for *.bank.example deleted.')).toBeTruthy();
    expect(await screen.findByText('No policies')).toBeTruthy();
  });
});
