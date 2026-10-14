import { describe, expect, it } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/preact';
import Account from '../src/pages/Account';
import Users from '../src/pages/admin/Users';
import type { DashboardUser, Tenant } from '../src/api/types';
import { json, mockFetch, problem, renderWithApp } from './helpers';

const tenants: Tenant[] = [
  { id: 't_acme', name: 'Acme Corp', status: 'active' },
  { id: 't_old', name: 'Old Co', status: 'suspended' },
];

const users: DashboardUser[] = [
  { id: 'u1', userName: 'admin', role: 'admin', enabled: true, createdAt: '2026-08-01T09:00:00.000Z' },
  { id: 'u2', userName: 'jane', role: 'tenant', tenantId: 't_acme', enabled: true, createdAt: '2026-08-02T09:00:00.000Z' },
  { id: 'u3', userName: 'old.admin', role: 'admin', enabled: false, createdAt: '2026-08-03T09:00:00.000Z' },
];

const lastAdmin = () => problem(409, 'conflict', { detail: 'This is the only enabled administrator. Create or enable another administrator first.', reason: 'last_admin' });

function routes(extra: Record<string, unknown> = {}) {
  return { 'GET /api/v1/admin/users': users, 'GET /api/v1/admin/tenants': tenants, ...extra };
}

describe('Users page', () => {
  it('lists users with role, tenant and status, and keeps you from resetting your own password there', async () => {
    mockFetch(routes());
    renderWithApp(<Users />, { role: 'admin' });
    const table = await screen.findByRole('table', { name: 'Dashboard users' });
    const jane = within(table).getByRole('row', { name: /jane/ });
    expect(jane.textContent).toContain('tenant user');
    expect(jane.textContent).toContain('Acme Corp');
    expect(jane.textContent).toContain('enabled');
    expect(within(table).getByRole('row', { name: /old.admin/ }).textContent).toContain('disabled');
    const me = within(table).getByRole('row', { name: /admin \(you\)/ });
    expect(me.textContent).toContain('All tenants');
    expect((within(me).getByRole('button', { name: 'Reset password of admin' }) as HTMLButtonElement).disabled).toBe(true);
    expect(within(me).getByRole('button', { name: 'Disable admin' })).toBeTruthy();
    expect(within(table).getByRole('button', { name: 'Enable old.admin' })).toBeTruthy();
  });

  it('creates a tenant user, validates before sending and shows the generated password once', async () => {
    const m = mockFetch(
      routes({
        'POST /api/v1/admin/users': () => json({ id: 'u9', userName: 'carol', role: 'tenant', tenantId: 't_acme', enabled: true, createdAt: '2026-10-14T09:00:00.000Z', password: 'Gen3rated-Passw0rd-x' }, 201),
      }),
    );
    renderWithApp(<Users />, { role: 'admin' });
    await screen.findByRole('table', { name: 'Dashboard users' });

    fireEvent.click(screen.getByRole('button', { name: 'Create user' }));
    expect(await screen.findByText('Enter a user name.')).toBeTruthy();
    expect(screen.getByText('Choose the tenant this user belongs to.')).toBeTruthy();
    expect(m.callsTo('POST', '/api/v1/admin/users')).toHaveLength(0);

    fireEvent.input(screen.getByLabelText('User name'), { target: { value: ' carol ' } });
    fireEvent.change(screen.getByLabelText('Tenant'), { target: { value: 't_acme' } });
    fireEvent.input(screen.getByLabelText('Password (optional)'), { target: { value: 'short' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create user' }));
    expect(await screen.findByText(/Use at least 10 characters, or leave it empty/)).toBeTruthy();

    fireEvent.input(screen.getByLabelText('Password (optional)'), { target: { value: '' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create user' }));
    const secret = await screen.findByTestId('secret-value');
    expect(secret.textContent).toBe('Gen3rated-Passw0rd-x');
    expect(m.callsTo('POST', '/api/v1/admin/users')[0].body).toEqual({ userName: 'carol', role: 'tenant', tenantId: 't_acme' });
    expect(screen.getByText('User carol created.')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'I have saved it' }));
    expect(screen.queryByTestId('secret-value')).toBeNull();
  });

  it('offers only active tenants and sends no tenant for an administrator', async () => {
    const m = mockFetch(routes({ 'POST /api/v1/admin/users': () => json({ id: 'u8', userName: 'boss', role: 'admin', enabled: true, createdAt: '2026-10-14T09:00:00.000Z' }, 201) }));
    renderWithApp(<Users />, { role: 'admin' });
    await screen.findByRole('table', { name: 'Dashboard users' });
    const tenantSelect = screen.getByLabelText('Tenant') as HTMLSelectElement;
    expect([...tenantSelect.options].map((o) => o.textContent)).toEqual(['Choose a tenant', 'Acme Corp']);
    fireEvent.change(screen.getByLabelText('Role'), { target: { value: 'admin' } });
    expect(screen.queryByLabelText('Tenant')).toBeNull();
    fireEvent.input(screen.getByLabelText('User name'), { target: { value: 'boss' } });
    fireEvent.input(screen.getByLabelText('Password (optional)'), { target: { value: 'chosen-by-the-admin' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create user' }));
    await screen.findByText('User boss created.');
    expect(m.callsTo('POST', '/api/v1/admin/users')[0].body).toEqual({ userName: 'boss', role: 'admin', password: 'chosen-by-the-admin' });
    expect(screen.queryByTestId('secret-value')).toBeNull(); // a password the admin chose is not shown again
  });

  it('shows the server field error of a taken name', async () => {
    mockFetch(routes({ 'POST /api/v1/admin/users': () => problem(400, 'validation_failed', { errors: [{ field: 'userName', message: 'A user with this name already exists.' }] }) }));
    renderWithApp(<Users />, { role: 'admin' });
    await screen.findByRole('table', { name: 'Dashboard users' });
    fireEvent.input(screen.getByLabelText('User name'), { target: { value: 'jane' } });
    fireEvent.change(screen.getByLabelText('Tenant'), { target: { value: 't_acme' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create user' }));
    expect(await screen.findByText('A user with this name already exists.')).toBeTruthy();
  });

  it('disables and enables a user after a confirmation', async () => {
    const m = mockFetch(routes({ 'PATCH /api/v1/admin/users/:id': (_c: unknown, p: Record<string, string>) => ({ ...users.find((u) => u.id === p.id) }) }));
    renderWithApp(<Users />, { role: 'admin' });
    await screen.findByRole('table', { name: 'Dashboard users' });
    fireEvent.click(screen.getByRole('button', { name: 'Disable jane' }));
    const dialog = await screen.findByRole('dialog');
    expect(dialog.textContent).toContain('signed out everywhere');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Disable' }));
    await screen.findByText('jane is disabled and was signed out everywhere.');
    expect(m.callsTo('PATCH', '/api/v1/admin/users/u2')[0].body).toEqual({ enabled: false });

    fireEvent.click(screen.getByRole('button', { name: 'Enable old.admin' }));
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Enable' }));
    await screen.findByText('old.admin can sign in again.');
    expect(m.callsTo('PATCH', '/api/v1/admin/users/u3')[0].body).toEqual({ enabled: true });
  });

  it('surfaces the last-administrator refusal in the dialog and keeps the dialog open', async () => {
    mockFetch(routes({ 'PATCH /api/v1/admin/users/:id': lastAdmin, 'DELETE /api/v1/admin/users/:id': lastAdmin }));
    renderWithApp(<Users />, { role: 'admin' });
    await screen.findByRole('table', { name: 'Dashboard users' });
    fireEvent.click(screen.getByRole('button', { name: 'Disable admin' }));
    let dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Disable' }));
    expect((await within(dialog).findAllByText(/only enabled administrator/)).length).toBeGreaterThan(0);
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());

    fireEvent.click(screen.getByRole('button', { name: 'Delete admin' }));
    dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete user' }));
    expect((await within(dialog).findAllByText(/only enabled administrator/)).length).toBeGreaterThan(0);
  });

  it('changes the role and sends only what changed', async () => {
    const m = mockFetch(routes({ 'PATCH /api/v1/admin/users/:id': () => ({ ...users[1], role: 'admin', tenantId: null }) }));
    renderWithApp(<Users />, { role: 'admin' });
    await screen.findByRole('table', { name: 'Dashboard users' });
    fireEvent.click(screen.getByRole('button', { name: 'Change role of jane' }));
    const dialog = await screen.findByRole('dialog');
    expect((within(dialog).getByRole('button', { name: 'Save' }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(within(dialog).getByLabelText('Role'), { target: { value: 'admin' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
    await screen.findByText('jane is now an administrator.');
    expect(m.callsTo('PATCH', '/api/v1/admin/users/u2')[0].body).toEqual({ role: 'admin' });
  });

  it('resets a password and shows the generated one once', async () => {
    const m = mockFetch(routes({ 'POST /api/v1/admin/users/:id/reset-password': () => json({ ...users[1], password: 'Reset-Passw0rd-123456' }) }));
    renderWithApp(<Users />, { role: 'admin' });
    await screen.findByRole('table', { name: 'Dashboard users' });
    fireEvent.click(screen.getByRole('button', { name: 'Reset password of jane' }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.input(within(dialog).getByLabelText('New password (optional)'), { target: { value: 'tiny' } });
    expect(within(dialog).getByText('Use at least 10 characters.')).toBeTruthy();
    expect((within(dialog).getByRole('button', { name: 'Reset password' }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.input(within(dialog).getByLabelText('New password (optional)'), { target: { value: '' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Reset password' }));
    expect((await screen.findByTestId('secret-value')).textContent).toBe('Reset-Passw0rd-123456');
    expect(m.callsTo('POST', '/api/v1/admin/users/u2/reset-password')[0].body).toEqual({});
  });

  it('deletes a user after a confirmation', async () => {
    const m = mockFetch(routes({ 'DELETE /api/v1/admin/users/:id': () => undefined }));
    renderWithApp(<Users />, { role: 'admin' });
    await screen.findByRole('table', { name: 'Dashboard users' });
    fireEvent.click(screen.getByRole('button', { name: 'Delete jane' }));
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Delete user' }));
    await screen.findByText('jane was deleted.');
    expect(m.callsTo('DELETE', '/api/v1/admin/users/u2')).toHaveLength(1);
  });
});

describe('Account page', () => {
  it('checks the form before sending and changes the password', async () => {
    const m = mockFetch({ 'POST /api/v1/me/password': () => undefined });
    renderWithApp(<Account />, { role: 'tenant' });
    fireEvent.click(screen.getByRole('button', { name: 'Change password' }));
    expect(await screen.findByText('Enter your current password.')).toBeTruthy();
    expect(screen.getByText('Use at least 10 characters.')).toBeTruthy();

    fireEvent.input(screen.getByLabelText('Current password'), { target: { value: 'old password!' } });
    fireEvent.input(screen.getByLabelText('New password'), { target: { value: 'a brand new password' } });
    fireEvent.input(screen.getByLabelText('New password again'), { target: { value: 'a brand new passwor' } });
    fireEvent.click(screen.getByRole('button', { name: 'Change password' }));
    expect(await screen.findByText('The two new passwords are not the same.')).toBeTruthy();
    expect(m.callsTo('POST', '/api/v1/me/password')).toHaveLength(0);

    fireEvent.input(screen.getByLabelText('New password again'), { target: { value: 'a brand new password' } });
    fireEvent.click(screen.getByRole('button', { name: 'Change password' }));
    await screen.findByText('Password changed. Your other sessions were signed out.');
    expect(m.callsTo('POST', '/api/v1/me/password')[0].body).toEqual({ currentPassword: 'old password!', newPassword: 'a brand new password' });
    expect((screen.getByLabelText('Current password') as HTMLInputElement).value).toBe('');
  });

  it('shows the server message for a wrong current password under the field', async () => {
    mockFetch({ 'POST /api/v1/me/password': () => problem(400, 'validation_failed', { errors: [{ field: 'currentPassword', message: 'The current password is not correct.' }] }) });
    renderWithApp(<Account />, { role: 'tenant' });
    fireEvent.input(screen.getByLabelText('Current password'), { target: { value: 'wrong password' } });
    fireEvent.input(screen.getByLabelText('New password'), { target: { value: 'a brand new password' } });
    fireEvent.input(screen.getByLabelText('New password again'), { target: { value: 'a brand new password' } });
    fireEvent.click(screen.getByRole('button', { name: 'Change password' }));
    expect(await screen.findByText('The current password is not correct.')).toBeTruthy();
    expect(screen.queryByText(/Password changed/)).toBeNull();
  });

  it('shows the lockout as an error with the wait time', async () => {
    mockFetch({ 'POST /api/v1/me/password': () => problem(429, 'rate_limited', {}, { 'Retry-After': '120' }) });
    renderWithApp(<Account />, { role: 'tenant' });
    fireEvent.input(screen.getByLabelText('Current password'), { target: { value: 'x'.repeat(12) } });
    fireEvent.input(screen.getByLabelText('New password'), { target: { value: 'a brand new password' } });
    fireEvent.input(screen.getByLabelText('New password again'), { target: { value: 'a brand new password' } });
    fireEvent.click(screen.getByRole('button', { name: 'Change password' }));
    expect(await screen.findByText(/Too many requests/)).toBeTruthy();
  });
});
