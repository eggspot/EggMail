import { describe, expect, it } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/preact';
import Credentials from '../src/pages/Credentials';
import { json, mockFetch, problem, renderWithApp } from './helpers';
import type { RecordedCall } from './helpers';

const keys = [
  { id: 'k1', name: 'Production sender', prefix: 'egk_a1b2c3', scopes: ['send'], createdAt: '2026-09-01T00:00:00.000Z', lastUsedAt: null },
  { id: 'k2', name: 'Reporting', prefix: 'egk_d4e5f6', scopes: ['read', 'suppressions'], createdAt: '2026-09-20T00:00:00.000Z', lastUsedAt: '2026-10-12T07:00:00.000Z' },
];
const smtp = [{ id: 's1', username: 'app-mailer', createdAt: '2026-09-01T00:00:00.000Z' }];

function base() {
  return { 'GET /api/v1/api-keys': keys, 'GET /api/v1/smtp-credentials': smtp };
}

describe('Credentials page', () => {
  it('lists API keys with prefix and scope chips, and SMTP users', async () => {
    mockFetch(base());
    renderWithApp(<Credentials />);
    expect(await screen.findByText('Production sender')).toBeTruthy();
    expect(screen.getByText('egk_a1b2c3')).toBeTruthy();
    expect(screen.getByText('suppressions', { selector: '.chip' })).toBeTruthy();
    expect(screen.getByText('Never')).toBeTruthy();
    expect(await screen.findByText('app-mailer')).toBeTruthy();
  });

  it('requires a name and at least one scope', async () => {
    const m = mockFetch(base());
    renderWithApp(<Credentials />);
    await screen.findByText('Production sender');
    fireEvent.click(screen.getByRole('checkbox', { name: /^send send mail/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Create API key' }));
    expect(await screen.findByText(/Give the key a name/)).toBeTruthy();
    expect(screen.getByText('Select at least one scope.')).toBeTruthy();
    expect(m.callsTo('POST', '/api/v1/api-keys')).toHaveLength(0);
  });

  it('shows a new API key once, with a copy button and a warning, then forgets it', async () => {
    const m = mockFetch({
      ...base(),
      'POST /api/v1/api-keys': (c: RecordedCall) => json({ id: 'k3', prefix: 'egk_zzzzzz', scopes: (c.body as { scopes: string[] }).scopes, name: (c.body as { name: string }).name, createdAt: '2026-10-12T00:00:00.000Z', key: 'egk_zzzzzz-SECRET-VALUE' }, 201),
    });
    renderWithApp(<Credentials />);
    await screen.findByText('Production sender');
    fireEvent.input(screen.getByLabelText('Key name'), { target: { value: 'CI' } });
    fireEvent.click(screen.getByRole('checkbox', { name: /^read read messages/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Create API key' }));
    const secret = await screen.findByTestId('secret-value');
    expect(secret.textContent).toBe('egk_zzzzzz-SECRET-VALUE');
    expect(screen.getByText(/shown only once/)).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Copy secret' })).toBeTruthy();
    expect(m.callsTo('POST', '/api/v1/api-keys')[0].body).toEqual({ name: 'CI', scopes: ['send', 'read'] });
    expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toContain('SECRET-VALUE');
    fireEvent.click(screen.getByRole('button', { name: 'I have saved it' }));
    expect(document.body.textContent).not.toContain('SECRET-VALUE');
  });

  it('maps server field errors for the key name', async () => {
    mockFetch({ ...base(), 'POST /api/v1/api-keys': () => problem(400, 'validation_failed', { errors: [{ field: 'name', message: 'Name already used.' }] }) });
    renderWithApp(<Credentials />);
    await screen.findByText('Production sender');
    fireEvent.input(screen.getByLabelText('Key name'), { target: { value: 'dup' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create API key' }));
    expect(await screen.findByText('Name already used.')).toBeTruthy();
  });

  it('revokes an API key after confirmation', async () => {
    const m = mockFetch({ ...base(), 'DELETE /api/v1/api-keys/:id': () => undefined });
    renderWithApp(<Credentials />);
    fireEvent.click(await screen.findByRole('button', { name: 'Revoke API key Reporting' }));
    const dialog = await screen.findByRole('dialog');
    expect(m.callsTo('DELETE', '/api/v1/api-keys/k2')).toHaveLength(0);
    fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke key' }));
    await waitFor(() => expect(m.callsTo('DELETE', '/api/v1/api-keys/k2')).toHaveLength(1));
  });

  it('shows the SMTP password once with usage guidance', async () => {
    const m = mockFetch({
      ...base(),
      'POST /api/v1/smtp-credentials': json({ id: 's2', username: 'mailer-2', createdAt: '2026-10-12T00:00:00.000Z', password: 'p4ssw0rd-ONCE' }, 201),
    });
    renderWithApp(<Credentials />);
    await screen.findByText('app-mailer');
    fireEvent.input(screen.getByLabelText('Username'), { target: { value: 'mailer-2' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create SMTP credential' }));
    expect((await screen.findByTestId('secret-value')).textContent).toBe('p4ssw0rd-ONCE');
    expect(screen.getByText(/AUTH PLAIN or LOGIN over STARTTLS or TLS only/)).toBeTruthy();
    expect(m.callsTo('POST', '/api/v1/smtp-credentials')[0].body).toEqual({ username: 'mailer-2' });
    fireEvent.click(screen.getByRole('button', { name: 'I have saved it' }));
    expect(screen.queryByTestId('secret-value')).toBeNull();
  });

  it('requires a username and shows duplicate errors from the server', async () => {
    mockFetch({ ...base(), 'POST /api/v1/smtp-credentials': () => problem(400, 'validation_failed', { errors: [{ field: 'username', message: 'This username already exists.' }] }) });
    renderWithApp(<Credentials />);
    await screen.findByText('app-mailer');
    fireEvent.click(screen.getByRole('button', { name: 'Create SMTP credential' }));
    expect(await screen.findByText('Enter a username.')).toBeTruthy();
    fireEvent.input(screen.getByLabelText('Username'), { target: { value: 'app-mailer' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create SMTP credential' }));
    expect(await screen.findByText('This username already exists.')).toBeTruthy();
  });

  it('revokes an SMTP credential after confirmation', async () => {
    const m = mockFetch({ ...base(), 'DELETE /api/v1/smtp-credentials/:id': () => undefined });
    renderWithApp(<Credentials />);
    fireEvent.click(await screen.findByRole('button', { name: 'Revoke SMTP credential app-mailer' }));
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Revoke credential' }));
    await waitFor(() => expect(m.callsTo('DELETE', '/api/v1/smtp-credentials/s1')).toHaveLength(1));
  });
});
