import { describe, expect, it } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/preact';
import Domains, { validateDomainName } from '../src/pages/Domains';
import { json, mockFetch, problem, renderWithApp } from './helpers';
import type { RecordedCall } from './helpers';
import { makeDomain } from './domainFixtures';

const list = [
  makeDomain({ id: 'd1', name: 'example.com', status: 'verified' }),
  makeDomain({ id: 'd2', name: 'old.example.org', status: 'failed', sendingPaused: true }),
];

describe('validateDomainName', () => {
  it('accepts hostnames and rejects schemes, paths and spaces', () => {
    expect(validateDomainName('mail.example.com')).toBeUndefined();
    expect(validateDomainName('')).toMatch(/Enter a domain/);
    expect(validateDomainName('https://example.com')).toMatch(/valid domain/);
    expect(validateDomainName('exa mple.com')).toMatch(/valid domain/);
    expect(validateDomainName('localhost')).toMatch(/valid domain/);
  });
});

describe('Domains page', () => {
  it('lists domains with status chips as text and a paused indicator', async () => {
    mockFetch({ 'GET /api/v1/domains': list });
    renderWithApp(<Domains />);
    const row = (await screen.findByRole('link', { name: 'example.com' })).closest('tr')!;
    expect(within(row).getByText('Verified')).toBeTruthy();
    const failedRow = screen.getByRole('link', { name: 'old.example.org' }).closest('tr')!;
    expect(within(failedRow).getByText('Failed')).toBeTruthy();
    expect(within(failedRow).getByText('Paused')).toBeTruthy();
  });

  it('shows an empty state', async () => {
    mockFetch({ 'GET /api/v1/domains': [] });
    renderWithApp(<Domains />);
    expect(await screen.findByText('No domains yet')).toBeTruthy();
  });

  it('shows a retryable error when loading fails', async () => {
    mockFetch({ 'GET /api/v1/domains': () => problem(500, 'server_error') });
    renderWithApp(<Domains />);
    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Try again' })).toBeTruthy();
  });

  it('validates the name on the client before calling the API', async () => {
    const m = mockFetch({ 'GET /api/v1/domains': [] });
    renderWithApp(<Domains />);
    await screen.findByText('No domains yet');
    fireEvent.input(screen.getByLabelText('Domain name'), { target: { value: 'not a domain' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add domain' }));
    expect(await screen.findByText(/Enter a valid domain name/)).toBeTruthy();
    expect(m.callsTo('POST', '/api/v1/domains')).toHaveLength(0);
    expect(screen.getByLabelText('Domain name').getAttribute('aria-invalid')).toBe('true');
  });

  it('maps server validation_failed field errors onto the field', async () => {
    mockFetch({
      'GET /api/v1/domains': [],
      'POST /api/v1/domains': () => problem(400, 'validation_failed', { errors: [{ field: 'name', message: 'This domain already exists.' }] }),
    });
    renderWithApp(<Domains />);
    await screen.findByText('No domains yet');
    fireEvent.input(screen.getByLabelText('Domain name'), { target: { value: 'example.com' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add domain' }));
    expect(await screen.findByText('This domain already exists.')).toBeTruthy();
  });

  it('creates a domain with a lower-cased name and sends the CSRF token', async () => {
    const m = mockFetch({
      'GET /api/v1/domains': [],
      'POST /api/v1/domains': (c: RecordedCall) => json(makeDomain({ id: 'new1', name: (c.body as { name: string }).name }), 201),
    });
    const { setCsrfToken } = await import('../src/api/client');
    setCsrfToken('tok');
    renderWithApp(<Domains />);
    await screen.findByText('No domains yet');
    fireEvent.input(screen.getByLabelText('Domain name'), { target: { value: 'Mail.Example.COM' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add domain' }));
    await waitFor(() => expect(m.callsTo('POST', '/api/v1/domains')).toHaveLength(1));
    const call = m.callsTo('POST', '/api/v1/domains')[0];
    expect(call.body).toEqual({ name: 'mail.example.com' });
    expect(call.headers.get('X-CSRF-Token')).toBe('tok');
  });

  it('requires typing the domain name to delete', async () => {
    const m = mockFetch({ 'GET /api/v1/domains': list, 'DELETE /api/v1/domains/:id': () => undefined });
    renderWithApp(<Domains />);
    await screen.findByRole('link', { name: 'example.com' });
    fireEvent.click(screen.getByRole('button', { name: 'Delete example.com' }));
    const dialog = await screen.findByRole('dialog');
    const confirm = within(dialog).getByRole('button', { name: 'Delete domain' }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    fireEvent.input(within(dialog).getByLabelText(/Type "example.com" to confirm/), { target: { value: 'example.com' } });
    expect(confirm.disabled).toBe(false);
    fireEvent.click(confirm);
    await waitFor(() => expect(m.callsTo('DELETE', '/api/v1/domains/d1')).toHaveLength(1));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });
});
