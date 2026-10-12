import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, screen, waitFor, within } from '@testing-library/preact';
import DomainDetail from '../src/pages/DomainDetail';
import { mockFetch, problem, renderWithApp } from './helpers';
import { LONG_KEY, makeDomain, records } from './domainFixtures';

afterEach(() => {
  vi.useRealTimers();
});

describe('DomainDetail: records', () => {
  it('shows every record with type, host, value, TTL, purpose and a text status chip', async () => {
    mockFetch({
      'GET /api/v1/domains/:id': makeDomain({
        status: 'temporary_failure',
        records: records({ dkim: { status: 'invalid', found: 'v=DKIM1; p=old' }, return_path: { status: 'missing', found: null } }),
      }),
    });
    renderWithApp(<DomainDetail id="d1" />);
    const table = await screen.findByRole('table', { name: 'DNS records to publish' });
    const hosts = within(table).getAllByTestId('dns-host').map((e) => e.textContent);
    expect(hosts).toContain('eggmail1._domainkey.mail.example.com');
    expect(within(table).getByText('Invalid')).toBeTruthy();
    expect(within(table).getByText('Missing')).toBeTruthy();
    expect(within(table).getByText('Pending')).toBeTruthy();
    expect(within(table).getByText('OK')).toBeTruthy();
    expect(within(table).getAllByText('3600').length).toBeGreaterThan(0);
    // found vs expected only for broken rows
    expect(within(table).getAllByText('Found in DNS')).toHaveLength(2);
    expect(within(table).getByText('v=DKIM1; p=old')).toBeTruthy();
    expect(within(table).getByText('nothing found')).toBeTruthy();
  });

  it('shows the long DKIM TXT value untruncated and the publishing hints', async () => {
    mockFetch({ 'GET /api/v1/domains/:id': makeDomain() });
    renderWithApp(<DomainDetail id="d1" />);
    const values = await screen.findAllByTestId('dns-value');
    expect(values[0].textContent).toContain(LONG_KEY);
    expect(screen.getByText(/leading-underscore label/)).toBeTruthy();
    expect(screen.getByText('<selector>._domainkey.<domain>')).toBeTruthy();
    expect(screen.getByText(/more than 255 characters/)).toBeTruthy();
    expect(screen.getByText(/DMARC is informational/)).toBeTruthy();
  });

  it('copy buttons write the host and the value to the clipboard', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } });
    mockFetch({ 'GET /api/v1/domains/:id': makeDomain() });
    renderWithApp(<DomainDetail id="d1" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Copy DKIM host' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith('eggmail1._domainkey.mail.example.com'));
    fireEvent.click(screen.getByRole('button', { name: 'Copy DKIM value' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(`v=DKIM1; k=rsa; p=${LONG_KEY}`));
    expect(await screen.findAllByText('Copied')).not.toHaveLength(0);
  });
});

describe('DomainDetail: state banners', () => {
  it('temporary_failure: sending continues, fix the records', async () => {
    mockFetch({ 'GET /api/v1/domains/:id': makeDomain({ status: 'temporary_failure', lastError: 'DKIM mismatch' }) });
    renderWithApp(<DomainDetail id="d1" />);
    expect(await screen.findByText('Temporary verification failure')).toBeTruthy();
    expect(screen.getByText(/Sending continues for now/)).toBeTruthy();
    expect(screen.getAllByText('DKIM mismatch').length).toBeGreaterThan(0);
  });

  it('failed: verification failed and sending is paused (alert role)', async () => {
    mockFetch({ 'GET /api/v1/domains/:id': makeDomain({ status: 'failed', sendingPaused: true }) });
    renderWithApp(<DomainDetail id="d1" />);
    const title = await screen.findByText('Verification failed');
    expect(title.closest('[role="alert"]')).toBeTruthy();
    expect(screen.getByText(/Sending from this domain is paused/)).toBeTruthy();
    expect(screen.getByText('Sending paused')).toBeTruthy();
  });

  it('sendingPaused on a non-failed domain gets its own banner', async () => {
    mockFetch({ 'GET /api/v1/domains/:id': makeDomain({ status: 'verified', sendingPaused: true }) });
    renderWithApp(<DomainDetail id="d1" />);
    expect(await screen.findByText(/Sending from mail.example.com is currently paused/)).toBeTruthy();
  });

  it('pending blocks sending until verified', async () => {
    mockFetch({ 'GET /api/v1/domains/:id': makeDomain({ status: 'pending' }) });
    renderWithApp(<DomainDetail id="d1" />);
    expect(await screen.findByText(/blocked until it is verified/)).toBeTruthy();
  });

  it('a verified domain shows no state banner', async () => {
    mockFetch({ 'GET /api/v1/domains/:id': makeDomain() });
    renderWithApp(<DomainDetail id="d1" />);
    await screen.findByRole('table');
    expect(screen.queryByText('Temporary verification failure')).toBeNull();
    expect(screen.queryByText('Verification failed')).toBeNull();
  });
});

describe('DomainDetail: loading states', () => {
  it('shows not found for 404', async () => {
    mockFetch({ 'GET /api/v1/domains/:id': () => problem(404, 'not_found') });
    renderWithApp(<DomainDetail id="nope" />);
    expect(await screen.findByText('Domain not found')).toBeTruthy();
  });

  it('shows a retryable error otherwise', async () => {
    mockFetch({ 'GET /api/v1/domains/:id': () => problem(500, 'server_error') });
    renderWithApp(<DomainDetail id="d1" />);
    expect(await screen.findByRole('button', { name: 'Try again' })).toBeTruthy();
  });
});

describe('DomainDetail: verify now cooldown', () => {
  it('disables the button for 30 s with a countdown, then re-enables it', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const m = mockFetch({
      'GET /api/v1/domains/:id': makeDomain({ status: 'temporary_failure' }),
      'POST /api/v1/domains/:id/verify': makeDomain({ status: 'temporary_failure', lastCheckedAt: '2026-10-12T08:00:00.000Z' }),
    });
    renderWithApp(<DomainDetail id="d1" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Verify now' }));
    const waiting = await screen.findByRole('button', { name: /Verify again in 30 s/ });
    expect((waiting as HTMLButtonElement).disabled).toBe(true);
    expect(m.callsTo('POST', '/api/v1/domains/d1/verify')).toHaveLength(1);

    await act(async () => {
      vi.advanceTimersByTime(12_000);
    });
    await waitFor(() => expect(screen.getByRole('button', { name: /Verify again in (1[7-9]|2\d) s/ })).toBeTruthy());

    await act(async () => {
      vi.advanceTimersByTime(20_000);
    });
    const again = await screen.findByRole('button', { name: 'Verify now' });
    expect((again as HTMLButtonElement).disabled).toBe(false);
    expect(screen.getByText('You can verify again.')).toBeTruthy();
  });

  it('on 429 uses Retry-After for the cooldown and explains it', async () => {
    mockFetch({
      'GET /api/v1/domains/:id': makeDomain(),
      'POST /api/v1/domains/:id/verify': () => problem(429, 'rate_limited', {}, { 'Retry-After': '17' }),
    });
    renderWithApp(<DomainDetail id="d1" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Verify now' }));
    expect(await screen.findByRole('button', { name: /Verify again in 1[67] s/ })).toBeTruthy();
    expect(screen.getByText(/Too many requests/)).toBeTruthy();
  });
});

describe('DomainDetail: DKIM rotation', () => {
  it('asks for confirmation, explains the 7 day overlap and refreshes the key', async () => {
    const rotated = makeDomain({ dkim: { selector: 'eggmail2', publicKey: 'NEWKEY', active: true, createdAt: '2026-10-12T08:00:00.000Z' } });
    const m = mockFetch({ 'GET /api/v1/domains/:id': makeDomain(), 'POST /api/v1/domains/:id/dkim/rotate': rotated });
    renderWithApp(<DomainDetail id="d1" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Rotate DKIM key' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(/at least 7 days/)).toBeTruthy();
    expect(m.callsTo('POST', '/api/v1/domains/d1/dkim/rotate')).toHaveLength(0);
    fireEvent.click(within(dialog).getByRole('button', { name: 'Rotate key' }));
    await waitFor(() => expect(m.callsTo('POST', '/api/v1/domains/d1/dkim/rotate')).toHaveLength(1));
    expect(await screen.findByText('eggmail2')).toBeTruthy();
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('cancel does not rotate', async () => {
    const m = mockFetch({ 'GET /api/v1/domains/:id': makeDomain() });
    renderWithApp(<DomainDetail id="d1" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Rotate DKIM key' }));
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Cancel' }));
    expect(m.callsTo('POST', '/api/v1/domains/d1/dkim/rotate')).toHaveLength(0);
  });
});
