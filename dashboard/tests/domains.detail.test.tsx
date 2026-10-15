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
    expect(screen.getByText(/DMARC, TLS-RPT and MTA-STS are recommended/)).toBeTruthy();
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

const ZONE = '; DNS records for mail.example.com\n\nmail.example.com. 3600 IN TXT "v=spf1 ~all"\n';

function extraRecords() {
  return [
    ...records(),
    { type: 'TXT', host: '_smtp._tls.mail.example.com', value: 'v=TLSRPTv1; rua=mailto:tls-rpt@mail.example.com', ttl: 3600, purpose: 'tls_rpt' as const, required: false, status: 'mismatch' as const, found: 'v=TLSRPTv1; rua=mailto:other@x.test', expected: 'v=TLSRPTv1; rua=mailto:tls-rpt@mail.example.com', note: 'Asks receivers to send daily TLS reports.' },
    { type: 'MX', host: 'bounces.example.net', value: '10 mta.example.net', ttl: 3600, purpose: 'bounce_mx' as const, required: false, status: 'missing' as const, found: null, expected: '10 mta.example.net', note: 'Published once by the operator.' },
  ];
}

describe('DomainDetail: setup, ready to send and the zone file', () => {
  it('shows the ready-to-send state, how many required and recommended records are published, and one Check DNS button', async () => {
    mockFetch({ 'GET /api/v1/domains/:id': makeDomain({ records: extraRecords() }) });
    renderWithApp(<DomainDetail id="d1" />);
    expect((await screen.findByTestId('ready-state')).textContent).toBe('Ready to send');
    expect(screen.getByTestId('record-progress').textContent).toContain('Required records: 2 of 2 published.');
    expect(screen.getByTestId('record-progress').textContent).toContain('Recommended records: 1 of 4 published.');
    expect(screen.getAllByRole('button', { name: 'Check DNS' })).toHaveLength(1);
  });

  it('a domain that cannot send yet says so', async () => {
    mockFetch({ 'GET /api/v1/domains/:id': makeDomain({ status: 'pending', readyToSend: false }) });
    renderWithApp(<DomainDetail id="d1" />);
    expect((await screen.findByTestId('ready-state')).textContent).toBe('Not ready to send');
  });

  it('labels each record required or recommended and shows mismatch, missing and the purpose of the new records', async () => {
    mockFetch({ 'GET /api/v1/domains/:id': makeDomain({ records: extraRecords() }) });
    renderWithApp(<DomainDetail id="d1" />);
    const table = await screen.findByRole('table', { name: 'DNS records to publish' });
    expect(within(table).getByText('Mismatch')).toBeTruthy();
    expect(within(table).getByText('TLS-RPT')).toBeTruthy();
    expect(within(table).getByText('Bounce MX')).toBeTruthy();
    expect(within(table).getAllByTestId('dns-level').map((e) => e.textContent).filter((t) => t === 'Required')).toHaveLength(2);
    expect(within(table).getAllByTestId('dns-level').map((e) => e.textContent).filter((t) => t === 'Recommended')).toHaveLength(4);
    // Found vs expected for the mismatch and the missing row.
    expect(within(table).getByText('v=TLSRPTv1; rua=mailto:other@x.test')).toBeTruthy();
    expect(within(table).getAllByText('Found in DNS')).toHaveLength(2);
    expect(within(table).getByText('Asks receivers to send daily TLS reports.')).toBeTruthy();
  });

  it('shows the zone file from the records endpoint and copies all of it', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } });
    const m = mockFetch({
      'GET /api/v1/domains/:id': makeDomain(),
      'GET /api/v1/domains/:id/records': { id: 'd1', name: 'mail.example.com', readyToSend: true, checkedAt: null, records: [], zoneFile: ZONE, mtaStsPolicy: null },
    });
    renderWithApp(<DomainDetail id="d1" />);
    expect((await screen.findByTestId('zone-file')).textContent).toBe(ZONE);
    fireEvent.click(screen.getByRole('button', { name: 'Copy zone file' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(ZONE));
    expect(m.callsTo('GET', '/api/v1/domains/d1/records').length).toBeGreaterThan(0);
    expect(screen.queryByTestId('mta-sts-policy')).toBeNull();
  });

  it('shows the MTA-STS policy file EggMail serves and the name that must point at the server', async () => {
    mockFetch({
      'GET /api/v1/domains/:id': makeDomain(),
      'GET /api/v1/domains/:id/records': {
        id: 'd1',
        name: 'mail.example.com',
        readyToSend: true,
        checkedAt: null,
        records: [],
        zoneFile: ZONE,
        mtaStsPolicy: { url: 'https://mta-sts.mail.example.com/.well-known/mta-sts.txt', host: 'mta-sts.mail.example.com', content: 'version: STSv1\r\nmode: testing\r\nmx: mta.example.net\r\nmax_age: 604800\r\n' },
      },
    });
    renderWithApp(<DomainDetail id="d1" />);
    expect((await screen.findByTestId('mta-sts-url')).textContent).toBe('https://mta-sts.mail.example.com/.well-known/mta-sts.txt');
    expect(screen.getByTestId('mta-sts-policy').textContent).toContain('mx: mta.example.net');
    expect(screen.getByText(/must point at this server/)).toBeTruthy();
  });

  it('still works when the records endpoint fails: the table is there, the zone file is not', async () => {
    mockFetch({ 'GET /api/v1/domains/:id': makeDomain(), 'GET /api/v1/domains/:id/records': () => problem(500, 'server_error') });
    renderWithApp(<DomainDetail id="d1" />);
    await screen.findByRole('table', { name: 'DNS records to publish' });
    expect(screen.queryByTestId('zone-file')).toBeNull();
  });

  it('Check DNS shows the result of the check in the table and loads the zone file again', async () => {
    const checked = makeDomain({ status: 'verified', lastCheckedAt: '2026-10-12T08:00:00.000Z', records: records({ spf: { status: 'ok', found: 'v=spf1 include:spf.eggmail.example.net ~all' } }) });
    const m = mockFetch({
      'GET /api/v1/domains/:id': makeDomain({ status: 'pending', readyToSend: false }),
      'POST /api/v1/domains/:id/verify': checked,
      'GET /api/v1/domains/:id/records': { id: 'd1', name: 'mail.example.com', readyToSend: true, checkedAt: null, records: [], zoneFile: ZONE, mtaStsPolicy: null },
    });
    renderWithApp(<DomainDetail id="d1" />);
    expect((await screen.findByTestId('ready-state')).textContent).toBe('Not ready to send');
    const before = m.callsTo('GET', '/api/v1/domains/d1/records').length;
    fireEvent.click(screen.getByRole('button', { name: 'Check DNS' }));
    await waitFor(() => expect(screen.getByTestId('ready-state').textContent).toBe('Ready to send'));
    await waitFor(() => expect(m.callsTo('GET', '/api/v1/domains/d1/records').length).toBeGreaterThan(before));
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

describe('DomainDetail: check DNS cooldown', () => {
  it('disables the button for 30 s with a countdown, then re-enables it', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const m = mockFetch({
      'GET /api/v1/domains/:id': makeDomain({ status: 'temporary_failure' }),
      'POST /api/v1/domains/:id/verify': makeDomain({ status: 'temporary_failure', lastCheckedAt: '2026-10-12T08:00:00.000Z' }),
    });
    renderWithApp(<DomainDetail id="d1" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Check DNS' }));
    const waiting = await screen.findByRole('button', { name: /Check again in 30 s/ });
    expect((waiting as HTMLButtonElement).disabled).toBe(true);
    expect(m.callsTo('POST', '/api/v1/domains/d1/verify')).toHaveLength(1);

    await act(async () => {
      vi.advanceTimersByTime(12_000);
    });
    await waitFor(() => expect(screen.getByRole('button', { name: /Check again in (1[7-9]|2\d) s/ })).toBeTruthy());

    await act(async () => {
      vi.advanceTimersByTime(20_000);
    });
    const again = await screen.findByRole('button', { name: 'Check DNS' });
    expect((again as HTMLButtonElement).disabled).toBe(false);
    expect(screen.getByText('You can check again.')).toBeTruthy();
  });

  it('on 429 uses Retry-After for the cooldown and explains it', async () => {
    mockFetch({
      'GET /api/v1/domains/:id': makeDomain(),
      'POST /api/v1/domains/:id/verify': () => problem(429, 'rate_limited', {}, { 'Retry-After': '17' }),
    });
    renderWithApp(<DomainDetail id="d1" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Check DNS' }));
    expect(await screen.findByRole('button', { name: /Check again in 1[67] s/ })).toBeTruthy();
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

  const withPending = () =>
    makeDomain({
      dkim: { selector: 'eggmail2', publicKey: 'NEWKEY', active: false, createdAt: '2026-10-12T08:00:00.000Z', retiredAt: null },
      dkimKeys: [
        { selector: 'eggmail1', publicKey: 'OLDKEY', active: true, createdAt: '2026-09-01T00:00:00.000Z', retiredAt: null },
        { selector: 'eggmail2', publicKey: 'NEWKEY', active: false, createdAt: '2026-10-12T08:00:00.000Z', retiredAt: null },
      ],
    });

  it('shows the signing key, the pending key as waiting for DNS, and cancels a pending rotation after confirmation', async () => {
    const cancelled = makeDomain({ dkimKeys: [{ selector: 'eggmail1', publicKey: 'OLDKEY', active: true, createdAt: '2026-09-01T00:00:00.000Z', retiredAt: null }] });
    const m = mockFetch({ 'GET /api/v1/domains/:id': withPending(), 'DELETE /api/v1/domains/:id/dkim/rotate': cancelled });
    renderWithApp(<DomainDetail id="d1" />);
    // The card describes the key that signs, not the pending one.
    expect((await screen.findByTestId('dkim-public-key')).textContent).toBe('OLDKEY');
    expect(screen.getByText('Key rotation pending')).toBeTruthy();
    expect(screen.getByText('Waiting for DNS')).toBeTruthy();
    expect(screen.getByText('Signing')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Cancel pending rotation' }));
    const dialog = await screen.findByRole('dialog');
    expect(m.callsTo('DELETE', '/api/v1/domains/d1/dkim/rotate')).toHaveLength(0);
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel rotation' }));
    await waitFor(() => expect(m.callsTo('DELETE', '/api/v1/domains/d1/dkim/rotate')).toHaveLength(1));
    await waitFor(() => expect(screen.queryByText('Key rotation pending')).toBeNull());
    expect(screen.queryByRole('button', { name: 'Cancel pending rotation' })).toBeNull();
  });

  it('offers no cancel button without a pending key', async () => {
    mockFetch({ 'GET /api/v1/domains/:id': makeDomain({ dkimKeys: [{ selector: 'eggmail1', publicKey: 'K', active: true, createdAt: '2026-09-01T00:00:00.000Z', retiredAt: null }] }) });
    renderWithApp(<DomainDetail id="d1" />);
    await screen.findByRole('button', { name: 'Rotate DKIM key' });
    expect(screen.queryByRole('button', { name: 'Cancel pending rotation' })).toBeNull();
  });
});
