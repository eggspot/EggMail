import { describe, expect, it } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/preact';
import Certificates from '../src/pages/admin/Certificates';
import Status from '../src/pages/admin/Status';
import Tenants from '../src/pages/admin/Tenants';
import type { AdminStatus, MaintenanceState, Tenant } from '../src/api/types';
import { json, mockFetch, problem, renderWithApp } from './helpers';

const adminStatus: AdminStatus = {
  version: '0.1.0',
  backend: 'sqlite',
  historyMode: 'full',
  uptimeSeconds: 120,
  queue: { depth: 0, deferred: 0, oldestDueAt: null },
  storage: { healthy: true, detail: 'ok', warnings: [] },
  certificates: [],
  switch: { state: 'none' },
};

describe('Certificates: ACME renewals', () => {
  it('lists the renewal state of ACME certificates, with failures and the last error', async () => {
    mockFetch({
      'GET /api/v1/admin/certificates': [],
      'GET /api/v1/admin/certificates/acme': [
        { certificateName: 'default', status: 'failed', lastAttemptAt: '2026-10-12T08:00:00.000Z', nextAttemptAt: '2026-10-12T14:00:00.000Z', failures: 3, lastError: 'DNS-01 challenge was not published' },
      ],
    });
    renderWithApp(<Certificates />, { role: 'admin' });
    const table = await screen.findByRole('table', { name: 'ACME certificate renewals' });
    const row = within(table).getByRole('row', { name: /default/ });
    expect(row.textContent).toContain('failed');
    expect(row.textContent).toContain('3');
    expect(row.textContent).toContain('DNS-01 challenge was not published');
  });

  it('says so when nothing was requested through ACME', async () => {
    mockFetch({ 'GET /api/v1/admin/certificates': [], 'GET /api/v1/admin/certificates/acme': [] });
    renderWithApp(<Certificates />, { role: 'admin' });
    expect(await screen.findByText('No certificate was requested through ACME yet.')).toBeTruthy();
  });
});

describe('Server status: maintenance', () => {
  const finished: MaintenanceState = {
    running: false,
    startedAt: '2026-10-12T08:00:00.000Z',
    finishedAt: '2026-10-12T08:00:03.000Z',
    error: null,
    reports: [{ job: 'retention', durationMs: 120, rowsAffected: 42, detail: 'deleted expired events' }],
  };

  it('shows the report of the last run', async () => {
    mockFetch({ 'GET /api/v1/admin/status': adminStatus, 'GET /api/v1/admin/maintenance': finished });
    renderWithApp(<Status />, { role: 'admin' });
    const table = await screen.findByRole('table', { name: 'Maintenance jobs of the last run' });
    expect(within(table).getByRole('row', { name: /retention/ }).textContent).toContain('42');
    expect(screen.getByText('finished')).toBeTruthy();
  });

  it('shows a failed run and a server that has not run maintenance yet', async () => {
    mockFetch({ 'GET /api/v1/admin/status': adminStatus, 'GET /api/v1/admin/maintenance': { ...finished, error: 'disk full', reports: [] } });
    const first = renderWithApp(<Status />, { role: 'admin' });
    expect(await screen.findByText('failed')).toBeTruthy();
    expect(screen.getByText(/disk full/)).toBeTruthy();
    first.unmount();

    mockFetch({ 'GET /api/v1/admin/status': adminStatus, 'GET /api/v1/admin/maintenance': { running: false, startedAt: null, finishedAt: null, error: null, reports: [] } });
    renderWithApp(<Status />, { role: 'admin' });
    expect(await screen.findByText(/No maintenance run since the server started/)).toBeTruthy();
  });

  it('shows an error with a retry instead of spinning when the report cannot be loaded', async () => {
    let fail = true;
    mockFetch({
      'GET /api/v1/admin/status': adminStatus,
      'GET /api/v1/admin/maintenance': () => (fail ? problem(500, 'server_error') : { running: false, startedAt: null, finishedAt: null, error: null, reports: [] }),
    });
    renderWithApp(<Status />, { role: 'admin' });
    expect(await screen.findByText('The maintenance report could not be loaded')).toBeTruthy();
    fail = false;
    fireEvent.click(within(screen.getByText('The maintenance report could not be loaded').closest('[role="alert"]') as HTMLElement).getByRole('button', { name: 'Try again' }));
    expect(await screen.findByText(/No maintenance run since the server started/)).toBeTruthy();
  });

  it('starts a run and reloads the report', async () => {
    const m = mockFetch({
      'GET /api/v1/admin/status': adminStatus,
      'GET /api/v1/admin/maintenance': { running: false, startedAt: null, finishedAt: null, error: null, reports: [] },
      'POST /api/v1/admin/maintenance/run': () => json({ status: 'started' }, 202),
    });
    renderWithApp(<Status />, { role: 'admin' });
    await screen.findByText(/No maintenance run since the server started/);
    fireEvent.click(screen.getByRole('button', { name: 'Run maintenance now' }));
    await waitFor(() => expect(m.callsTo('POST', '/api/v1/admin/maintenance/run')).toHaveLength(1));
    await waitFor(() => expect(m.callsTo('GET', '/api/v1/admin/maintenance').length).toBeGreaterThan(1));
    expect(await screen.findByText('Maintenance run started.')).toBeTruthy();
  });
});

describe('Tenants: the header picker follows changes', () => {
  const tenant: Tenant = { id: 't_new', name: 'New Co', status: 'active', createdAt: '2026-10-12T08:00:00.000Z' };

  it('refreshes the picker after creating, and selects the tenant when none was acted on yet', async () => {
    const refreshed: (string | undefined)[] = [];
    mockFetch({ 'GET /api/v1/admin/tenants': [], 'POST /api/v1/admin/tenants': () => json(tenant, 201) });
    renderWithApp(<Tenants />, { role: 'admin', tenantId: null, refreshTenants: async (select?: string) => void refreshed.push(select) });
    await screen.findByText('No tenants yet');
    fireEvent.input(screen.getByLabelText('Name'), { target: { value: 'New Co' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create tenant' }));
    await screen.findByText('Tenant New Co created.');
    expect(refreshed).toEqual(['t_new']);
  });

  it('keeps acting on the current tenant when another one is created', async () => {
    const refreshed: (string | undefined)[] = [];
    mockFetch({ 'GET /api/v1/admin/tenants': [], 'POST /api/v1/admin/tenants': () => json(tenant, 201) });
    renderWithApp(<Tenants />, { role: 'admin', tenantId: 't_1', refreshTenants: async (select?: string) => void refreshed.push(select) });
    await screen.findByText('No tenants yet');
    fireEvent.input(screen.getByLabelText('Name'), { target: { value: 'New Co' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create tenant' }));
    await screen.findByText('Tenant New Co created.');
    expect(refreshed).toEqual([undefined]);
  });
});
