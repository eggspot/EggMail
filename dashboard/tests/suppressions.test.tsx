import { describe, expect, it } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/preact';
import Suppressions from '../src/pages/Suppressions';
import { json, mockFetch, problem, renderWithApp } from './helpers';

const page1 = {
  items: [
    { address: 'anna@gmail.example', reason: 'bounce', createdAt: '2026-10-01T00:00:00.000Z' },
    { address: 'ben@corp.example', reason: 'complaint', createdAt: '2026-10-02T00:00:00.000Z' },
  ],
  next_cursor: 'c2',
};
const page2 = { items: [{ address: 'zed@isp.example', reason: 'manual', createdAt: '2026-09-01T00:00:00.000Z' }], next_cursor: null };

function pages() {
  return (c: { query: URLSearchParams }) => (c.query.get('cursor') === 'c2' ? page2 : page1);
}

describe('Suppressions page', () => {
  it('lists addresses with reasons and loads more with the cursor', async () => {
    const m = mockFetch({ 'GET /api/v1/suppressions': pages() });
    renderWithApp(<Suppressions />);
    expect(await screen.findByText('anna@gmail.example')).toBeTruthy();
    expect(screen.getByText('complaint', { selector: '.chip' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }));
    expect(await screen.findByText('zed@isp.example')).toBeTruthy();
    expect(m.callsTo('GET', '/api/v1/suppressions').map((c) => c.query.get('cursor'))).toEqual([null, 'c2']);
    expect(screen.queryByRole('button', { name: 'Load more' })).toBeNull();
  });

  it('filters loaded entries and says so while more pages exist', async () => {
    mockFetch({ 'GET /api/v1/suppressions': pages() });
    renderWithApp(<Suppressions />);
    await screen.findByText('anna@gmail.example');
    expect(screen.getByText(/applies to loaded entries only/)).toBeTruthy();
    fireEvent.input(screen.getByLabelText('Filter loaded addresses'), { target: { value: 'corp' } });
    expect(screen.queryByText('anna@gmail.example')).toBeNull();
    expect(screen.getByText('ben@corp.example')).toBeTruthy();
    fireEvent.input(screen.getByLabelText('Filter loaded addresses'), { target: { value: 'nothing' } });
    expect(screen.getByText(/No loaded address matches/)).toBeTruthy();
  });

  it('shows an empty state', async () => {
    mockFetch({ 'GET /api/v1/suppressions': { items: [], next_cursor: null } });
    renderWithApp(<Suppressions />);
    expect(await screen.findByText('The suppression list is empty')).toBeTruthy();
  });

  it('shows an error with retry when loading fails', async () => {
    mockFetch({ 'GET /api/v1/suppressions': () => problem(500, 'server_error') });
    renderWithApp(<Suppressions />);
    expect(await screen.findByRole('button', { name: 'Try again' })).toBeTruthy();
  });

  it('validates the address, then adds it to the top of the list', async () => {
    const m = mockFetch({
      'GET /api/v1/suppressions': { items: [], next_cursor: null },
      'POST /api/v1/suppressions': (c) => json({ ...(c.body as object), createdAt: '2026-10-12T00:00:00.000Z' }, 201),
    });
    renderWithApp(<Suppressions />);
    await screen.findByText('The suppression list is empty');
    fireEvent.input(screen.getByLabelText('Email address'), { target: { value: 'nope' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add to suppression list' }));
    expect(await screen.findByText('Enter a valid email address.')).toBeTruthy();
    expect(m.callsTo('POST', '/api/v1/suppressions')).toHaveLength(0);
    fireEvent.input(screen.getByLabelText('Email address'), { target: { value: 'New@Example.com' } });
    fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'complaint' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add to suppression list' }));
    expect(await screen.findByText('new@example.com is on the suppression list.')).toBeTruthy();
    expect(m.callsTo('POST', '/api/v1/suppressions')[0].body).toEqual({ address: 'new@example.com', reason: 'complaint' });
    expect(screen.getAllByText('new@example.com').length).toBeGreaterThan(0);
  });

  it('maps server field errors', async () => {
    mockFetch({
      'GET /api/v1/suppressions': { items: [], next_cursor: null },
      'POST /api/v1/suppressions': () => problem(400, 'validation_failed', { errors: [{ field: 'address', message: 'Role addresses are not allowed.' }] }),
    });
    renderWithApp(<Suppressions />);
    await screen.findByText('The suppression list is empty');
    fireEvent.input(screen.getByLabelText('Email address'), { target: { value: 'abuse@example.com' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add to suppression list' }));
    expect(await screen.findByText('Role addresses are not allowed.')).toBeTruthy();
  });

  it('removes an address after confirmation (URL-encoding the address)', async () => {
    const m = mockFetch({ 'GET /api/v1/suppressions': page2, 'DELETE /api/v1/suppressions/:address': () => undefined });
    renderWithApp(<Suppressions />);
    fireEvent.click(await screen.findByRole('button', { name: 'Remove zed@isp.example' }));
    const dialog = await screen.findByRole('dialog');
    expect(m.callsTo('DELETE', '/api/v1/suppressions/zed%40isp.example')).toHaveLength(0);
    fireEvent.click(within(dialog).getByRole('button', { name: 'Remove address' }));
    await waitFor(() => expect(m.callsTo('DELETE', '/api/v1/suppressions/zed%40isp.example')).toHaveLength(1));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(screen.queryByRole('button', { name: 'Remove zed@isp.example' })).toBeNull();
    expect(screen.getByText(/was removed/)).toBeTruthy();
  });

  it('treats 404 on remove as already removed', async () => {
    mockFetch({ 'GET /api/v1/suppressions': page2, 'DELETE /api/v1/suppressions/:address': () => problem(404, 'not_found') });
    renderWithApp(<Suppressions />);
    fireEvent.click(await screen.findByRole('button', { name: 'Remove zed@isp.example' }));
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Remove address' }));
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Remove zed@isp.example' })).toBeNull());
  });
});
