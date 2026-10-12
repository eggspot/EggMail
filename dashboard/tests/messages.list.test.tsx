import { describe, expect, it } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/preact';
import Messages from '../src/pages/Messages';
import { flush, mockFetch, problem, renderWithApp } from './helpers';
import { summary } from './messageFixtures';

const A = summary({ id: 'a'.repeat(32), subject: 'First subject' });
const B = summary({ id: 'b'.repeat(32), subject: 'Second subject', status: 'bounced', recipients: ['x@y.test', 'z@y.test', 'w@y.test'] });

describe('Messages list', () => {
  it('shows a loading state and then the results with links to the detail page', async () => {
    const m = mockFetch({ 'GET /api/v1/messages': { items: [A, B], next_cursor: null } });
    renderWithApp(<Messages />);
    expect(screen.getByRole('status').textContent).toContain('Searching');
    const link = await screen.findByRole('link', { name: 'First subject' });
    expect(link.getAttribute('href')).toBe(`/messages/${A.id}`);
    expect(screen.getByText('Second subject')).toBeTruthy();
    expect(screen.getByText('+2 more')).toBeTruthy();
    expect(m.callsTo('GET', '/api/v1/messages')[0].query.get('limit')).toBe('25');
    expect(screen.queryByRole('button', { name: 'Load more' })).toBeNull();
  });

  it('submits the filters, converting datetime-local values to ISO', async () => {
    const m = mockFetch({ 'GET /api/v1/messages': { items: [A], next_cursor: null } });
    renderWithApp(<Messages />);
    await screen.findByText('First subject');
    fireEvent.input(screen.getByLabelText('Recipient'), { target: { value: ' alex@gmail.com ' } });
    fireEvent.input(screen.getByLabelText('Subject contains'), { target: { value: 'welcome' } });
    fireEvent.change(screen.getByLabelText('Status'), { target: { value: 'bounced' } });
    fireEvent.input(screen.getByLabelText('Received from'), { target: { value: '2026-10-01T08:00' } });
    fireEvent.submit(screen.getByRole('search'));
    await waitFor(() => expect(m.callsTo('GET', '/api/v1/messages')).toHaveLength(2));
    const q = m.callsTo('GET', '/api/v1/messages')[1].query;
    expect(q.get('recipient')).toBe('alex@gmail.com');
    expect(q.get('subject')).toBe('welcome');
    expect(q.get('status')).toBe('bounced');
    expect(q.get('from')).toBe(new Date('2026-10-01T08:00').toISOString());
    expect(q.has('sender')).toBe(false);
    expect(q.has('to')).toBe(false);
  });

  it('loads more with the cursor and appends rows', async () => {
    const m = mockFetch({
      'GET /api/v1/messages': (call) => (call.query.get('cursor') === 'c2' ? { items: [B], next_cursor: null } : { items: [A], next_cursor: 'c2' }),
    });
    renderWithApp(<Messages />);
    await screen.findByText('First subject');
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }));
    await screen.findByText('Second subject');
    expect(screen.getByText('First subject')).toBeTruthy();
    expect(m.callsTo('GET', '/api/v1/messages')[1].query.get('cursor')).toBe('c2');
    expect(screen.queryByRole('button', { name: 'Load more' })).toBeNull();
  });

  it('shows an empty state after a search without matches', async () => {
    mockFetch({ 'GET /api/v1/messages': { items: [], next_cursor: null } });
    renderWithApp(<Messages />);
    expect(await screen.findByText('No messages yet')).toBeTruthy();
    fireEvent.submit(screen.getByRole('search'));
    expect(await screen.findByText('No messages match')).toBeTruthy();
  });

  it('shows a friendly error with a retry that reloads', async () => {
    let fail = true;
    mockFetch({ 'GET /api/v1/messages': () => (fail ? problem(500, 'server_error') : { items: [A], next_cursor: null }) });
    renderWithApp(<Messages />);
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('unexpected error');
    fail = false;
    fireEvent.click(within(alert).getByRole('button', { name: 'Try again' }));
    expect(await screen.findByText('First subject')).toBeTruthy();
  });

  it('does not call the message API at all when history is statsonly and explains why', async () => {
    const m = mockFetch({});
    renderWithApp(<Messages />, { mode: 'statsonly' });
    await flush();
    expect(screen.getByText('Per-message history is not recorded')).toBeTruthy();
    expect(screen.queryByRole('search')).toBeNull();
    expect(m.calls).toHaveLength(0);
  });

  it('handles a 410 history_not_recorded answer when the capabilities were stale', async () => {
    mockFetch({ 'GET /api/v1/messages': problem(410, 'history_not_recorded', { history_mode: 'StatsOnly' }) });
    renderWithApp(<Messages />, { mode: 'full' });
    expect(await screen.findByText('Per-message history is not recorded')).toBeTruthy();
  });
});
