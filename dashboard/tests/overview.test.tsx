import { describe, expect, it } from 'vitest';
import { screen, within } from '@testing-library/preact';
import Overview from '../src/pages/Overview';
import { mockFetch, renderWithApp } from './helpers';

const stats = { granularity: 'hour', rows: [] };

describe('Overview: recent events', () => {
  it('shows the sending domain column only when the server records one', async () => {
    mockFetch({
      'GET /api/v1/stats': stats,
      'GET /api/v1/stats/recent-events': [{ at: '2026-10-12T08:00:00.000Z', type: 'delivered', recipientDomain: 'example.org' }],
    });
    const first = renderWithApp(<Overview />);
    const table = await screen.findByRole('table', { name: 'Recent delivery events, newest first' });
    expect(within(table).queryByRole('columnheader', { name: 'Sending domain' })).toBeNull();
    expect(within(table).getByText('example.org')).toBeTruthy();
    first.unmount();

    mockFetch({
      'GET /api/v1/stats': stats,
      'GET /api/v1/stats/recent-events': [{ at: '2026-10-12T08:00:00.000Z', type: 'delivered', recipientDomain: 'example.org', sendingDomain: 'mail.example.com' }],
    });
    renderWithApp(<Overview />);
    const withColumn = await screen.findByRole('table', { name: 'Recent delivery events, newest first' });
    expect(within(withColumn).getByRole('columnheader', { name: 'Sending domain' })).toBeTruthy();
    expect(within(withColumn).getByText('mail.example.com')).toBeTruthy();
  });
});
