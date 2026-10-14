import { describe, expect, it } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/preact';
import Statistics from '../src/pages/Statistics';
import { mergeUnrolledDays } from '../src/lib/messages';
import type { StatsRow } from '../src/api/types';
import { mockFetch, renderWithApp } from './helpers';

const row = (period: string, over: Partial<StatsRow> = {}): StatsRow => ({
  period,
  sendingDomain: 'mail.example.com',
  recipientDomain: 'example.org',
  accepted: 0,
  delivered: 0,
  deferred: 0,
  hardBounce: 0,
  softBounce: 0,
  expired: 0,
  complained: 0,
  rejected: 0,
  suppressed: 0,
  ...over,
});

describe('mergeUnrolledDays', () => {
  it('adds the days without a daily row by summing their hourly rows per series', () => {
    const daily = [row('2026-10-11T00:00:00.000Z', { accepted: 10, delivered: 9 })];
    const hourly = [
      row('2026-10-11T22:00:00.000Z', { accepted: 99 }), // already rolled up: ignored
      row('2026-10-12T08:00:00.000Z', { accepted: 2, delivered: 2 }),
      row('2026-10-12T09:00:00.000Z', { accepted: 3, delivered: 1, hardBounce: 1, deferred: 1 }),
      row('2026-10-12T09:00:00.000Z', { recipientDomain: 'other.test', accepted: 1, suppressed: 1 }),
    ];
    const merged = mergeUnrolledDays(daily, hourly);
    expect(merged).toHaveLength(3);
    expect(merged[0]).toBe(daily[0]);
    const sameSeries = merged.find((r) => r.recipientDomain === 'example.org' && r.period === '2026-10-12T00:00:00.000Z');
    expect(sameSeries).toMatchObject({ accepted: 5, delivered: 3, hardBounce: 1, deferred: 1 });
    expect(merged.find((r) => r.recipientDomain === 'other.test')).toMatchObject({ period: '2026-10-12T00:00:00.000Z', accepted: 1, suppressed: 1 });
  });

  it('does not change anything without hourly rows, and ignores unparsable periods', () => {
    const daily = [row('2026-10-11T00:00:00.000Z', { accepted: 1 })];
    expect(mergeUnrolledDays(daily, [])).toEqual(daily);
    expect(mergeUnrolledDays(daily, [row('not a date', { accepted: 5 })])).toEqual(daily);
  });
});

describe('Statistics page, daily ranges', () => {
  it('shows traffic of days the server has not rolled up yet, taken from the hourly rows', async () => {
    const now = new Date();
    const hour = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 0)).toISOString();
    const m = mockFetch({
      'GET /api/v1/domains': [],
      'GET /api/v1/stats': (c: { query: URLSearchParams }) =>
        c.query.get('granularity') === 'day' ? { granularity: 'day', rows: [] } : { granularity: 'hour', rows: [row(hour, { accepted: 4, delivered: 3, hardBounce: 1 })] },
    });
    renderWithApp(<Statistics />);
    fireEvent.change(await screen.findByLabelText('Period'), { target: { value: '30d' } });
    const table = await screen.findByRole('table', { name: 'Statistics by recipient domain' });
    const line = within(table).getByRole('row', { name: /example\.org/ });
    expect(within(line).getAllByRole('cell')[0].textContent).toBe('4');
    await waitFor(() => expect(m.calls.some((c) => c.path === '/api/v1/stats' && c.query.get('granularity') === 'day')).toBe(true));
  });
});
