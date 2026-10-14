import { useMemo, useState } from 'preact/hooks';
import { api } from '../api/endpoints';
import { StackedBarChart } from '../components/charts/StackedBarChart';
import { Card, EmptyState, ErrorNotice, Field, Loading, Notice, PageHeader, TextField } from '../components/ui';
import { formatNumber, formatPercent } from '../lib/format';
import { useApi, useDocumentTitle } from '../lib/hooks';
import { bucketRows, byRecipientDomain, mergeUnrolledDays, totalsOf } from '../lib/messages';
import type { DomainRow } from '../lib/messages';

type Granularity = 'hour' | 'day';
interface Preset {
  id: string;
  label: string;
  ms: number;
  granularity: Granularity;
}

const DAY = 86_400_000;
export const PRESETS: Preset[] = [
  { id: '24h', label: 'Last 24 hours', ms: DAY, granularity: 'hour' },
  { id: '7d', label: 'Last 7 days', ms: 7 * DAY, granularity: 'hour' },
  { id: '30d', label: 'Last 30 days', ms: 30 * DAY, granularity: 'day' },
  { id: '400d', label: 'Last 400 days', ms: 400 * DAY, granularity: 'day' },
];

type SortKey = 'domain' | 'accepted' | 'delivered' | 'deferred' | 'bounced' | 'complained' | 'rate';
const COLUMNS: { key: SortKey; label: string; num?: boolean }[] = [
  { key: 'domain', label: 'Recipient domain' },
  { key: 'accepted', label: 'Accepted', num: true },
  { key: 'delivered', label: 'Delivered', num: true },
  { key: 'deferred', label: 'Deferred', num: true },
  { key: 'bounced', label: 'Bounced', num: true },
  { key: 'complained', label: 'Complaints', num: true },
  { key: 'rate', label: 'Delivery rate', num: true },
];

const rateOf = (r: DomainRow) => (r.accepted ? r.delivered / r.accepted : 0);
function sortValue(r: DomainRow, key: SortKey): string | number {
  return key === 'domain' ? r.domain : key === 'rate' ? rateOf(r) : r[key];
}

export function sortDomainRows(rows: DomainRow[], key: SortKey, dir: 'asc' | 'desc'): DomainRow[] {
  const sign = dir === 'asc' ? 1 : -1;
  return [...rows].sort((a, b) => {
    const x = sortValue(a, key);
    const y = sortValue(b, key);
    const c = typeof x === 'string' ? x.localeCompare(y as string) : x - (y as number);
    return c * sign || a.domain.localeCompare(b.domain);
  });
}

function Counter({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div class="stat">
      <div class="stat-value">{value}</div>
      <div class="stat-label">{label}</div>
      {hint && <div class="stat-label">{hint}</div>}
    </div>
  );
}

export default function Statistics() {
  useDocumentTitle('Statistics');
  const [presetId, setPresetId] = useState('7d');
  const [granularity, setGranularity] = useState<Granularity>('hour');
  const [domain, setDomain] = useState('');
  const [sort, setSort] = useState<{ key: SortKey; dir: 'asc' | 'desc' }>({ key: 'accepted', dir: 'desc' });
  const preset = PRESETS.find((p) => p.id === presetId) ?? PRESETS[1];
  // Hourly rows are only kept for 30 days, so longer ranges are daily only.
  const hourAllowed = preset.ms <= 30 * DAY;
  const effective: Granularity = hourAllowed ? granularity : 'day';

  const domains = useApi(() => api.domains(), []);
  // The range is anchored when the filters change, not on every render.
  const range = useMemo(() => {
    const to = Date.now();
    return { from: to - preset.ms, to };
  }, [presetId, effective, domain]);
  const stats = useApi(async () => {
    const query = { from: new Date(range.from).toISOString(), to: new Date(range.to).toISOString(), granularity: effective, domain: domain || undefined };
    const rows = await api.stats(query);
    if (effective !== 'day') return rows;
    // Daily rows exist only for days that are over: add today and yesterday from the hourly rows when they have not been rolled up.
    const recentFrom = Math.max(range.from, Math.floor(range.to / DAY) * DAY - DAY);
    const recent = await api.stats({ ...query, from: new Date(recentFrom).toISOString(), granularity: 'hour' });
    return mergeUnrolledDays(rows, recent);
  }, [range, effective, domain]);

  const rows = stats.data ?? [];
  const totals = useMemo(() => totalsOf(rows), [rows]);
  const points = useMemo(() => bucketRows(rows, effective, range.from, range.to), [rows, effective, range]);
  const domainRows = useMemo(() => sortDomainRows(byRecipientDomain(rows), sort.key, sort.dir), [rows, sort]);

  const pickPreset = (id: string) => {
    const p = PRESETS.find((x) => x.id === id) ?? PRESETS[1];
    setPresetId(id);
    setGranularity(p.granularity);
  };
  const toggleSort = (key: SortKey) => setSort((s) => (s.key === key ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: key === 'domain' ? 'asc' : 'desc' }));
  const domainNames = domains.data?.map((d) => d.name) ?? [];

  return (
    <>
      <PageHeader title="Statistics" subtitle="Aggregated counters. Available on every storage backend and in both history modes." />
      <Card title="Range">
        <div class="form-grid">
          <Field label="Period">
            {({ id }) => (
              <select id={id} value={presetId} onChange={(e) => pickPreset((e.currentTarget as HTMLSelectElement).value)}>
                {PRESETS.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.label}
                  </option>
                ))}
              </select>
            )}
          </Field>
          <fieldset>
            <legend>Granularity</legend>
            <div class="row">
              {(['hour', 'day'] as const).map((g) => (
                <label key={g} class="check">
                  <input type="radio" name="granularity" value={g} checked={effective === g} disabled={g === 'hour' && !hourAllowed} onChange={() => setGranularity(g)} />
                  {g === 'hour' ? 'Hourly' : 'Daily'}
                </label>
              ))}
            </div>
            {!hourAllowed && <p class="hint">Hourly data is kept for 30 days, so this range is shown daily.</p>}
          </fieldset>
          {domainNames.length > 0 ? (
            <Field label="Sending domain">
              {({ id }) => (
                <select id={id} value={domain} onChange={(e) => setDomain((e.currentTarget as HTMLSelectElement).value)}>
                  <option value="">All domains</option>
                  {domainNames.map((n) => (
                    <option key={n} value={n}>
                      {n}
                    </option>
                  ))}
                </select>
              )}
            </Field>
          ) : (
            <TextField label="Sending domain (optional)" value={domain} onInput={setDomain} placeholder="example.com" autocomplete="off" />
          )}
        </div>
      </Card>

      {stats.error !== undefined && <ErrorNotice error={stats.error} onRetry={stats.reload} />}
      {stats.data === undefined && stats.error === undefined && <Loading label="Loading statistics" />}

      {stats.data !== undefined && (
        <>
          <section aria-label="Summary" class="grid-tight stats-summary">
            <Counter label="Accepted" value={formatNumber(totals.accepted)} />
            <Counter label="Delivered" value={formatNumber(totals.delivered)} hint={formatPercent(totals.delivered, totals.accepted) + ' of accepted'} />
            <Counter label="Deferred" value={formatNumber(totals.deferred)} />
            <Counter label="Bounced" value={formatNumber(totals.bounced)} />
            <Counter label="Complaints" value={formatNumber(totals.complained)} />
            <Counter label="Suppressed" value={formatNumber(totals.suppressed)} />
          </section>

          <Card title={effective === 'hour' ? 'Messages per hour' : 'Messages per day'}>
            <StackedBarChart data={points} granularity={effective} title={`Messages per ${effective}, ${preset.label.toLowerCase()}`} />
          </Card>

          <Card title="By recipient domain">
            {domainRows.length === 0 ? (
              <EmptyState title="No traffic in this range">
                <p>Nothing was accepted in the selected period{domain ? ` for ${domain}` : ''}.</p>
              </EmptyState>
            ) : (
              <>
                <p class="muted small">Large recipient domains are listed individually; the rest are grouped by the server into buckets.</p>
                <div class="table-wrap">
                  <table>
                    <caption class="sr-only">Statistics by recipient domain</caption>
                    <thead>
                      <tr>
                        {COLUMNS.map((c) => (
                          <th key={c.key} scope="col" class={c.num ? 'num' : undefined} aria-sort={sort.key === c.key ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}>
                            <button type="button" class="th-sort" onClick={() => toggleSort(c.key)}>
                              {c.label}
                              <span aria-hidden="true">{sort.key === c.key ? (sort.dir === 'asc' ? ' ▲' : ' ▼') : ''}</span>
                            </button>
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {domainRows.map((r) => (
                        <tr key={r.domain}>
                          <th scope="row">{r.domain}</th>
                          <td class="num">{formatNumber(r.accepted)}</td>
                          <td class="num">{formatNumber(r.delivered)}</td>
                          <td class="num">{formatNumber(r.deferred)}</td>
                          <td class="num">{formatNumber(r.bounced)}</td>
                          <td class="num">{formatNumber(r.complained)}</td>
                          <td class="num">{formatPercent(r.delivered, r.accepted)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </Card>
          {stats.loading && <Notice tone="info">Refreshing...</Notice>}
        </>
      )}
    </>
  );
}
