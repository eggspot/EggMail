import { useMemo, useState } from 'preact/hooks';
import { api } from '../api/endpoints';
import type { AdminStatus, RecentEvent } from '../api/types';
import { StackedBarChart } from '../components/charts/StackedBarChart';
import { Card, Chip, ErrorNotice, KeyValue, Loading, Notice, PageHeader, StatusChip } from '../components/ui';
import { formatDateTime, formatNumber, formatPercent, formatRelative } from '../lib/format';
import { useApi, useDocumentTitle, usePolling } from '../lib/hooks';
import { bucketRows, totalsOf } from '../lib/messages';
import { useApp } from '../state/app';

const DAY = 86_400_000;
const REFRESH_MS = 15_000;

function Counter({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div class="stat">
      <div class="stat-value">{value}</div>
      <div class="stat-label">{label}</div>
      {hint && <div class="stat-label">{hint}</div>}
    </div>
  );
}

function RecentEvents() {
  const events = useApi(() => api.recentEvents(25), []);
  const [updated, setUpdated] = useState<Date | null>(null);
  usePolling(async () => {
    events.reload();
    setUpdated(new Date());
  }, REFRESH_MS);
  const list: RecentEvent[] = events.data ?? [];
  // The server's recent-events ring does not record the sending domain (api.md); show the column only when events carry one.
  const showSending = list.some((e) => e.sendingDomain);
  return (
    <Card title="Recent events">
      <p class="muted small" aria-live="polite">
        The latest delivery events across your domains (no message content). Refreshes every 15 seconds{updated ? `; last refresh ${updated.toLocaleTimeString()}` : ''}.
      </p>
      {events.error !== undefined && <ErrorNotice error={events.error} onRetry={events.reload} />}
      {events.data === undefined && events.error === undefined && <Loading label="Loading recent events" />}
      {events.data !== undefined && list.length === 0 && <p class="muted">No events yet.</p>}
      {list.length > 0 && (
        <div class="table-wrap">
          <table>
            <caption class="sr-only">Recent delivery events, newest first</caption>
            <thead>
              <tr>
                <th scope="col">Time</th>
                <th scope="col">Event</th>
                <th scope="col">Recipient domain</th>
                {showSending && <th scope="col">Sending domain</th>}
              </tr>
            </thead>
            <tbody>
              {list.map((e, i) => (
                <tr key={`${e.at}-${i}`}>
                  <td>
                    <time dateTime={e.at} title={formatDateTime(e.at)}>
                      {formatRelative(e.at)}
                    </time>
                  </td>
                  <td>
                    <StatusChip status={e.type} />
                  </td>
                  <td>{e.recipientDomain ?? '-'}</td>
                  {showSending && <td>{e.sendingDomain ?? '-'}</td>}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function AdminPanel() {
  const status = useApi<AdminStatus>(() => api.adminStatus(), []);
  const s = status.data;
  return (
    <Card title="Server health" actions={<a href="/admin/status">Open status page</a>}>
      {status.error !== undefined && (
        <Notice tone="warn" title="Server status is unavailable">
          The admin status could not be loaded. The rest of this page is not affected.
        </Notice>
      )}
      {status.data === undefined && status.error === undefined && <Loading label="Loading server status" />}
      {s && (
        <>
          <KeyValue
            items={[
              ['Queue depth', formatNumber(s.queue.depth)],
              ['Deferred in queue', formatNumber(s.queue.deferred)],
              ['Oldest due', s.queue.oldestDueAt ? formatRelative(s.queue.oldestDueAt) : 'nothing waiting'],
              ['Storage', s.storage.healthy ? <Chip tone="ok">healthy</Chip> : <Chip tone="bad">unhealthy</Chip>],
              ['Backend (informational)', s.backend],
              ['Version', s.version],
            ]}
          />
          {s.storage.detail && <p class="muted small">{s.storage.detail}</p>}
          {s.pressure && (
            <div class="pressure" aria-label="Storage pressure indicators (advisory)">
              <h3>Storage pressure (advisory only)</h3>
              <KeyValue
                items={[
                  ['Writer queue depth', formatNumber(s.pressure.writerQueueDepth)],
                  ['Seconds over the queue threshold', formatNumber(s.pressure.writerQueueOverThresholdSeconds)],
                  ['Commit latency p99', `${s.pressure.commitP99Ms} ms`],
                ]}
              />
              <p class="muted small">
                {s.pressure.advisory
                  ? 'The advisory thresholds are exceeded. This is a hint that the storage backend may be becoming a constraint. '
                  : 'Below the advisory thresholds. '}
                EggMail never switches storage by itself; switching is always a manual, explicit action on the Storage switch page.
              </p>
            </div>
          )}
        </>
      )}
    </Card>
  );
}

export default function Overview() {
  useDocumentTitle('Overview');
  const { me, capabilities } = useApp();
  const range = useMemo(() => {
    const to = Date.now();
    return { from: to - DAY, to };
  }, []);
  const stats = useApi(() => api.stats({ from: new Date(range.from).toISOString(), to: new Date(range.to).toISOString(), granularity: 'hour' }), [range]);
  const rows = stats.data ?? [];
  const totals = useMemo(() => totalsOf(rows), [rows]);
  const points = useMemo(() => bucketRows(rows, 'hour', range.from, range.to), [rows, range]);

  return (
    <>
      <PageHeader
        title="Overview"
        subtitle={capabilities ? `Last 24 hours. Storage backend: ${capabilities.backend}, history: ${capabilities.history.mode === 'full' ? 'per-message' : 'statistics only'}.` : 'Last 24 hours.'}
      />
      {stats.error !== undefined && <ErrorNotice error={stats.error} onRetry={stats.reload} />}
      {stats.data === undefined && stats.error === undefined && <Loading label="Loading statistics" />}
      {stats.data !== undefined && (
        <>
          <section aria-label="Key counters" class="grid-tight stats-summary">
            <Counter label="Accepted" value={formatNumber(totals.accepted)} />
            <Counter label="Delivered" value={formatNumber(totals.delivered)} hint={`${formatPercent(totals.delivered, totals.accepted)} delivery rate`} />
            <Counter label="Deferred" value={formatNumber(totals.deferred)} hint={`${formatPercent(totals.deferred, totals.accepted)} of accepted`} />
            <Counter label="Bounced" value={formatNumber(totals.bounced)} hint={`${formatPercent(totals.bounced, totals.accepted)} bounce rate`} />
            <Counter label="Complaints" value={formatNumber(totals.complained)} />
            <Counter label="Suppressed" value={formatNumber(totals.suppressed)} />
          </section>
          <Card title="Last 24 hours" actions={<a href="/statistics">More statistics</a>}>
            <StackedBarChart data={points} granularity="hour" title="Messages per hour, last 24 hours" />
          </Card>
        </>
      )}
      {me?.role === 'admin' && <AdminPanel />}
      <RecentEvents />
    </>
  );
}
