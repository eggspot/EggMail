import { useState } from 'preact/hooks';
import { api } from '../../api/endpoints';
import type { AdminStatus } from '../../api/types';
import { CertificateExpiry } from '../../components/CertificateExpiry';
import { PressureIndicators } from '../../components/PressureIndicators';
import { Button, Card, Chip, ErrorNotice, KeyValue, Loading, Notice, PageHeader, StatusChip } from '../../components/ui';
import { formatDateTime, formatNumber, formatRelative } from '../../lib/format';
import { useAction, useApi, useDocumentTitle, usePolling } from '../../lib/hooks';
import { STATE_LABEL } from '../../lib/switchFlow';

const REFRESH_MS = 10_000;

function formatUptime(seconds: number | undefined): string {
  if (seconds === undefined) return '-';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return d ? `${d} d ${h} h` : h ? `${h} h ${m} min` : `${m} min`;
}

export default function Status(_props: Record<string, unknown>) {
  useDocumentTitle('Server status');
  const status = useApi(() => api.adminStatus(), []);
  const [outcome, setOutcome] = useState<{ ok: boolean; text: string } | null>(null);

  usePolling(
    async () => {
      try {
        status.setData(await api.adminStatus());
      } catch {
        /* keep the last snapshot; the explicit reload shows errors */
      }
      return true;
    },
    REFRESH_MS,
  );

  const maintenance = useAction(async () => {
    await api.runMaintenance();
    setOutcome({ ok: true, text: 'Maintenance run started.' });
    status.reload();
  });

  const s: AdminStatus | undefined = status.data;
  return (
    <>
      <PageHeader
        title="Server status"
        subtitle="Refreshes every 10 seconds."
        actions={
          <>
            <Button onClick={status.reload} busy={status.loading && !!s}>
              Refresh
            </Button>
            <Button
              onClick={() => {
                setOutcome(null);
                void maintenance.run();
              }}
              busy={maintenance.busy}
            >
              Run maintenance now
            </Button>
          </>
        }
      />
      {outcome && (
        <Notice tone="ok">
          <span role="status">{outcome.text}</span>
        </Notice>
      )}
      {maintenance.error !== undefined && <ErrorNotice error={maintenance.error} title="Maintenance could not be started" />}
      {status.loading && !s && <Loading />}
      {status.error !== undefined && !s && <ErrorNotice error={status.error} onRetry={status.reload} />}
      {s && (
        <>
          <Card title="Server">
            <KeyValue
              items={[
                ['Version', s.version],
                ['Storage backend (informational)', s.backend],
                ['History mode', s.historyMode],
                ['Uptime', formatUptime(s.uptimeSeconds)],
                [
                  'Storage switch',
                  <>
                    <Chip tone={s.switch.state === 'none' ? 'neutral' : 'info'}>{STATE_LABEL[s.switch.state]}</Chip> <a href="/admin/storage">Open the storage switch</a>
                  </>,
                ],
              ]}
            />
          </Card>

          <Card title="Queue">
            <div class="grid-tight">
              <div class="stat">
                <div class="stat-value">{formatNumber(s.queue.depth)}</div>
                <div class="stat-label">Queued messages</div>
              </div>
              <div class="stat">
                <div class="stat-value">{formatNumber(s.queue.deferred)}</div>
                <div class="stat-label">Deferred</div>
              </div>
              <div class="stat">
                <div class="stat-value">{s.queue.oldestDueAt ? formatRelative(s.queue.oldestDueAt) : '-'}</div>
                <div class="stat-label">Oldest due</div>
              </div>
            </div>
          </Card>

          <Card title="Storage health">
            <p>
              <StatusChip status={s.storage.healthy ? 'ok' : 'failed'} label={s.storage.healthy ? 'healthy' : 'unhealthy'} /> {s.storage.detail}
            </p>
            {s.storage.warnings.length > 0 ? (
              <ul>
                {s.storage.warnings.map((w) => (
                  <li key={w.code}>
                    <Chip tone="warn">{w.code}</Chip> {w.message}
                  </li>
                ))}
              </ul>
            ) : (
              <p class="muted">No storage warnings.</p>
            )}
          </Card>

          <Card title="Certificates">
            {s.certificates.length === 0 ? (
              <p class="muted">No certificates are loaded. <a href="/admin/certificates">Manage certificates</a></p>
            ) : (
              <div class="table-wrap">
                <table>
                  <caption class="sr-only">Certificate expiry</caption>
                  <thead>
                    <tr>
                      <th scope="col">Subject</th>
                      <th scope="col">Source</th>
                      <th scope="col">Not after</th>
                      <th scope="col">Expiry</th>
                    </tr>
                  </thead>
                  <tbody>
                    {s.certificates.map((c) => (
                      <tr key={c.subject + c.notAfter}>
                        <th scope="row">{c.subject}</th>
                        <td>{c.source}</td>
                        <td>{formatDateTime(c.notAfter)}</td>
                        <td>
                          <CertificateExpiry notAfter={c.notAfter} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          <PressureIndicators pressure={s.pressure} />
        </>
      )}
    </>
  );
}
