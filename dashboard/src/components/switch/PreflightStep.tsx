import type { PreflightReport } from '../../api/types';
import { formatBytes, formatDuration, formatNumber } from '../../lib/format';
import { backendLabel } from '../../lib/switchFlow';
import type { SwitchForm } from '../../lib/switchFlow';
import { Button, Chip, Notice } from '../ui';
import type { Tone } from '../ui';

function severityOf(c: PreflightReport['checks'][number]): { tone: Tone; label: string } {
  if (!c.ok || c.severity === 'error') return { tone: 'bad', label: 'Problem' };
  if (c.severity === 'warning') return { tone: 'warn', label: 'Warning' };
  return { tone: 'ok', label: 'OK' };
}

/** Step 2: the preflight report. Reading only; the next button just moves to the confirmation step. */
export function PreflightStep({ report, form, onBack, onContinue }: { report: PreflightReport; form: SwitchForm; onBack: () => void; onContinue: () => void }) {
  return (
    <div class="stack">
      {report.ok ? (
        <Notice tone="ok" title="Preflight passed">
          The target looks ready for {backendLabel(form.to)}. Nothing has been changed.
        </Notice>
      ) : (
        <Notice tone="bad" title="Preflight found problems">
          Fix the problems below, then go back and run the preflight again. You cannot start the switch until it passes.
        </Notice>
      )}

      <div class="table-wrap">
        <table>
          <caption class="sr-only">Preflight checks</caption>
          <thead>
            <tr>
              <th scope="col">Check</th>
              <th scope="col">Result</th>
              <th scope="col">Details</th>
            </tr>
          </thead>
          <tbody>
            {report.checks.map((c) => {
              const sev = severityOf(c);
              return (
                <tr key={c.name}>
                  <th scope="row">{c.name}</th>
                  <td>
                    <Chip tone={sev.tone}>{sev.label}</Chip>
                  </td>
                  <td class="wrap">{c.message}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <dl class="kv">
        <div>
          <dt>Queued messages</dt>
          <dd>{formatNumber(report.counts.queuedMessages)}</dd>
        </div>
        <div>
          <dt>Statistics rows</dt>
          <dd>{formatNumber(report.counts.statsRows)}</dd>
        </div>
        <div>
          <dt>History rows</dt>
          <dd>
            {formatNumber(report.counts.historyRows)} ({formatBytes(report.counts.historyBytes)})
          </dd>
        </div>
        {report.estimate && (
          <div>
            <dt>Estimate</dt>
            <dd>
              {report.estimate.seconds !== undefined && formatDuration(report.estimate.seconds * 1000)}
              {report.estimate.bytes !== undefined && ` for about ${formatBytes(report.estimate.bytes)}`}{' '}
              {report.estimate.unverified && <Chip tone="warn">unverified, not measured</Chip>}
            </dd>
          </div>
        )}
      </dl>

      {report.notCarried.length > 0 && (
        <section aria-labelledby="not-carried">
          <h3 id="not-carried">What will not carry over</h3>
          <ul>
            {report.notCarried.map((t) => (
              <li key={t}>{t}</li>
            ))}
          </ul>
        </section>
      )}

      {report.orchestratorManaged && (
        <Notice tone="info" title="Orchestrator-managed configuration">
          The storage settings come from your deployment (environment, ConfigMap or compose). EggMail never rewrites those. After you confirm, it prepares a cutover patch that you apply yourself.
        </Notice>
      )}

      <div class="row">
        <Button onClick={onBack}>Back</Button>
        <Button variant="primary" onClick={onContinue} disabled={!report.ok}>
          Continue
        </Button>
      </div>
    </div>
  );
}
