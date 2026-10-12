import type { PressureIndicators as Pressure } from '../api/types';
import { formatNumber } from '../lib/format';
import { Chip, Notice } from './ui';

/**
 * Advisory storage-pressure indicators (design 4.4, decision C). Display only: nothing here ever starts,
 * schedules or recommends an automatic switch. The optional link only navigates to the manual wizard.
 */
export function PressureIndicators({ pressure, showLink = true }: { pressure?: Pressure; showLink?: boolean }) {
  if (!pressure) return null;
  const queueOver = pressure.writerQueueDepth > 1000;
  const commitOver = pressure.commitP99Ms > 100;
  return (
    <section class="card" aria-labelledby="pressure-title" data-testid="pressure">
      <div class="card-head">
        <h2 id="pressure-title">Storage pressure (advisory)</h2>
        <Chip tone="neutral">advisory only</Chip>
      </div>
      <div class="grid-tight">
        <div class="stat">
          <div class="stat-value">{formatNumber(pressure.writerQueueDepth)}</div>
          <div class="stat-label">
            Writer queue depth {queueOver ? <Chip tone="warn">above 1,000</Chip> : <Chip tone="ok">below 1,000</Chip>}
          </div>
          <div class="hint">Threshold: over 1,000 for 5 minutes. Seconds over threshold: {formatNumber(pressure.writerQueueOverThresholdSeconds)}.</div>
        </div>
        <div class="stat">
          <div class="stat-value">{formatNumber(pressure.commitP99Ms)} ms</div>
          <div class="stat-label">
            Commit p99 {commitOver ? <Chip tone="warn">above 100 ms</Chip> : <Chip tone="ok">below 100 ms</Chip>}
          </div>
          <div class="hint">Threshold: about 100 ms.</div>
        </div>
      </div>
      <p class="muted small">
        These are advisory indicators only. EggMail never switches storage by itself.
        {pressure.advisory && ' If you want to move to the other backend, you can start a switch yourself.'}
        {showLink && pressure.advisory && (
          <>
            {' '}
            <a href="/admin/storage">Open the storage switch wizard</a>
          </>
        )}
      </p>
      {pressure.advisory && (
        <Notice tone="info">The thresholds are exceeded right now. Nothing has been changed and nothing will be: switching is always a manual, guided action.</Notice>
      )}
    </section>
  );
}
