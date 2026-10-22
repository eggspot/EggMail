import type { PressureIndicators as Pressure } from '../api/types';
import { formatNumber } from '../lib/format';
import { Chip, Notice } from './ui';

/**
 * Advisory storage-pressure indicators (design 4.4, decision C). Display only: nothing here ever starts,
 * schedules or recommends an automatic switch. The optional link only navigates to the manual wizard.
 */
export function PressureIndicators({ pressure, showLink = true }: { pressure?: Pressure; showLink?: boolean }) {
  if (!pressure) return null;
  const depth = pressure.queueDepthThreshold ?? 1000;
  const seconds = pressure.queueThresholdSeconds ?? 300;
  const p99 = pressure.commitP99ThresholdMs ?? 100;
  const queueOver = pressure.writerQueueDepth >= depth;
  const commitOver = pressure.commitP99Ms > p99;
  const duration =
    seconds % 60 !== 0 ? `${formatNumber(seconds)} seconds` : seconds === 60 ? '1 minute' : `${formatNumber(seconds / 60)} minutes`;
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
            Writer queue depth {queueOver ? <Chip tone="warn">at or above {formatNumber(depth)}</Chip> : <Chip tone="ok">below {formatNumber(depth)}</Chip>}
          </div>
          <div class="hint">
            Threshold: {formatNumber(depth)} or more for {duration}. Seconds over threshold: {formatNumber(pressure.writerQueueOverThresholdSeconds)}.
          </div>
        </div>
        <div class="stat">
          <div class="stat-value">{formatNumber(pressure.commitP99Ms)} ms</div>
          <div class="stat-label">
            Commit p99 {commitOver ? <Chip tone="warn">above {formatNumber(p99)} ms</Chip> : <Chip tone="ok">at or below {formatNumber(p99)} ms</Chip>}
          </div>
          <div class="hint">Threshold: {formatNumber(p99)} ms.</div>
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
