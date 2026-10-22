import type { PressureIndicators as Pressure } from '../api/types';
import { formatNumber } from '../lib/format';
import { Chip, Notice } from './ui';

function formatDuration(seconds: number): string {
  return seconds % 60 !== 0 ? `${formatNumber(seconds)} seconds` : seconds === 60 ? '1 minute' : `${formatNumber(seconds / 60)} minutes`;
}

/** True when the figures are those of the PostgreSQL connection pool (decision 109) rather than the SQLite writers. */
export function isPoolPressure(pressure: Pressure): boolean {
  return pressure.poolPendingRequests !== undefined;
}

/**
 * Advisory storage-pressure indicators (design 4.4, decision C). Display only: nothing here ever starts,
 * schedules or recommends an automatic switch. SQLite reports its writers (decision 108); the optional link only
 * navigates to the manual wizard. PostgreSQL reports its connection pool (decision 109), where moving to SQLite
 * is never the remedy, so it shows no switch link.
 */
export function PressureIndicators({ pressure, showLink = true }: { pressure?: Pressure; showLink?: boolean }) {
  if (!pressure) return null;
  return isPoolPressure(pressure) ? <PoolPressure pressure={pressure} /> : <WriterPressure pressure={pressure} showLink={showLink} />;
}

function WriterPressure({ pressure, showLink }: { pressure: Pressure; showLink: boolean }) {
  const depth = pressure.queueDepthThreshold ?? 1000;
  const seconds = pressure.queueThresholdSeconds ?? 300;
  const p99 = pressure.commitP99ThresholdMs ?? 100;
  const queueDepth = pressure.writerQueueDepth ?? 0;
  const commitP99 = pressure.commitP99Ms ?? 0;
  const queueOver = queueDepth >= depth;
  const commitOver = commitP99 > p99;
  return (
    <section class="card" aria-labelledby="pressure-title" data-testid="pressure">
      <div class="card-head">
        <h2 id="pressure-title">Storage pressure (advisory)</h2>
        <Chip tone="neutral">advisory only</Chip>
      </div>
      <div class="grid-tight">
        <div class="stat">
          <div class="stat-value">{formatNumber(queueDepth)}</div>
          <div class="stat-label">
            Writer queue depth {queueOver ? <Chip tone="warn">at or above {formatNumber(depth)}</Chip> : <Chip tone="ok">below {formatNumber(depth)}</Chip>}
          </div>
          <div class="hint">
            Threshold: {formatNumber(depth)} or more for {formatDuration(seconds)}. Seconds over threshold: {formatNumber(pressure.writerQueueOverThresholdSeconds ?? 0)}.
          </div>
        </div>
        <div class="stat">
          <div class="stat-value">{formatNumber(commitP99)} ms</div>
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

function PoolPressure({ pressure }: { pressure: Pressure }) {
  const threshold = pressure.poolWaitingPercentThreshold ?? 50;
  const waiting = pressure.poolWaitingPercent ?? 0;
  const timeouts = pressure.poolTimeouts ?? 0;
  const window = formatDuration(pressure.poolWindowSeconds ?? 300);
  const samples = pressure.poolSamples ?? 0;
  return (
    <section class="card" aria-labelledby="pressure-title" data-testid="pressure">
      <div class="card-head">
        <h2 id="pressure-title">Database connection pool (advisory)</h2>
        <Chip tone="neutral">advisory only</Chip>
      </div>
      <div class="grid-tight">
        <div class="stat">
          <div class="stat-value">{formatNumber(waiting)}%</div>
          <div class="stat-label">
            Samples with callers waiting{' '}
            {waiting >= threshold ? <Chip tone="warn">at or above {formatNumber(threshold)}%</Chip> : <Chip tone="ok">below {formatNumber(threshold)}%</Chip>}
          </div>
          <div class="hint">
            Over the last {window} ({formatNumber(samples)} samples). Waiting right now: {formatNumber(pressure.poolPendingRequests ?? 0)}.
          </div>
        </div>
        <div class="stat">
          <div class="stat-value">
            {formatNumber(pressure.poolConnectionsInUse ?? 0)} / {formatNumber(pressure.poolMaxSize ?? 0)}
          </div>
          <div class="stat-label">
            Connections in use {timeouts > 0 ? <Chip tone="warn">{formatNumber(timeouts)} timed out</Chip> : <Chip tone="ok">no timeouts</Chip>}
          </div>
          <div class="hint">Requests that timed out waiting for a connection in the last {window}: {formatNumber(timeouts)}.</div>
        </div>
      </div>
      <p class="muted small">These are advisory indicators only. EggMail changes nothing by itself.</p>
      {pressure.advisory && (
        <Notice tone="info">
          Requests are waiting for a free database connection. Consider raising Storage:Postgres:MaxPoolSize (within the server's max_connections) or giving
          the database more capacity.
        </Notice>
      )}
    </section>
  );
}
