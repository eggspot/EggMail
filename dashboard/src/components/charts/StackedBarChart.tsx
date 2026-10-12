import { useId } from 'preact/hooks';
import { formatNumber } from '../../lib/format';

export interface ChartPoint {
  period: string;
  delivered: number;
  deferred: number;
  bounced: number;
}

const W = 640;
const H = 220;
const M = { top: 10, right: 8, bottom: 26, left: 44 };

/** Rounds up to a "nice" axis maximum (1, 2, 5 x 10^n). */
export function niceMax(max: number): number {
  if (max <= 0) return 1;
  const pow = 10 ** Math.floor(Math.log10(max));
  const f = max / pow;
  const nice = f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10;
  return nice * pow;
}

function label(period: string, granularity: 'hour' | 'day'): string {
  const d = new Date(period);
  if (Number.isNaN(d.getTime())) return period;
  return granularity === 'hour'
    ? d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'UTC' })
    : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' });
}

function fullLabel(period: string, granularity: 'hour' | 'day'): string {
  const d = new Date(period);
  if (Number.isNaN(d.getTime())) return period;
  return granularity === 'hour'
    ? `${d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' })} UTC`
    : d.toLocaleDateString(undefined, { dateStyle: 'medium', timeZone: 'UTC' });
}

export function Legend() {
  return (
    <ul class="legend" aria-label="Legend">
      <li>
        <span class="swatch series-delivered" aria-hidden="true" />
        Delivered
      </li>
      <li>
        <span class="swatch series-deferred" aria-hidden="true" />
        Deferred
      </li>
      <li>
        <span class="swatch series-bounced" aria-hidden="true" />
        Bounced
      </li>
    </ul>
  );
}

/**
 * Stacked delivered / deferred / bounced bars per period. Hand-written SVG using attributes and CSS classes
 * only (no inline styles). A collapsible data table gives the same numbers to assistive technology.
 */
export function StackedBarChart({ data, granularity, title }: { data: ChartPoint[]; granularity: 'hour' | 'day'; title: string }) {
  const uid = useId();
  const total = data.reduce((n, p) => n + p.delivered + p.deferred + p.bounced, 0);
  if (!data.length || total === 0) {
    return (
      <p class="muted" role="status">
        No messages in this period.
      </p>
    );
  }
  const max = niceMax(Math.max(...data.map((p) => p.delivered + p.deferred + p.bounced)));
  const plotW = W - M.left - M.right;
  const plotH = H - M.top - M.bottom;
  const slot = plotW / data.length;
  const barW = Math.max(1, slot * 0.78);
  const yFor = (v: number) => (v / max) * plotH;
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => f * max);
  const labelEvery = Math.max(1, Math.ceil(data.length / 8));
  const delivered = data.reduce((n, p) => n + p.delivered, 0);
  const deferred = data.reduce((n, p) => n + p.deferred, 0);
  const bounced = data.reduce((n, p) => n + p.bounced, 0);
  const summary = `${title}: ${formatNumber(delivered)} delivered, ${formatNumber(deferred)} deferred, ${formatNumber(bounced)} bounced across ${data.length} ${granularity === 'hour' ? 'hours' : 'days'}.`;

  return (
    <figure class="chart-figure">
      <svg class="chart" viewBox={`0 0 ${W} ${H}`} role="img" aria-labelledby={`${uid}-t`} data-testid="stacked-bar-chart">
        <title id={`${uid}-t`}>{summary}</title>
        {ticks.map((t) => (
          <g key={t}>
            <line class="grid-line" x1={M.left} x2={W - M.right} y1={M.top + plotH - yFor(t)} y2={M.top + plotH - yFor(t)} />
            <text x={M.left - 6} y={M.top + plotH - yFor(t) + 4} text-anchor="end">
              {formatNumber(Math.round(t))}
            </text>
          </g>
        ))}
        {data.map((p, i) => {
          const x = M.left + i * slot + (slot - barW) / 2;
          const hD = yFor(p.delivered);
          const hF = yFor(p.deferred);
          const hB = yFor(p.bounced);
          const base = M.top + plotH;
          const tip = `${fullLabel(p.period, granularity)}: ${formatNumber(p.delivered)} delivered, ${formatNumber(p.deferred)} deferred, ${formatNumber(p.bounced)} bounced`;
          return (
            <g key={p.period} data-period={p.period}>
              <title>{tip}</title>
              {hD > 0 && <rect class="series-delivered" x={x} y={base - hD} width={barW} height={hD} data-series="delivered" />}
              {hF > 0 && <rect class="series-deferred" x={x} y={base - hD - hF} width={barW} height={hF} data-series="deferred" />}
              {hB > 0 && <rect class="series-bounced" x={x} y={base - hD - hF - hB} width={barW} height={hB} data-series="bounced" />}
              {i % labelEvery === 0 && (
                <text x={x + barW / 2} y={H - 8} text-anchor="middle">
                  {label(p.period, granularity)}
                </text>
              )}
            </g>
          );
        })}
        <line class="axis-line" x1={M.left} x2={W - M.right} y1={M.top + plotH} y2={M.top + plotH} />
      </svg>
      <Legend />
      <details class="chart-data">
        <summary>Show data table</summary>
        <div class="table-wrap">
          <table>
            <caption class="sr-only">{title}</caption>
            <thead>
              <tr>
                <th scope="col">{granularity === 'hour' ? 'Hour (UTC)' : 'Day (UTC)'}</th>
                <th scope="col" class="num">
                  Delivered
                </th>
                <th scope="col" class="num">
                  Deferred
                </th>
                <th scope="col" class="num">
                  Bounced
                </th>
              </tr>
            </thead>
            <tbody>
              {data.map((p) => (
                <tr key={p.period}>
                  <th scope="row">{fullLabel(p.period, granularity)}</th>
                  <td class="num">{formatNumber(p.delivered)}</td>
                  <td class="num">{formatNumber(p.deferred)}</td>
                  <td class="num">{formatNumber(p.bounced)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </figure>
  );
}

/** A tiny trend line for a counter. */
export function Sparkline({ values, label: ariaLabel, tone = 'delivered' }: { values: number[]; label: string; tone?: 'delivered' | 'deferred' | 'bounced' }) {
  const w = 120;
  const h = 28;
  if (values.length < 2) return <span class="muted small">no trend</span>;
  const max = Math.max(...values, 1);
  const step = w / (values.length - 1);
  const points = values.map((v, i) => `${(i * step).toFixed(1)},${(h - 2 - (v / max) * (h - 4)).toFixed(1)}`).join(' ');
  return (
    <svg class="sparkline" viewBox={`0 0 ${w} ${h}`} width={w} height={h} role="img" aria-label={ariaLabel}>
      <title>{ariaLabel}</title>
      <polyline class={`stroke-${tone}`} points={points} stroke-width="2" stroke-linejoin="round" stroke-linecap="round" />
    </svg>
  );
}
