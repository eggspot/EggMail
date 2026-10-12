export function formatBytes(n: number | null | undefined): string {
  if (n === null || n === undefined || Number.isNaN(n)) return '-';
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 100 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

export function formatNumber(n: number | null | undefined): string {
  if (n === null || n === undefined || Number.isNaN(n)) return '-';
  return new Intl.NumberFormat('en-US').format(n);
}

export function formatPercent(part: number, total: number): string {
  if (!total) return '-';
  const p = (part / total) * 100;
  return `${p >= 10 ? p.toFixed(0) : p.toFixed(1)}%`;
}

/** Date and time in the viewer's locale with the timezone name, e.g. "12 Oct 2026, 08:00 UTC". */
export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '-';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' });
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)} ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)} s`;
  const m = Math.floor(s / 60);
  return `${m} min ${Math.round(s - m * 60)} s`;
}

/** "in 3 days" / "2 hours ago" style text relative to `now`. */
export function formatRelative(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return '-';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return iso;
  const diff = Math.round((t - now) / 1000);
  const abs = Math.abs(diff);
  const units: [number, string][] = [
    [86400, 'day'],
    [3600, 'hour'],
    [60, 'minute'],
  ];
  let text = `${abs} second${abs === 1 ? '' : 's'}`;
  for (const [size, name] of units) {
    if (abs >= size) {
      const n = Math.floor(abs / size);
      text = `${n} ${name}${n === 1 ? '' : 's'}`;
      break;
    }
  }
  if (abs < 5) return 'just now';
  return diff >= 0 ? `in ${text}` : `${text} ago`;
}

/** Whole days until the date (negative when past). */
export function daysUntil(iso: string, now: number = Date.now()): number {
  return Math.floor((new Date(iso).getTime() - now) / 86400000);
}

/** Value for <input type="datetime-local"> to ISO UTC (and back) helpers. */
export function toIsoOrUndefined(local: string): string | undefined {
  if (!local) return undefined;
  const d = new Date(local);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

export function shortId(id: string): string {
  return id.length > 12 ? `${id.slice(0, 8)}...${id.slice(-4)}` : id;
}

/** Splits a long value into chunks for readable wrapping in a monospace cell. */
export function chunk(value: string, size: number): string[] {
  const out: string[] = [];
  for (let i = 0; i < value.length; i += size) out.push(value.slice(i, i + size));
  return out;
}
