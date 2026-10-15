import { useState } from 'preact/hooks';
import type { CapabilityWarning } from '../api/types';
import { safeGet, safeSet } from '../lib/hooks';
import { useApp } from '../state/app';

const SYNC_OFF_EXPLANATION =
  'The SQLite data files use PRAGMA synchronous=OFF. A process kill or container restart is safe, but an operating system crash or power loss can corrupt the database and lose all queued mail, including mail already acknowledged. Set Sqlite:SyncMode to Normal or Full, or use the PostgreSQL backend, if you need power-loss safety.';

const KNOWN_TITLES: Record<string, string> = {
  sqlite_sync_off: 'Not power-loss safe',
  acme_pending: 'Certificate pending',
  acme_failing: 'Certificate request failing',
};

function collapsedKey(code: string) {
  return `eggmail.warning.collapsed.${code}`;
}

export function WarningItem({ warning }: { warning: CapabilityWarning }) {
  const loud = warning.code === 'sqlite_sync_off';
  // A per-session collapse only (sessionStorage): the warning reappears in every new session.
  const [collapsed, setCollapsed] = useState(() => safeGet('session', collapsedKey(warning.code)) === '1');
  const toggle = () => {
    const next = !collapsed;
    setCollapsed(next);
    safeSet('session', collapsedKey(warning.code), next ? '1' : null);
  };
  const title = KNOWN_TITLES[warning.code] ?? warning.code.replace(/_/g, ' ');
  const detail = loud ? SYNC_OFF_EXPLANATION : '';
  return (
    <div class={`banner ${loud ? 'banner-loud' : 'banner-warn'}`} role={loud ? 'alert' : 'status'} data-warning={warning.code}>
      <div class="banner-main">
        <strong>{loud ? `Warning: ${title}` : title}</strong>
        <span class="banner-text">{warning.message}</span>
        {!collapsed && detail && <p class="banner-detail">{detail}</p>}
      </div>
      {detail && (
        <button type="button" class="btn btn-small" aria-expanded={!collapsed} onClick={toggle}>
          {collapsed ? 'Show details' : 'Collapse'}
        </button>
      )}
    </div>
  );
}

/** Persistent banner for `capabilities.warnings`. Rendered on every page, including the login page. */
export function WarningBanner() {
  const { capabilities } = useApp();
  const warnings = capabilities?.warnings ?? [];
  if (!warnings.length) return null;
  return (
    <div class="banners" aria-label="Server warnings">
      {warnings.map((w) => (
        <WarningItem key={w.code} warning={w} />
      ))}
    </div>
  );
}
