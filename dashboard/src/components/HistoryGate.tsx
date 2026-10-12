import type { ComponentChildren } from 'preact';
import { useApp } from '../state/app';
import { EmptyState } from './ui';

/** Explanatory empty state shown wherever per-message history is not recorded. */
export function HistoryNotRecorded({ what = 'This page' }: { what?: string }) {
  return (
    <EmptyState title="Per-message history is not recorded">
      <p>
        {what} needs per-message history, but this server runs with <code>History:Mode=StatsOnly</code>. Only aggregated statistics and the recent-events ring are
        kept, so individual messages cannot be searched, viewed or resent.
      </p>
      <p>
        Statistics and the recent events are still available on the Overview and Statistics pages. To record per-message history, an administrator can set{' '}
        <code>History:Mode=Full</code> and restart the server. Sending mail works the same either way.
      </p>
    </EmptyState>
  );
}

/** Renders children only when per-message history is recorded (`capabilities.history.mode === "full"`). */
export function HistoryGate({ children, what }: { children: ComponentChildren; what?: string }) {
  const { historyMode } = useApp();
  if (historyMode === 'statsonly') return <HistoryNotRecorded what={what} />;
  return <>{children}</>;
}
