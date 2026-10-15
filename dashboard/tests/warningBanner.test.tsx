import { describe, expect, it } from 'vitest';
import { fireEvent, screen } from '@testing-library/preact';
import { WarningBanner } from '../src/components/WarningBanner';
import { HistoryGate } from '../src/components/HistoryGate';
import { makeCapabilities, renderWithApp } from './helpers';

const syncOff = { code: 'sqlite_sync_off', message: 'SQLite runs with synchronous=OFF.' };

describe('WarningBanner', () => {
  it('renders nothing without warnings', () => {
    const { container } = renderWithApp(<WarningBanner />);
    expect(container.querySelector('.banner')).toBeNull();
  });

  it('shows sqlite_sync_off as a loud alert with the full explanation and the server message', () => {
    renderWithApp(<WarningBanner />, { capabilities: makeCapabilities({ warnings: [syncOff] }) });
    const alert = screen.getByRole('alert');
    expect(alert.getAttribute('data-warning')).toBe('sqlite_sync_off');
    expect(alert.className).toContain('banner-loud');
    expect(alert.textContent).toContain('SQLite runs with synchronous=OFF.');
    expect(alert.textContent).toMatch(/power loss/i);
    expect(alert.textContent).toMatch(/corrupt/i);
    expect(alert.textContent).toContain('Sqlite:SyncMode');
  });

  it('can be collapsed for the session but never disappears', () => {
    renderWithApp(<WarningBanner />, { capabilities: makeCapabilities({ warnings: [syncOff] }) });
    fireEvent.click(screen.getByRole('button', { name: 'Collapse' }));
    const alert = screen.getByRole('alert');
    expect(alert.textContent).toContain('SQLite runs with synchronous=OFF.'); // one-line summary stays
    expect(alert.textContent).not.toMatch(/corrupt/i);
    expect(window.sessionStorage.getItem('eggmail.warning.collapsed.sqlite_sync_off')).toBe('1');
    expect(window.localStorage.length).toBe(0); // not permanently dismissible
    expect(screen.getByRole('button', { name: 'Show details' }).getAttribute('aria-expanded')).toBe('false');
  });

  it('starts collapsed when the session already collapsed it, and expands again', () => {
    window.sessionStorage.setItem('eggmail.warning.collapsed.sqlite_sync_off', '1');
    renderWithApp(<WarningBanner />, { capabilities: makeCapabilities({ warnings: [syncOff] }) });
    fireEvent.click(screen.getByRole('button', { name: 'Show details' }));
    expect(screen.getByRole('alert').textContent).toMatch(/corrupt/i);
  });

  it('shows other warnings as polite status banners', () => {
    renderWithApp(<WarningBanner />, { capabilities: makeCapabilities({ warnings: [{ code: 'certificate_expiring', message: 'Certificate expires in 9 days.' }] }) });
    expect(screen.getByRole('status').textContent).toContain('Certificate expires in 9 days.');
    expect(screen.queryByRole('alert')).toBeNull();
  });
});

describe('certificate (ACME) warnings', () => {
  it('shows the pending and failing states with a readable title and the server text', () => {
    renderWithApp(<WarningBanner />, {
      capabilities: makeCapabilities({
        warnings: [
          { code: 'acme_pending', message: 'The certificate for mail.example.com is being requested.' },
          { code: 'acme_failing', message: 'Last error: Timeout during connect. Next attempt: 2026-10-15 08:30 UTC.' },
        ],
      }),
    });
    const banners = screen.getAllByRole('status');
    expect(banners).toHaveLength(2);
    expect(banners[0].textContent).toContain('Certificate pending');
    expect(banners[0].textContent).toContain('being requested');
    expect(banners[1].textContent).toContain('Certificate request failing');
    expect(banners[1].textContent).toContain('Next attempt: 2026-10-15 08:30 UTC.');
  });
});

describe('history mode adaptation', () => {
  it('shows an explanatory empty state instead of children when history is statsonly', () => {
    renderWithApp(
      <HistoryGate what="Message search">
        <p>per-message content</p>
      </HistoryGate>,
      { mode: 'statsonly' },
    );
    expect(screen.queryByText('per-message content')).toBeNull();
    expect(screen.getByRole('heading', { name: /history is not recorded/i })).toBeTruthy();
    expect(screen.getByText(/Message search needs per-message history/)).toBeTruthy();
    expect(document.body.textContent).toContain('History:Mode=StatsOnly');
  });

  it('renders children when history is full', () => {
    renderWithApp(
      <HistoryGate>
        <p>per-message content</p>
      </HistoryGate>,
      { mode: 'full' },
    );
    expect(screen.getByText('per-message content')).toBeTruthy();
  });

  it('adapts to history.mode only and never to the backend name', () => {
    for (const backend of ['sqlite', 'postgres', 'something-new']) {
      const { unmount } = renderWithApp(
        <HistoryGate>
          <p>content-{backend}</p>
        </HistoryGate>,
        { mode: 'full', capabilities: makeCapabilities({ backend, mode: 'full' }) },
      );
      expect(screen.getByText(`content-${backend}`)).toBeTruthy();
      unmount();
    }
    for (const backend of ['sqlite', 'postgres']) {
      const { unmount } = renderWithApp(
        <HistoryGate>
          <p>hidden</p>
        </HistoryGate>,
        { mode: 'statsonly', capabilities: makeCapabilities({ backend, mode: 'statsonly' }) },
      );
      expect(screen.queryByText('hidden')).toBeNull();
      unmount();
    }
  });
});
