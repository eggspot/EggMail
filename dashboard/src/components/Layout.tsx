import type { ComponentChildren } from 'preact';
import { useEffect, useRef, useState } from 'preact/hooks';
import { useLocation } from 'preact-iso';
import { getTheme, nextTheme, setTheme } from '../state/theme';
import type { ThemeChoice } from '../state/theme';
import { useApp } from '../state/app';
import { WarningBanner } from './WarningBanner';

interface NavItem {
  href: string;
  label: string;
  admin?: boolean;
}

export const NAV_ITEMS: NavItem[] = [
  { href: '/', label: 'Overview' },
  { href: '/messages', label: 'Messages' },
  { href: '/send', label: 'Send test' },
  { href: '/domains', label: 'Domains' },
  { href: '/webhooks', label: 'Webhooks' },
  { href: '/suppressions', label: 'Suppressions' },
  { href: '/credentials', label: 'API keys and SMTP' },
  { href: '/statistics', label: 'Statistics' },
  { href: '/settings', label: 'Settings' },
  { href: '/account', label: 'Account' },
  { href: '/admin/tenants', label: 'Tenants', admin: true },
  { href: '/admin/users', label: 'Users', admin: true },
  { href: '/admin/status', label: 'Server status', admin: true },
  { href: '/admin/certificates', label: 'Certificates', admin: true },
  { href: '/admin/storage', label: 'Storage switch', admin: true },
];

function isActive(path: string, href: string) {
  return href === '/' ? path === '/' : path === href || path.startsWith(`${href}/`);
}

const THEME_LABEL: Record<ThemeChoice, string> = { system: 'System theme', light: 'Light theme', dark: 'Dark theme' };

export function ThemeToggle() {
  const [theme, setThemeState] = useState<ThemeChoice>(getTheme());
  return (
    <button
      type="button"
      class="btn btn-small"
      onClick={() => {
        const n = nextTheme(theme);
        setTheme(n);
        setThemeState(n);
      }}
      aria-label={`Color theme: ${THEME_LABEL[theme]}. Activate to change.`}
    >
      {THEME_LABEL[theme]}
    </button>
  );
}

/** App shell for signed-in pages: header, navigation, persistent warning banner and focus handling. */
export function Layout({ children }: { children: ComponentChildren }) {
  const { me, capabilities, isAdmin, tenants, tenantId, setTenantId, logout } = useApp();
  const { path } = useLocation();
  const [navOpen, setNavOpen] = useState(false);
  const mainRef = useRef<HTMLElement>(null);
  const first = useRef(true);

  // Move focus to the page content after a navigation so keyboard and screen reader users land on it.
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    setNavOpen(false);
    mainRef.current?.focus();
  }, [path]);

  const items = NAV_ITEMS.filter((i) => !i.admin || isAdmin);

  return (
    <div class="shell">
      <a class="skip-link" href="#main" onClick={(e) => { e.preventDefault(); mainRef.current?.focus(); }}>
        Skip to content
      </a>
      <header class="topbar">
        <button type="button" class="btn btn-small nav-toggle" aria-expanded={navOpen} aria-controls="site-nav" onClick={() => setNavOpen(!navOpen)}>
          Menu
        </button>
        <a class="brand" href="/">
          <span class="brand-egg" aria-hidden="true" /> EggMail
        </a>
        <div class="topbar-info muted small" data-testid="backend-info">
          {capabilities && (
            <span>
              v{capabilities.version} · storage: {capabilities.backend} · history: {capabilities.history.mode}
            </span>
          )}
        </div>
        <div class="topbar-actions">
          {isAdmin && tenants.length > 0 && (
            <label class="tenant-picker">
              <span class="sr-only">Acting on tenant</span>
              <select value={tenantId ?? ''} onChange={(e) => setTenantId((e.currentTarget as HTMLSelectElement).value)} aria-label="Acting on tenant">
                {tenants.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                  </option>
                ))}
              </select>
            </label>
          )}
          <ThemeToggle />
          <span class="user small">
            {me?.user} <span class="muted">({me?.role})</span>
          </span>
          <button type="button" class="btn btn-small" onClick={() => void logout()}>
            Sign out
          </button>
        </div>
      </header>
      <WarningBanner />
      <div class="body">
        <nav id="site-nav" class={`sidenav${navOpen ? ' open' : ''}`} aria-label="Main">
          <ul>
            {items.map((i) => (
              <li key={i.href}>
                <a href={i.href} aria-current={isActive(path, i.href) ? 'page' : undefined}>
                  {i.label}
                </a>
              </li>
            ))}
          </ul>
        </nav>
        <main id="main" ref={mainRef} tabIndex={-1} class="main">
          {children}
        </main>
      </div>
    </div>
  );
}
