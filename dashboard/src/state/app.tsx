import { createContext } from 'preact';
import type { ComponentChildren } from 'preact';
import { useCallback, useContext, useEffect, useMemo, useState } from 'preact/hooks';
import { api } from '../api/endpoints';
import { ApiError, setCsrfToken, setTenantId as setClientTenant, setUnauthorizedHandler } from '../api/client';
import type { Capabilities, HistoryMode, Me, Tenant } from '../api/types';
import { safeGet, safeSet } from '../lib/hooks';

export type AppStatus = 'loading' | 'anonymous' | 'authenticated' | 'offline';

export interface AppContextValue {
  status: AppStatus;
  me: Me | null;
  capabilities: Capabilities | null;
  /** Set when the server answered 503 not_ready or could not be reached. */
  offlineError: ApiError | null;
  /** Admin only: tenants to choose from and the one currently acted on. */
  tenants: Tenant[];
  tenantId: string | null;
  setTenantId: (id: string) => void;
  /** The UI adapts to this and never to the backend name. */
  historyMode: HistoryMode;
  isAdmin: boolean;
  login: (user: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  retry: () => void;
  refreshCapabilities: () => Promise<void>;
  /** Admin only: reloads the tenant list behind the header picker (after a tenant was created, renamed or suspended). `select` also acts on that tenant. */
  refreshTenants: (select?: string) => Promise<void>;
}

const defaultValue: AppContextValue = {
  status: 'loading',
  me: null,
  capabilities: null,
  offlineError: null,
  tenants: [],
  tenantId: null,
  setTenantId: () => {},
  historyMode: 'full',
  isAdmin: false,
  login: async () => {},
  logout: async () => {},
  retry: () => {},
  refreshCapabilities: async () => {},
  refreshTenants: async () => {},
};

export const AppContext = createContext<AppContextValue>(defaultValue);
export const useApp = () => useContext(AppContext);

const TENANT_KEY = 'eggmail.tenant';
const CAPABILITIES_REFRESH_MS = 60_000;

function isOffline(e: unknown): e is ApiError {
  return e instanceof ApiError && (e.status === 0 || e.code === 'not_ready' || e.status >= 500);
}

export function AppProvider({ children }: { children: ComponentChildren }) {
  const [status, setStatus] = useState<AppStatus>('loading');
  const [me, setMe] = useState<Me | null>(null);
  const [capabilities, setCapabilities] = useState<Capabilities | null>(null);
  const [offlineError, setOfflineError] = useState<ApiError | null>(null);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [tenantId, setTenantIdState] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);

  const applyTenant = useCallback((id: string | null) => {
    setTenantIdState(id);
    setClientTenant(id);
    // The tenant choice is not a secret; it only survives a reload within this tab.
    safeSet('session', TENANT_KEY, id);
  }, []);

  const loadTenants = useCallback(
    async (user: Me) => {
      if (user.role !== 'admin') {
        setTenants([]);
        applyTenant(null);
        return;
      }
      const list = await api.tenants();
      setTenants(list);
      const stored = safeGet('session', TENANT_KEY);
      const pick = list.find((t) => t.id === stored) ?? list[0];
      applyTenant(pick ? pick.id : null);
    },
    [applyTenant],
  );

  const refreshTenants = useCallback(
    async (select?: string) => {
      const list = await api.tenants();
      setTenants(list);
      const current = list.find((t) => t.id === (select ?? tenantId));
      // Keep acting on the same tenant; the first tenant of a fresh install is chosen by itself.
      if (select && current) applyTenant(current.id);
      else if (!current && list[0]) applyTenant(list[0].id);
    },
    [applyTenant, tenantId],
  );

  const refreshCapabilities = useCallback(async () => {
    try {
      setCapabilities(await api.capabilities());
    } catch {
      /* keep the last known capabilities; the page-level calls surface real outages */
    }
  }, []);

  // Bootstrap: capabilities (no auth) and the session probe.
  useEffect(() => {
    let live = true;
    setUnauthorizedHandler(() => {
      setCsrfToken(null);
      setMe(null);
      setStatus('anonymous');
    });
    (async () => {
      setStatus('loading');
      try {
        const caps = await api.capabilities();
        if (!live) return;
        setCapabilities(caps);
      } catch (e) {
        if (!live) return;
        if (isOffline(e)) {
          setOfflineError(e);
          setStatus('offline');
          return;
        }
      }
      try {
        const user = await api.me();
        if (!live) return;
        await loadTenants(user);
        if (!live) return;
        setMe(user);
        setOfflineError(null);
        setStatus('authenticated');
      } catch (e) {
        if (!live) return;
        if (e instanceof ApiError && e.status === 401) {
          setMe(null);
          setOfflineError(null);
          setStatus('anonymous');
        } else if (isOffline(e)) {
          setOfflineError(e);
          setStatus('offline');
        } else {
          setStatus('anonymous');
        }
      }
    })();
    return () => {
      live = false;
      setUnauthorizedHandler(null);
    };
  }, [attempt, loadTenants]);

  // Keep the warning banner current while signed in.
  useEffect(() => {
    if (status !== 'authenticated') return;
    const id = setInterval(refreshCapabilities, CAPABILITIES_REFRESH_MS);
    return () => clearInterval(id);
  }, [status, refreshCapabilities]);

  const login = useCallback(
    async (user: string, password: string) => {
      const who = await api.login(user, password);
      await loadTenants(who);
      setMe(who);
      setStatus('authenticated');
      void refreshCapabilities();
    },
    [loadTenants, refreshCapabilities],
  );

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } catch {
      /* the cookie may already be gone */
    }
    setMe(null);
    applyTenant(null);
    setStatus('anonymous');
  }, [applyTenant]);

  const value = useMemo<AppContextValue>(
    () => ({
      status,
      me,
      capabilities,
      offlineError,
      tenants,
      tenantId,
      setTenantId: applyTenant,
      historyMode: capabilities?.history.mode ?? 'full',
      isAdmin: me?.role === 'admin',
      login,
      logout,
      retry: () => setAttempt((n) => n + 1),
      refreshCapabilities,
      refreshTenants,
    }),
    [status, me, capabilities, offlineError, tenants, tenantId, applyTenant, login, logout, refreshCapabilities, refreshTenants],
  );

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}
