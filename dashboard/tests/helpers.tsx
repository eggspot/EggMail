import { vi } from 'vitest';
import { render } from '@testing-library/preact';
import type { ComponentChildren } from 'preact';
import { LocationProvider } from 'preact-iso';
import { AppContext } from '../src/state/app';
import type { AppContextValue } from '../src/state/app';
import type { Capabilities, HistoryMode, Me, Role } from '../src/api/types';

export interface RecordedCall {
  method: string;
  path: string;
  query: URLSearchParams;
  headers: Headers;
  body: unknown;
}

export type RouteHandler = unknown | ((call: RecordedCall, params: Record<string, string>) => unknown);

export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });
}

/** An RFC 9457 problem response. */
export function problem(status: number, code: string, extra: Record<string, unknown> = {}, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify({ type: `https://eggmail.example/problems/${code}`, title: code, status, code, request_id: 'req-test', ...extra }), {
    status,
    headers: { 'Content-Type': 'application/problem+json', ...headers },
  });
}

function compile(pattern: string): { method: string; re: RegExp; names: string[] } {
  const [method, path] = pattern.split(' ');
  const names: string[] = [];
  const re = new RegExp('^' + path.replace(/:([A-Za-z]+)/g, (_m, n) => (names.push(n), '([^/]+)')) + '$');
  return { method, re, names };
}

/**
 * Stubs global fetch with a route table: keys are "METHOD /path/:param", values are a JSON body, a
 * Response, or a function (call, params) => body | Response. Unmatched requests answer 404 problem+json
 * and are recorded, so tests can assert on unexpected calls.
 */
export function mockFetch(routes: Record<string, RouteHandler> = {}) {
  const calls: RecordedCall[] = [];
  const table = Object.entries(routes).map(([k, v]) => ({ ...compile(k), handler: v }));
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url, 'http://localhost');
    const method = (init?.method ?? 'GET').toUpperCase();
    let body: unknown;
    if (typeof init?.body === 'string') {
      try {
        body = JSON.parse(init.body);
      } catch {
        body = init.body;
      }
    }
    const call: RecordedCall = { method, path: url.pathname, query: url.searchParams, headers: new Headers(init?.headers), body };
    calls.push(call);
    for (const r of table) {
      if (r.method !== method) continue;
      const m = r.re.exec(url.pathname);
      if (!m) continue;
      const params: Record<string, string> = {};
      r.names.forEach((n, i) => (params[n] = decodeURIComponent(m[i + 1])));
      const out = typeof r.handler === 'function' ? await (r.handler as (c: RecordedCall, p: Record<string, string>) => unknown)(call, params) : r.handler;
      if (out instanceof Response) return out;
      if (out === undefined) return new Response(null, { status: 204 });
      return json(out);
    }
    return problem(404, 'not_found', { detail: `no mock for ${method} ${url.pathname}` });
  });
  vi.stubGlobal('fetch', fn);
  return { fn, calls, callsTo: (method: string, path: string) => calls.filter((c) => c.method === method && c.path === path) };
}

export function makeCapabilities(over: Partial<Capabilities> & { mode?: HistoryMode } = {}): Capabilities {
  const { mode, ...rest } = over;
  return {
    version: '0.1.0',
    backend: 'sqlite',
    history: { mode: mode ?? 'full' },
    content: { retentionDays: 7, storeAttachments: false },
    limits: { maxMessageBytes: 26214400, maxRecipients: 50 },
    warnings: [],
    ...rest,
  };
}

export function makeApp(over: Partial<AppContextValue> & { role?: Role; mode?: HistoryMode } = {}): AppContextValue {
  const role: Role = over.role ?? 'tenant';
  const mode = over.mode ?? 'full';
  const me: Me = { user: role, role, tenantId: role === 'admin' ? null : 't_1', csrfToken: 'csrf-test' };
  return {
    status: 'authenticated',
    me,
    capabilities: makeCapabilities({ mode }),
    offlineError: null,
    signInNotice: null,
    tenants: [],
    tenantId: role === 'admin' ? 't_1' : null,
    setTenantId: () => {},
    historyMode: mode,
    isAdmin: role === 'admin',
    login: async () => {},
    logout: async () => {},
    retry: () => {},
    refreshCapabilities: async () => {},
    refreshMe: async () => {},
    refreshTenants: async () => {},
    ...over,
  };
}

/** Renders a page or component inside the router location and a fixed app context. */
export function renderWithApp(ui: ComponentChildren, over: Partial<AppContextValue> & { role?: Role; mode?: HistoryMode } = {}) {
  const value = makeApp(over);
  return render(
    <LocationProvider>
      <AppContext.Provider value={value}>{ui}</AppContext.Provider>
    </LocationProvider>,
  );
}

/** Lets pending promises and effects settle. */
export const flush = () => new Promise<void>((r) => setTimeout(r, 0));
