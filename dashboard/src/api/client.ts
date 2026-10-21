import type { FieldError, Problem } from './types';

/** Error raised for every failed API call (problem+json, network failure or unexpected body). */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly title: string;
  readonly detail: string;
  readonly requestId?: string;
  readonly fieldErrors: FieldError[];
  /** Seconds from the Retry-After header, when present. */
  readonly retryAfter?: number;
  readonly problem: Problem;

  constructor(problem: Problem, retryAfter?: number) {
    super(problem.detail || problem.title || `HTTP ${problem.status}`);
    this.name = 'ApiError';
    this.problem = problem;
    this.status = problem.status;
    this.code = problem.code || defaultCode(problem.status);
    this.title = problem.title || '';
    this.detail = problem.detail || '';
    this.requestId = problem.request_id;
    this.fieldErrors = Array.isArray(problem.errors) ? problem.errors : [];
    this.retryAfter = retryAfter;
  }
}

function defaultCode(status: number): string {
  switch (status) {
    case 0:
      return 'network_error';
    case 401:
      return 'unauthorized';
    case 403:
      return 'forbidden';
    case 404:
      return 'not_found';
    case 429:
      return 'rate_limited';
    case 503:
      return 'not_ready';
    default:
      return status >= 500 ? 'server_error' : 'http_error';
  }
}

export type Method = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
export type Query = Record<string, string | number | boolean | undefined | null>;

export interface RequestOptions {
  query?: Query;
  body?: unknown;
  headers?: Record<string, string>;
  signal?: AbortSignal;
  /** Do not call the global 401 handler (used for login and the session probe). */
  skipUnauthorizedHandler?: boolean;
}

const MUTATING = new Set<Method>(['POST', 'PUT', 'PATCH', 'DELETE']);

export const API_BASE = '/api/v1';

interface ClientState {
  csrfToken: string | null;
  tenantId: string | null;
  onUnauthorized: (() => void) | null;
}

const state: ClientState = { csrfToken: null, tenantId: null, onUnauthorized: null };

export function setCsrfToken(token: string | null | undefined): void {
  state.csrfToken = token || null;
}
export function getCsrfToken(): string | null {
  return state.csrfToken;
}
/** Admins select the tenant they act on with the X-Tenant-Id header. */
export function setTenantId(id: string | null): void {
  state.tenantId = id || null;
}
export function getTenantId(): string | null {
  return state.tenantId;
}
export function setUnauthorizedHandler(fn: (() => void) | null): void {
  state.onUnauthorized = fn;
}

function buildUrl(path: string, query?: Query): string {
  const base = path.startsWith('/') ? path : `${API_BASE}/${path}`;
  if (!query) return base;
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null || v === '') continue;
    qs.set(k, String(v));
  }
  const s = qs.toString();
  return s ? `${base}?${s}` : base;
}

async function parseProblem(res: Response): Promise<ApiError> {
  const retry = Number(res.headers.get('Retry-After'));
  const retryAfter = Number.isFinite(retry) && retry > 0 ? retry : undefined;
  let problem: Problem = { status: res.status };
  const type = res.headers.get('Content-Type') || '';
  try {
    if (type.includes('json')) {
      const body = (await res.json()) as Partial<Problem> | null;
      if (body && typeof body === 'object') problem = { ...body, status: body.status ?? res.status };
    } else {
      const text = await res.text();
      if (text) problem = { status: res.status, detail: text.slice(0, 300) };
    }
  } catch {
    // keep the synthesized problem
  }
  return new ApiError(problem, retryAfter);
}

/** Core request function. All API access goes through here (CSRF, tenant header, problem+json). */
export async function request<T>(method: Method, path: string, opts: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json', ...opts.headers };
  let body: string | undefined;
  if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(opts.body);
  }
  if (MUTATING.has(method) && state.csrfToken) headers['X-CSRF-Token'] = state.csrfToken;
  if (state.tenantId) headers['X-Tenant-Id'] = state.tenantId;

  let res: Response;
  try {
    res = await fetch(buildUrl(path, opts.query), {
      method,
      headers,
      body,
      credentials: 'same-origin',
      cache: 'no-store',
      signal: opts.signal,
    });
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e;
    throw new ApiError({ status: 0, code: 'network_error', title: 'Network error', detail: String(e) });
  }

  if (!res.ok) {
    const err = await parseProblem(res);
    if (err.status === 401 && !opts.skipUnauthorizedHandler) state.onUnauthorized?.();
    throw err;
  }
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  if (!text) return undefined as T;
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new ApiError({ status: res.status, code: 'bad_response', title: 'Unexpected response', detail: 'The server returned a body that is not JSON.' });
  }
}

export const http = {
  get: <T>(path: string, query?: Query, signal?: AbortSignal) => request<T>('GET', path, { query, signal }),
  post: <T>(path: string, body?: unknown, opts?: RequestOptions) => request<T>('POST', path, { ...opts, body }),
  put: <T>(path: string, body?: unknown) => request<T>('PUT', path, { body }),
  patch: <T>(path: string, body?: unknown) => request<T>('PATCH', path, { body }),
  del: <T>(path: string) => request<T>('DELETE', path),
};

/**
 * Downloads a file the API serves as an attachment (a received message, an attachment). A plain link would not carry the tenant an administrator acts on
 * (the X-Tenant-Id header), so the bytes are fetched here and handed to the browser as a Blob. Nothing is rendered: the caller saves it.
 */
export async function download(path: string, signal?: AbortSignal): Promise<Blob> {
  const headers: Record<string, string> = {};
  if (state.tenantId) headers['X-Tenant-Id'] = state.tenantId;
  let res: Response;
  try {
    res = await fetch(buildUrl(path), { method: 'GET', headers, credentials: 'same-origin', cache: 'no-store', signal });
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e;
    throw new ApiError({ status: 0, code: 'network_error', title: 'Network error', detail: String(e) });
  }
  if (!res.ok) {
    const err = await parseProblem(res);
    if (err.status === 401) state.onUnauthorized?.();
    throw err;
  }
  return res.blob();
}

/** Operational endpoints live outside /api/v1; this reads /readyz without the problem handling. */
export async function probeReady(): Promise<{ ready: boolean; warnings?: unknown }> {
  try {
    const res = await fetch('/readyz', { cache: 'no-store', credentials: 'same-origin' });
    let warnings: unknown;
    try {
      warnings = ((await res.json()) as { warnings?: unknown }).warnings;
    } catch {
      /* ignore */
    }
    return { ready: res.ok, warnings };
  } catch {
    return { ready: false };
  }
}

/** Normalizes list responses that may be a bare array or `{ items }`. */
export function itemsOf<T>(value: T[] | { items: T[] } | null | undefined): T[] {
  if (!value) return [];
  return Array.isArray(value) ? value : (value.items ?? []);
}
