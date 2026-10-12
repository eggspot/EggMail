import { useCallback, useEffect, useRef, useState } from 'preact/hooks';

export interface ApiState<T> {
  data: T | undefined;
  error: unknown;
  loading: boolean;
  reload: () => void;
  setData: (value: T | undefined | ((prev: T | undefined) => T | undefined)) => void;
}

/**
 * Loads data with `fn` on mount and whenever `deps` change. Stale data stays visible while a reload
 * runs. Superseded or unmounted requests are ignored (and aborted through the signal).
 */
export function useApi<T>(fn: (signal: AbortSignal) => Promise<T>, deps: unknown[] = []): ApiState<T> {
  const [data, setData] = useState<T | undefined>(undefined);
  const [error, setError] = useState<unknown>(undefined);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  useEffect(() => {
    const ctrl = new AbortController();
    let live = true;
    setLoading(true);
    fnRef
      .current(ctrl.signal)
      .then((value) => {
        if (!live) return;
        setData(value);
        setError(undefined);
      })
      .catch((e) => {
        if (!live || (e instanceof DOMException && e.name === 'AbortError')) return;
        setError(e);
      })
      .finally(() => {
        if (live) setLoading(false);
      });
    return () => {
      live = false;
      ctrl.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { data, error, loading, reload, setData };
}

export interface ActionState<A extends unknown[], R> {
  run: (...args: A) => Promise<R | undefined>;
  busy: boolean;
  error: unknown;
  clearError: () => void;
}

/** Wraps a mutation: tracks busy and error state and never throws to the caller. */
export function useAction<A extends unknown[], R>(fn: (...args: A) => Promise<R>): ActionState<A, R> {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(undefined);
  const fnRef = useRef(fn);
  fnRef.current = fn;
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const run = useCallback(async (...args: A) => {
    setBusy(true);
    setError(undefined);
    try {
      return await fnRef.current(...args);
    } catch (e) {
      if (mounted.current) setError(e);
      return undefined;
    } finally {
      if (mounted.current) setBusy(false);
    }
  }, []);

  return { run, busy, error, clearError: () => setError(undefined) };
}

/** Counts down from `seconds` after `start()` is called; `remaining` is 0 when idle. */
export function useCooldown(): { remaining: number; start: (seconds: number) => void } {
  const [until, setUntil] = useState(0);
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (until <= Date.now()) return;
    const id = setInterval(() => {
      const n = Date.now();
      setNow(n);
      if (n >= until) clearInterval(id);
    }, 250);
    return () => clearInterval(id);
  }, [until]);
  const remaining = Math.max(0, Math.ceil((until - now) / 1000));
  return {
    remaining,
    start: (seconds: number) => {
      const n = Date.now();
      setNow(n);
      setUntil(n + seconds * 1000);
    },
  };
}

/** Interval polling that stops when the callback returns false or the component unmounts. */
export function usePolling(callback: () => void | boolean | Promise<void | boolean>, ms: number, enabled = true): void {
  const cb = useRef(callback);
  cb.current = callback;
  useEffect(() => {
    if (!enabled) return;
    let stopped = false;
    const id = setInterval(async () => {
      const keepGoing = await cb.current();
      if (keepGoing === false && !stopped) {
        stopped = true;
        clearInterval(id);
      }
    }, ms);
    return () => clearInterval(id);
  }, [ms, enabled]);
}

export function useDocumentTitle(title: string): void {
  useEffect(() => {
    document.title = title ? `${title} - EggMail` : 'EggMail';
  }, [title]);
}

/** Safe wrappers: storage can throw (private windows, blocked site data). Never used for secrets. */
export function safeGet(storage: 'local' | 'session', key: string): string | null {
  try {
    return (storage === 'local' ? window.localStorage : window.sessionStorage).getItem(key);
  } catch {
    return null;
  }
}
export function safeSet(storage: 'local' | 'session', key: string, value: string | null): void {
  try {
    const s = storage === 'local' ? window.localStorage : window.sessionStorage;
    if (value === null) s.removeItem(key);
    else s.setItem(key, value);
  } catch {
    /* ignore */
  }
}
