import { afterEach, vi } from 'vitest';
import { cleanup } from '@testing-library/preact';
import { setCsrfToken, setTenantId, setUnauthorizedHandler } from '../src/api/client';

afterEach(() => {
  // Test files that run in the node environment (mock server tests) have no DOM to clean up.
  if (typeof document === 'undefined') return;
  cleanup();
  vi.unstubAllGlobals();
  setCsrfToken(null);
  setTenantId(null);
  setUnauthorizedHandler(null);
  try {
    window.sessionStorage.clear();
    window.localStorage.clear();
  } catch {
    /* ignore */
  }
  document.documentElement.removeAttribute('data-theme');
});
