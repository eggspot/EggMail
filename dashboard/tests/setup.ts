import { afterEach, vi } from 'vitest';
import { cleanup } from '@testing-library/preact';
import { setCsrfToken, setTenantId, setUnauthorizedHandler } from '../src/api/client';

afterEach(() => {
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
