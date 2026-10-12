import { safeGet, safeSet } from '../lib/hooks';

export type ThemeChoice = 'system' | 'light' | 'dark';
const KEY = 'eggmail.theme';

export function getTheme(): ThemeChoice {
  const v = safeGet('local', KEY);
  return v === 'light' || v === 'dark' ? v : 'system';
}

/** Applies the choice through the data-theme attribute (no inline styles, CSP-safe). */
export function applyTheme(choice: ThemeChoice): void {
  const root = document.documentElement;
  if (choice === 'system') root.removeAttribute('data-theme');
  else root.setAttribute('data-theme', choice);
}

export function setTheme(choice: ThemeChoice): void {
  safeSet('local', KEY, choice === 'system' ? null : choice);
  applyTheme(choice);
}

export function nextTheme(choice: ThemeChoice): ThemeChoice {
  return choice === 'system' ? 'light' : choice === 'light' ? 'dark' : 'system';
}
