// @vitest-environment node
// Reads the design tokens out of src/styles/app.css and checks WCAG contrast for every text pair, in
// the light theme, the prefers-color-scheme: dark theme and the manual data-theme="dark" theme.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const css = readFileSync(new URL('../src/styles/app.css', import.meta.url), 'utf8');

function block(startRe) {
  const m = startRe.exec(css);
  if (!m) throw new Error(`block not found: ${startRe}`);
  let i = css.indexOf('{', m.index) + 1;
  let depth = 1;
  const start = i;
  while (depth && i < css.length) {
    if (css[i] === '{') depth++;
    if (css[i] === '}') depth--;
    i++;
  }
  const body = css.slice(start, i - 1);
  const out = {};
  for (const t of body.matchAll(/(--[a-z0-9-]+):\s*([^;]+);/g)) out[t[1]] = t[2].trim();
  return out;
}

const light = block(/^:root\s*\{/m);
const darkMedia = block(/:root:not\(\[data-theme='light'\]\)\s*\{/);
const darkManual = block(/:root\[data-theme='dark'\]\s*\{/);

function luminance(hex) {
  const n = parseInt(hex.slice(1), 16);
  const [r, g, b] = [(n >> 16) & 255, (n >> 8) & 255, n & 255].map((v) => {
    const c = v / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
function ratio(a, b) {
  const [l1, l2] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (l1 + 0.05) / (l2 + 0.05);
}

// [foreground token, background token, minimum ratio]
const TEXT_PAIRS = [
  ['--text', '--bg', 4.5],
  ['--text', '--surface', 4.5],
  ['--text', '--surface-2', 4.5],
  ['--muted', '--bg', 4.5],
  ['--muted', '--surface', 4.5],
  ['--muted', '--surface-2', 4.5],
  ['--accent', '--surface', 4.5],
  ['--accent', '--bg', 4.5],
  ['--accent-contrast', '--accent', 4.5],
  ['--ok-fg', '--ok-bg', 4.5],
  ['--warn-fg', '--warn-bg', 4.5],
  ['--bad-fg', '--bad-bg', 4.5],
  ['--info-fg', '--info-bg', 4.5],
  ['--neutral-fg', '--neutral-bg', 4.5],
  ['--loud-fg', '--loud-bg', 4.5],
  ['--bad-fg', '--surface', 4.5],
  // non-text contrast: focus ring and chart series on the card surface need 3:1
  ['--focus', '--surface', 3],
  ['--focus', '--bg', 3],
  ['--series-delivered', '--surface', 3],
  ['--series-deferred', '--surface', 3],
  ['--series-bounced', '--surface', 3],
  ['--series-other', '--surface', 3],
];

describe.each([
  ['light', light],
  ['dark (prefers-color-scheme)', { ...light, ...darkMedia }],
  ['dark (manual toggle)', { ...light, ...darkManual }],
])('contrast: %s theme', (_name, tokens) => {
  it.each(TEXT_PAIRS)('%s on %s is at least %s:1', (fg, bg, min) => {
    expect(tokens[fg], `${fg} defined`).toMatch(/^#[0-9a-f]{6}$/i);
    expect(tokens[bg], `${bg} defined`).toMatch(/^#[0-9a-f]{6}$/i);
    expect(ratio(tokens[fg], tokens[bg])).toBeGreaterThanOrEqual(min);
  });
});

describe('theme blocks stay in sync', () => {
  it('the two dark blocks define the same tokens with the same values', () => {
    const a = { ...darkMedia };
    const b = { ...darkManual };
    delete a['--shadow'];
    delete b['--shadow'];
    expect(a).toEqual(b);
  });
  it('every light token has a dark counterpart', () => {
    for (const key of Object.keys(light)) {
      if (key === '--shadow') continue;
      expect(darkManual, key).toHaveProperty(key);
    }
  });
});

describe('stylesheet hygiene', () => {
  it('has no external URLs, data URLs or imports', () => {
    expect(css).not.toMatch(/url\(/);
    expect(css).not.toMatch(/@import/);
  });
  it('respects reduced motion and provides a visible focus style', () => {
    expect(css).toContain('prefers-reduced-motion');
    expect(css).toContain(':focus-visible');
  });
});
