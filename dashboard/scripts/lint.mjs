#!/usr/bin/env node
// Tiny dependency-free lint: security and CSP rules that tsc cannot express. Run via `npm run lint`
// (which runs `tsc --noEmit` first). Exits 1 when a rule is violated.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(fileURLToPath(import.meta.url), '..', '..');
const srcDir = join(root, 'src');

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (/\.(ts|tsx)$/.test(name)) out.push(p);
  }
  return out;
}

/** Rules applied to every source line that is not a comment. */
const lineRules = [
  { re: /dangerouslySetInnerHTML|\.innerHTML\b|\.outerHTML\b|insertAdjacentHTML|document\.write/, msg: 'raw HTML injection is forbidden (message HTML only goes into the sandboxed iframe)' },
  { re: /\beval\s*\(|new Function\s*\(/, msg: 'eval and new Function are forbidden (CSP)' },
  { re: /\bstyle\s*=\s*[{"']|\.setAttribute\(\s*['"]style['"]/, msg: 'inline styles are forbidden (CSP style-src self); use CSS classes' },
  { re: /\bon[a-z]+\s*=\s*["']/, msg: 'string event-handler attributes are forbidden' },
  { re: /https?:\/\//, msg: 'no external URLs: the dashboard only talks to same-origin /api/v1' },
  { re: /console\.(log|debug|info)\b/, msg: 'leftover console output' },
  { re: /\bdebugger\b/, msg: 'leftover debugger statement' },
  { re: /(localStorage|sessionStorage)\.setItem\([^)]*(token|secret|password|csrf|apikey)/i, msg: 'never store secrets in web storage' },
  { re: /TODO: stub/, msg: 'unfinished page stub' },
];

const problems = [];
const files = walk(srcDir);
for (const file of files) {
  const rel = relative(root, file).split(sep).join('/');
  const text = readFileSync(file, 'utf8');
  const lines = text.split('\n');
  let inBlockComment = false;
  lines.forEach((raw, i) => {
    let line = raw;
    if (inBlockComment) {
      if (line.includes('*/')) {
        inBlockComment = false;
        line = line.slice(line.indexOf('*/') + 2);
      } else return;
    }
    if (line.includes('/*') && !line.includes('*/')) {
      inBlockComment = true;
      line = line.slice(0, line.indexOf('/*'));
    }
    line = line.replace(/\/\*.*?\*\//g, '').replace(/(^|\s)\/\/.*$/, '$1');
    if (!line.trim()) return;
    for (const r of lineRules) {
      if (r.re.test(line)) problems.push(`${rel}:${i + 1}: ${r.msg}`);
    }
    // fetch is only allowed inside the API client
    if (/\bfetch\s*\(/.test(line) && rel !== 'src/api/client.ts') problems.push(`${rel}:${i + 1}: use the api client instead of fetch`);
    if (/target\s*=\s*["']_blank["']/.test(line) && !/noopener/.test(line)) problems.push(`${rel}:${i + 1}: target=_blank needs rel="noopener noreferrer"`);
  });
  // Every iframe must be sandboxed.
  const iframeRe = /<iframe\b[^>]*>/gs;
  for (const m of text.matchAll(iframeRe)) {
    if (!/\bsandbox\b/.test(m[0])) problems.push(`${rel}: <iframe> without a sandbox attribute`);
    if (/sandbox=["'][^"']*allow-/.test(m[0])) problems.push(`${rel}: <iframe sandbox> must not grant allow-* flags`);
  }
}

if (problems.length) {
  console.error(`lint: ${problems.length} problem(s)`);
  for (const p of problems) console.error('  ' + p);
  process.exit(1);
}
console.log(`lint: ${files.length} source files ok`);
