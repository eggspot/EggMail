#!/usr/bin/env node
// Verifies that the production build is compatible with a strict Content-Security-Policy:
//   default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'
// Fails on inline <script>/<style>, style= attributes, inline event handlers, javascript: URLs,
// eval / new Function, data: URLs in CSS, and external hosts.
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(fileURLToPath(import.meta.url), '..', '..');
const dist = process.argv[2] ? join(process.cwd(), process.argv[2]) : join(root, 'dist');

export function checkHtml(name, html) {
  const problems = [];
  for (const m of html.matchAll(/<script\b([^>]*)>/gi)) {
    if (!/\bsrc\s*=/.test(m[1])) problems.push(`${name}: inline <script>`);
  }
  if (/<style\b/i.test(html)) problems.push(`${name}: inline <style> element`);
  if (/\sstyle\s*=/i.test(html)) problems.push(`${name}: style= attribute`);
  if (/\son[a-z]+\s*=/i.test(html)) problems.push(`${name}: inline event handler attribute`);
  if (/javascript:/i.test(html)) problems.push(`${name}: javascript: URL`);
  for (const m of html.matchAll(/\b(?:src|href)\s*=\s*["']?(https?:)?\/\/[^"'\s>]+/gi)) problems.push(`${name}: external resource ${m[0]}`);
  return problems;
}

export function checkJs(name, js) {
  const problems = [];
  if (/(^|[^.\w$])eval\s*\(/.test(js)) problems.push(`${name}: eval(`);
  if (/new\s+Function\s*\(/.test(js)) problems.push(`${name}: new Function(`);
  if (/setAttribute\(\s*["']style["']/.test(js)) problems.push(`${name}: setAttribute("style")`);
  for (const m of js.matchAll(/https?:\/\/[^\s"'`)]+/g)) {
    // XML namespaces and the doc links inside Preact error messages are strings, not requests.
    if (!/^https?:\/\/(www\.w3\.org|preactjs\.com|github\.com\/preactjs|react\.dev|reactjs\.org)/.test(m[0])) problems.push(`${name}: external URL ${m[0]}`);
  }
  return problems;
}

export function checkCss(name, css) {
  const problems = [];
  if (/url\(\s*["']?data:/i.test(css)) problems.push(`${name}: data: URL in CSS`);
  if (/@import\s+(url\()?\s*["']?(https?:)?\/\//i.test(css)) problems.push(`${name}: external @import`);
  if (/url\(\s*["']?(https?:)?\/\//i.test(css)) problems.push(`${name}: external url()`);
  return problems;
}

function walk(dir) {
  const out = [];
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

export function checkDist(dir) {
  const problems = [];
  if (!existsSync(join(dir, 'index.html'))) return [`${dir}: no index.html (run npm run build first)`];
  for (const file of walk(dir)) {
    const rel = relative(dir, file).split(sep).join('/');
    const text = readFileSync(file, 'utf8');
    if (rel.endsWith('.html')) problems.push(...checkHtml(rel, text));
    else if (/\.m?js$/.test(rel)) problems.push(...checkJs(rel, text));
    else if (rel.endsWith('.css')) problems.push(...checkCss(rel, text));
    else if (rel.endsWith('.svg') && /<script\b|\son[a-z]+\s*=/i.test(text)) problems.push(`${rel}: script in SVG`);
  }
  return problems;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const problems = checkDist(dist);
  if (problems.length) {
    console.error(`check-csp: ${problems.length} problem(s)`);
    for (const p of problems) console.error('  ' + p);
    process.exit(1);
  }
  console.log(`check-csp: ${relative(process.cwd(), dist) || '.'} is compatible with script-src 'self'; style-src 'self'`);
}
