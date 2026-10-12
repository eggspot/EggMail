#!/usr/bin/env node
// Prints raw and gzip sizes of the production build (dist/).
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';

const dist = join(fileURLToPath(import.meta.url), '..', '..', 'dist');

function walk(dir) {
  const out = [];
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

const rows = walk(dist).map((f) => {
  const buf = readFileSync(f);
  return { file: relative(dist, f).split(sep).join('/'), raw: buf.length, gzip: gzipSync(buf, { level: 9 }).length };
});
rows.sort((a, b) => b.gzip - a.gzip);
const kb = (n) => (n / 1024).toFixed(1).padStart(8) + ' KiB';
let totals = { raw: 0, gzip: 0 };
const byType = {};
for (const r of rows) {
  console.log(`${kb(r.gzip)} gzip ${kb(r.raw)} raw  ${r.file}`);
  totals.raw += r.raw;
  totals.gzip += r.gzip;
  const ext = r.file.split('.').pop();
  byType[ext] ??= { raw: 0, gzip: 0 };
  byType[ext].raw += r.raw;
  byType[ext].gzip += r.gzip;
}
console.log('');
for (const [ext, t] of Object.entries(byType)) console.log(`${ext.padEnd(5)} total ${kb(t.gzip)} gzip ${kb(t.raw)} raw`);
console.log(`all   total ${kb(totals.gzip)} gzip ${kb(totals.raw)} raw`);
const entry = rows.find((r) => /^assets\/index-.*\.js$/.test(r.file));
const css = rows.filter((r) => r.file.endsWith('.css')).reduce((a, r) => a + r.gzip, 0);
if (entry) console.log(`initial load (entry JS + CSS): ${((entry.gzip + css) / 1024).toFixed(1)} KiB gzip`);
