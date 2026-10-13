import { spawn } from 'node:child_process';
import fs from 'node:fs';

// Browser smoke test: signs in to a running EggMail with a real headless Chrome and visits every page, reporting console errors,
// CSP violations and pages that show an error banner. Usage:
//   EGGMAIL_URL=http://127.0.0.1:8080 EGGMAIL_USER=admin EGGMAIL_PASSWORD=... node scripts/browser-smoke.mjs <output directory>
// Needs Google Chrome (path in CHROME, default is the macOS location) and Node 22 (global WebSocket). Not part of CI.
const BASE = process.env.EGGMAIL_URL ?? 'http://127.0.0.1:8080';
const USER = process.env.EGGMAIL_USER ?? 'admin';
const PASSWORD = process.env.EGGMAIL_PASSWORD ?? '';
const OUT = process.argv[2];
const chrome = spawn(process.env.CHROME ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', [
  '--headless=new', '--disable-gpu', '--remote-debugging-port=9333', `--user-data-dir=${OUT}/profile`, '--window-size=1280,900', 'about:blank',
], { stdio: 'ignore' });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let targets;
for (let i = 0; i < 50; i++) { try { targets = await (await fetch('http://127.0.0.1:9333/json')).json(); break; } catch { await sleep(200); } }
const page = targets.find((t) => t.type === 'page');
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => (ws.onopen = r));
let id = 0; const pending = new Map(); const problems = [];
ws.onmessage = (m) => {
  const msg = JSON.parse(m.data);
  if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); return; }
  if (msg.method === 'Runtime.exceptionThrown') problems.push('exception: ' + (msg.params.exceptionDetails.exception?.description ?? msg.params.exceptionDetails.text));
  if (msg.method === 'Runtime.consoleAPICalled' && ['error', 'warning'].includes(msg.params.type)) problems.push('console.' + msg.params.type + ': ' + msg.params.args.map((a) => a.value ?? a.description).join(' '));
  if (msg.method === 'Log.entryAdded' && ['error', 'warning'].includes(msg.params.entry.level)) problems.push('log.' + msg.params.entry.level + ': ' + msg.params.entry.text + ' ' + (msg.params.entry.url ?? ''));
};
const send = (method, params = {}) => new Promise((resolve) => { const i = ++id; pending.set(i, resolve); ws.send(JSON.stringify({ id: i, method, params })); });
const evalJs = async (expression) => (await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true })).result?.result?.value;
const shot = async (name) => { const r = await send('Page.captureScreenshot', { format: 'png' }); fs.writeFileSync(`${OUT}/${name}.png`, Buffer.from(r.result.data, 'base64')); };
await send('Runtime.enable'); await send('Log.enable'); await send('Page.enable');
const go = async (path) => { await send('Page.navigate', { url: BASE + path }); await sleep(1200); };

await go('/');
console.log('title:', await evalJs('document.title'));
await shot('01-login');
// Sign in as the bootstrap admin by typing, like a person would.
const typeInto = async (index, text) => { await evalJs(`document.querySelectorAll('input')[${index}].focus()`); await send('Input.insertText', { text }); };
await typeInto(0, USER); await typeInto(1, PASSWORD);
await evalJs("document.querySelector('form button[type=submit], form button')?.click()");
await sleep(1500);
console.log('after login path:', await evalJs('location.pathname'), '| heading:', await evalJs("document.querySelector('h1')?.textContent"));
await shot('02-overview');
const routes = ['/admin/tenants', '/admin/status', '/admin/certificates', '/admin/storage', '/messages', '/domains', '/webhooks', '/suppressions', '/credentials', '/statistics', '/settings', '/send'];
for (const r of routes) {
  await go(r);
  const h1 = await evalJs("document.querySelector('h1')?.textContent");
  const err = await evalJs("document.querySelector('[role=alert]:not([data-warning])')?.textContent ?? ''");
  console.log(r.padEnd(20), '->', (h1 ?? '(no h1)').padEnd(28), err ? 'ALERT: ' + err.slice(0, 120) : '');
  await shot('r' + r.replaceAll('/', '_'));
}
console.log('problems:', problems.length ? '\n  ' + [...new Set(problems)].join('\n  ') : 'none');
ws.close(); chrome.kill();
process.exit(0);
