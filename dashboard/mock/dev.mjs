#!/usr/bin/env node
// `npm run dev:mock`: starts the mock API (MOCK_PORT, default 8787) and the Vite dev server (5173), which
// proxies /api to the mock. Open http://localhost:5173. Environment switches are the same as mock/server.mjs.
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const root = join(fileURLToPath(import.meta.url), '..', '..');
const mockPort = process.env.MOCK_PORT || '8787';
const env = { ...process.env, PORT: mockPort, MOCK_PORT: mockPort };

const children = [
  spawn(process.execPath, [join(root, 'mock', 'server.mjs')], { cwd: root, env, stdio: 'inherit' }),
  spawn(process.execPath, [join(root, 'node_modules', 'vite', 'bin', 'vite.js')], { cwd: root, env, stdio: 'inherit' }),
];

const stop = () => children.forEach((c) => c.kill('SIGTERM'));
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
for (const c of children) c.on('exit', (code) => {
  stop();
  process.exit(code ?? 0);
});
