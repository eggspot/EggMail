#!/usr/bin/env node
// Starts the mock EggMail API and serves dashboard/dist (or proxies the Vite dev server when VITE_URL is set).
//
//   node mock/server.mjs                 # http://127.0.0.1:8787, sign in as admin/eggmail or tenant/eggmail
//   MOCK_HISTORY=statsonly node mock/server.mjs
//   MOCK_BACKEND=postgres MOCK_WARNINGS= node mock/server.mjs
//   MOCK_NOT_READY=1 node mock/server.mjs   # every API call answers 503 not_ready
//
// Environment: PORT (8787), HOST (127.0.0.1), MOCK_HISTORY (full|statsonly), MOCK_BACKEND (sqlite|postgres),
// MOCK_WARNINGS (comma separated codes, default sqlite_sync_off on sqlite), MOCK_NOT_READY, MOCK_LATENCY_MS,
// MOCK_DIST, VITE_URL.
import { fileURLToPath } from 'node:url';
import { createMockServer } from './app.mjs';

export { createMockServer };

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const app = await createMockServer();
  const port = await app.listen(Number(process.env.PORT || 8787), process.env.HOST || '127.0.0.1');
  const o = app.options;
  console.log(`EggMail mock API on http://${process.env.HOST || '127.0.0.1'}:${port}`);
  console.log(`  history=${o.history} backend=${o.backend} warnings=[${o.warnings.join(',')}] notReady=${o.notReady}`);
  console.log('  sign in: admin / eggmail (all tenants)  or  tenant / eggmail (Acme Corp)');
}
