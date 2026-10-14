import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { publishApp } from './support/stack.mjs';

// Publishes the host once for the whole run (instead of once per worker process, and again on every retry) and puts the dashboard
// build into its wwwroot. Workers inherit EGGMAIL_E2E_APP_DIR. A directory given from outside is used as it is and never deleted.
export default async function globalSetup() {
  if (process.env.EGGMAIL_E2E_APP_DIR) {
    publishApp(); // only refreshes wwwroot
    return undefined;
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eggmail-e2e-app-'));
  process.env.EGGMAIL_E2E_APP_DIR = dir;
  publishApp(true);
  return async () => {
    fs.rmSync(dir, { recursive: true, force: true });
  };
}
