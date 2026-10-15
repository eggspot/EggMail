import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { startFakeDns } from './fakeDns.mjs';
import { startSmtpSink } from './sinks.mjs';

/** `count` distinct free loopback TCP ports, all held open until every number is known (asking for one at a time can hand the same port out twice). */
async function freePorts(count) {
  const servers = [];
  try {
    for (let i = 0; i < count; i++) {
      const server = net.createServer();
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', resolve);
      });
      servers.push(server);
    }
    return servers.map((server) => server.address().port);
  } finally {
    await Promise.all(servers.map((server) => new Promise((resolve) => server.close(resolve))));
  }
}

export const NOTICE_BEGIN = '==================== EGGMAIL FIRST START: DASHBOARD ADMINISTRATOR ====================';
export const NOTICE_END = '==================== END OF THE ONE-TIME PASSWORD (it is never shown again) ====================';

/**
 * The environment of a start with NOTHING configured: the process environment minus every variable that would configure EggMail. What a test adds on
 * top is the EGGMAIL_* variables under test and the three kinds of settings a shared test machine cannot do without, each listed in `harness`:
 * a data directory in a temp folder (the image has /data), free ports (the image has fixed container ports) and loopback binding.
 */
function cleanEnvironment() {
  // Docker and Kubernetes set HOSTNAME (the container id or pod name) in every container. Configuration keys are not case sensitive, so it is the key
  // "Hostname": the image always has it, and EGGMAIL_HOSTNAME has to beat it.
  const env = { ...process.env, DOTNET_NOLOGO: '1', DOTNET_CLI_TELEMETRY_OPTOUT: '1', HOSTNAME: os.hostname() };
  for (const name of Object.keys(env)) {
    if (/^(EGGMAIL_(?!E2E|TEST)|CLOUDFLARE_|MTA_|Hostname$)/.test(name) || name.includes('__')) delete env[name];
  }
  return env;
}

/**
 * Starts the published host (`mta serve`, exactly what the Docker image runs) with no configuration, plus the fakes it needs to deliver mail on a
 * test machine: a DNS server (the recipients' MX), an SMTP sink (the recipients' mail server).
 *
 * `variables` are EGGMAIL_* variables under test. The `harness` settings below are the ONLY other configuration, and they are not about EggMail's
 * behaviour: `Sqlite__DataDirectory` (a directory that does not exist yet: the first start must create it), the ports and loopback binding (so
 * parallel runs do not collide), and the lab settings that point outbound delivery at the fakes instead of the internet (`Dns__Servers__0`,
 * `Delivery__RemotePort`, `Delivery__AllowPrivateMxAddresses`). The Docker release smoke test (deploy/smoke/image.sh) uses the same assertions
 * against the published image with the same lab settings and nothing else.
 */
export async function startZeroConfigStack({ variables = {}, name = 'zero' } = {}) {
  const appDir = process.env.EGGMAIL_E2E_APP_DIR;
  if (!appDir) throw new Error('EGGMAIL_E2E_APP_DIR is not set: the Playwright global setup publishes the host.');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `eggmail-${name}-`));
  const dataDir = path.join(root, 'data'); // deliberately not created
  const dns = await startFakeDns();
  const sink = await startSmtpSink();
  const [httpPort, httpsPort, submission, submissions, alternate, bounce] = await freePorts(6);
  const ports = { http: httpPort, https: httpsPort, submission, submissions, alternate, bounce };

  const harness = {
    Sqlite__DataDirectory: dataDir,
    Dashboard__BindAddress: '127.0.0.1',
    Dashboard__HttpPort: String(httpPort),
    Dashboard__HttpsPort: String(httpsPort),
    Dns__Servers__0: dns.endpoint,
    Delivery__RemotePort: String(sink.port),
    Delivery__AllowPrivateMxAddresses: 'true',
  };
  for (const [listener, port] of Object.entries({ submission, submissions, alternate, bounce })) {
    harness[`Smtp__Listeners__${listener}__Port`] = String(port);
    harness[`Smtp__Listeners__${listener}__BindAddress`] = '127.0.0.1';
  }
  const env = { ...cleanEnvironment(), ...harness, ...variables };

  const logPath = path.join(root, 'server.log');
  const logFd = fs.openSync(logPath, 'a');
  let child = null;
  let exited = true;
  let runStartedAt = 0;
  const log = () => fs.readFileSync(logPath, 'utf8');

  const start = async () => {
    runStartedAt = fs.statSync(logPath).size;
    child = spawn('dotnet', [path.join(appDir, 'mta.dll')], { cwd: appDir, env, stdio: ['ignore', logFd, logFd] });
    exited = false;
    child.once('exit', () => { exited = true; });
    const deadline = Date.now() + 90_000;
    for (;;) {
      if (exited) throw new Error(`the server exited during start-up:\n${log()}`);
      try {
        if ((await fetch(`http://127.0.0.1:${httpPort}/readyz`)).ok) return;
      } catch { /* not listening yet */ }
      if (Date.now() > deadline) throw new Error(`the server did not become ready:\n${log()}`);
      await new Promise((r) => setTimeout(r, 200));
    }
  };
  const stop = async () => {
    if (exited) return;
    child.kill('SIGTERM');
    await new Promise((resolve) => {
      const timer = setTimeout(() => { child.kill('SIGKILL'); resolve(); }, 15_000);
      child.once('exit', () => { clearTimeout(timer); resolve(); });
    });
  };

  const cleanup = async () => {
    fs.closeSync(logFd);
    await Promise.all([dns.close(), sink.close()]);
    fs.rmSync(root, { recursive: true, force: true });
  };
  try {
    await start();
  } catch (error) {
    await stop();
    await cleanup();
    throw error;
  }
  return {
    root,
    dataDir,
    ports,
    dns,
    sink,
    baseURL: `http://127.0.0.1:${httpPort}`,
    httpsURL: `https://127.0.0.1:${httpsPort}`,
    log,
    /** The log of the current run only (everything written since the last (re)start). */
    currentRunLog: () => log().slice(runStartedAt),
    /** The password between the markers of the first-start notice, or null when the log has no notice. Throws when the notice is there more than once. */
    oneTimePassword() {
      const text = log();
      const blocks = text.split(NOTICE_BEGIN).slice(1).map((b) => b.split(NOTICE_END)[0]);
      if (blocks.length === 0) return null;
      if (blocks.length > 1) throw new Error(`the one-time password notice appears ${blocks.length} times`);
      return /^\s*password:\s+(\S+)\s*$/m.exec(blocks[0])?.[1] ?? null;
    },
    /** Runs `mta <args>` with the server's environment (for example `--healthcheck`) and returns its exit status and output. */
    cli(...args) {
      const result = spawnSync('dotnet', [path.join(appDir, 'mta.dll'), ...args], { cwd: appDir, env, encoding: 'utf8', timeout: 60_000 });
      return { status: result.status, output: (result.stdout ?? '') + (result.stderr ?? '') };
    },
    async restart() {
      await stop();
      await start();
    },
    async stop() {
      await stop();
      await cleanup();
    },
  };
}
