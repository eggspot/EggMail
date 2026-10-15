import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startFakeDns } from './fakeDns.mjs';
import { startSmtpSink, startWebhookReceiver } from './sinks.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
export const dashboardDir = path.resolve(here, '..', '..');
const repoRoot = path.resolve(dashboardDir, '..');

export const ADMIN_USER = 'e2e-admin';
export const ADMIN_PASSWORD = 'e2e-correct-horse-battery-staple';

/**
 * `count` distinct free loopback TCP ports. All the sockets are held open until every port is known: asking for one port at a time
 * (bind to 0, release, repeat) can hand the same number out twice, and the server then refuses to start with "Listeners 'submission'
 * and 'bounce' use the same port" (seen in CI).
 */
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

function run(command, args, options) {
  const result = spawnSync(command, args, { encoding: 'utf8', ...options });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed (${result.status}):\n${result.stdout}\n${result.stderr}`);
  }
  return result.stdout;
}

let publishedAppDir;
/**
 * The published host with the production dashboard build in its wwwroot, which is exactly what the Docker image contains.
 * `global-setup.mjs` calls it once per run with `EGGMAIL_E2E_APP_DIR` pointing at an empty directory (`publish` true runs `dotnet
 * publish`, incremental when CI already built Release). With an existing directory only wwwroot is refreshed.
 */
export function publishApp(publish = false) {
  if (publishedAppDir) return publishedAppDir;
  const dist = path.join(dashboardDir, 'dist');
  if (!fs.existsSync(path.join(dist, 'index.html'))) throw new Error('dashboard/dist is missing: run `npm run build` first.');
  const appDir = process.env.EGGMAIL_E2E_APP_DIR;
  if (!appDir) throw new Error('EGGMAIL_E2E_APP_DIR is not set: the Playwright global setup publishes the host.');
  if (publish) {
    run('dotnet', ['publish', path.join(repoRoot, 'src', 'Mta.Host', 'Mta.Host.csproj'), '-c', 'Release', '-o', appDir, '--nologo', '-v', 'q'], { cwd: repoRoot });
  }
  fs.rmSync(path.join(appDir, 'wwwroot'), { recursive: true, force: true });
  fs.cpSync(dist, path.join(appDir, 'wwwroot'), { recursive: true });
  publishedAppDir = appDir;
  return appDir;
}

/**
 * Starts a real EggMail server (`mta serve`, SQLite in a fresh temp directory, loopback ports, an administrator made with
 * `mta admin create`) together with the fakes it talks to: a DNS server (the domain checks and the recipients' MX), an SMTP sink
 * (the recipients' mail server) and a webhook receiver.
 *
 * `switchConnections` ({ name: npgsqlConnectionString }) become `SwitchTarget:Connections:<name>`, the PostgreSQL targets the storage
 * switch can reach.
 *
 * `tenantUsers` ([{ user, password, tenantName }]) are dashboard accounts of role `tenant`. `mta admin create` needs the tenant to
 * exist and the SQLite data directory to be free, so the server is started once to create the tenants through the API, stopped,
 * given the accounts, and started again.
 */
export async function startStack({ name = 'main', tenantUsers = [], switchConnections = {}, extraArgs = [] } = {}) {
  const appDir = process.env.EGGMAIL_E2E_APP_DIR;
  if (!appDir) throw new Error('EGGMAIL_E2E_APP_DIR is not set: the Playwright global setup publishes the host.');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `eggmail-e2e-${name}-`));
  const dataDir = path.join(root, 'data');
  fs.mkdirSync(dataDir, { recursive: true });
  const passwordFile = path.join(root, 'admin-password.txt');
  fs.writeFileSync(passwordFile, ADMIN_PASSWORD, { mode: 0o600 });

  const dns = await startFakeDns();
  const sink = await startSmtpSink();
  const webhooks = await startWebhookReceiver();
  const [httpPort, submission, submissions, alternate, bounce] = await freePorts(5);
  const smtpPorts = { submission, submissions, alternate, bounce };

  const configArgs = [
    `--Sqlite:DataDirectory=${dataDir}`,
    '--Hostname=mta.eggmail.test',
    '--Dashboard:BindAddress=127.0.0.1',
    `--Dashboard:HttpPort=${httpPort}`,
    '--Dashboard:HttpsEnabled=false',
    `--Dns:Servers:0=${dns.endpoint}`,
    '--Delivery:BounceDomain=bounces.eggmail.test',
    `--Delivery:RemotePort=${sink.port}`,
    '--Delivery:AllowPrivateMxAddresses=true',
    '--Webhooks:AllowHttp=true',
    '--Backup:Enabled=false',
    '--Observability:MetricsEndpointEnabled=false',
    '--Tls:ReportingEnabled=false',
  ];
  for (const [listener, port] of Object.entries(smtpPorts)) {
    configArgs.push(`--Smtp:Listeners:${listener}:Port=${port}`, `--Smtp:Listeners:${listener}:BindAddress=127.0.0.1`);
  }
  configArgs.push('--Smtp:Listeners:submissions:Enabled=false', '--Smtp:Listeners:alternate:Enabled=false');
  configArgs.push(...extraArgs);
  for (const [connectionName, connectionString] of Object.entries(switchConnections)) configArgs.push(`--SwitchTarget:Connections:${connectionName}=${connectionString}`);

  const env = { ...process.env, MTA_ADMIN_PASSWORD: '', DOTNET_NOLOGO: '1', DOTNET_CLI_TELEMETRY_OPTOUT: '1' };
  const cli = (...args) => run('dotnet', [path.join(appDir, 'mta.dll'), ...args, ...configArgs], { cwd: appDir, env });
  const baseURL = `http://127.0.0.1:${httpPort}`;
  const logPath = path.join(root, 'server.log');
  const logFd = fs.openSync(logPath, 'a');

  let child = null;
  let exited = true;
  const startServer = async () => {
    child = spawn('dotnet', [path.join(appDir, 'mta.dll'), 'serve', ...configArgs], { cwd: appDir, env, stdio: ['ignore', logFd, logFd] });
    exited = false;
    child.once('exit', () => { exited = true; });
    const deadline = Date.now() + 90_000;
    for (;;) {
      if (exited) throw new Error(`the server exited during start-up:\n${fs.readFileSync(logPath, 'utf8')}`);
      try {
        const response = await fetch(`${baseURL}/readyz`);
        if (response.ok) return;
      } catch { /* not listening yet */ }
      if (Date.now() > deadline) throw new Error(`the server did not become ready:\n${fs.readFileSync(logPath, 'utf8')}`);
      await new Promise((r) => setTimeout(r, 200));
    }
  };
  const stopServer = async () => {
    if (exited) return;
    child.kill('SIGTERM');
    await new Promise((resolve) => {
      const timer = setTimeout(() => { child.kill('SIGKILL'); resolve(); }, 15_000);
      child.once('exit', () => { clearTimeout(timer); resolve(); });
    });
  };

  cli('admin', 'create', '--user', ADMIN_USER, '--role', 'admin', '--password-file', passwordFile);
  await startServer();

  if (tenantUsers.length > 0) {
    const { ApiClient } = await import('./apiClient.mjs');
    const api = await new ApiClient(baseURL).signIn(ADMIN_USER, ADMIN_PASSWORD);
    const slugs = [];
    for (const u of tenantUsers) slugs.push((await api.ok('POST', '/api/v1/admin/tenants', { name: u.tenantName })).slug);
    await stopServer();
    for (const [i, u] of tenantUsers.entries()) {
      const file = path.join(root, `password-${i}.txt`);
      fs.writeFileSync(file, u.password, { mode: 0o600 });
      cli('admin', 'create', '--user', u.user, '--role', 'tenant', '--tenant', slugs[i], '--password-file', file);
    }
    await startServer();
  }

  return {
    baseURL,
    httpPort,
    smtpPorts,
    root,
    dataDir,
    logPath,
    dns,
    sink,
    webhooks,
    log: () => fs.readFileSync(logPath, 'utf8'),
    /** Stops the server and starts it again with the same arguments: what an operator does after a switch wrote the bootstrap file. */
    async restart(...extraRestartArgs) {
      await stopServer();
      configArgs.push(...extraRestartArgs);
      await startServer();
    },
    /** Stops the server and starts it again with other storage settings: what an operator does after applying a cutover patch. */
    async restartWithStorage(...storageArgs) {
      await stopServer();
      for (let i = configArgs.length - 1; i >= 0; i--) {
        if (configArgs[i].startsWith('--Sqlite:DataDirectory=') || configArgs[i].startsWith('--Storage:')) configArgs.splice(i, 1);
      }
      configArgs.push(...storageArgs);
      await startServer();
    },
    async stop() {
      await stopServer();
      fs.closeSync(logFd);
      await Promise.all([dns.close(), sink.close(), webhooks.close()]);
      fs.rmSync(root, { recursive: true, force: true });
    },
  };
}
