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

/** A free loopback TCP port (bind to 0 and release it; good enough on a test machine). */
async function freePort() {
  return await new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
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
 * Publishes the host once per test run (`dotnet publish`, incremental when CI already built Release) and puts the production
 * dashboard build into its wwwroot, which is exactly what the Docker image contains.
 */
export function publishApp() {
  if (publishedAppDir) return publishedAppDir;
  const dist = path.join(dashboardDir, 'dist');
  if (!fs.existsSync(path.join(dist, 'index.html'))) throw new Error('dashboard/dist is missing: run `npm run build` first.');
  const appDir = process.env.EGGMAIL_E2E_APP_DIR ?? path.join(os.tmpdir(), `eggmail-e2e-app-${process.pid}`);
  if (!process.env.EGGMAIL_E2E_APP_DIR) {
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
 */
export async function startStack({ name = 'main' } = {}) {
  const appDir = publishApp();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `eggmail-e2e-${name}-`));
  const dataDir = path.join(root, 'data');
  fs.mkdirSync(dataDir, { recursive: true });
  const passwordFile = path.join(root, 'admin-password.txt');
  fs.writeFileSync(passwordFile, ADMIN_PASSWORD, { mode: 0o600 });

  const dns = await startFakeDns();
  const sink = await startSmtpSink();
  const webhooks = await startWebhookReceiver();
  const httpPort = await freePort();
  const smtpPorts = { submission: await freePort(), submissions: await freePort(), alternate: await freePort(), bounce: await freePort() };

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

  const env = { ...process.env, MTA_ADMIN_PASSWORD: '', DOTNET_NOLOGO: '1', DOTNET_CLI_TELEMETRY_OPTOUT: '1' };
  run('dotnet', [path.join(appDir, 'mta.dll'), 'admin', 'create', '--user', ADMIN_USER, '--role', 'admin', '--password-file', passwordFile, ...configArgs], { cwd: appDir, env });

  const logPath = path.join(root, 'server.log');
  const logFd = fs.openSync(logPath, 'a');
  const child = spawn('dotnet', [path.join(appDir, 'mta.dll'), 'serve', ...configArgs], { cwd: appDir, env, stdio: ['ignore', logFd, logFd] });
  let exited = false;
  child.once('exit', () => { exited = true; });

  const baseURL = `http://127.0.0.1:${httpPort}`;
  const deadline = Date.now() + 90_000;
  for (;;) {
    if (exited) throw new Error(`the server exited during start-up:\n${fs.readFileSync(logPath, 'utf8')}`);
    try {
      const response = await fetch(`${baseURL}/readyz`);
      if (response.ok) break;
    } catch { /* not listening yet */ }
    if (Date.now() > deadline) throw new Error(`the server did not become ready:\n${fs.readFileSync(logPath, 'utf8')}`);
    await new Promise((r) => setTimeout(r, 200));
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
    async stop() {
      if (!exited) {
        child.kill('SIGTERM');
        await new Promise((resolve) => {
          const timer = setTimeout(() => { child.kill('SIGKILL'); resolve(); }, 15_000);
          child.once('exit', () => { clearTimeout(timer); resolve(); });
        });
      }
      fs.closeSync(logFd);
      await Promise.all([dns.close(), sink.close(), webhooks.close()]);
      fs.rmSync(root, { recursive: true, force: true });
    },
  };
}
