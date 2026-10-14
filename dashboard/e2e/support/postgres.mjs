import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

// A PostgreSQL server for the storage-switch tests, found like the .NET tests find theirs:
//   1. EGGMAIL_TEST_POSTGRES, a connection string to an existing server (CI provides one). Only databases named eggmail_e2e_* are
//      ever created or dropped.
//   2. A throwaway cluster from locally installed binaries (initdb, postgres, psql): temp directory, random loopback port, trust
//      authentication, fsync off. It is stopped by its own process id when the run ends.
//   3. Neither: provisionPostgres() returns null and the tests that need it are skipped, with the reason.

const BIN_CANDIDATES = [
  process.env.EGGMAIL_TEST_PG_BIN,
  '/opt/homebrew/opt/postgresql@18/bin',
  '/opt/homebrew/opt/postgresql@17/bin',
  '/opt/homebrew/opt/postgresql@16/bin',
  '/usr/local/opt/postgresql@18/bin',
  '/usr/local/opt/postgresql@17/bin',
  '/usr/local/opt/postgresql@16/bin',
  ...(fs.existsSync('/usr/lib/postgresql') ? fs.readdirSync('/usr/lib/postgresql').sort().reverse().map((v) => `/usr/lib/postgresql/${v}/bin`) : []),
  ...(process.env.PATH ?? '').split(path.delimiter),
].filter(Boolean);

const findBinary = (name) => BIN_CANDIDATES.map((d) => path.join(d, name)).find((p) => fs.existsSync(p));

function parseConnectionString(text) {
  const parts = Object.fromEntries(
    text.split(';').filter(Boolean).map((kv) => {
      const i = kv.indexOf('=');
      return [kv.slice(0, i).trim().toLowerCase(), kv.slice(i + 1).trim()];
    }),
  );
  return { host: parts.host ?? 'localhost', port: parts.port ?? '5432', user: parts.username ?? parts['user id'] ?? 'postgres', password: parts.password ?? '', database: parts.database ?? 'postgres' };
}

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

/** @returns {Promise<{ description: string, createDatabase: () => string, dropDatabases: () => void, stop: () => Promise<void> } | null>} */
export async function provisionPostgres() {
  const psql = findBinary('psql');
  if (!psql) return null;
  let admin;
  let cluster = null;

  const external = process.env.EGGMAIL_TEST_POSTGRES;
  if (external) {
    admin = parseConnectionString(external);
  } else {
    const initdb = findBinary('initdb');
    const postgres = findBinary('postgres');
    if (!initdb || !postgres) return null;
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'eggmail-e2e-pg-'));
    const data = path.join(root, 'data');
    const init = spawnSync(initdb, ['-D', data, '-U', 'postgres', '-A', 'trust', '--no-sync', '-E', 'UTF8', '--no-locale'], { encoding: 'utf8' });
    if (init.status !== 0) throw new Error(`initdb failed: ${init.stderr}`);
    const port = await freePort();
    const child = spawn(postgres, ['-D', data, '-p', String(port), '-c', 'listen_addresses=127.0.0.1', '-c', 'unix_socket_directories=', '-c', 'fsync=off', '-c', 'synchronous_commit=off',
      '-c', 'full_page_writes=off', '-c', 'max_connections=200'], { stdio: ['ignore', 'ignore', 'ignore'] });
    cluster = { root, child };
    admin = { host: '127.0.0.1', port: String(port), user: 'postgres', password: '', database: 'postgres' };
    const deadline = Date.now() + 60_000;
    for (;;) {
      const ready = spawnSync(psql, ['-h', admin.host, '-p', admin.port, '-U', admin.user, '-d', 'postgres', '-Atc', 'select 1'], { encoding: 'utf8' });
      if (ready.status === 0) break;
      if (child.exitCode !== null) throw new Error('the throwaway PostgreSQL exited during start-up');
      if (Date.now() > deadline) throw new Error('the throwaway PostgreSQL did not become ready');
      await new Promise((r) => setTimeout(r, 200));
    }
  }

  const sql = (statement, database = admin.database) => {
    const result = spawnSync(psql, ['-h', admin.host, '-p', admin.port, '-U', admin.user, '-d', database, '-v', 'ON_ERROR_STOP=1', '-Atc', statement],
      { encoding: 'utf8', env: { ...process.env, PGPASSWORD: admin.password } });
    if (result.status !== 0) throw new Error(`psql failed: ${result.stderr}`);
    return result.stdout;
  };
  const created = [];
  return {
    description: external ? 'the server from EGGMAIL_TEST_POSTGRES' : 'a throwaway local cluster',
    /** Creates an empty database and returns its Npgsql connection string. */
    createDatabase() {
      const name = `eggmail_e2e_${Math.random().toString(36).slice(2, 12)}`;
      sql(`CREATE DATABASE ${name}`);
      created.push(name);
      return `Host=${admin.host};Port=${admin.port};Username=${admin.user};Password=${admin.password};Database=${name};Pooling=true;Maximum Pool Size=8`;
    },
    dropDatabases() {
      for (const name of created.splice(0)) {
        if (!name.startsWith('eggmail_e2e_')) continue;
        try { sql(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`); } catch { /* the cluster is deleted at exit anyway */ }
      }
    },
    async stop() {
      this.dropDatabases();
      if (cluster) {
        cluster.child.kill('SIGTERM');
        await new Promise((resolve) => {
          if (cluster.child.exitCode !== null) return resolve();
          const timer = setTimeout(() => { cluster.child.kill('SIGKILL'); resolve(); }, 15_000);
          cluster.child.once('exit', () => { clearTimeout(timer); resolve(); });
        });
        fs.rmSync(cluster.root, { recursive: true, force: true });
      }
    },
  };
}
