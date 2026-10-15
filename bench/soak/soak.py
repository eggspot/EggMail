#!/usr/bin/env python3
"""Soak test of a REAL EggMail process (docs/soak.md).

Starts the published-layout host (`dotnet publish` output, `mta serve`) on SQLite or a PostgreSQL 17 server, a sink MX and a DNS stub on loopback,
provisions a tenant, a verified sending domain and an SMTP credential through the public API, then keeps the load generator (`mta-tools load
--persist`) submitting numbered mail for the requested time. While it runs it

  * samples the process every minute (RSS, file descriptors, threads, GC counts, queue depth, counters, disk, latency) into samples.csv,
  * kills the server with SIGKILL and restarts it every few minutes (crash drills),
  * takes a backup of the live store and restores it into a second, quiet instance (backup + restore drills).

After the load stops it waits for the queue to drain, reconciles every message the server acknowledged against what the sink received (lost?
duplicated? were the duplicates flagged possible_duplicate?), stops the server with SIGTERM, and evaluate.py decides PASS or FAIL.

  bench/soak/run-soak.sh --hours 2 --backend sqlite        (the wrapper publishes the host and the tools first)

Python 3 standard library only (3.9 or newer); runs on Linux and macOS.
"""
import argparse
import csv
import datetime
import json
import os
import platform
import random
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(REPO, "deploy", "smoke"))
sys.path.insert(0, HERE)

import evaluate  # noqa: E402
from sink import SoakSink  # noqa: E402
from smoke import DnsStub  # noqa: E402  (the DNS stub of the release smoke test: MX, A and TXT answers over UDP and TCP)

SENDER_DOMAIN = "soak-sender.test"
SENDER_USER = "soak-sender@" + SENDER_DOMAIN
ADMIN_USER = "soakadmin"
SINK_HOST = "sink.soak.test"
CSV_COLUMNS = [
    "iso", "ts", "elapsed_s", "generation", "uptime_s", "phase", "up", "rss_mb", "fds", "threads", "tp_threads", "gc_gen0", "gc_gen1", "gc_gen2",
    "gc_alloc_mb", "working_set_mb", "queue_depth", "queue_deferred", "smtp_accepted", "delivered", "sink_received", "sink_unique",
    "load_accepted", "load_rejected", "load_connect_errors", "lat_p50_ms", "lat_p95_ms", "lat_p99_ms", "disk_mb",
]


def now():
    return time.time()


def iso(ts=None):
    return datetime.datetime.fromtimestamp(ts or now(), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(message):
    print("[soak %s] %s" % (time.strftime("%H:%M:%S"), message), flush=True)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class SoakError(Exception):
    pass


# --------------------------------------------------------------------------- HTTP API

class Api:
    """The few API calls the harness needs. Unlike deploy/smoke/smoke.py it raises instead of exiting."""

    def __init__(self, base, user, password):
        self.base = base.rstrip("/")
        self.user = user
        self.password = password
        self.cookie = None
        self.csrf = None
        self.tenant = None

    def raw(self, method, path, body=None, headers=None, timeout=15):
        request = urllib.request.Request(self.base + path, data=json.dumps(body).encode() if body is not None else None, method=method)
        if body is not None:
            request.add_header("Content-Type", "application/json")
        if self.cookie:
            request.add_header("Cookie", self.cookie)
        if self.csrf and method not in ("GET", "HEAD"):
            request.add_header("X-CSRF-Token", self.csrf)
        if self.tenant:
            request.add_header("X-Tenant-Id", self.tenant)
        for key, value in (headers or {}).items():
            request.add_header(key, value)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, response.read(), response.headers
        except urllib.error.HTTPError as error:
            return error.code, error.read(), error.headers

    def login(self):
        self.cookie = self.csrf = None
        status, raw, headers = self.raw("POST", "/api/v1/session", {"user": self.user, "password": self.password})
        if status not in (200, 201):
            raise SoakError("sign-in failed: HTTP %d %s" % (status, raw[:200]))
        cookies = headers.get_all("Set-Cookie") or []
        self.cookie = next((c.split(";", 1)[0] for c in cookies if c.startswith("eggmail_session=")), None)
        status, raw, _ = self.raw("GET", "/api/v1/me")
        self.csrf = json.loads(raw)["csrfToken"]

    def call(self, method, path, body=None, expect=(200, 201, 202, 204), timeout=15):
        for attempt in (1, 2):
            if self.cookie is None:
                self.login()
            status, raw, headers = self.raw(method, path, body, timeout=timeout)
            if status == 401 and attempt == 1:
                self.cookie = None
                continue
            if status not in expect:
                raise SoakError("%s %s -> HTTP %d: %s" % (method, path, status, raw[:300].decode("utf-8", "replace")))
            return status, (json.loads(raw) if raw else None)
        raise SoakError("unreachable")


def http_ok(url, timeout=3):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.status == 200
    except (urllib.error.URLError, OSError, ValueError):
        return False


METRIC_LINE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+(\S+)\s*$")


def parse_metrics(text):
    """name -> list of (labels dict, value)."""
    metrics = {}
    for line in text.splitlines():
        if not line or line[0] == "#":
            continue
        m = METRIC_LINE.match(line)
        if not m:
            continue
        labels = dict(re.findall(r'(\w+)="([^"]*)"', m.group(2) or ""))
        try:
            metrics.setdefault(m.group(1), []).append((labels, float(m.group(3))))
        except ValueError:
            pass
    return metrics


def metric_sum(metrics, name, **labels):
    values = [v for l, v in metrics.get(name, []) if all(l.get(k) == want for k, want in labels.items())]
    return sum(values) if values else None


# --------------------------------------------------------------------------- operating system view of a process

def run_text(argv, timeout=10):
    try:
        return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout, universal_newlines=True).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def process_stats(pid):
    """(rss MB, open file descriptors, threads) of a process; None where this system cannot say."""
    rss = fds = threads = None
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/%d/status" % pid) as handle:
                for line in handle:
                    if line.startswith("VmRSS:"):
                        rss = int(line.split()[1]) / 1024.0
                    elif line.startswith("Threads:"):
                        threads = int(line.split()[1])
            fds = len(os.listdir("/proc/%d/fd" % pid))
        except OSError:
            pass
    else:
        out = run_text(["ps", "-o", "rss=", "-p", str(pid)]).strip()
        if out.isdigit():
            rss = int(out) / 1024.0
        out = run_text(["ps", "-M", "-p", str(pid)])
        if out:
            threads = max(0, len(out.strip().splitlines()) - 1)
        # -a: lsof ORs its selections by default (this process OR any numeric descriptor, which lists the whole machine)
        out = run_text(["lsof", "-a", "-n", "-P", "-p", str(pid), "-d", "0-65535", "-F", "f"])
        if out:
            fds = sum(1 for line in out.splitlines() if line.startswith("f"))
    return rss, fds, threads


def directory_mb(path, skip=()):
    total = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in skip]
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
    return total / 1048576.0


# --------------------------------------------------------------------------- PostgreSQL

class Postgres:
    """A PostgreSQL server for the soak: a postgres:17 container (Actions) or a throwaway cluster from the binaries on PATH (a laptop)."""

    def __init__(self, mode, workdir, port):
        self.mode = mode
        self.port = port
        self.workdir = workdir
        self.user = "eggmail"
        self.password = "eggmail"
        self.database = "eggmail_soak"
        self.container = "eggmail-soak-pg-%d" % os.getpid()
        self.exec_prefix = []
        self.host = "127.0.0.1"

    def start(self):
        if self.mode == "docker":
            run = subprocess.run(["docker", "run", "-d", "--name", self.container, "-p", "127.0.0.1:%d:5432" % self.port,
                                  "-e", "POSTGRES_USER=eggmail", "-e", "POSTGRES_PASSWORD=eggmail", "-e", "POSTGRES_DB=" + self.database,
                                  "postgres:17", "-c", "max_connections=200"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
            if run.returncode != 0:
                raise SoakError("docker run postgres:17 failed: " + run.stdout)
            self.exec_prefix = ["docker", "exec", "-i", self.container]
        elif self.mode == "local":
            data = os.path.join(self.workdir, "pgdata")
            subprocess.run(["initdb", "-D", data, "-U", self.user, "--auth=trust", "-E", "UTF8", "--locale=C"], check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["pg_ctl", "-D", data, "-w", "-l", os.path.join(self.workdir, "postgres.log"), "-o",
                            "-p %d -c listen_addresses=127.0.0.1 -c unix_socket_directories= -c max_connections=200" % self.port, "start"], check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["createdb", "-h", "127.0.0.1", "-p", str(self.port), "-U", self.user, self.database], check=True)
        # The container's entrypoint starts a temporary server to create the database and then restarts it: a first answer is not yet "ready".
        steady = 0
        for _ in range(90):
            steady = steady + 1 if self.psql("select 1", db="postgres", check=False) == "1" else 0
            if steady >= (4 if self.mode == "docker" else 1):
                break
            time.sleep(1)
        else:
            raise SoakError("PostgreSQL did not become ready")
        if self.psql("select 1", db=self.database, check=False) != "1":
            self.psql("create database %s" % self.database, db="postgres")
        version = self.psql("show server_version", db="postgres")
        log("PostgreSQL %s (%s) ready on port %d" % (version, self.mode, self.port))
        return version

    def _argv(self, tool, args):
        if self.exec_prefix:
            return self.exec_prefix + [tool, "-U", self.user] + args
        return [tool, "-h", self.host, "-p", str(self.port), "-U", self.user] + args

    def psql(self, sql, db=None, check=True):
        env = dict(os.environ, PGPASSWORD=self.password)
        run = subprocess.run(self._argv("psql", ["-d", db or self.database, "-At", "-v", "ON_ERROR_STOP=1", "-c", sql]), env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        if run.returncode != 0:
            if check:
                raise SoakError("psql failed: %s %s" % (sql, run.stderr.strip()))
            return None
        return run.stdout.strip()

    def dump(self, path):
        env = dict(os.environ, PGPASSWORD=self.password)
        with open(path, "wb") as handle:
            run = subprocess.run(self._argv("pg_dump", ["-Fc", "-d", self.database]), env=env, stdout=handle, stderr=subprocess.PIPE)
        if run.returncode != 0:
            raise SoakError("pg_dump failed: " + run.stderr.decode("utf-8", "replace")[:300])

    def restore(self, path, database):
        self.psql("create database %s" % database, db="postgres")
        env = dict(os.environ, PGPASSWORD=self.password)
        with open(path, "rb") as handle:
            run = subprocess.run(self._argv("pg_restore", ["-d", database, "--no-owner"]), env=env, stdin=handle, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if run.returncode not in (0, 1):      # 1 = warnings only (for example a role that does not exist)
            raise SoakError("pg_restore failed: " + run.stderr.decode("utf-8", "replace")[:300])

    def database_mb(self):
        value = self.psql("select pg_database_size('%s')" % self.database, check=False)
        return int(value) / 1048576.0 if value and value.isdigit() else None

    def connection_string(self, database=None, options=""):
        return "Host=%s;Port=%d;Username=%s;Password=%s;Database=%s;Maximum Pool Size=64%s" % (
            self.host, self.port, self.user, self.password, database or self.database, (";Options='%s'" % options) if options else "")

    def stop(self):
        if self.mode == "docker":
            subprocess.run(["docker", "rm", "-f", self.container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif self.mode == "local":
            subprocess.run(["pg_ctl", "-D", os.path.join(self.workdir, "pgdata"), "-m", "fast", "stop"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# --------------------------------------------------------------------------- the run

class Soak:
    def __init__(self, args):
        self.args = args
        self.out = os.path.abspath(args.out)
        os.makedirs(self.out, exist_ok=True)
        self.start_ts = now()
        self.duration_s = args.hours * 3600.0
        self.tail_start_s = self.duration_s * (1.0 - args.quiet_tail)
        self.events_lock = threading.Lock()
        self.state_lock = threading.RLock()
        self.stopping = threading.Event()
        self.phase = "setup"
        self.host = None                # subprocess.Popen of the server under test
        self.generation = 0
        self.host_started = 0.0
        self.drill_busy = False
        self.pg = None
        self.dns = None
        self.sink = None
        self.api = None
        self.loader = None
        self.password = secrets.token_urlsafe(18)
        self.smtp_password = None
        self.rand = random.Random(args.seed)
        self.stats_pos = 0
        self.stats_pending = []         # load-stats lines since the last sample
        self.last_stats = None
        self.unexpected_exits = 0
        self.backup_done = set()
        self.backup_count = 0
        self.pending_checks = []        # (due time, bytes of ack.log at the kill) of crash drills whose recovery check has not run yet
        self.ports = {name: free_port() for name in ("submission", "submissions", "alternate", "bounce", "http", "https", "dns", "sink", "pg")}
        self.data_dir = os.path.join(self.out, "data")
        self.host_log = open(os.path.join(self.out, "host.log"), "ab", buffering=0)
        self.csv_handle = open(os.path.join(self.out, "samples.csv"), "w", newline="")
        self.csv = csv.DictWriter(self.csv_handle, fieldnames=CSV_COLUMNS)
        self.csv.writeheader()
        self.csv_handle.flush()

    # -- bookkeeping

    def elapsed(self):
        return now() - self.start_ts

    def event(self, type_, **fields):
        record = dict(type=type_, ts=round(now(), 3), iso=iso(), elapsed_s=round(self.elapsed(), 1))
        record.update(fields)
        with self.events_lock:
            with open(os.path.join(self.out, "events.jsonl"), "a") as handle:
                handle.write(json.dumps(record) + "\n")
        log("%s %s" % (type_, json.dumps(fields) if fields else ""))

    # -- configuration of the server under test

    def host_env(self, data_dir, ports, database=None, quiet=False):
        a = self.args
        env = dict(os.environ)
        for key in [k for k in env if k.startswith(("Sqlite__", "Storage__", "Smtp__", "Dashboard__", "Delivery__", "Dns__", "History__", "Backup__"))]:
            del env[key]
        env.update({
            "Hostname": "soak.local",
            "Sqlite__DataDirectory": data_dir,
            "History__Mode": "Full" if a.history == "full" else "StatsOnly",
            "Dashboard__BindAddress": "127.0.0.1",
            "Dashboard__HttpPort": str(ports["http"]),
            "Dashboard__HttpsPort": str(ports["https"]),
            "Dashboard__BootstrapAdminUser": ADMIN_USER,
            "Dashboard__BootstrapAdminPasswordFile": os.path.join(self.out, "admin-password.txt"),
            "Observability__QueueSampleSeconds": "5",
            "DOTNET_gcServer": "0",
        })
        for name in ("submission", "submissions", "alternate", "bounce"):
            env["Smtp__Listeners__%s__Port" % name] = str(ports[name])
            env["Smtp__Listeners__%s__BindAddress" % name] = "127.0.0.1"
        if quiet:
            # The restored copy must not send anything: its resolver does not exist, so every delivery attempt defers.
            env.update({"Dns__Servers__0": "127.0.0.1:1", "Delivery__RemotePort": "1", "Backup__Enabled": "false"})
        else:
            env.update({
                "Dns__Servers__0": "127.0.0.1:%d" % self.ports["dns"],
                "Delivery__RemotePort": str(self.ports["sink"]),
                "Delivery__AllowPrivateMxAddresses": "true",
                # Lab destinations: the default ceilings (600 messages a minute to one domain) are a policy for the public internet.
                "Delivery__Throttle__MaxConnections": "40",
                "Delivery__Throttle__MaxMessagesPerMinute": "100000",
                "Delivery__Throttle__InitialConnections": "20",
                "Delivery__Throttle__InitialMessagesPerMinute": "100000",
                "Delivery__Throttle__MaxMessagesPerConnection": "1000",
            })
            if a.claim_lease_min:
                env["Delivery__ClaimLease"] = "00:%02d:00" % a.claim_lease_min if a.claim_lease_min < 60 else "%02d:00:00" % (a.claim_lease_min // 60)
        if a.backend == "sqlite":
            env["Storage__Backend"] = "Sqlite"
            env["Sqlite__SyncMode"] = {"off": "Off", "normal": "Normal", "full": "Full"}[a.sync]
            if not quiet:
                env["Backup__Enabled"] = "true" if a.backup_interval_min > 0 else "false"
                # Due soon after every check: the scheduler looks every ten minutes, and a backup is taken when the newest is older than this.
                env["Backup__IntervalHours"] = str(max(0.005, a.backup_interval_min / 60.0 / 2.0))
                env["Backup__Keep"] = "3"
        else:
            options = "-c synchronous_commit=off" if a.sync == "off" else ""
            conn = self.pg.connection_string(database, options)
            env["Storage__Backend"] = "Postgres"
            env["Storage__Postgres__RuntimeConnectionString"] = conn
            env["Storage__Postgres__OwnerConnectionString"] = conn
        if a.extra_env:
            for pair in a.extra_env:
                key, _, value = pair.partition("=")
                env[key] = value
        return env

    # -- the server process

    def start_host(self, timeout=180):
        with self.state_lock:
            self.host = subprocess.Popen(self.host_argv("serve"), env=self.host_env(self.data_dir, self.ports, None), stdout=self.host_log, stderr=subprocess.STDOUT,
                                         stdin=subprocess.DEVNULL, start_new_session=True)
            self.generation += 1
            self.host_started = now()
        started = now()
        base = "http://127.0.0.1:%d" % self.ports["http"]
        while now() - started < timeout:
            if self.host.poll() is not None:
                raise SoakError("the server exited with code %s while starting (see host.log)" % self.host.returncode)
            if http_ok(base + "/readyz") and self.port_open(self.ports["submission"]):
                return now() - started
            time.sleep(0.25)
        raise SoakError("the server was not ready after %d s" % timeout)

    @staticmethod
    def port_open(port):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            return False

    def stop_host(self, kill=False, timeout=90):
        """SIGKILL (crash) or SIGTERM (graceful). Returns (exit code, seconds)."""
        proc = self.host
        started = now()
        os.kill(proc.pid, signal.SIGKILL if kill else signal.SIGTERM)
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.kill(proc.pid, signal.SIGKILL)
            code = proc.wait()
            code = "killed after %d s without exiting" % timeout
        return code, round(now() - started, 2)

    # -- provisioning through the public API

    def provision(self):
        a = self.args
        self.api = Api("http://127.0.0.1:%d" % self.ports["http"], ADMIN_USER, self.password)
        self.api.login()
        _, tenant = self.api.call("POST", "/api/v1/admin/tenants", {"name": "Soak"})
        self.api.tenant = tenant["id"]
        _, domain = self.api.call("POST", "/api/v1/domains", {"name": SENDER_DOMAIN})
        for record in domain["records"]:
            if record["type"] == "TXT":
                self.dns.add_txt(record["host"], record["expected"])

        deadline = now() + 180
        while now() < deadline:
            status, found = self.api.call("POST", "/api/v1/domains/%s/verify" % domain["id"], expect=(200, 429))
            if status == 200 and found["status"] == "verified":
                break
            time.sleep(5 if status == 429 else 2)
        else:
            raise SoakError("the sending domain did not verify")
        _, credential = self.api.call("POST", "/api/v1/smtp-credentials", {"username": SENDER_USER})
        self.smtp_password = credential["password"]
        self.event("provisioned", tenant=self.api.tenant, domain=SENDER_DOMAIN)

    # -- the load generator

    def start_load(self):
        a = self.args
        domains = ",".join("r%d.soak.test" % (i + 1) for i in range(a.recipient_domains))
        argv = ["dotnet", a.tools_dll, "load", "--port", str(self.ports["submission"]), "--starttls", "--auth", "%s:%s" % (SENDER_USER, self.smtp_password),
                "--from", SENDER_USER, "--rcpt-domain", domains, "--connections", str(a.connections), "--rate", str(a.rate), "--size-mix", a.size_mix,
                "--duration-s", str(int(self.duration_s)), "--persist", "--io-timeout-s", "60", "--id-prefix", "soak",
                "--ack-log", os.path.join(self.out, "ack.log"), "--stats-jsonl", os.path.join(self.out, "load-stats.jsonl"), "--stats-interval-s", "10",
                "--json", os.path.join(self.out, "load-result.json"), "--label", "soak"]
        self.load_log = open(os.path.join(self.out, "load.log"), "ab", buffering=0)
        self.loader = subprocess.Popen(argv, stdout=self.load_log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
        self.phase = "load"
        self.event("load_start", pid=self.loader.pid, rate=a.rate, size_mix=a.size_mix, connections=a.connections)

    # -- sampling

    def read_new_stats(self):
        path = os.path.join(self.out, "load-stats.jsonl")
        try:
            with open(path, "rb") as handle:
                handle.seek(self.stats_pos)
                data = handle.read()
        except OSError:
            return
        complete = data.rfind(b"\n") + 1
        self.stats_pos += complete
        for line in data[:complete].decode("utf-8", "replace").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            self.stats_pending.append(row)
            self.last_stats = row

    def metrics(self):
        try:
            with urllib.request.urlopen("http://127.0.0.1:%d/metrics" % self.ports["http"], timeout=5) as response:
                return parse_metrics(response.read().decode("utf-8", "replace"))
        except (urllib.error.URLError, OSError, ValueError):
            return {}

    def sample(self):
        with self.state_lock:
            proc = self.host
            generation = self.generation
            started = self.host_started
        row = {c: "" for c in CSV_COLUMNS}
        t = now()
        row.update(iso=iso(t), ts=round(t, 3), elapsed_s=round(t - self.start_ts, 1), generation=generation, uptime_s=round(t - started, 1), phase=self.phase)
        alive = proc is not None and proc.poll() is None
        row["up"] = 1 if alive else 0
        if alive:
            rss, fds, threads = process_stats(proc.pid)
            row.update(rss_mb=_r(rss), fds=fds, threads=threads)
            m = self.metrics()
            if m:
                gens = {l.get("gc_heap_generation"): v for l, v in m.get("dotnet_gc_collections_total", [])}
                row.update(gc_gen0=gens.get("gen0"), gc_gen1=gens.get("gen1"), gc_gen2=gens.get("gen2"))
                alloc = metric_sum(m, "dotnet_gc_heap_total_allocated_bytes_total")
                row["gc_alloc_mb"] = _r(alloc / 1048576.0) if alloc is not None else ""
                working = metric_sum(m, "dotnet_process_memory_working_set_bytes")
                row["working_set_mb"] = _r(working / 1048576.0) if working is not None else ""
                row["tp_threads"] = _i(metric_sum(m, "dotnet_thread_pool_thread_count_total"))
                row["smtp_accepted"] = _i(metric_sum(m, "mta_smtp_server_messages_total"))
                row["delivered"] = _i(metric_sum(m, "mta_delivery_attempts_total", outcome="delivered"))
                depths = [metric_sum(m, "mta_delivery_queue_depth", state=s) for s in ("queued", "deferred", "leased")]
                row["queue_depth"] = _i(sum(d for d in depths if d is not None)) if any(d is not None for d in depths) else ""
                row["queue_deferred"] = _i(depths[1])
        if self.sink is not None:
            row["sink_received"] = self.sink.total_received
            row["sink_unique"] = self.sink.unique_received()
        self.read_new_stats()
        pending, self.stats_pending = self.stats_pending, []
        if self.last_stats:
            row.update(load_accepted=self.last_stats["accepted"], load_rejected=self.last_stats["rejected"], load_connect_errors=self.last_stats["connect_errors"])
        if pending:
            busy = [p for p in pending if p.get("interval_accepted", 0) > 0]
            if busy:
                row["lat_p50_ms"] = _r(sum(p["p50_ms"] for p in busy) / len(busy))
                row["lat_p95_ms"] = _r(sum(p["p95_ms"] for p in busy) / len(busy))
                row["lat_p99_ms"] = _r(max(p["p99_ms"] for p in busy))
        try:
            if self.args.backend == "sqlite":
                row["disk_mb"] = _r(directory_mb(self.data_dir, skip=("backups", "quarantine")))
            else:
                row["disk_mb"] = _r(self.pg.database_mb())
        except Exception:
            pass
        self.csv.writerow(row)
        self.csv_handle.flush()

    def sampler(self):
        interval = self.args.sample_interval_s
        next_at = now()
        while not self.stopping.is_set():
            try:
                self.sample()
            except Exception as error:      # a failed sample is a gap in the CSV, never the end of the run
                log("sample failed: %r" % error)
            self.watch_host()
            next_at += interval
            self.stopping.wait(max(0.1, next_at - now()))

    def watch_host(self):
        """The server may only die when a drill kills it or the run stops it. Anything else is a finding; restart it so the run goes on."""
        with self.state_lock:
            proc = self.host
            busy = self.drill_busy
        if proc is None or busy or self.phase in ("done", "setup", "stopping") or proc.poll() is None:
            return
        self.unexpected_exits += 1
        self.event("host_unexpected_exit", exit_code=proc.returncode, generation=self.generation)
        try:
            with self.state_lock:
                self.drill_busy = True
            self.start_host()
        except SoakError as error:
            self.event("host_restart_failed", error=str(error))
        finally:
            with self.state_lock:
                self.drill_busy = False

    # -- drills

    def acked_sequences(self, upto_bytes=None):
        sequences = []
        try:
            with open(os.path.join(self.out, "ack.log"), "rb") as handle:
                data = handle.read(upto_bytes) if upto_bytes is not None else handle.read()
        except OSError:
            return sequences
        data = data[:data.rfind(b"\n") + 1]
        for line in data.decode("ascii", "replace").splitlines():
            head = line.split("\t", 1)[0]
            if head.isdigit():
                sequences.append(int(head))
        return sequences

    def crash_drill(self):
        a = self.args
        with self.state_lock:
            self.drill_busy = True
        try:
            try:
                ack_size = os.path.getsize(os.path.join(self.out, "ack.log"))
            except OSError:
                ack_size = 0
            self.event("crash_kill", pid=self.host.pid, generation=self.generation)
            self.stop_host(kill=True, timeout=30)
            killed = now()
            try:
                self.start_host(timeout=a.ready_limit_s)
            except SoakError as error:
                self.event("crash_failed", error=str(error), after_s=round(now() - killed, 1))
                return
            ready_after = now() - killed
            self.event("crash_ready", ready_after_s=round(ready_after, 1), limit_s=a.ready_limit_s, generation=self.generation, acked_before_kill=len(self.acked_sequences(ack_size)))
            self.pending_checks.append((now() + a.recovery_grace_min * 60.0, ack_size))
        finally:
            with self.state_lock:
                self.drill_busy = False

    def crash_check(self, ack_size, at_end=False):
        """Every message acknowledged before the kill must have reached the sink by now (restart plus the recovery grace, or the end of the run)."""
        acked = self.acked_sequences(ack_size)
        missing = [s for s in acked if self.sink.count_of(s) == 0]
        self.event("crash_check", checked=len(acked), missing=len(missing), missing_sample=missing[:10], at_end=at_end)

    def run_due_checks(self, everything=False):
        due = [c for c in self.pending_checks if everything or c[0] <= now()]
        self.pending_checks = [c for c in self.pending_checks if c not in due]
        for _, ack_size in due:
            self.crash_check(ack_size, at_end=everything)

    def new_backup_dir(self):
        """The newest finished backup this run has not drilled yet (the server logs 'backup written to <path>' when it is complete)."""
        try:
            with open(os.path.join(self.out, "host.log"), "rb") as handle:
                text = handle.read().decode("utf-8", "replace")
        except OSError:
            return None
        paths = re.findall(r"backup written to ([^\"\\\n]+)", text)
        for path in reversed(paths):
            if path not in self.backup_done and os.path.isdir(path):
                return path
        return None

    def backup_drill(self, source=None):
        a = self.args
        self.backup_count += 1
        number = self.backup_count
        restore_dir = os.path.join(self.out, "restore-%d" % number)
        started = now()
        instance = None
        database = None
        detail = ""
        try:
            ports = {name: free_port() for name in ("submission", "submissions", "alternate", "bounce", "http", "https")}
            if a.backend == "sqlite":
                self.backup_done.add(source)
                shutil.copytree(source, restore_dir)
                import sqlite3
                counts = {}
                for name in sorted(os.listdir(restore_dir)):
                    if name.endswith(".db"):
                        connection = sqlite3.connect("file:%s?mode=ro" % os.path.join(restore_dir, name), uri=True)
                        verdict = connection.execute("PRAGMA integrity_check").fetchone()[0]
                        if verdict != "ok":
                            raise SoakError("%s: integrity_check says %s" % (name, verdict))
                        if name == "queue.db":
                            counts["queue_rows"] = connection.execute("select count(*) from delivery_queue").fetchone()[0]
                        connection.close()
                detail = "files %s" % sorted(n for n in os.listdir(restore_dir) if n.endswith(".db"))
                env = self.host_env(restore_dir, ports, quiet=True)
            else:
                database = "soak_restore_%d" % number
                dump_path = os.path.join(self.out, "restore-%d.dump" % number)
                self.pg.dump(dump_path)
                self.pg.restore(dump_path, database)
                os.remove(dump_path)
                counts = {"queue_rows": int(self.pg.psql("select count(*) from delivery_queue", db=database))}
                env = self.host_env(None, ports, database=database, quiet=True)
                env["Sqlite__DataDirectory"] = restore_dir
                os.makedirs(restore_dir, exist_ok=True)
            argv = self.host_argv("serve")
            log_path = os.path.join(self.out, "restore-%d.log" % number)
            with open(log_path, "wb") as log_file:
                instance = subprocess.Popen(argv, env=env, stdout=log_file, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
                base = "http://127.0.0.1:%d" % ports["http"]
                until = now() + 180
                while now() < until and not http_ok(base + "/readyz"):
                    if instance.poll() is not None:
                        raise SoakError("the restored instance exited with code %s (restore-%d.log)" % (instance.returncode, number))
                    time.sleep(0.5)
                if not http_ok(base + "/readyz"):
                    raise SoakError("the restored instance was not ready in 180 s")
                probe = Api(base, ADMIN_USER, self.password)
                probe.login()      # the administrator is part of the restored state
                _, status = probe.call("GET", "/api/v1/admin/status")
                counts["queue_depth_reported"] = status["queue"]["depth"]
                probe.tenant = self.api.tenant
                if a.history == "full":
                    _, page = probe.call("GET", "/api/v1/messages?limit=5")
                    if not page.get("items"):
                        raise SoakError("the restored instance lists no message although history is recorded")
                    counts["messages_listed"] = len(page["items"])
            self.event("backup_drill", ok=True, source=os.path.basename(source or "pg_dump"), seconds=round(now() - started, 1), detail="%s; %s" % (detail, counts))
        except Exception as error:
            self.event("backup_drill", ok=False, error=str(error)[:500], source=source)
        finally:
            if instance is not None and instance.poll() is None:
                try:
                    os.kill(instance.pid, signal.SIGTERM)
                    instance.wait(timeout=60)
                except (OSError, subprocess.TimeoutExpired):
                    instance.kill()
                    instance.wait()
            if database:
                self.pg.psql("drop database if exists %s with (force)" % database, db="postgres", check=False)
            if restore_dir.startswith(self.out + os.sep + "restore-") and os.path.isdir(restore_dir):
                shutil.rmtree(restore_dir)

    def drills(self):
        a = self.args
        jitter = lambda base: base * self.rand.uniform(0.8, 1.2)       # noqa: E731
        crash_next = self.start_ts + jitter(a.crash_interval_min * 60) if a.crash_interval_min > 0 else None
        backup_next = self.start_ts + a.backup_interval_min * 60 if a.backup_interval_min > 0 else None
        backup_armed = False
        while not self.stopping.is_set() and self.phase == "load":
            t = now()
            quiet = self.elapsed() >= self.tail_start_s
            self.run_due_checks()
            if not quiet and crash_next is not None and t >= crash_next:
                self.crash_drill()
                crash_next = now() + jitter(a.crash_interval_min * 60)
            if not quiet and backup_next is not None and t >= backup_next:
                backup_armed = True
                backup_next = None
            if backup_armed and not quiet:
                if a.backend == "sqlite":
                    source = self.new_backup_dir()
                    if source:
                        self.backup_drill(source)
                        backup_armed = False
                        backup_next = now() + a.backup_interval_min * 60
                else:
                    self.backup_drill()
                    backup_armed = False
                    backup_next = now() + a.backup_interval_min * 60
            self.stopping.wait(1.0)

    # -- the end of the run

    def drain(self):
        a = self.args
        self.phase = "drain"
        started = now()
        self.event("drain_start")
        calm = 0
        depth = deferred = None
        while now() - started < a.drain_timeout_min * 60:
            try:
                _, status = self.api.call("GET", "/api/v1/admin/status")
                depth, deferred = status["queue"]["depth"], status["queue"].get("deferred", 0)
            except (SoakError, OSError, ValueError) as error:
                log("drain poll failed: %s" % error)
                time.sleep(5)
                continue
            calm = calm + 1 if depth == 0 and deferred == 0 else 0
            if calm >= 3:
                break
            time.sleep(5)
        result = {"drained": calm >= 3, "depth": depth, "deferred": deferred, "seconds": round(now() - started, 1), "limit_seconds": a.drain_timeout_min * 60}
        self.event("drain_end", **result)
        return result

    def reconcile(self):
        """Every acknowledged message against the sink; duplicates against the API's possible_duplicate events."""
        acked = {}
        try:
            with open(os.path.join(self.out, "ack.log"), "rb") as handle:
                for line in handle.read().decode("ascii", "replace").splitlines():
                    parts = line.split("\t", 2)
                    if parts[0].isdigit():
                        acked[int(parts[0])] = parts[2] if len(parts) > 2 else ""
        except OSError:
            pass
        lost = sorted(s for s in acked if self.sink.count_of(s) == 0)
        duplicates = sorted(s for s in acked if self.sink.count_of(s) > 1)
        result = {
            "acknowledged": len(acked), "delivered_unique_of_acknowledged": len(acked) - len(lost), "lost_count": len(lost), "lost_sample": lost[:50],
            "sink_unique": self.sink.unique_received(), "sink_total": self.sink.total_received, "sink_foreign": self.sink.foreign,
            "sink_dropped_acks": self.sink.dropped_acks, "sink_tempfails": self.sink.tempfails,
            "duplicates": len(duplicates), "duplicates_verifiable": self.args.history == "full",
        }
        if duplicates and self.args.history == "full":
            flagged = unflagged = checked = 0
            unflagged_sample = []
            error = None
            for sequence in duplicates[:3000]:
                match = re.search(r"\b([0-9a-f]{32})\b", acked[sequence])
                if not match:
                    error = "the 250 reply carries no message id: %r" % acked[sequence]
                    break
                try:
                    _, events = self.api.call("GET", "/api/v1/messages/%s/events" % match.group(1))
                except SoakError as problem:
                    error = str(problem)
                    break
                checked += 1
                if any(e.get("type") == "possible_duplicate" for e in events):
                    flagged += 1
                else:
                    unflagged += 1
                    unflagged_sample.append(sequence)
            result.update(duplicates_checked=checked, duplicates_flagged=flagged,
                          duplicates_unflagged=None if error else unflagged, duplicates_unflagged_sample=unflagged_sample[:50])
            if error:
                result["duplicates_error"] = error
        elif not duplicates:
            result.update(duplicates_checked=0, duplicates_flagged=0, duplicates_unflagged=0)
        return result

    def scan_host_log(self):
        errors = critical = lines = 0
        sample = []
        try:
            with open(os.path.join(self.out, "host.log"), "rb") as handle:
                for raw in handle:
                    lines += 1
                    text = raw.decode("utf-8", "replace")
                    if '"LogLevel":"Critical"' in text:
                        critical += 1
                    elif '"LogLevel":"Error"' in text:
                        errors += 1
                    else:
                        continue
                    if len(sample) < 5:
                        sample.append(text.strip()[:220])
        except OSError:
            pass
        return {"critical": critical, "errors": errors, "lines": lines, "sample": sample}

    # -- everything

    def host_argv(self, *arguments):
        exe = self.args.host_exe
        return ([exe] if os.path.basename(exe) in ("mta", "mta.exe") else ["dotnet", exe]) + list(arguments)

    def write_config(self):
        a = self.args
        version = run_text(self.host_argv("--version")).strip()
        label = "%s, %s, %d logical cores, load generator, sink, DNS stub%s on the same machine" % (
            platform.platform(), platform.machine(), os.cpu_count() or 0, ", PostgreSQL" if a.backend == "postgres" else "")
        config = {
            "backend": a.backend, "history": a.history, "sync": a.sync, "rate_msgs_per_s": a.rate, "size_mix": a.size_mix, "connections": a.connections,
            "crash_interval_min": a.crash_interval_min, "backup_interval_min": a.backup_interval_min, "duration_s": self.duration_s,
            "warmup_s": round(a.warmup_min * 60), "quiet_tail": a.quiet_tail, "sample_interval_s": a.sample_interval_s, "recovery_grace_min": a.recovery_grace_min,
            "claim_lease_min": a.claim_lease_min or 15, "version": version, "machine": label, "environment_label": label,
            "sink_tempfail_rate": a.sink_tempfail_rate, "sink_drop_ack_rate": a.sink_drop_ack_rate, "started": iso(self.start_ts),
        }
        with open(os.path.join(self.out, "config.json"), "w") as handle:
            json.dump(config, handle, indent=2)

    def run(self):
        a = self.args
        self.write_config()
        with open(os.path.join(self.out, "admin-password.txt"), "w") as handle:
            handle.write(self.password)
        os.chmod(os.path.join(self.out, "admin-password.txt"), 0o600)
        os.makedirs(self.data_dir, exist_ok=True)
        threads = []
        try:
            if a.backend == "postgres":
                self.pg = Postgres(a.pg_mode, self.out, self.ports["pg"])
                self.pg.start()
            self.dns = DnsStub(self.ports["dns"], "127.0.0.1")
            self.sink = SoakSink(self.ports["sink"], tempfail_rate=a.sink_tempfail_rate, drop_ack_rate=a.sink_drop_ack_rate, seed=a.seed)
            self.dns.add_a(SINK_HOST, "127.0.0.1")
            for i in range(a.recipient_domains):
                self.dns.add_mx("r%d.soak.test" % (i + 1), 10, SINK_HOST)
            ready = self.start_host()
            self.event("host_ready", seconds=round(ready, 1), generation=self.generation, backend=a.backend, pid=self.host.pid)
            self.provision()
            self.start_ts = now()          # the clock of the run starts when the load does
            self.start_load()
            threads = [threading.Thread(target=self.sampler, name="sampler", daemon=True), threading.Thread(target=self.drills, name="drills", daemon=True)]
            for t in threads:
                t.start()
            while self.loader.poll() is None:
                time.sleep(1)
                if self.elapsed() > self.duration_s + 120:
                    self.event("load_overran", note="the load generator did not stop by itself; stopping it")
                    self.loader.terminate()
                    break
            self.event("load_end", exit_code=self.loader.returncode, seconds=round(self.elapsed(), 1))
            self.phase = "drain"
            threads[1].join(timeout=900)          # a drill in progress finishes first
            if self.host.poll() is not None:
                self.watch_host()
            drain = self.drain()
            time.sleep(2)
            self.run_due_checks(everything=True)
            verification = self.reconcile()
            verification["drain"] = drain
            verification["load_exit_code"] = self.loader.returncode
            verification["unexpected_exits"] = self.unexpected_exits
            self.phase = "stopping"
            if self.host.poll() is None:
                code, seconds = self.stop_host(kill=False, timeout=90)
                verification["shutdown"] = {"exit_code": code, "seconds": seconds}
            verification["host_log"] = self.scan_host_log()
            with open(os.path.join(self.out, "verification.json"), "w") as handle:
                json.dump(verification, handle, indent=2)
            self.phase = "done"
        except KeyboardInterrupt:
            self.event("interrupted")
            raise
        except Exception as error:
            self.event("run_failed", error=repr(error)[:500])
            raise
        finally:
            self.stopping.set()
            self.cleanup()
        return 0

    def cleanup(self):
        for proc in (self.loader, self.host):
            if proc is not None and proc.poll() is None:
                try:
                    os.kill(proc.pid, signal.SIGKILL)
                except OSError:
                    pass
        if self.sink is not None:
            try:
                self.sink.stop()
            except Exception:
                pass
        if self.pg is not None:
            self.pg.stop()
        self.csv_handle.close()


def _r(value):
    return "" if value is None else round(value, 2)


def _i(value):
    return "" if value is None else int(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--hours", type=float, default=2.0, help="how long the load runs (the 6 h limit of a hosted-runner job applies in Actions)")
    parser.add_argument("--backend", choices=["sqlite", "postgres"], default="sqlite")
    parser.add_argument("--history", choices=["full", "statsonly"], default="full", help="History:Mode")
    parser.add_argument("--sync", choices=["off", "normal", "full"], default="off",
                        help="SQLite: Sqlite:SyncMode. PostgreSQL: off sets synchronous_commit=off for the server's connections, normal and full leave it on")
    parser.add_argument("--rate", type=float, default=30.0, help="messages per second, in total")
    parser.add_argument("--size-mix", default="1024:55,8192:30,65536:12,524288:3", help="message size in bytes : weight, comma separated")
    parser.add_argument("--connections", type=int, default=8)
    parser.add_argument("--recipient-domains", type=int, default=4, help="number of distinct recipient domains (all resolve to the sink)")
    parser.add_argument("--crash-interval-min", type=float, default=20.0, help="kill -9 and restart this often (0: never)")
    parser.add_argument("--backup-interval-min", type=float, default=30.0, help="backup + restore drill this often (0: never)")
    parser.add_argument("--quiet-tail", type=float, default=0.25, help="no drills in the last fraction of the run: the uninterrupted stretch the trend criteria judge")
    parser.add_argument("--sample-interval-s", type=float, default=60.0)
    parser.add_argument("--warmup-min", type=float, default=None, help="process warm-up that trend criteria ignore (default: 15%% of the run, at most 10 minutes)")
    parser.add_argument("--ready-limit-s", type=float, default=120.0, help="a restarted server must be ready within this")
    parser.add_argument("--recovery-grace-min", type=float, default=None,
                        help="messages acknowledged before a kill must be delivered this long after the restart (default: the claim lease, 15 minutes, plus 10)")
    parser.add_argument("--claim-lease-min", type=int, default=0, help="Delivery:ClaimLease in minutes (0: the product default of 15); shorter lets short runs see crash recovery")
    parser.add_argument("--drain-timeout-min", type=float, default=30.0)
    parser.add_argument("--sink-tempfail-rate", type=float, default=0.005, help="share of messages the sink answers 451 after DATA")
    parser.add_argument("--sink-drop-ack-rate", type=float, default=0.005, help="share of messages the sink keeps but never acknowledges (forces possible duplicates)")
    parser.add_argument("--seed", type=int, default=20261015)
    parser.add_argument("--out", default="soak-results")
    parser.add_argument("--host-exe", default=None, help="the published mta (default: <repo>/artifacts/soak/publish/mta)")
    parser.add_argument("--tools-dll", default=None, help="mta-tools.dll (default: <repo>/artifacts/soak/tools/mta-tools.dll)")
    parser.add_argument("--pg-mode", choices=["docker", "local"], default=None, help="PostgreSQL: the binaries on PATH (initdb, pg_ctl, psql, pg_dump, pg_restore, createdb) or a docker container (default: the binaries if all exist, else docker)")
    parser.add_argument("--extra-env", action="append", help="NAME=value passed to the server (repeatable), for example Delivery__Workers=16")
    for name, (default, meaning) in evaluate.THRESHOLDS.items():
        parser.add_argument("--" + name.replace("_", "-"), type=float, default=default, help="verdict threshold: " + meaning)
    args = parser.parse_args()

    if args.host_exe is None:
        args.host_exe = os.path.join(REPO, "artifacts", "soak", "publish", "mta")
    if args.tools_dll is None:
        args.tools_dll = os.path.join(REPO, "artifacts", "soak", "tools", "mta-tools.dll")
    for path in (args.host_exe, args.tools_dll):
        if not os.path.exists(path):
            parser.error("%s does not exist; run bench/soak/run-soak.sh, which publishes both" % path)
    if args.recovery_grace_min is None:
        args.recovery_grace_min = (args.claim_lease_min or 15) + 10.0
    if os.path.isdir(args.out) and os.listdir(args.out):
        parser.error("--out %s exists and is not empty" % args.out)
    if args.warmup_min is None:
        args.warmup_min = min(10.0, 0.15 * args.hours * 60)
    if args.backend == "postgres" and args.pg_mode is None:
        # Developer machines run no Docker (project rule): the binaries on PATH first; the Actions runner has none on PATH and uses the container.
        args.pg_mode = "local" if all(shutil.which(tool) for tool in ("initdb", "pg_ctl", "psql", "pg_dump", "pg_restore", "createdb")) else "docker"
    if args.hours <= 0 or not 0 <= args.quiet_tail < 1:
        parser.error("--hours must be positive and --quiet-tail in [0, 1)")

    soak = Soak(args)

    def terminate(signum, frame):
        soak.stopping.set()
        raise KeyboardInterrupt()

    signal.signal(signal.SIGTERM, terminate)
    run_error = None
    try:
        soak.run()
    except KeyboardInterrupt:
        run_error = "interrupted"
    except Exception as error:
        run_error = repr(error)
        log("the run failed: %s" % run_error)
    thresholds = {name: getattr(args, name) for name in evaluate.THRESHOLDS}
    result = evaluate.evaluate(soak.out, thresholds)
    if run_error:
        result["verdict"] = "FAIL"
        result["criteria"].insert(0, {"name": "the run itself", "status": "FAIL", "detail": run_error})
    with open(os.path.join(soak.out, "verdict.json"), "w") as handle:
        json.dump(result, handle, indent=2)
    summary = evaluate.summary_markdown(soak.out, result)
    with open(os.path.join(soak.out, "summary.md"), "w") as handle:
        handle.write(summary)
    print(summary, flush=True)
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
