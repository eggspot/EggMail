# Soak test

A soak test runs the **real host process** under sustained load for hours, repeatedly kills it, and then asks one question: *did every message the server acknowledged get delivered, and did the process stay healthy while it did?* The in-process tests and the throughput benchmarks cannot answer that: they run for seconds, share a process with the code under test, and never see a leak that costs 1 MB a minute or a file descriptor that is opened and forgotten once an hour.

Everything lives in `bench/soak/`. The same script runs on a laptop and in GitHub Actions (`.github/workflows/soak.yml`).

**Status (2026-10-15).** The harness is built and has run end to end on SQLite and on PostgreSQL, locally and on a hosted runner, at lengths of 6 to 40 minutes (the run list is at the end). **No multi-hour run has been made yet**, so nothing here says that EggMail passes a six hour soak; what exists is the instrument and its first short readings. The trend criteria only mean something on long runs (a 20 minute run reports them as `SKIP`, never as `PASS`).

## What a run does

```
 run-soak.sh ── dotnet publish (mta + mta-tools) ── soak.py
                                                       │
   DNS stub (MX, A, TXT) ◄── resolver ──┐              │ starts, kills, restarts, samples, reconciles
   sink MX (counts by Message-ID) ◄─ delivery ─┐       ▼
                                       ┌───────┴─────────────┐
   mta-tools load --persist ── SMTP ──►│ mta serve (SQLite or│──► PostgreSQL 17
   (STARTTLS + AUTH, numbered mail,    │ PostgreSQL), the    │    (container or local binaries)
    paced, size mix, ack log)          │ published layout    │
                                       └─────────────────────┘
```

1. **Start.** `dotnet publish` of `src/Mta.Host` (framework dependent, the layout of the image) and of `src/Mta.Tools`. For PostgreSQL a `postgres:17` container (Actions) or a throwaway cluster from the binaries on `PATH` (a laptop; the project does not use Docker on developer machines). `mta serve` is started on loopback ports chosen at random, with the configuration below.
2. **Provision through the public API**, like `deploy/smoke/smoke.py`: administrator sign-in, a tenant, a sending domain (the harness is the DNS server, so the domain verifies), an SMTP credential.
3. **Load** for `--hours`: `mta-tools load --persist` opens `--connections` STARTTLS+AUTH connections and submits `--rate` messages a second with a size mix (default `1024:55,8192:30,65536:12,524288:3`, bytes:weight), to four recipient domains that all resolve to the sink. Every message has a unique, numbered `Message-ID` (`<soak.000000000042@soak-sender.test>`). The generator writes **an ack log**: one line per message the server answered `250` to, with the server's message id. It reconnects through outages (that is what `--persist` is for) and bounds every network operation (`--io-timeout-s 60`).
4. **Sink.** A plain-SMTP sink on loopback counts, per sequence number, how often each message arrived. It misbehaves on purpose, because real receivers do and both cases are what the delivery engine must get right: 0.5 % of messages are answered `451` after `DATA` (must be retried), and 0.5 % are kept and then the connection is closed without the final reply (the server cannot know the outcome, retries, the sink sees a **duplicate**, and the server must have flagged it `possible_duplicate`).
5. **Sampling.** Every `--sample-interval-s` (60) one row of `samples.csv`: see the table below.
6. **Crash drills** every `--crash-interval-min` (20, with up to 20 % jitter): `kill -9` of the server, immediate restart with the same configuration, and a note of how long it took to be ready (`/readyz` and the submission port). Each drill remembers which messages had been acknowledged *before* the kill; after the recovery grace (the claim lease plus 10 minutes: 25) every one of them must have reached the sink.
7. **Backup and restore drills** every `--backup-interval-min` (30). SQLite: the scheduled backup of the running server (`Backup:*`, set to be due soon after each ten-minute check) is copied, every file gets `PRAGMA integrity_check`, and a **second `mta serve` is started on the restored copy** (quiet: its resolver does not exist, so it sends nothing) and must become ready, accept the administrator's sign-in and list messages. PostgreSQL: `pg_dump -Fc` of the live database, `pg_restore` into a new database, the same second instance on it, then the database is dropped.
8. **Quiet tail.** No drills in the last `--quiet-tail` (25 %) of the run: one uninterrupted process for the trend criteria to judge.
9. **End.** The generator stops by itself at the deadline. The harness waits for the queue to drain (up to `--drain-timeout-min`, 30), reconciles the ack log against the sink, asks the API whether each duplicate was flagged, stops the server with `SIGTERM` (exit code and time recorded), scans `host.log` for error-level lines, and `evaluate.py` decides.

### Server configuration the harness sets

Listener ports random on `127.0.0.1`; `Dns:Servers` the stub; `Delivery:RemotePort` the sink; `Delivery:AllowPrivateMxAddresses=true`; the per-destination ceilings raised (`Delivery:Throttle:*`: they are a policy for the public internet, 600 messages a minute to one domain, and would turn the soak into a throttle test); `Observability:QueueSampleSeconds=5`; `History:Mode`, `Sqlite:SyncMode` (or `synchronous_commit=off` for PostgreSQL when `--sync off`) as requested; everything else is the product default, including `Delivery:ClaimLease` (15 minutes) unless `--claim-lease-min` says otherwise. `--extra-env NAME=value` passes anything else.

### What a crash does to in-flight mail (and why the grace is 25 minutes)

A delivery that a killed process had claimed stays leased until `Delivery:ClaimLease` (15 minutes) runs out; only then is it handed out again, flagged `possible_duplicate` (the first holder may have finished the SMTP transaction). So after a `kill -9`, messages that were in flight wait up to a lease before they are retried, and that is the product's behaviour, not a harness artefact. The harness's grace is the lease plus ten minutes (a deferred message is retried after 2 and then 5 minutes). A short proof run can shorten the lease with `--claim-lease-min 2` and says so in `config.json`.

## Samples (`samples.csv`)

| Column | Source |
|---|---|
| `ts`, `iso`, `elapsed_s`, `generation`, `uptime_s`, `phase`, `up` | The harness. `generation` counts server processes (a crash drill starts a new one), `uptime_s` is the age of the current process, `phase` is `load`, `drain` or `stopping`, `up` is 0 while the process is dead |
| `rss_mb`, `fds`, `threads` | The operating system, for the server's pid: `/proc/<pid>` on Linux; `ps` and `lsof -a -p <pid> -d 0-65535` on macOS |
| `gc_gen0`, `gc_gen1`, `gc_gen2`, `gc_alloc_mb`, `working_set_mb`, `tp_threads` | `/metrics`: `dotnet_gc_collections_total`, `dotnet_gc_heap_total_allocated_bytes_total`, `dotnet_process_memory_working_set_bytes`, `dotnet_thread_pool_thread_count_total` (the .NET runtime meter, exported by the host since this harness needed it; [operations.md](operations.md#monitoring)) |
| `queue_depth`, `queue_deferred` | `/metrics`: `mta_delivery_queue_depth` (queued + deferred + leased; sampled by the server every 5 s) and the deferred state alone |
| `smtp_accepted`, `delivered` | `/metrics`: `mta_smtp_server_messages_total`, `mta_delivery_attempts_total{outcome="delivered"}`. Counters of the **current process**: they restart at 0 after a kill |
| `sink_received`, `sink_unique` | The sink: receipts including duplicates, and distinct messages |
| `load_accepted`, `load_rejected`, `load_connect_errors` | The generator's cumulative counters (`load-stats.jsonl`, every 10 s): `250` replies; a live server answered 4xx/5xx; no answer (connection refused, reset, timeout) |
| `lat_p50_ms`, `lat_p95_ms`, `lat_p99_ms` | The generator, per submission (`MAIL FROM` to the final reply), over the samples' interval: mean of the 10 s p50 and p95, **maximum** of the 10 s p99 |
| `disk_mb` | SQLite: size of the data directory without `backups/`; PostgreSQL: `pg_database_size` |

GC counts, heap and thread-pool numbers are samples of what the runtime reports; they do not replace a profiler when a criterion fails, they tell you which question to ask it.

## Pass and fail criteria

`evaluate.py` applies these. Thresholds are the command-line defaults of `soak.py` / `run-soak.sh` (and of `evaluate.py` itself) and are printed in `verdict.json`; change them only with a reason you can write down.

| # | Criterion | PASS when | Why this number |
|---|---|---|---|
| 1 | **No acknowledged message lost** | every message in the ack log reached the sink at least once: `lost = 0` | The contract of a durable queue: `250` means the server owns the message. No tolerance |
| 2 | **No unflagged duplicate** | every message the sink received more than once has a `possible_duplicate` event (`GET /messages/{id}/events`); `unflagged = 0`. At most 3,000 duplicates are looked up. With `History:Mode=StatsOnly` no events exist: the criterion is `SKIP` with the count of duplicates | At-least-once delivery is the contract; a duplicate the server did not flag is a bug (decision 83) |
| 3 | **Error rate** | at most **0.5 %** of submissions failed outside the crash windows: (refused by a live server + connection errors) / (accepted + those). A crash window runs from each kill until the restarted server was ready **plus 30 s** | A healthy server under a steady, in-capacity load refuses essentially nothing; 0.5 % leaves room for a restart race and a slow second, not for a regression |
| 4 | **Queue drains to zero** | after the load stops, `GET /admin/status` shows `queue.depth = 0` and `deferred = 0` three polls in a row within `--drain-timeout-min` (30; shortened in Actions so the report always fits the job) | The offered rate is below capacity; whatever is left is a stuck delivery |
| 5 | **RSS flat after warm-up** | on the last process generation (the uninterrupted tail), after warm-up (`--warmup-min`: 15 % of the run, at most 10 minutes, counted in the process's own uptime), the **median RSS of the last quarter of the samples exceeds the median of the first quarter by at most 20 %** | Medians, not points: a garbage collection or a 512 KB message is a spike, a leak is a shift. 20 % allows the heap to settle into its working size and is far below the doubling a real leak produces over hours. The Theil-Sen slope (MB per hour) is reported too |
| 6 | **File descriptors flat** | last-quarter median minus first-quarter median at most `max(10, 10 % of the first)` | A leak is a steady climb; a quarter-to-quarter difference of a few connections is noise |
| 7 | **OS threads flat** | the same, at most `max(6, 10 %)` | |
| 8 | **Crash drills recover** | every kill was followed by a ready server within **120 s**, and every message acknowledged before the kill was delivered by the recovery grace | |
| 9 | **Backup and restore drills** | every drill: backup complete, integrity check `ok` on every file, the restored instance became ready, the administrator signed in, messages are listed (history `Full`) | |
| 10 | **Load ran for the whole duration** | the generator reports at least 95 % of the requested time | A run whose load died at minute 3 proved nothing |
| 11 | **Server stayed up between drills** | no exit of the server that a drill did not cause | |
| 12 | **Graceful shutdown** | `SIGTERM` ends the process with exit code 0 (waits up to 90 s) | |
| 13 | **Host log** | no `Critical` line and no `Error` line in `host.log` (`Error` alone is a `WARN`: it needs a human, but several things log at error level for conditions that are handled) | |
| – | Advisory (`WARN`, never `FAIL`) | RSS growth in *every* earlier process generation; p99 submission latency of the last quarter more than 3x the first quarter's | A restart every 20 minutes cannot show a slow leak; the p99 of a shared runner is too noisy to fail on |

A criterion that cannot be judged (fewer than 8 samples in the tail, `StatsOnly` duplicates) is `SKIP` with the reason. The verdict is `FAIL` if any criterion failed, otherwise `PASS`, and says `PASS (n criteria skipped)` when some were skipped. A run that dies on its own (the harness raises) is a `FAIL` with a "the run itself" line.

`python3 bench/soak/evaluate.py --self-test` checks the criteria against synthetic runs (a clean run, a lost message, an unflagged duplicate, an undrained queue, a leak, a descriptor leak, errors, `StatsOnly`, a too-short run). It runs in `ci` and in every `run-soak.sh`.

## Running it

```sh
bench/soak/run-soak.sh --hours 2 --backend sqlite                       # a laptop: SQLite, 2 hours of load
bench/soak/run-soak.sh --hours 6 --backend postgres --sync full         # PostgreSQL with synchronous_commit on
bench/soak/run-soak.sh --hours 0.33 --backend sqlite --crash-interval-min 4 --backup-interval-min 5 --quiet-tail 0.4 \
    --sample-interval-s 15 --claim-lease-min 2                           # a 20 minute proof run (trends are judged on a short tail)
bench/soak/run-soak.sh --help                                            # every option
```

`run-soak.sh` needs the .NET 10 SDK and python3 (3.9 or newer, standard library only); it raises the open-file limit (macOS defaults to 256), publishes into `artifacts/soak/`, runs the self-test and starts `soak.py`. `--skip-build` reuses the publish output. Results go to `artifacts/soak/results/<UTC time>-<backend>/` (or `--out`, which must not exist or be empty). The exit code is 0 for PASS and 1 for FAIL. PostgreSQL uses `initdb`/`pg_ctl`/`psql`/`pg_dump`/`pg_restore`/`createdb` from `PATH` when all exist (a throwaway cluster inside the results folder, stopped at the end), else a `postgres:17` container (`--pg-mode docker|local` forces one). Leave the machine alone while it runs: a laptop that sleeps or a CPU taken by another job turns into latency and error-rate noise.

Options worth knowing:

| Option | Default | |
|---|---|---|
| `--hours` | 2 | Hours of load. Setup, the drain and the shutdown come on top |
| `--backend` | `sqlite` | `sqlite` or `postgres` |
| `--history` | `full` | `History:Mode` (`statsonly` skips criterion 2) |
| `--sync` | `off` | SQLite `Sqlite:SyncMode` (`off`, `normal`, `full`). PostgreSQL: `off` sets `synchronous_commit=off`, `normal` and `full` keep the durable default |
| `--rate`, `--size-mix`, `--connections` | 30 msg/s, `1024:55,8192:30,65536:12,524288:3`, 8 | The offered load. Keep it below what the machine sustains: the point is hours of steady work, not the maximum rate (that is [benchmarks.md](benchmarks.md)) |
| `--crash-interval-min`, `--backup-interval-min` | 20, 30 | 0 turns a drill off |
| `--quiet-tail` | 0.25 | Fraction of the run without drills, for the trend criteria |
| `--sample-interval-s` | 60 | |
| `--claim-lease-min` | 0 (product default, 15) | Shorter lets short runs see crash recovery |
| `--sink-tempfail-rate`, `--sink-drop-ack-rate` | 0.005, 0.005 | The sink's deliberate misbehaviour |
| `--rss-growth-pct`, `--error-rate-pct`, ... | see criteria | Thresholds |

### In GitHub Actions

`gh workflow run soak --ref <branch> -f hours=2 -f backend=sqlite` (inputs: `hours`, `backend` = `sqlite` / `postgres` / `both`, `history`, `sync`, `rate`, `size_mix`, `connections`, `crash_interval_min`, `backup_interval_min`, `quiet_tail`, `sample_interval_s`, `claim_lease_min`). One job on `ubuntu-latest`, the cheapest runner, billed for its wall time: **a 6 hour soak bills about 360 Linux minutes**, so it never runs on a push or a pull request. The run's summary page shows the verdict table and the trend lines; the artifact `soak-results-<run id>` holds `summary.md`, `verdict.json`, `samples.csv`, `events.jsonl`, `load-stats.jsonl`, `ack.log`, `verification.json`, `host.log`, `load.log` and `config.json` (not the data directory or the restored copies) for 14 days. The summary starts with "noisy, not publishable": a hosted runner shares its machine with the load generator, the sink, the database and other tenants of the host.

**The 6 hour limit.** GitHub ends a hosted-runner job after 6 hours (360 minutes), checkout, publish and shutdown included, so a hosted soak is at most about **5.4 hours of load** for one backend. The first step of the job refuses a plan that does not fit; the soak step has its own 345-minute limit and the drain is shortened to what is left, so the summary and the artifact are always produced. With `backend=both` the two runs share the job, so `hours` is per backend and must fit twice. **Longer than that** needs either chained dispatches (start the next one when this one ends; every run is judged on its own, which is sound for the delivery criteria and weaker for the leak criteria) or a self-hosted runner, where the same `run-soak.sh` runs with no limit (set `runs-on` in a copy of the workflow, or just run the script under `tmux`).

**Schedule.** The workflow has a monthly `schedule`, **off by default**: it needs the repository variable `EGGMAIL_SOAK_SCHEDULE=true`. With the variable unset the schedule starts the workflow, the job's `if` skips it, and nothing is billed.

## What the soak does not cover

- **A shared machine.** The server, the generator, the sink, the stub and the database share one host. The numbers are for trends within a run, never for comparing runs on different machines, and a failure caused by a starved CPU looks like a server problem. Rerun before believing a latency or error-rate failure; do not rerun a lost message.
- **Power loss and operating-system crashes.** `kill -9` is a process crash: with `Sqlite:SyncMode=Off` the operating system still has the data. Whether `Off` survives losing power is a different test, which needs a machine that can lose power; `--sync full` or PostgreSQL are the configurations to claim that for, and even then the soak only kills the process.
- **The real internet.** The sink speaks plain SMTP on loopback; there is no TLS to the receiver, no real DNS, no MTA-STS or DANE, no greylisting, no real reputation limits (the destination throttles are raised).
- **Multiple replicas** (decisions 82, 83 have their own chaos tests), **ACME**, **webhooks**, the dashboard.
- **Long-term growth of the stores** beyond the run: retention jobs run at their normal schedule, which on a few-hour run means the retention deletes mostly never fire. A multi-day run would be needed for that.
- **The Python sink and DNS stub are single-process**; at the default 30 messages a second they are idle. If you raise `--rate` far, check that the sink's CPU is not the limit before reading the numbers.

## Interpreting a failure

| Symptom | First look |
|---|---|
| `lost > 0` | `verification.json` has the first sequence numbers; `ack.log` has the server's id for each (`GET /api/v1/messages/<id>` and its `/events`); `events.jsonl` says whether it was acknowledged shortly before a kill (`crash_check` lists what was still missing at the grace) |
| unflagged duplicate | the same: the events of the id; a delivery that was retried without a `possible_duplicate` event is the bug |
| RSS / FD / thread growth | `samples.csv` columns `gc_gen2`, `working_set_mb`, `tp_threads` and `disk_mb` next to it; the Theil-Sen slope in the criterion's detail; rerun the tail with `--crash-interval-min 0` to rule the drills out |
| error rate | `load-stats.jsonl` times the failures; `host.log` around them |
| queue does not drain | `GET /api/v1/admin/status`, the oldest due time, `host.log` for the destination (the sink) errors; a message deferred past the drain limit shows as `deferred` |
| restore drill fails | `restore-<n>.log` is kept next to the run's files |

## Runs so far

Hosted-runner and laptop runs are recorded here with the commit, the machine and the verdict. Short runs are proofs that the harness works, not claims about EggMail.

| Date | Where | Backend and options | Length | Verdict |
|---|---|---|---|---|
