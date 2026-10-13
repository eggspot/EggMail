# Performance measurement plan

EggMail's primary goal is to be the fastest SMTP server. **Performance is a permanent first-class goal on both storage backends:** the SQLite backend is engineered for large, high-throughput workloads and is not treated as a toy. Because the backends are feature-identical (they differ only in how data is stored), both are benchmarked and optimized **separately on the identical feature set**: same protocol features, same history level, same settings, each backend with its own results, regression gate and budgets. "Lite" and "Full" below are the two backends' default deployment shapes (SQLite and PostgreSQL); they have identical behavioural defaults, including `History:Mode=Full`. This document defines what that claim means and how it is measured. **No publishable measurements exist yet** (the only numbers are development-time observations and noisy CI trend numbers, both labelled as such below). All targets are proposals to be tuned after the first runs. Claim "fastest" only once an independent run reproduces it.

## Scope of the claim

"Fastest" means **SMTP ingest (accept) throughput and latency**, reported separately from outbound delivery. Do not mix vendor outbound figures with our ingest numbers. (For reference, KumoMTA's published rate is for outbound delivery to a sink: about 3.3M × 100 KB messages/hour on 8 cores.)

## Metrics

- Accepted messages/s and MB/s, measured when the `250` after end-of-data returns
- p50 and p99 transaction latency
- Connections/s, with and without TLS
- RSS, and memory per idle connection
- CPU per 1,000 messages
- Allocations per message

The SQLite backend additionally reports `sqlite_commit_latency_ms`, `sqlite_writer_batch_size`, `sqlite_writer_queue_depth` and WAL size, which also feed the dashboard's advisory storage-pressure indicator (advisory only; backend switching is manual). The PostgreSQL backend additionally reports round trips per message, claim latency, WAL volume and connection-pool saturation.

Because `History:Mode` changes how much is written per message, results always state it. The matrix is backend × history level; the four combinations are all valid. The default for both backends is `Full` history, so the headline numbers use `Full` on the default SQLite backend as well as on PostgreSQL; `StatsOnly` results are published alongside, since any combination is allowed. Default `Full` history means the SQLite backend writes more per message by default than a statistics-only configuration would, which the published results make visible. Switch-engine throughput (export/import of a bundle) is measured separately and is not part of the ingest claim.

## Targets (proposed)

| Budget | Target |
|---|---|
| Allocation per ingested message, excluding body buffers | under 2 KB |
| Memory per idle connection | under 8 KB without TLS, under 40 KB with TLS |
| p99 command latency, local | under 1 ms |
| Ingest, non-durable | at least 5k msg/s per core |
| Outbound to a sink | at least 3k msg/s per core |
| Gen2 GCs at steady load | essentially none |
| EF Core database layer (starting proposal for both backends; each may get its own budget after first runs) | no more than about 20 KB per database round trip, amortized over batches of tens to hundreds of rows |

The protocol-path rows apply to both backends and are measured separately on each. The 2 KB budget applies to the SMTP/protocol path; EF costs several KB per operation even when tuned, hence the separate database budget. The earlier SQLite-backend ceiling guess (thousands of messages/s on local NVMe, hundreds on cloud block storage) was an inference made for `synchronous=FULL`; it is not re-derived for the new default `OFF`. No credible published SQLite commit rate was found. Measure it; no SQLite-backend throughput target is set until the first runs.

## Fairness rules

1. **Report durable and non-durable results as a pair, per backend.** "Durable" means the data is fsynced (or equivalent) before the `250`. Never compare one durable result against another system's non-durable one.
   - **The SQLite backend's default is a non-durable configuration:** `Sqlite:SyncMode=Off` (`synchronous=OFF`) is process-crash-safe but not power-loss-safe, and per the SQLite docs can corrupt the database on an OS crash or power loss. A headline SQLite number measured under the default must therefore always be published next to the durable result with `Sqlite:SyncMode=Full` (and, as a middle point, `Normal`). Config files, WAL/checkpoint settings, history level and message sizes are identical across the pair.
   - **PostgreSQL:** the durable result uses Postgres defaults (WAL synced at commit). A non-durable counterpart for comparison with other servers can use Postgres `synchronous_commit=off` (a Postgres setting that can lose recent commits but not corrupt the database); it is published only as a pair with the durable result. Both are proposals to confirm in the first runs.
   - Comparing SQLite-`Off` against any baseline's durable result is unfair and not allowed; compare like with like (durable vs durable, non-durable vs non-durable).
2. Known baseline behavior: Postfix fsyncs queue files; KumoMTA's spool flush defaults to `false`; Haraka's behavior is **unverified**.
3. Baselines run on **identical hardware under our own harness**. Do not cite vendor numbers as baselines (Haraka, for example, claims only "thousands of messages per second" without a benchmark).
4. Use a sink that creates back-pressure. KumoMTA's testing docs warn that discard-everything sinks distort results.
5. Never test against the public internet.
6. Publish results per release with hardware, message size, concurrency and GC mode, using the **median of at least 3 runs**.
7. Include a reproducible compose setup in the repository, using the released single image ([release.md](release.md)) so the numbers describe what users run. A quick-start user gets the SQLite backend with `Sqlite:SyncMode=Off` and `Full` history: that exact default configuration is benchmarked, and published with its durable (`Sqlite:SyncMode=Full`) pair.
8. **The two backends are reported separately**, never blended into one number, and always on the identical feature set and history level. A cross-backend comparison is informational only, is made at the same `History:Mode`, and carries the same durable/non-durable pairing.
9. Disk and filesystem for SQLite runs are published (device type, local vs cloud block, filesystem), because that backend is bound by the local disk. PostgreSQL runs publish the server version, instance/storage class and HA setup.

## Baselines

- Required: Postfix, KumoMTA, Haraka
- Optional: Stalwart, mox
- Cut order: baselines beyond Postfix and KumoMTA are cuttable ([plan.md](plan.md#cut-order))

## Tools

- **Postfix `smtp-source` / `smtp-sink`:** `-s` sessions (concurrency), `-m` count, `-l` size, `-d` reuse connection, `-r` recipients. No pipelining, no TLS, and documented as unsupported.
- **KumoMTA `traffic-gen` and Smart Sink** (see its performance testing docs).
- **swaks:** correctness only, not load.
- **Own load generator:** no maintained standalone tool covers TLS and pipelining, so one is written and kept in the repository (`Mta.Tools`).
- **BenchmarkDotNet** with `[MemoryDiagnoser]` for parsers, dot-stuffing, DKIM canonicalization, the DNS codec and MIME; `dotnet-counters` and `dotnet-trace` for profiling.
- CI regression gate on the budgets, run for both backends (about 2.5 engineer-weeks for harness, generator, baseline compose and gate; see [plan.md](plan.md)). What is built so far is the allocation gate for the SQLite backend (see "Automation" below); a gate on the BenchmarkDotNet micro-benchmarks (`bench/Mta.Benchmarks`, time-based and therefore unfit for shared runners) and an allocation gate for the PostgreSQL backend are not built.

## Workload parameters to publish and vary

Message size, concurrency, TLS on/off, pipelining on/off, recipients per message, durable vs non-durable commit, backend (SQLite and PostgreSQL separately), `History:Mode` (`StatsOnly`, `Full`), `Sqlite:SyncMode` (`Off`, `Normal`, `Full`), GC mode (workstation non-concurrent vs server with DATAS; the choice is to be made from these benchmarks).

## Unverified

- SQLite commit rate on SSD with any `synchronous` setting, including the new default `OFF` (one search snippet claimed about 442 inserts/s WAL+FULL vs 33k/s NORMAL; unopened and not our workload)
- Haraka's ingest behavior and fsync policy
- Switch-engine and history-migration throughput on both backends (no measurement exists)
- All numeric targets above (proposals)

## Running the harness (`mta-tools`)

```sh
dotnet build src/Mta.Tools -c Release
dotnet src/Mta.Tools/bin/Release/net10.0/mta-tools.dll sink --port 2525                      # discard sink (optionally --delay-ms for back-pressure)
dotnet src/Mta.Tools/bin/Release/net10.0/mta-tools.dll load --port 2525 --connections 16 \
    --messages 100000 --size 2048 --pipelining --label "sink-pipelined"                       # closed-loop ingest benchmark
```

`load` reports accepted messages/s, MB/s and p50/p95/p99 transaction latency, and (with `--server-pid`) the server's CPU per 1,000 messages.

**Sample, not a claim:** the SMTP server alone against the discard `sink` on one developer machine (10-core Apple silicon, load generator and server on the same host, loopback, no TLS, no storage) accepted about 63k messages/s of 2 KB with 16 pipelined connections (p99 about 0.6 ms). This measures the protocol path only, not durable ingest through storage; numbers with storage, TLS and on dedicated hardware are published per release under the fairness rules above.



## Automation (GitHub Actions)

Billing comes first: nothing here runs on every pull request. Two workflows, both separate from `ci` and `release`:

| Workflow | Trigger | What it does | Cost |
|---|---|---|---|
| `bench-gate` | weekly (Monday 04:41 UTC, skipped when `main` has no commit in the last 8 days) and manual | Builds the harness, measures **allocation per message** two ways and compares with `bench/baseline/allocations.json`; fails above the thresholds | about one billed minute (the first run took 52 s) |
| `bench-throughput` | manual only | Runs the pipeline harness for several configurations (3 runs each), publishes the raw JSON as an artifact and a markdown summary (median and range); optionally measures JIT versus ReadyToRun start-up and size | about 10 to 15 minutes |

### The allocation gate

Allocation counts, unlike throughput, do not depend on how fast or how loaded the machine is, so a shared runner can gate on them. Two measurements, both from `bench/Mta.Bench.Pipeline`:

- **Per step (exact).** `--micro true --json`: bytes per call of `MimeMessage.Parse`, the header editor, content extraction, address parsing, id and address parsing, and the whole `SubmissionService.SubmitAsync` (in-memory storage, `History:Mode=Full`), measured with `GC.GetAllocatedBytesForCurrentThread`. Repeatable to the byte (16,567 B on a laptop and 16,568 B on the CI runner for `SubmitAsync`). **Threshold: +5 %.**
- **Per accepted message through the real runtime.** 20,000 messages of 2 KB over 8 connections with the load generator, SQLite, `Sqlite:SyncMode=Off`, `History:Mode=Full`, no delivery, total process allocation divided by accepted messages. It includes background work (batched writers), so it varies by about 2 % between runs of the same code (33.0 to 33.8 KB in three laptop runs although throughput differed by 4x; 32.8 KB on the CI runner). **Threshold: +10 %.**

A value above the baseline plus the threshold fails the workflow (the summary table names the measurement). A value more than the threshold below the baseline is reported as "improved (update the baseline)" and does not fail. To accept a deliberate change, copy `bench-candidate.json` from the run's artifacts over `bench/baseline/allocations.json` in the same pull request and fill in `recordedOn`. The comparison logic was checked by hand against a deliberately lowered baseline (65.7 % regression reported, exit code 1). Run it on a branch that touches the ingest path with `gh workflow run bench-gate --ref <branch>`.

The gate prevents regressions; it does not mean the budget is met. The design budget (under 2 KB per message excluding body buffers) is **not** met: about 16.6 KB in `SubmitAsync` alone and about 33 KB per message end to end. It also does not cover the delivery path, PostgreSQL, throughput or latency.

### The throughput run

`gh workflow run bench-throughput --ref <branch>` (inputs: messages per run, runs per configuration, PostgreSQL on or off, ReadyToRun measurement on or off). Configurations: SQLite non-durable (`Sqlite:SyncMode=Off`, the default) and its durable pair (`Full`), `StatsOnly` history, SQLite with delivery to the counting sink (end-to-end recipients per second), and PostgreSQL 17 in a container on the same machine, durable and with `synchronous_commit=off`. The summary starts with the label **"GitHub-hosted ubuntu-latest 2-core runner, noisy, not publishable"** and prints the core count the process actually saw. The load generator, the server, the sink and the database share one machine that other jobs also share, so the numbers are for trends and for catching order-of-magnitude mistakes. They break fairness rules 1, 3, 6 and 9 (no pair on identical quiet hardware, no baselines, one noisy run set, no disk published) and must not be quoted or compared with other servers.

## Baseline comparison: Postfix and KumoMTA (`bench/compare`)

`bench/compare/compose.yaml` is the reproducible comparison setup the fairness rules ask for (rule 7): EggMail (the released image), a Postfix built from Debian's package and KumoMTA, driven by the same load generator (`mta-tools load`) into the same sink (`mta-tools sink`, optional back-pressure) on one private network, one system at a time (Compose profiles). The header of the file has the exact commands, the durable and non-durable switch of each system (EggMail `Sqlite:SyncMode`, Postfix tmpfs queue, KumoMTA spool flush) and the caveats that must accompany any number: the two baselines take unauthenticated mail without TLS on the private network while EggMail requires STARTTLS and AUTH, so the comparison favours them slightly.

**Status: written, never run.** Docker is not used on the development machine and the owner runs the comparison by hand on a quiet Linux host. The EggMail path (provisioning script) was exercised against a locally running server; the Postfix configuration and the KumoMTA policy were written from the documentation of the two projects and will probably need small fixes on the first run (the KumoMTA image tag is not pinned, option names must be checked against the pinned version). Haraka, Stalwart and mox are not included (cut order).

## CI trend numbers (2026-10-13)

**GitHub-hosted ubuntu-latest 2-core runner, noisy, not publishable.** (Measured on a runner whose process saw 4 logical cores, Ubuntu 24.04, .NET 10.0.12; the label above is the one the workflow prints. The load generator, the server, the counting sink and PostgreSQL 17 in a container all share that machine, and so do the other jobs of the host.) One manual run of `bench-throughput` ([run 38427180654](https://github.com/eggspot/EggMail/actions/runs/38427180654)), pipeline harness, 2 KB messages, 16 connections, TLS and AUTH on, `History:Mode=Full` unless stated, median of 3 runs (range in brackets):

| Configuration | Ingest msg/s | p50 / p99 ms | Alloc B/msg | CPU ms per 1000 msg |
|---|---:|---|---:|---:|
| SQLite `Sqlite:SyncMode=Off` (the default, non-durable) | 7,184 (6,493-7,499) | 1.96 / 4.92 | 32,713 | 354 |
| SQLite `Sqlite:SyncMode=Full` (its durable pair) | 2,806 (2,447-2,883) | 4.80 / 20.2 | 32,592 | 417 |
| SQLite `Off`, `History:Mode=StatsOnly` | 9,386 (9,266-9,548) | 1.42 / 4.26 | 18,413 | 262 |
| SQLite `Off`, application assemblies precompiled with ReadyToRun | 7,488 (7,342-7,526) | 1.89 / 4.56 | 32,490 | 341 |
| PostgreSQL 17, default durability (WAL synced at commit) | 3,222 (3,140-3,304) | 4.13 / 14.4 | 37,828 | 430 |
| PostgreSQL 17, `synchronous_commit=off` (its non-durable pair) | 3,426 (3,202-3,702) | 3.93 / 17.6 | 37,982 | 469 |
| SQLite `Off`, with delivery to the counting sink (10,000 messages): ingest | 1,845 (1,834-1,915) | 7.81 / 18.2 | 101,034 | 1,800 |
| ... the same, end to end | 1,642 recipients/s until the sink had them all | | | |

How little these numbers can be trusted: the same SQLite `Off` configuration measured 4,114, 5,027 and 7,184 msg/s in the three runs of this workflow done on 2026-10-13 (different runner instances), and the same code on a 10-core laptop gave 1,400 to 6,100. Only the allocation columns are stable (within about 1 % across runs), which is why the regression gate uses them. Read the table for shape, not for values: SQLite `Off` is faster than `Full` and PostgreSQL on this runner; `StatsOnly` is about 30 % faster than `Full` history; `synchronous_commit=off` did not help PostgreSQL measurably here (the runner's disk is fast and the load generator is probably the limit); the durable SQLite row is not comparable with the PostgreSQL durable row (different fsync behaviour, different storage). Nothing here is a claim about being the fastest, and no other server was run on the same machine.

## Pipeline harness and first profile (2026-10-13)

`bench/Mta.Bench.Pipeline` runs the real runtime in one process (SMTP ingest, storage, DKIM signing at delivery, delivery engine), a counting sink as the remote MTA and the separate-process load generator (`mta-tools load`) as the client:

```
dotnet build -c Release src/Mta.Tools
dotnet run -c Release --project bench/Mta.Bench.Pipeline -- --sync off --history full --messages 30000 --connections 32 --size 2048 --deliver false
dotnet run -c Release --project bench/Mta.Bench.Pipeline -- --sync full --messages 10000 --deliver true      # durable pair, with delivery to the sink
# --backend postgres (EGGMAIL_BENCH_POSTGRES=<connection string>), --history statsonly, --content false, --alloc-profile true
```

**These are development-time observations, not results.** They were taken on one 10-core macOS laptop while other builds and test runs were using the same machine, so throughput varies by a factor of two between runs of the same configuration; macOS `fsync` is weaker than on Linux, so the `Full` rows are optimistic. Do not quote them. The harness exists so the real measurements can be made on a quiet Linux host and published as durable/non-durable pairs per backend (fairness rules above).

What the first runs were good for was finding allocation hot spots with the built-in sampler (`--alloc-profile true`, runtime `GCAllocationTick` events):

| Finding | Effect | Status |
|---|---|---|
| The sender check read the tenant's domains with an EF query per message | about 66 KB allocated per message (of 104 KB) | fixed: cached for 5 s in `SubmissionService` (a domain that is added, verified or paused takes effect within that time) |
| Header repair copied the message three times | about 4 KB per 2 KB message | fixed: one editor pass including the `Received` field |
| The delivery path created an EF context (and its service scope) for every config read, for example the suppression check per recipient | about 40 KB per message end to end (148 KB down to 109 KB) | fixed for SQLite: config reads use pooled contexts (`ConfigReadContext`); the PostgreSQL provider still creates a context per read |
| Content extraction for history (`History:Mode=Full`, `Content:Mode=Retain`) | roughly halves ingest throughput in the quick runs | open: extraction runs inline in the SMTP session; moving it off the accept path or limiting it is an option |
| `Microsoft.Data.Sqlite` parameter binding | about 10 % of ingest allocations | open |

Current budget status: the design budget of under 2 KB per ingested message excluding body buffers is **not met** (about 22 to 36 KB per 2 KB message depending on history mode, measured as total process allocation per message). It is a gate to close, not a claim.

Per-step allocation of the ingest path (`dotnet run -c Release --project bench/Mta.Bench.Pipeline -- --micro true`, 2 KB message): `MimeMessage.Parse` 1.5 KB, header editing 6.3 KB, content extraction for history 5.5 KB, whole `SubmissionService.SubmitAsync` 19.6 KB. The message is parsed three times per submission (sender check, editor, extractor); parsing once and sharing it is the next saving. The 2 KB budget remains unmet.
