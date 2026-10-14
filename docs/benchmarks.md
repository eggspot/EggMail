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

The SQLite backend additionally reports `sqlite_commit_latency_ms`, `sqlite_writer_batch_size`, `sqlite_writer_queue_depth` and WAL size, which also feed the dashboard's advisory storage-pressure indicator (advisory only; backend switching is manual). They are exported as `mta_storage_sqlite_commit_duration_seconds` (a histogram in seconds), `mta_storage_sqlite_writer_batch_size`, `mta_storage_sqlite_writer_queue_depth` and `mta_storage_sqlite_wal_size_bytes`, per database file ([operations.md](operations.md#monitoring)). The PostgreSQL backend additionally reports round trips per message, claim latency, WAL volume and connection-pool saturation; command latency and pool saturation are exported from the driver (`db_client_operation_duration_seconds`, `db_client_connection_count` against `db_client_connection_max`) and claim latency as `mta_delivery_claim_duration_seconds`. Round trips per message and WAL volume are not metrics; they are measured by the benchmark harness.

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

- **Per step (exact).** `--micro true --json`: bytes per call of `MimeMessage.Parse`, the header editor, content extraction, address parsing, id and address parsing, and the whole `SubmissionService.SubmitAsync` (in-memory storage, `History:Mode=Full`), measured with `GC.GetAllocatedBytesForCurrentThread`. Repeatable to the byte (identical on a laptop and on the CI runner: 10,760 B for `SubmitAsync` with in-memory storage and a 2 KB message). **Threshold: +5 %.**
- **Per accepted message through the real runtime.** 20,000 messages of 2 KB over 8 connections with the load generator, SQLite, `Sqlite:SyncMode=Off`, `History:Mode=Full`, no delivery, total process allocation divided by accepted messages. It includes background work (batched writers), so it varies by about 2 % between runs of the same code (33.0 to 33.8 KB in three laptop runs of the code at the time although throughput differed by 4x; 11.2 KB on the CI runner after the allocation work of decisions 64 to 68). **Threshold: +10 %.**

A value above the baseline plus the threshold fails the workflow (the summary table names the measurement). A value more than the threshold below the baseline is reported as "improved (update the baseline)" and does not fail. To accept a deliberate change, copy `bench-candidate.json` from the run's artifacts over `bench/baseline/allocations.json` in the same pull request and fill in `recordedOn`. The comparison logic was checked by hand against a deliberately lowered baseline (65.7 % regression reported, exit code 1). Run it on a branch that touches the ingest path with `gh workflow run bench-gate --ref <branch>`.

The gate prevents regressions; it does not mean the budget is met. The design budget (under 2 KB per message excluding body buffers) is **not** met (see decision 67 for what "excluding body buffers" means): about 10.8 KB in `SubmitAsync` alone and about 11.2 KB per message end to end at the time of the baseline. It also does not cover the delivery path, PostgreSQL, throughput or latency.

### The throughput run

`gh workflow run bench-throughput --ref <branch>` (inputs: messages per run, runs per configuration, PostgreSQL on or off, ReadyToRun measurement on or off). Configurations: SQLite non-durable (`Sqlite:SyncMode=Off`, the default) and its durable pair (`Full`), `StatsOnly` history, SQLite with delivery to the counting sink (end-to-end recipients per second), and PostgreSQL 17 in a container on the same machine, durable and with `synchronous_commit=off`. The summary starts with the label **"GitHub-hosted ubuntu-latest 2-core runner, noisy, not publishable"** and prints the core count the process actually saw. The load generator, the server, the sink and the database share one machine that other jobs also share, so the numbers are for trends and for catching order-of-magnitude mistakes. They break fairness rules 1, 3, 6 and 9 (no pair on identical quiet hardware, no baselines, one noisy run set, no disk published) and must not be quoted or compared with other servers.

## Baseline comparison: Postfix and KumoMTA (`bench/compare`)

`bench/compare/compose.yaml` is the reproducible comparison setup the fairness rules ask for (rule 7): EggMail (the released image), a Postfix built from Debian's package and KumoMTA, driven by the same load generator (`mta-tools load`) into the same sink (`mta-tools sink`, optional back-pressure) on one private network, one system at a time (Compose profiles). The header of the file has the exact commands, the durable and non-durable switch of each system (EggMail `Sqlite:SyncMode`, Postfix tmpfs queue, KumoMTA spool flush) and the caveats that must accompany any number: the two baselines take unauthenticated mail without TLS on the private network while EggMail requires STARTTLS and AUTH, so the comparison favours them slightly.

**Status: written, never run.** Docker is not used on the development machine and the owner runs the comparison by hand on a quiet Linux host. The EggMail path (provisioning script) was exercised against a locally running server; the Postfix configuration and the KumoMTA policy were written from the documentation of the two projects and will probably need small fixes on the first run (the KumoMTA image tag is not pinned, option names must be checked against the pinned version). Haraka, Stalwart and mox are not included (cut order).

## CI trend numbers (2026-10-13)

**GitHub-hosted ubuntu-latest 2-core runner, noisy, not publishable.** (These runs predate the allocation work of decisions 64 to 68, so the allocation column is that of the earlier code. Measured on a runner whose process saw 4 logical cores, Ubuntu 24.04, .NET 10.0.12; the label above is the one the workflow prints. The load generator, the server, the counting sink and PostgreSQL 17 in a container all share that machine, and so do the other jobs of the host.) One manual run of `bench-throughput` ([run 38427180654](https://github.com/eggspot/EggMail/actions/runs/38427180654)), pipeline harness, 2 KB messages, 16 connections, TLS and AUTH on, `History:Mode=Full` unless stated, median of 3 runs (range in brackets):

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

Current budget status: the design budget of under 2 KB per ingested message excluding body buffers is **not met** (about 22 to 36 KB per 2 KB message depending on history mode, measured as total process allocation per message). It is a gate to close, not a claim. *(First round; superseded by the second round below, which also covers the delivery path.)*

Per-step allocation of the ingest path (`dotnet run -c Release --project bench/Mta.Bench.Pipeline -- --micro true`, 2 KB message): `MimeMessage.Parse` 1.5 KB, header editing 6.3 KB, content extraction for history 5.5 KB, whole `SubmissionService.SubmitAsync` 19.6 KB. The message is parsed three times per submission (sender check, editor, extractor); parsing once and sharing it is the next saving. The 2 KB budget remains unmet. *(Done in the second round, below.)*


## Allocation work, second round (2026-10-13)

Parse once, native SQLite statements, and a pass over the delivery path. Everything below was measured with the harness in `bench/Mta.Bench.Pipeline` on one 10-core Apple-silicon laptop that was **shared with other builds and test runs throughout** (the load average was between 13 and 40 for the whole session). **Allocation figures are exact and repeatable** (bytes counted by the runtime, no sampling). **Time and throughput figures are not** exact: in the first, shared window they moved by a factor of two or three between runs of the same build; the throughput table below comes from a second, quiet window with six alternating runs of each build, and is still not a result. Dev-machine observations, not claims; the publication rules above still apply.

"Before" is `main` at commit `0cab93f` built and run with the same harness (its harness was patched only to print the same columns). "After" is this branch.

### What the budget measures

The design budget is "under 2 KB per ingested message, excluding body buffers". The following are counted as body buffers because their size is the size of the message and the protocol path cannot avoid them: the stored copy of the message (one array of the message size plus the server-added `Received` field), the history copy of the text and HTML bodies as .NET strings (two bytes per character; only with `History:Mode=Full` and `Content:Retain`), and on delivery the message read back from the spool (one array). Everything else counts. Because those are proportional to the message, the fixed cost is measured with a message that has almost no body ("tiny", 214 bytes with its headers) next to the 2 KB one.

### Ingest, per step (`--micro true`, bytes allocated per operation; before to after)

| Step | Before | After | What changed |
|---|---|---|---|
| `MimeMessage.Parse` (2 KB message) | 1,536 | 672 | header array sized for the block; the Content-Type and Content-Transfer-Encoding values are read from the bytes without building the value string; shared strings for the media types, parameter names and charset names every message uses; a reusable work list for parameters; 32-byte header records |
| Sender check (`From` header to domain) | 864 | 80 | a single address, with or without a plain display name, is answered from its bytes; anything else (quotes, comments, encoded words, groups, folding, non-ASCII) goes through the full address parser; a differential test compares both on 40,000 generated values |
| Header repair (remove Bcc, add Message-ID and Date, prepend Received) | 3,232 | 2,256 to 2,672 | lazy lists, the `Received` field is referenced instead of copied, no rule object when there is no Bcc; the rest is the 2.1 KB stored message |
| Content extraction for history | 5,424 | 3,808 | works on the parse already made (1.5 KB of the old figure was a second parse); the rest is the 3.6 KB text string |
| `SubmissionService.SubmitAsync`, InMemory, 2 KB / tiny | 16,619 / 8,576 | 10,464 / 3,272 | parse once, no LINQ or closures in the path, in-memory intake without LINQ |
| `SubmissionService.SubmitAsync`, SQLite, one caller, 2 KB / tiny | 26,621 / 19,403 | 10,358 / 4,967 | native statements, see below |
| `SubmissionService.SubmitAsync`, SQLite, 32 concurrent callers (group commit), 2 KB / tiny | 24,098 / 16,873 | 7,878 / 2,585 | the same |

Wall time per message in the same micro-benchmark (fastest of three passes, shared machine): SQLite with 32 callers 24.2 us to 18.5 us (2 KB) and 17.5 us to 15.1 us (tiny); one caller 126 us to 88 us (2 KB) and 97 us to 89 us (tiny); InMemory unchanged (7.2 us and 3.4 us; that backend is dominated by its own bookkeeping).

### The SMTP server alone (`--sink-only true`: plain text, no storage, no TLS, no authentication)

4,058 B/message to **1,090 B/message** (2 KB message). What changed: pooled async state machines on the session's `ValueTask` methods; one `Received` builder per session that caches the parts that only change with the greeting name, the TLS state or the authenticated user (the field is written into one exactly sized array instead of through three strings and two builders); the message handed to the handler as a single-segment sequence; the discard writer created only when needed; no enumerators over the reply list; MAIL and RCPT paths decoded in stack memory. This is under the 2 KB budget.

### The whole pipeline (SQLite, `Sqlite:SyncMode=Off`, `History:Mode=Full`, 32 connections, one recipient, authenticated; process allocation per message)

| | Before | After |
|---|---|---|
| Ingest, 2 KB, STARTTLS and AUTH (`--tls true`) | 33.4 KB | **11.0 KB** |
| Ingest, 2 KB, plain text (`--tls false`) | not measurable (the old harness always used TLS) | 10.3 KB |
| Ingest, 200-byte message, plain text | not measurable | **4.8 KB** |
| Delivery to a sink MX, per recipient (`--split true`, DKIM signing on) | 66.0 KB | **25.5 KB** |

Throughput and CPU, measured in a second, quiet window (six alternating before/after runs of `--sync off --history full --messages 30000 --connections 32 --size 2048 --deliver true --split true`, so ingest and delivery are each measured alone; the machine had no other significant load at the start, its one-minute load average was 2.3 before the first run and rose to about 14 by the last, which is mostly the harness itself: ten cores, 32 connections, 64 delivery workers):

| | Before, six runs | After, six runs | Median change |
|---|---|---|---|
| Ingest, msg/s | 14.9k, 16.7k, 14.8k, 15.7k, 15.7k, 16.0k (median 15.7k) | 16.0k, 18.0k, 17.0k, 17.2k, 17.1k, 17.6k (median 17.2k) | +9 % |
| Ingest, process CPU ms per 1,000 messages | 328, 304, 332, 331, 320, 318 (median 324) | 294, 300, 299, 295, 306, 303 (median 300) | -8 % |
| Delivery, recipients/s | 4,224, 4,248, 4,204, 4,151, 4,213, 4,192 (median 4,208) | 4,614, 4,540, 4,487, 4,392, 4,546, 3,471 (median 4,513) | +7 % |
| Delivery, process CPU ms per 1,000 messages | 2,007, 1,965, 1,932, 1,981, 1,946, 1,970 (median 1,967) | 1,862, 1,875, 1,876, 1,848, 1,869, 1,819 (median 1,866) | -5 % |

The allocation figures are identical from run to run; the throughput ranges of the two builds overlap slightly for ingest (before up to 16.7k, after from 16.0k) and the medians differ by 9 %. Delivery is bound by RSA-2048 signing (about 0.83 ms of the 1.8 ms CPU per message), and one after-run (3.5k) shows what a disturbed run looks like. An earlier set of runs on the same machine under a load average of 13 to 40 (other builds and tests running) gave ingest 13.4k, 14.6k, 15.0k before and 5.2k, 17.9k, 8.4k after: nothing can be concluded from runs taken while the machine is shared, and they are not used. These are still one laptop, loopback and a counting sink: the direction (fewer bytes, less CPU, no regression) is supported by these runs, the size of the gain is not a published result.

### Where the remaining ingest allocation goes (plain text, tiny message, SQLite: 4.8 KB)

About 1.1 KB is the SMTP session (`SmtpMessage`, `MailFromInfo`, the recipient array, the `Received` array, the reply, pooled state machines that miss the pool under concurrency, the strings of the two `EmailAddress` values). About 2.5 KB is `SubmitAsync` and the storage intake: the parse tree (about 0.7 KB: `MimeMessage`, `MimePart`, `HeaderList`, `ContentType`, the header record array), the extracted content record and its strings, `SubmissionRequest`, `AcceptedMessage` and the recipient array, two writer commands (queue and history) with their states, the stat key, the Message-ID string kept for history, and the strings the history row needs. The rest is the handler, authentication state and the reply text.

**The 2 KB budget is not met for the whole path**: 4.8 KB with a tiny body (about 4.2 KB once the unavoidable per-message copies are taken out) and 10.3 KB with a 2 KB body, of which 5.7 KB are the two body copies. The SMTP protocol path alone is under it (1.1 KB). Getting the rest under 2 KB means removing about 2 KB more, and what is left is structure, not tuning: a reusable parser context instead of a fresh object graph per message (about 0.6 KB), a cache of parsed `EmailAddress` values per session (about 0.15 KB), pooled writer commands (about 0.25 KB), one object for the request and the accepted message (about 0.3 KB), and giving history the body as UTF-8 bytes instead of a string. Each is an API change across packages and none was done in this round. The budget is **not revised**; 4.8 KB is the floor of the current design, not a new target.

### Delivery path, per delivery (`--micro-delivery true`; SQLite, bytes allocated; before to after)

| Step | Before | After | What changed |
|---|---|---|---|
| Suppression check per recipient | 15,270 | 57 | a prepared statement on an open read connection instead of an EF query on a pooled context (EF registered the provider's SQL functions again on every connection open) |
| Read the raw message from the spool | 3,634 | 2,146 (the message itself is 2,009) | the same read sessions |
| Claim (per delivery, batches of 64) | 1,763 | 630 | native statement, no LINQ |
| Record a delivered attempt, one at a time | 12,648 | 4,743 | native statements, pooled state machines |
| Record a delivered attempt, 32 concurrent | 9,853 | 2,204 | the same, shared transaction |
| InMemory claim (4,000 queued) | 90,583 | 378 | one pass for the first `max` due rows instead of a list of all of them |

Inside the processor: no webhook event payload is built for an attempt when no enabled endpoint of the tenant subscribes to the event type (about 6 KB of JSON that the fan-out threw away; the check uses the same endpoint list as the fan-out, so it only says no when the fan-out would have queued nothing); trace lines are formatted only when debug logging is on; no LINQ or closures on the group path; a precomputed `outcome` tag for the attempts counter; pooled async builders on the private methods. In the SMTP client: one reusable timeout source per connection instead of a linked source and a timer for every reply read, MAIL and RCPT lines written into stack memory, a reply parser that reads a line in place and shares the usual enhanced status strings, and the pool key built once per target.

What is still large on delivery (25.5 KB per recipient, of which the 2 KB message array and the sink MX running in this process, about 1.1 KB, are part): the MX lookup per delivery (`MxResolver` builds tasks, lists and arrays for every call; the harness's static resolver adds LINQ of its own), the MTA-STS policy lookup (a task, a timeout source and a continuation per call), the TLS policy decision objects, the VERP envelope sender (a handful of strings), the attempt and history event objects, the JSON of the TLS state stored with every event, the NOOP before and the RSET after every reuse of a pooled connection (two extra round trips and their allocations; protocol behaviour, left as it is), and the DKIM signature header (907 B). These are the next candidates; a short-lived per-domain cache of the resolved MX and the policy decision would remove most of the first three but changes when a DNS change is noticed, so it needs a decision first.

### How to reproduce and profile

```sh
dotnet build -c Release src/Mta.Tools
dotnet run -c Release --project bench/Mta.Bench.Pipeline -- --micro true [--only "SQLite"] [--alloc-profile true]   # per-step ingest allocation and time
dotnet run -c Release --project bench/Mta.Bench.Pipeline -- --micro-delivery true                                   # per-step delivery allocation
dotnet run -c Release --project bench/Mta.Bench.Pipeline -- --sink-only true --messages 40000                       # the SMTP server alone
dotnet run -c Release --project bench/Mta.Bench.Pipeline -- --sync off --history full --messages 20000 --size 2048 --deliver true --split true   # ingest, then delivery, each measured alone
#   --tls false  measures the server without the TLS stack;  --size 200  the fixed cost per message
```

The `--alloc-profile` sampler (one `GCAllocationTick` per about 100 KB) shows types but not who allocated them, and it aliases on a periodic single-thread loop. For attribution with call stacks, record an EventPipe trace of the harness process and aggregate it with `bench/Mta.Bench.AllocStacks` (a developer tool that references the TraceEvent package; it is deliberately **not** in `EggMail.slnx`, so CI neither restores nor builds it and billed minutes are unchanged; `dotnet run --project` builds it on demand):

```sh
DOTNET_EnableEventPipe=1 DOTNET_EventPipeOutputPath=/tmp/pipeline.nettrace DOTNET_EventPipeConfig='Microsoft-Windows-DotNETRuntime:0x39:5' \
  dotnet bench/Mta.Bench.Pipeline/bin/Release/net10.0/Mta.Bench.Pipeline.dll --sync off --history full --messages 8000 --deliver true --split true
dotnet run -c Release --project bench/Mta.Bench.AllocStacks -- /tmp/pipeline.nettrace 4 60 - method      # the first Mta.* frame and the type, by bytes
#   modes: stack (leaf type and its frames), method (above), owner (by type); the optional fourth argument filters the lines
```

Start the application's dll directly (not through `dotnet run`: the SDK host would write into the same trace file); the harness already removes `DOTNET_EnableEventPipe` from the load generator's environment. The aggregation is by bytes: a share times the run's total allocation divided by the message count is the cost per message.
