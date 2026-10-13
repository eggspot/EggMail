# Performance measurement plan

EggMail's primary goal is to be the fastest SMTP server. **Performance is a permanent first-class goal on both storage backends:** the SQLite backend is engineered for large, high-throughput workloads and is not treated as a toy. Because the backends are feature-identical (they differ only in how data is stored), both are benchmarked and optimized **separately on the identical feature set**: same protocol features, same history level, same settings, each backend with its own results, regression gate and budgets. "Lite" and "Full" below are the two backends' default deployment shapes (SQLite and PostgreSQL); they have identical behavioural defaults, including `History:Mode=Full`. This document defines what that claim means and how it will be measured. **No measurements exist yet.** All targets are proposals to be tuned after the first runs. Claim "fastest" only once an independent run reproduces it.

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
- CI regression gate on the micro-benchmarks and budgets, run for both backends (about 2.5 engineer-weeks for harness, generator, baseline compose and gate; see [plan.md](plan.md)).

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
