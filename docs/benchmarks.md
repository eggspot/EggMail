# Performance measurement plan

EggMail's primary goal is to be the fastest SMTP server. This document defines what that claim means and how it will be measured. **No measurements exist yet.** All targets are proposals to be tuned after the first runs. Claim "fastest" only once an independent run reproduces it.

## Scope of the claim

"Fastest" means **SMTP ingest (accept) throughput and latency**, reported separately from outbound delivery. Do not mix vendor outbound figures with our ingest numbers. (For reference, KumoMTA's published rate is for outbound delivery to a sink: about 3.3M × 100 KB messages/hour on 8 cores.)

## Metrics

- Accepted messages/s and MB/s, measured when the `250` after end-of-data returns
- p50 and p99 transaction latency
- Connections/s, with and without TLS
- RSS, and memory per idle connection
- CPU per 1,000 messages
- Allocations per message

Lite mode additionally reports `lite_commit_latency_ms`, `lite_writer_batch_size`, `lite_writer_queue_depth` and WAL size, which also feed the dashboard's storage-pressure indicator.

## Targets (proposed)

| Budget | Target |
|---|---|
| Allocation per ingested message, excluding body buffers | under 2 KB |
| Memory per idle connection | under 8 KB without TLS, under 40 KB with TLS |
| p99 command latency, local | under 1 ms |
| Ingest, non-durable | at least 5k msg/s per core |
| Outbound to a sink | at least 3k msg/s per core |
| Gen2 GCs at steady load | essentially none |
| EF Core database layer | no more than about 20 KB per database round trip, amortized over batches of tens to hundreds of rows |

The 2 KB budget applies to the SMTP/protocol path; EF costs several KB per operation even when tuned, hence the separate database budget. The Lite ceiling is expected to be thousands of messages/s on local NVMe and hundreds on cloud block storage, which is an **inference to be measured**; no credible published SQLite commit rate was found.

## Fairness rules

1. **Report durable and non-durable results as a pair.** Durable means fsync (or equivalent commit) before the `250`. Never compare one durable result against another system's non-durable one.
2. Known baseline behavior: Postfix fsyncs queue files; KumoMTA's spool flush defaults to `false`; Haraka's behavior is **unverified**.
3. Baselines run on **identical hardware under our own harness**. Do not cite vendor numbers as baselines (Haraka, for example, claims only "thousands of messages per second" without a benchmark).
4. Use a sink that creates back-pressure. KumoMTA's testing docs warn that discard-everything sinks distort results.
5. Never test against the public internet.
6. Publish results per release with hardware, message size, concurrency and GC mode, using the **median of at least 3 runs**.
7. Include a reproducible compose setup in the repository.

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
- CI regression gate on the micro-benchmarks and budgets (about 2.5 engineer-weeks for harness, generator, baseline compose and gate; see [plan.md](plan.md)).

## Workload parameters to publish and vary

Message size, concurrency, TLS on/off, pipelining on/off, recipients per message, durable vs non-durable commit, Full vs Lite, `Lite:SyncMode`, GC mode (workstation non-concurrent vs server with DATAS; the choice is to be made from these benchmarks).

## Unverified

- SQLite commit rate on SSD with `synchronous=FULL` (one search snippet claimed about 442 inserts/s WAL+FULL vs 33k/s NORMAL; unopened and not our workload)
- Haraka's ingest behavior and fsync policy
- All numeric targets above (proposals)
