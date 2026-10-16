# Offline test coverage

What the test suite proves without the real internet, a real CA, real hardware or wall-clock time, and what it cannot. Each section states both sides.

## Accelerated lifecycle and leaks

**This does not replace a wall-clock 7-day soak.** [soak.md](soak.md) runs the real process under load for hours, and a multi-day run of the real process is still to be made. These tests answer a narrower question: *if the clock moves through days, weeks or a year, does every time-driven rule fire at the instant it documents, on both storage backends, without losing data, leaking state or growing without bound?* Time is a virtual clock (`IClock`; decision 73), so a test that covers 450 days takes seconds and asserts no elapsed time.

Run the family with `dotnet test --filter "FullyQualifiedName~Lifecycle"` (or `~Leak`) in `Mta.Storage.Tests`, `Mta.Storage.Sqlite.Tests`, `Mta.Storage.Postgres.Tests`, `Mta.Host.Tests`, `Mta.Tls.Tests`, `Mta.Dns.Tests` and `Mta.Integration.Tests`. PostgreSQL scenarios use `EGGMAIL_TEST_POSTGRES` or a throwaway local cluster and are skipped when neither exists. Two environment variables apply to all of them (`tests/Support/Accelerated.cs`):

| Variable | Meaning |
|---|---|
| `EGGMAIL_ACCEL_SCALE` | Integer multiplier (default 1) of iteration counts and virtual spans. The defaults are sized for the CI runner (seconds per test); use 10 or more locally, and about 25 for the 10,000-iteration runtime and PostgreSQL leak flows |
| `EGGMAIL_ACCEL_SEED` | Replays a randomized interleaving. Every randomized test logs its seed and, on failure, its operation trace |

### What is covered

| Area | Where | What is asserted |
|---|---|---|
| Retention over many days, History:Mode Full and StatsOnly, `0` = unlimited | `LifecycleConformance.*` (`Mta.Storage.Tests/Conformance`), derived for InMemory, SQLite (sync Off with a tiny delete batch, default batch, Normal, Full) and PostgreSQL | Metadata, content, retained raw, webhook outbox and attempt log, idempotency keys, hourly and daily statistics (30/400 days), the recent-events ring are removed exactly at their boundary, never earlier, checked against an independent model and on the physical rows of the files and tables; deferred, leased and unfinished-spool rows are never touched; the other tenant is untouched; a guard test fails when a maintenance job appears that the suite does not know |
| Statistics rollup | same | Hourly to daily per completed day, idempotent re-runs, stable daily top-N, totals correct across the 400-day boundary, a maintenance gap longer than the hourly retention loses no daily row |
| PostgreSQL partitions | `PostgresLifecyclePartitionTests` | Created ahead, detached then dropped at retention, a plateau of partition count over virtual months, a rotation interrupted between detach and drop completes on the next run, replicas maintaining at once |
| SQLite deletes and file size | `SqliteLifecycleFileTests` | Batched deletes make progress across runs and interleave with intake and claims; the file size stops growing in steady state |
| Queue lifetime, store level | `LifecycleConformance.Queue` | The full retry schedule (2m, 5m, 15m, 30m, 1h, 2h, 4h, then every 4h) up to the 5-day expiry; expiry claimed exactly once with several sweepers and replicas; lease and release cycles flag `possible_duplicate` without counting attempts |
| Queue lifetime, engine level | `EngineLifecycleTests` (`Mta.Integration.Tests`), SQLite and PostgreSQL | The real delivery engine and processor: the ladder with its jitter bounds, exactly one expiry notice (also across a crash between the notice and its record, across restarts, with two processes), stats and webhook event once, `possible_duplicate` rules, quiesce and resume keep the ladder position, a remote that is down for days, a recipient mix reaches one final state each |
| Webhooks | `LifecycleConformance.Webhooks`, `WebhookLifecycleTests` | The ladder (5 s, 5 m, 30 m, 2 h, 5 h, 10 h, 10 h) at exact instants, 410 disables, auto-disable after 5 days of continuous failure and not with interleaved successes, one `webhook.endpoint.disabled` notice, re-enable and replay, outbox cleanup incl. `0`, the SSRF guard judged again at each attempt |
| Sending limits and warm-up | `SendingLimitsLifecycleTests`, `SendingStateLifecycleTests` | The warm-up ramp day by day, counter windows at the exact hour, midnight, month, year and leap-day ticks, throttle and breaker recovery, counters across restarts and crashes on SQLite and PostgreSQL against a model |
| Certificate renewal | `AcmeRenewalLifecycleTests` | 430 virtual days with an **in-process fake CA**: lifetime rule, ARI window with a seeded random, minimum-age floor, back-off 10 min to 6 h, a multi-day CA outage, two replicas with the lease lock, hot reload by polling; the certificate never expires un-renewed while the CA answers; the number of orders is bounded |
| Backups | `BackupLifecycleTests` | Six weeks: exactly N kept, oldest removed first, unrelated files and directories untouched, interrupted and failed backups never count or evict |
| Keys and sessions | `DkimRotationLifecycleTests`, `VerpKeysLifecycleTests`, `AuthLifecycleTests`, `AuthStateLifecycleTests`, `ThrottleLifecycleTests` | DKIM pending, active, retired and the selector overlap over a year; VERP tokens valid for 14 days after retirement; session absolute (12 h) and idle (2 h) expiry; auth throttle lockout windows incl. the shared store |
| Domain re-verification | `DomainReverificationLifecycleTests` | Check cadence over 90 days, temporary_failure after the confirmation window, failed and sending paused after 72 h, recovery, no check storm |
| TLS-RPT, MTA-STS, DNS | `TlsRptLifecycleTests`, `MtaStsLifecycleTests`, `DnsCacheLifecycleTests` | One report per policy domain and UTC day, the retry schedule and the 6th-attempt rule, restart keeps the journal; policy cache until `max_age`, id change refetches, bounded size; DNS TTL clamps, no stale answer, bounded cache |
| Crash and restart loops | `CrashLoopLifecycleConformance` + SQLite, PostgreSQL, process-kill, memory-queue, outage and `RuntimeCrashLoopLifecycleTests` | Seeded random interleavings of intake, claims, outcomes, lease expiry, cancel, stats, webhooks, config writes and maintenance with the storage or the whole runtime killed and reopened over the same files or database: no acknowledged message lost, one final state per recipient, duplicates only flagged `possible_duplicate`, idempotency keys and acknowledged config writes survive, stats never double counted; on PostgreSQL an operation cut by a connection loss is all or nothing and raises `StorageUnavailableException` without hanging |
| Resource leaks | `Mta.Host.Tests/Leaks`, `tests/Support/LeakProbe.cs` | After warm-up, no growth between batches (B2 to B3, after forced GC) in managed heap (generous tolerance), threads, file descriptors, timers, pending thread-pool work, outstanding `ArrayPool` rentals, prepared SQLite statements, server connections of the PostgreSQL test database and metric series, for storage on all backends, DNS, SMTP sessions with and without STARTTLS, the connection pool, DKIM and MIME, the real runtime (submit, deliver, record, webhook), API requests and config refresh; the probe is itself shown to catch seven kinds of deliberate leak |

### Real bugs these tests found and fixed

- `AcmeRenewalService` built its lease owner from the first 12 hex digits of a UUIDv7 (the millisecond timestamp), so two replicas starting in the same millisecond shared an owner and could both renew.
- An interrupted or failed SQLite backup left a directory that counted as the newest backup (postponing the next one and evicting good ones); a backup dated in the future blocked all backups. Backups are now written to a `.partial` name, renamed when complete, and future-dated ones are ignored.
- `VerpKeyStore`: replicas starting together on an empty store each created a VERP key and the later write won, so bounces arriving at the other replica were ignored. The key is now created under a lease.
- PostgreSQL: a partition detached but never dropped (rotation interrupted) was never dropped.
- A crash between queueing the expiry notice and recording the expiry produced a second notice; notices now carry an idempotency key.
- A cancelled outbound SMTP connection waited 5 s for the reply to QUIT (every connection cut by a quiesce or shutdown).
- `webhook.endpoint.disabled` was sent once per failing item of the endpoint instead of once.
- The SMTP server kept a 2 s timer alive after every closed session.
- `GET /messages/{id}` answered 500 for ids whose time field is outside the supported range (about one random GUID in ten).

### What is NOT proven

- **Real wall-clock behaviour.** No test sleeps or measures time. The real `PeriodicTimer` loops (maintenance, flush, certificate poll, backup check, verification poll, delivery idle poll) are stepped by calling their passes directly; their cadence, drift, and a clock that steps (NTP, suspend) are not exercised. A slow leak below the per-batch tolerance is invisible (about 100 bytes per iteration for heap at the default scale; a single file descriptor or thread leaked once in about 100 iterations is below the tolerance). Only a long run of the real process finds those ([soak.md](soak.md)).
- **OS-level leaks under real load**, kernel and socket-buffer behaviour, and fragmentation of the managed heap over days.
- **Power loss and OS crashes.** A crash here is a dispose without flush, an abandoned connection, or (for a few SQLite cycles) a real `SIGKILL` of a child process. `synchronous=OFF` corruption after a power loss is not exercised.
- **Real network faults.** `TcpProxy` gives a clean close or refusal; there are no half-open connections, partial packets, resets in the middle of TLS, or slow links. SMTP client timeouts are real-time and are covered only through cuts.
- **Real external systems.** The CA is an in-process fake (the Pebble tests cover the protocol), DNS, HTTPS and the remote MTAs are fakes.
- **A kill inside a SQLite transaction or between its files** beyond what the real child kill produces; several PostgreSQL replicas killed at once; the PostgreSQL scale of production (tests use PostgreSQL 16 locally and 17 in CI, small data).
- **Inbound mail.** Only the in-memory implementation of the inbound storage exists on main when these tests were written, so inbound retention and the inbound lifecycle are not covered on SQLite and PostgreSQL yet.
- Findings noted, not changed: API keys have no expiry field; a VERP key is never pruned (an operator must keep a retired key at least 14 days); after a DKIM rotation the switch waits for the next daily check unless "Verify now" is used (asserted at most 25 hours); the circuit breaker keeps an entry for a host that failed and is never contacted again (bounded by the number of hosts); EF Core rents an `ArrayPool` array per query without returning it (excluded from the pool balance check by stack).
