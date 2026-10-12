# EggMail design

Status: design phase, no code. Source of truth for individual choices is [decisions.md](decisions.md); this document explains how they fit together. Items marked **unverified** were not confirmed against a primary source; defaults marked **proposed** are the design authors' choices.

## 1. Goals and scope

EggMail is an open-source, self-hosted outbound email server: SMTP ingress, HTTP API, delivery tracking, webhooks and a dashboard. Primary goal: the fastest SMTP server, claimed only after reproducible measurement ([benchmarks.md](benchmarks.md)). Target runtime: .NET 10 LTS (supported to 2028-11-14), deployed as a Docker image.

"Fastest" is scoped to **SMTP ingest** (accept) throughput and latency, reported separately from outbound delivery.

**Design principle: performance is a permanent first-class goal in both modes.** Lite is engineered to perform well for large and high-throughput workloads and is not treated as a toy; optimization work applies to Full and Lite alike, and each is benchmarked separately ([benchmarks.md](benchmarks.md)).

## 2. Architecture

### 2.1 Build boundary

Hand-written, using only the BCL and ASP.NET Core shared framework (no package references, enforced by a CI check on `project.assets.json`):

- SMTP server and client: BDAT/CHUNKING, full SMTPUTF8, PIPELINING, SIZE, 8BITMIME, ENHANCEDSTATUSCODES, STARTTLS, AUTH PLAIN/LOGIN
- MIME parse and build
- DKIM sign and verify (RSA-2048 only, `rsa-sha256`)
- SPF, DMARC, DSN/ARF
- DNS client (UDP/TCP wire format, EDNS0, MX/A/AAAA/TXT/TLSA/PTR/CNAME, caching, retries; talks to a local validating resolver)
- MTA-STS, TLS-RPT, DANE
- ARC is optional and deferrable

Allowed libraries elsewhere: Npgsql + EF Core, Microsoft.Data.Sqlite, Certes (ACME), OpenTelemetry with OTLP, ASP.NET Core Data Protection, the dashboard frontend stack, and test tooling (MimeKit and MailKit as test oracles only).

The one carve-out from "no external binaries": DANE uses a local validating resolver (Unbound on loopback), because the DNS client cannot validate DNSSEC and the AD bit is only trustworthy from a local validator.

### 2.2 Indicative solution layout

Carried from the earlier plan with the custom storage engine removed; treat as indicative.

```
src/
  Mta.Core              ids, time, results, options
  Mta.Dns               packet codec + resolver (I/O behind IDnsTransport)
  Mta.Mime              parse/compose, header folding
  Mta.Dkim              canonicalization, sign/verify
  Mta.Auth              SPF / DMARC / ARC
  Mta.Smtp.Protocol     commands, replies, dot-stuffing, state machine (pure, no I/O)
  Mta.Smtp.Server       listeners, sessions, pipelines, STARTTLS
  Mta.Smtp.Client       outbound delivery, connection reuse, MX selection
  Mta.Storage          store interfaces + shared logic
  Mta.Storage.Postgres  EF Core provider (Full)
  Mta.Storage.Sqlite    EF Core provider (Lite)
  Mta.Policy            routing, rate limits, retries, tenancy
  Mta.Observability     metrics, JSON logs, trace context
  Mta.Host              composition root, config, API, dashboard
  Mta.Tools             load generator, sink, crash harness
tests/  bench/
```

Dependencies point downward. The pure libraries do no I/O so they can be fuzzed and benchmarked directly. The package-reference ban applies to `Mta.Smtp.*`, `Mta.Mime`, `Mta.Dkim`, `Mta.Auth` and `Mta.Dns`.

### 2.3 Key interfaces

| Interface | Responsibility |
|---|---|
| `IDnsResolver` / `IDnsTransport` | Resolve with caching; send and receive DNS packets |
| `ISmtpTransport` | Deliver one message to a remote host |
| `IQueueStore` | Enqueue, claim/lease, retry, complete (provider-specific claim SQL) |
| `IMessageBodyStore` | Spool, content and retained-raw tables; partitioning (Full) vs plain DELETE (Lite). Postgres/SQLite implementations only; FS/S3 providers are not built but the interface remains |
| `IEventStore` | Delivery events (Full only; Lite has just the recent-events ring) |
| `IStatsStore` | Hourly/daily counters; one shared implementation using `INSERT … ON CONFLICT DO UPDATE` |
| `ICertificateStore` | Serve certificates, reload on change |
| `ISpfEvaluator`, `IDmarcEvaluator`, `IDkimSigner`, `IDkimVerifier` | Authentication |
| `IRoutingPolicy` | Routing, rate limits, retry schedule per message |
| `IClock` (and file-system seam) | Test seams for time and crash simulation |

### 2.4 Shared vs provider-specific

Shared: SMTP server/client, MIME, DKIM/SPF/DMARC, DNS, scheduler logic, routing and throttling, webhook dispatch, API, auth, tenants, domain verification, dashboard shell and overview, secrets handling, TLS/ACME, observability.

Provider-specific: `IQueueStore`, `IMessageBodyStore`, `IEventStore`, retention jobs, migrations.

Two EF Core providers, one `DbContext`, a separate migrations assembly per provider selected by configuration. Branch on `migrationBuilder.ActiveProvider` for partition DDL, which exists only in the Postgres migration. Isolate provider-specific annotations in a per-provider model hook (the EF docs do not cover them in a shared model; **unverified** which behave). CI runs `has-pending-model-changes` once per provider; `Migrate()` throws on pending changes in EF 9+. The test matrix doubles; SQLite tests are fast and are the default for local development.

## 3. SMTP stack and performance design

- **Pipelines-based server.** Copy Kestrel's zero-byte-read default (`WaitForDataBeforeAllocatingBuffer`) so idle connections hold no buffer; cap read/write buffers explicitly (Kestrel defaults are 1 MiB and 64 KiB). Always call `AdvanceTo(consumed, examined)` and never touch a `ReadOnlySequence` afterwards.
- **DATA path.** Scan for `\r\n.\r\n` incrementally with `SearchValues<byte>`. The body is buffered in memory up to the 25 MiB limit (Lite: 10 MiB) behind a **global in-flight bytes budget**; when exhausted, reply `452`. Objects of 85,000 bytes or more land on the large object heap. Start with EF `byte[]`; use Npgsql directly for the body insert only if profiling shows LOH pressure (owner permission for raw Npgsql is an open question).
- **Smuggling and STARTTLS hardening.** Only `\r\n` ends a line; reject bare CR/LF and NUL with a 5xx and close; end DATA only on `\r\n.\r\n`. On STARTTLS, if the reader holds any bytes beyond the command line, close the connection; rebuild pipes over `SslStream` and reset session state (RFC 3207 §4.2). The client must re-EHLO after TLS and ignore the pre-TLS capability list. The client never emits a bare CR/LF.
- **Group commit.** One writer per database file drains queued commands into one transaction so the per-commit cost (an fsync under `Normal`/`Full`; transaction overhead under Lite's default `Off`) is amortized across many messages. `250` is sent only after the commit returns. In Full, events are buffered in a channel and flushed every few milliseconds; claims fetch N rows per round trip.
- **TLS.** One shared `SslServerAuthenticationOptions` and certificate; stable `TargetHost` on outbound so session resumption works.
- **GC.** Start with workstation non-concurrent GC below 2 cores and server GC with DATAS above; decide from benchmarks.
- **EF Core on the hot path.** Use `AddPooledDbContextFactory` with a short-lived context per batch (never per message, never long-lived in a worker); `AsNoTracking`, `ExecuteUpdate`/`ExecuteSql`, `SqlQuery<T>`, compiled queries for fixed lookups. EF costs several KB per operation even when tuned, so the per-message allocation budget applies to the SMTP/protocol path; the database layer has its own proposed budget (see [benchmarks.md](benchmarks.md)).

## 4. Storage

### 4.1 Full mode (PostgreSQL via EF Core only)

One database, one schema, three roles: **owner** (runs migrations, owns objects), **runtime** (the app; default privileges set with `ALTER DEFAULT PRIVILEGES FOR ROLE <owner>`), and **read-only** (dashboard queries, with `statement_timeout`, e.g. 5 s, and `idle_in_transaction_session_timeout`). One database is kept because a transaction cannot span databases: one transaction writes message, delivery rows, content and event together, and splitting would force an outbox. Minimum PostgreSQL 16; default `postgres:17`. **Managed HA is a deployment prerequisite**; `451` during a database outage is accepted.

Tables:

| Table | Partitioning | Holds / lifetime |
|---|---|---|
| `delivery_queue` | none (live rows only, small) | One row per recipient delivery: id, message_id, recipient, domain, due_at, attempt, lease_owner, lease_until, state, last_error. Row deleted on completion. Own autovacuum settings, lower fillfactor (proposed) |
| `message_spool` | none | Full raw `.eml`, byte-for-byte as accepted, until all recipients are final, then deleted |
| `message_content` | day | Subject, text, html, attachment index (name, type, size), extracted at accept time. Dropped after `Content:RetentionDays` |
| `message_raw_retained` | day | Raw `.eml` including attachments. Only when attachment storage is on; written by moving the spool row at the final state in one transaction |
| delivery events | day | 30 days of metadata |
| webhook, tenant, key, domain, suppression, config tables | none | See §6 |

Rules:

- Retention is partition drop: `DETACH PARTITION … CONCURRENTLY`, then `DROP`. A background in-app job creates partitions ahead under a transaction-level advisory lock (`pg_try_advisory_xact_lock`; session-level locks are incompatible with PgBouncer transaction pooling). `pg_partman` is optional.
- Partition constraints must include the partition key, concurrent detach is not allowed with a DEFAULT partition, and foreign keys into partitioned tables must include the partition key, so references to the big tables are soft. Autovacuum does not analyze partitioned parents; schedule a manual `ANALYZE`. The Npgsql provider has no partition API (efcore.pg#1035), so DDL goes in `migrationBuilder.Sql`.
- **Claim:** native `UPDATE … WHERE id IN (SELECT … FOR UPDATE SKIP LOCKED LIMIT @n) RETURNING …` via `Database.SqlQuery<T>`. Do not compose LINQ over it. A pure-LINQ `ExecuteUpdate` claim (three round trips, loses races under contention) exists only as a test double behind the same interface. **Unverified:** that the Npgsql provider does not wrap `UPDATE … RETURNING` in `SqlQuery<T>`; confirm in a spike.
- **Migrations:** `Mail__Database__Migrate=Auto` by default (EF 9+ takes a database-wide lock, so concurrent startup is safe), or `Never` plus an `mta migrate-db` subcommand and an idempotent SQL script for locked-down setups. Two connection strings: schema owner and runtime.
- **Connections:** Npgsql's default pool is 100 per connection string; set explicit sizes (roughly 8–16 claim workers, 16 API, 8 dashboard, 2 maintenance; proposed) and keep the total across replicas under about half of `max_connections`. Enforce with `ALTER ROLE … CONNECTION LIMIT`.
- **Split later only if** sustained volume exceeds roughly 1M messages/day or WAL exceeds roughly 50 GB/day (move events or bodies to a separate instance, accepting an outbox), a compliance rule needs secrets in a separate store, or analytics load belongs on a replica. These thresholds are unsourced rules of thumb.
- **No blob store.** Filesystem, S3 and R2 providers were dropped; bodies live in Postgres `bytea` and restore together with metadata. `IMessageBodyStore` stays so a provider could be added later (about 12–14 weeks, if volume demands it).

### 4.2 Lite mode (SQLite via Microsoft.Data.Sqlite)

Single node, one replica, multi-tenant, local volume only (WAL does not work on network filesystems). Microsoft.Data.Sqlite 10.0.12 bundles SQLite 3.53.3, so `UPDATE … RETURNING` works; the WAL-reset bug (3.7.0–3.51.2) is fixed in 3.51.3.

**Three database files, each with its own WAL and its own writer:**

| File | Contents | Sync mode |
|---|---|---|
| `queue.db` | Spool bodies, delivery queue, webhook outbox | `Lite:SyncMode`, default **`OFF`** |
| `stats.db` | Aggregates, recent-events ring, webhook attempt log | `Lite:SyncMode`, default **`OFF`** |
| `config.db` | Tenants, API keys, domains, DKIM keys, suppressions, webhook endpoints, Data Protection keys | `Lite:ConfigSyncMode`, default `FULL` (rarely written) |

The `OFF` default for `queue.db` and `stats.db` is **owner-decided**. Keeping `config.db` at `FULL` is the design authors' recommendation (it is rarely written and holds DKIM keys, API-key hashes and the Data Protection key ring, whose loss or corruption would be severe) and **awaits owner confirmation** ([open-questions.md](open-questions.md)).

Separate files keep a stats rollup from stalling queue commits. That independent-writer property is inferred from per-file WALs; no explicit sqlite.org statement was found (**unverified**). SQLite documents that a transaction across several databases in WAL mode is atomic per file but not as a set, so **every cross-file effect must be idempotent and ordered**. Example: on a hard bounce, write the suppression to `config.db` first, then complete the queue row; a crash in between just means the retry bounces again.

**Writer design:** one writer thread per file. Callers submit write commands through a bounded channel and await the result; the writer drains up to N commands or T milliseconds (e.g. 2 ms) into one `BEGIN IMMEDIATE … COMMIT`. Under load, batches grow. The `250` is sent after the commit returns (see "Acknowledgement and sync mode" below for what that does and does not guarantee). Reads use separate short connections. Avoid `Cache=Shared` with WAL; one connection per operation.

**There is no rate limiter in the product.** The only back-pressure is natural: the bounded channel into the writer (SMTP reads slow through TCP flow control) and `452` for disk full.

**Acknowledgement and sync mode (read this before deploying Lite).** The earlier design acknowledged after a `synchronous=FULL` commit and called the queue "durable". The owner chose `PRAGMA synchronous=OFF` as the default for speed, so that wording no longer applies and the term "durable queue" is retired for Lite. Lite's default is **process-crash-safe, not power-loss-safe**:

- `250`/`202` now means the data has been **handed to the operating system**, not synced to disk.
- A **process kill or container restart is safe**: per the SQLite docs, "If the application running SQLite crashes, the data will be safe".
- If the **operating system crashes or the host loses power**, the SQLite docs say that with `synchronous=OFF` "the database might become corrupted", and their durability matrix lists WAL mode with `OFF` as "Not consistent". This is **corruption, not just loss of the last commits**: the whole `queue.db` (all queued mail and the webhook outbox, including mail already acknowledged with `250`) or `stats.db` may be unusable. By contrast, `NORMAL` in WAL mode is documented as safe from corruption but may roll back recently committed transactions, and `FULL` is documented as durable (ACID) in WAL mode. Source: [sqlite.org/pragma.html](https://www.sqlite.org/pragma.html#pragma_synchronous).
- A server that acknowledges `250` takes responsibility for the message (RFC 5321). Under the default, that responsibility is not backed by a disk sync. Operators who need it must opt in to `Normal` or `Full`, or use Full mode (Postgres).

Knobs (names are proposed):

| Knob | Values | Default | Notes |
|---|---|---|---|
| `Lite:SyncMode` | `Off` \| `Normal` \| `Full` | `Off` | Applies to `queue.db` and `stats.db`. `Normal`: WAL synced at checkpoints only, safe from corruption, may lose recent commits on power loss. `Full`: WAL synced on every commit, ACID in WAL mode |
| `Lite:ConfigSyncMode` | `Off` \| `Normal` \| `Full` | `Full` | Applies to `config.db`. Recommendation, pending owner confirmation |
| `Lite:QueuePersistence` | `Persistent` \| `Memory` | `Persistent` | Renamed from the earlier `Lite:QueueDurability = Durable \| Memory` because "durable" is no longer accurate. `Memory` is an explicit opt-in: "accepted means in memory; lost on restart" |

All leases clear on startup (single process) and delivery is at-least-once, so a message in flight at crash time may duplicate.

Cost and benefit versus `Lite:SyncMode=Full` (qualitative; no numbers measured): SQLite documents that commits "can be much faster" with `OFF`, and with no fsync per commit the writer is no longer bound by fsync latency. The price is the corruption exposure above. The size of the speedup on our workload is **unmeasured** and must be benchmarked as a pair ([benchmarks.md](benchmarks.md)). Group commit is kept in all modes: under `Normal`/`Full` it amortizes fsync; under `Off` it still amortizes per-transaction overhead (inference, to be measured).

**Corruption detection and recovery (new scope).**

- At startup, run an integrity check on each file: `PRAGMA quick_check` by default (O(N), skips UNIQUE and index-content checks) or the full `PRAGMA integrity_check` (O(N log N)) by configuration. Startup time grows with file size. A passing check does not prove the file is free of corruption.
- If a file fails: **quarantine** it (move the file and its `-wal`/`-shm` to a timestamped quarantine directory, never delete), **start with an empty file** for that database, and raise an alert (dashboard banner, log, metric). The quarantined file is kept for manual salvage.
- Consequences by file: a quarantined `queue.db` loses all queued mail and pending webhook events; a quarantined `stats.db` loses statistics history and the attempt log; `config.db` at `FULL` is expected to survive (not guaranteed). If `config.db` is on `Off` and is quarantined, the instance starts without tenants, keys and DKIM keys and must be restored from backup or re-provisioned.
- Optional scheduled backups with `VACUUM INTO` (works while running; `BackupDatabase` blocks writers). A restore returns the state at the last backup; mail accepted since is lost.
- Cross-file ordering rules (suppression to `config.db` first, then complete the queue row) are unchanged.

**Queue and message limits:** 48 h queue lifetime, 10 MiB max message (both proposed defaults).

**What Lite persists:** the queue and spool bodies (only while queued), suppressions, tenants, API keys, domains, DKIM keys, the Data Protection key ring, webhook endpoints and outbox, and aggregated statistics. No per-message history.

**Statistics.** One row per (period, tenant, sending domain, recipient-domain bucket) with about ten counters (accepted, delivered, deferral attempts, hard bounce, soft bounce, expired, complained, rejected, suppressed), written as upserts. Counters accumulate in memory and flush about every 10 s, so a crash loses at most that window.

| Knob | Default |
|---|---|
| `Stats:HourlyRetentionDays` | 30 (matches Full metadata); `0` = keep forever, see §5.1 |
| `Stats:DailyRetentionDays` | 400; `0` = keep forever, see §5.1 |
| `Stats:RecipientDomainTopNHourly` | 20 (rest bucketed as "other") |
| `Stats:RecipientDomainTopNDaily` | 10 |
| `Stats:MaxSeriesPerHour` | 200,000 (overflow goes to "other") |
| `Lite:RecentEvents` | 1,000 (content-free ring, recipient domain only) |

Size model (assumes about 120 B per row plus a similar index, about 250 B per row total, and active series at 30% of the maximum; both assumptions **unverified**): 50 tenants × 2 domains × 21 buckets ≈ 0.45M hourly rows plus 0.25M daily rows ≈ 0.2 GB; 1,000 tenants × 3 domains × 21 buckets ≈ 13.7M hourly rows plus 4M daily rows ≈ 4–5 GB.

**Rollup job** (in `stats.db`, so it never blocks the queue): hourly, roll each completed day up with `INSERT … SELECT … GROUP BY`, delete expired hourly rows in batches of about 5k with short pauses, then `PRAGMA incremental_vacuum`.

**Housekeeping:** `auto_vacuum=INCREMENTAL` must be set before tables exist; `VACUUM` needs up to 2× free space. Set `journal_size_limit`; run `wal_checkpoint(PASSIVE)` after batches and `TRUNCATE` at idle, because long-lived readers starve checkpoints (dashboard reads hit `stats.db`, not `queue.db`). Export WAL size as a metric. Back up with `VACUUM INTO` while running (`SqliteConnection.BackupDatabase` blocks writers). Keep the SQLite schema small and stable: AlterColumn/DropColumn need table rebuilds, idempotent scripts are unsupported, a killed migration can leave an abandoned `__EFMigrationsLock`, and `DateTimeOffset`/`decimal`/`TimeSpan` comparisons run client-side (store UTC `DateTime` or `long`).

**Honest ceiling.** Lite is engineered for large, high-throughput workloads; its performance is a first-class goal ([benchmarks.md](benchmarks.md)). With the default `Off` the limit is no longer fsync latency but single-writer CPU, WAL write bandwidth and checkpoint I/O (each body is written to the WAL and again at checkpoint, at least 2× disk writes); with `Normal`/`Full` fsync latency returns as a limit. No credible published commits/s figure for SQLite on SSD with `FULL` was found; one snippet (about 442 inserts/s WAL+FULL vs 33k/s NORMAL) is **unverified** and not our workload. The earlier expectation of thousands of messages/s on local NVMe and hundreds on cloud block storage was an inference made for `FULL`; it is not re-derived for `Off`. Measure it.

**Dashboard indicators (advisory only).** A "storage pressure" indicator fed by `lite_commit_latency_ms`, `lite_writer_batch_size`, `lite_writer_queue_depth` and WAL size. Suggested default signals: writer queue depth over 1,000 for 5 minutes, or p99 commit latency over about 100 ms (both configurable; calibrate after benchmarking, since commit latency will be much lower under `Off`). These are **advisory indicators on the dashboard only**; the system **never switches mode automatically**. Suggested docs wording: *"Lite has no built-in rate limit. Throughput is bounded by your hardware. If the writer queue stays deep or p99 commit latency is high, you have reached the ceiling; consider faster local disk or moving to Full."* Reasons to consider Full: more than one node or HA, per-message search, history or resend, power-loss safety without the cost of `Lite:SyncMode=Full`, or an indicator that stays red. The owner decides whether and when to switch (§4.3).

**Lite dashboard and API:** counters and rates, per-hour/day charts, per-domain breakdowns, live queue depth and deferrals by destination, the recent-events ring, domain verification, API keys and suppressions. No message search, timeline, content or resend. The UI reads a capabilities endpoint to hide those pages; per-message API endpoints return `501` with code `not_supported_in_lite_mode`. Sends still return an id, for log correlation only.

**Bounce correlation without per-message rows:** a stateless signed VERP token (tenant id, domain id, timestamp, HMAC). The recipient to suppress comes from the DSN's `Final-Recipient`.

### 4.3 Mode switching is manual, never automatic

EggMail never changes mode on its own: no auto-failover, no auto-upgrade, no threshold that triggers a switch. The dashboard offers an **owner-triggered, guided "Switch mode" action** that walks through explicit steps and requires confirmation. The mode is deployment configuration (`Mail__Provider`, the Postgres connection strings and, for Full, a managed Postgres), so the guided action orchestrates the in-app steps and ends with a restart under the new configuration; it cannot provision Postgres or change container topology. This builds on the earlier drain-and-switch path; the earlier "Full → Lite unsupported" (decision 14) is preserved in the narrowed form below.

**Lite → Full (supported, guided):**

1. Preflight: Postgres reachable, version at least 16, owner and runtime roles and connection strings configured, migrations applied (or `Auto`), Data Protection key ring / certificate available to the target.
2. Drain (`mta drain`): stop accepting new mail and wait for an empty queue. Queued messages are **not** migrated, so the switch does not proceed with a non-empty queue; the owner can wait, cancel (resume accepting), or let messages expire.
3. Export config: tenants, domains, API-key hashes, suppressions and optionally stats. DKIM keys need the same Data Protection key ring or certificate.
4. Import into Postgres and verify counts.
5. Explicit confirmation by the owner, then restart under Full. Lite files are left untouched as a fallback.

**Full → Lite (not an in-place switch):** per-message history (events, retained content, retained raw) has no home in Lite, so this direction **loses visibility of all per-message history**. Safest choice, adopted here and marked as an open question: the dashboard offers only a **config-only export** (tenants, domains, API-key hashes, suppressions, optionally aggregate stats) to seed a *new* Lite installation. It is non-destructive: Full keeps running with its data until the owner decommissions it, and the export requires explicit typed confirmation stating that history will not carry over. There is no in-place Full → Lite switch and no deletion of Full data. See [open-questions.md](open-questions.md).

Effort: the guided flow (preflight, confirmations, config-only export, UI) is new scope on top of the earlier drain/export/import work; see [plan.md](plan.md).


## 5. Content retention (Full)

The raw message is delivered verbatim (apps may DKIM-sign their own mail; rebuilding MIME would break the signature), so it stays untouched in `message_spool` until every recipient is final. Stripping a partitioned row in place would create dead tuples and rewrite TOAST, so content is split into separate tables instead.

- Default stored content: subject + text + html + attachment index. Attachments are **not** stored unless enabled.
- Attachment flag precedence: per-send API flag, then per-tenant setting, then global default (`false`), behind the master switch `Content:AllowAttachmentStorage`. SMTP ingress uses the tenant setting only.
- Config (proposed): `Content:Mode = Retain | None` (default `Retain`; `None` deletes content at the final state), `Content:RetentionDays = 7` (range 6–30, **no unlimited value**; see §5.1), `Content:StoreAttachments = false`, `Content:MaxStoredBodyBytes = 256 KiB` (truncated with a flag), `Content:StoreSubject` configurable (subjects can contain personal data). Metadata is kept 30 days (`Retention:MetadataDays`, `0` = keep forever, see §5.1); anything content-like (e.g. a preview) follows the content retention.
- Resend: from retained raw when attachment storage was on; for attachment-free messages, "send again from content" re-composes from stored subject/body and is labelled as re-composed (headers not byte-identical); otherwise the dashboard shows "attachments were not stored" and the API returns a clear error.
- The dashboard renders stored HTML only in a sandboxed iframe under a strict CSP, with plain text as the default.
- Size model (illustrative, not measured; 100k messages/day, about 20 KB content per message, an assumption): about 2 GB/day and 14 GB at 7 days before TOAST compression. Worst case spool (all mail deferred 5 days) about 25 GB. With attachment storage on: about 35 GB at 7 days, about 150 GB at 30 days.

### 5.1 Retention knobs and unlimited retention

**Convention (applies everywhere): a retention value of `0` means "keep forever" (unlimited).** Negative values are invalid. Unlimited means no automatic cleanup: disk grows without bound and the operator must clean up manually or with external tooling. The dashboard shows a warning next to any knob set to `0`.

| Knob | Default | Allowed | Unlimited (`0`)? | Cost / reasoning |
|---|---|---|---|---|
| `Webhooks:OutboxRetentionDays`, `Webhooks:AttemptLogDays` | 7 | any positive integer, or `0` (**owner-decided**; the earlier cap of 30 is removed) | Yes | Rows grow with event volume. In Lite the outbox lives in `queue.db`, the hot file, so unlimited outbox retention inflates the file the writer commits to and slows vacuum/backup; the attempt log lives in `stats.db`. Prefer a finite outbox value in Lite |
| `Retention:MetadataDays` (Full events, day-partitioned) | 30 | positive integer, or `0` | Yes, with warning | Partitions are never dropped, so the partition count grows by one per day. PostgreSQL's partitioning docs caution that very many partitions raise planning time and memory (not re-fetched this round, **unverified**); consider week-sized partitions if used. Backup size and restore time grow too |
| `Stats:HourlyRetentionDays` (Lite) | 30 | positive integer, or `0` | Yes, with warning | Hourly rows are the bulk of `stats.db` (about 13.7M rows, 4–5 GB total, in the modeled large case at 30 days); unlimited growth is linear in time. The `Stats:MaxSeriesPerHour` cap still bounds each hour |
| `Stats:DailyRetentionDays` (Lite) | 400 | positive integer, or `0` | Yes | Daily rows are small (modeled as about 10k rows/day in the large case, top 10 domains), so this is the safest knob to leave unlimited |
| `Content:RetentionDays` (Full) | 7 | **6 to 30 only** | **No** | See below |
| Suppressions | no expiry | n/a | Already unlimited | Needed for correctness |
| `Lite:RecentEvents` | 1,000 | count, not time | n/a | A bounded ring by design |

**Why `Content:RetentionDays` stays 6–30 and has no unlimited value.** The floor of 6 exists because content must outlive the 5-day queue lifetime (otherwise the dashboard view and resend would vanish before the message is final). The ceiling of 30 is a safety bound, not a technical limit: content holds personal data (subjects, bodies, optionally attachments), so unlimited retention is a privacy and compliance liability, and it is the largest storage consumer (about 150 GB at 30 days with attachments in the modeled example, with a revisit threshold of roughly 200–300 GB). For operators who need to keep nothing, `Content:Mode=None` deletes content at the final state. Whether to raise the ceiling or add an explicit override is an open question ([open-questions.md](open-questions.md)). Retention in Full for content is by partition drop, which is why day granularity and a finite window matter.


- Revisit the Postgres-only body design if retained content passes roughly 200–300 GB, WAL passes roughly 50 GB/day or restore time becomes unacceptable (rules of thumb, unsourced).

## 6. Webhooks (shared by Full and Lite)

- **Format:** [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md): headers `webhook-id`, `webhook-timestamp`, `webhook-signature`; HMAC-SHA256 over `id.timestamp.payload`; signature `v1,<base64>`; secrets `whsec_…`; rotation by signing with old and new keys (space-delimited). The event id is the idempotency key; delivery is at-least-once and unordered. The spec says only "some allowable tolerance" for replay; the default 5-minute window is Stripe's library convention.
- **Retry schedule (default):** immediately, 5 s, 5 min, 30 min, 2 h, 5 h, 10 h, 10 h (about 27 hours), identical to Svix and Resend. Other platforms differ (Postmark 6 retries, Mailgun 8 hours, Stripe up to 3 days).
- **Delivery rules:** success is 2xx within 15 s; `410` disables the endpoint; `429`, `502` or `504` throttle; redirects are not followed; an endpoint is disabled after 5 days of continuous failure and the tenant is notified; per-endpoint concurrency capped (default 4).
- **SSRF protection:** HTTPS required by default (`Webhooks:AllowHttp=false`). Resolve the host, validate resolved IPs against a denylist (loopback, private ranges, link-local, `169.254.169.254`, `fc00::/7`, `fe80::/10`, multicast), connect only to the validated addresses keeping the host name for SNI and `Host` (defeats DNS rebinding). A per-tenant allowlist overrides for internal endpoints.
- **Schema:** `webhook_endpoint` (config DB: id, tenant, url, wrapped secret, event types, enabled, disabled reason); `webhook_outbox` (queue DB in Lite: id, endpoint, tenant, event type, event id, JSON payload, next_attempt_at, attempt count, state, lease), inserted in the same transaction that completes the delivery row so a crash cannot lose an event whose outcome is already durable; `webhook_attempt` (stats DB in Lite: outbox id, time, status code, duration, error class, response snippet of at most 1 KB; losing a few rows on a crash is acceptable).
- **Retention:** finished outbox rows and the attempt log are kept 7 days by default, configurable to any positive number of days, and **`0` keeps them forever** (owner-decided; the earlier 30-day cap is removed). Unlimited retention means no cleanup: disk grows with event volume and the operator must clean up manually or externally (§5.1). `Webhooks:OutboxRetentionDays`, `Webhooks:AttemptLogDays`.
- **Writer interaction:** the dispatcher claims due rows through the queue writer and results flow back in the same group-commit batches; the load is small (a few events per message; about 12 events/s average at 1M messages/day).
- **Unverified:** Stripe's and Postmark's webhook timeouts; SendGrid's 24 h retry (search snippet only).

## 7. Network, TLS and ports

### 7.1 Listeners

| Public port | Container port | Mode | Default |
|---|---|---|---|
| 587 | 5587 | STARTTLS | on |
| 465 | 4465 | Implicit TLS (RFC 8314) | on |
| 2525 | 2525 | STARTTLS (last-resort for networks blocking 587/465) | on |
| 2587 / 2465 | 2587 / 2465 | STARTTLS / implicit | off |
| 25 | 2526 | **Bounce/DSN role only** (unauthenticated, bounce domain only; STARTTLS offered, not required) | bounce role |
| any | any | Plain, loopback or internal network only, no AUTH | off |
| 8080 | 8080 | Dashboard/API HTTP (probes, internal, not published) | on |
| 8443 (optionally 443) | 8443 | Dashboard/API HTTPS | on |

Each listener is switchable. Proposed config shape: `Mail__Smtp__Listeners__<name>__Port|Mode|Role|AuthRequired|BindAddress|Enabled`. High container ports avoid root and capabilities; publish only enabled ports. Rate limits, connection caps and auth lockouts are keyed globally, not per port, and the listener name is logged on every event. The HTTP API on 443 is the escape hatch for networks that block every SMTP port. Check LoadBalancer limits per cloud (inbound 25 may not be available); add a NetworkPolicy allowing only enabled ports. The convention (587/465/2525, with 2587/2465 optional) follows SES, Resend, Mailgun, Postmark and SendGrid; SendGrid's full list is from a secondary source (**unverified**).

### 7.2 Outbound

Direct MX delivery uses port 25. A relay fallback chain on 587, 465 or 2525 is **opt-in per domain**; each route has host, port, TLS mode, credentials and health state. Move to the next route on connect timeout or refusal; retry the same route on 4xx; never fall through on a 5xx content rejection; use a circuit breaker with cooldown. Every delivery records which route was used (a relay changes sending IP, SPF, bounce path and alignment, so fallback must never silently change identity). This fall-through logic is the design authors' own, not from a source.

### 7.3 TLS

- One shared certificate store for SMTP and the dashboard. Own `ServerCertificateSelector`; TLS 1.2 minimum (1.3 on). Certificate hot reload by polling (every 30–60 s on mtime/size/thumbprint, debounce 2–5 s, validate key match, `NotAfter`, SAN and chain before swapping; keep the old certificate and alert on failure). inotify is unreliable with Kubernetes' `..data` symlink swap.
- Sources: mounted PEM/PFX, cert-manager (prefer under Kubernetes; the app only watches files), self-signed on first run (flagged in the dashboard), or built-in ACME with Certes (pin 4.1.x behind an interface; **DNS-01 by default**, Cloudflare first, pluggable DNS-provider interface; renew using ARI). Let's Encrypt moves the default profile to 64-day certificates on 2027-02-10 and 45 days on 2028-02-16, and no longer sends expiry emails, so expiry must be monitored. Certes was dormant 2021–2026 with a single recent author; the fallback is an own client (6–12 weeks).
- Outbound: opportunistic by default (Postfix `may` equivalent) with per-domain levels (none, may, encrypt, verify); MTA-STS enforce; DANE via the local validating resolver (a failing DANE result is not overridden by MTA-STS). In opportunistic mode, accept untrusted certificates but record the errors; revocation checks off for MX delivery.
- Record per delivery attempt: TLS used/version/cipher, peer certificate subject/issuer/validity/SHA-256, SSL policy errors, verified, policy applied (none, opportunistic, required, mta-sts-enforce/testing, dane), policy id, MX host, STARTTLS advertised, plaintext fallback, failure reason.
- MTA-STS: fetch `https://mta-sts.<domain>/.well-known/mta-sts.txt` with no redirects and only HTTP 200, cache until `max_age`, refetch when the `_mta-sts` TXT id changes, keep the cached policy if a fetch fails.

## 8. Domain verification

Records (decided): DKIM TXT with RSA-2048 (`<selector>._domainkey`, one selector per domain per key; the verifier must concatenate TXT strings since 2048-bit keys exceed 255 characters; CNAME delegation optional later), a return-path CNAME to the operator's bounce domain, SPF `include` optional (keep flat; `~all`), DMARC informational (never blocks sending). Rotation: publish selector N+1, verify, switch signing, keep N at least 7 days, never reuse selector names.

State machine (**proposed** in earlier research; the decisions record is truncated at this item, so the exact machine is to be confirmed in implementation): `Pending → Verifying → Verified → TemporaryFailure → Failed`, plus sending `Paused` on failure. `Verified → TemporaryFailure` after two consecutive failed checks; `TemporaryFailure → Verified` when records return, or → `Failed` and pause after a configurable grace period (72 hours is a reasonable default following SES and Resend). Cadence: every 1–2 minutes for 15 minutes, every 15 minutes for 24 hours, then hourly until verified; daily once verified, hourly in `TemporaryFailure`; "Verify now" rate-limited to once per 30 s per domain. `Pending`, `Verifying` and `Failed` block sending; `TemporaryFailure` keeps sending with a banner and alert; a missing return-path record falls back to the shared bounce domain.

## 9. Security

### 9.1 Secrets
- API keys are shown once and stored as SHA-256 digests (high-entropy keys); constant-time comparison via `CryptographicOperations.FixedTimeEquals`.
- SMTP auth: PLAIN and LOGIN only, only after TLS, so passwords can be stored as hashes (CRAM-MD5 would need plaintext).
- DKIM private keys and the Data Protection key ring are wrapped with a certificate or KMS (`Secrets:KeyProtection = Certificate | Kms | None`; `None` is for dev only); credentials come from the `*_FILE` secret convention. Never delete old Data Protection keys.
- Dashboard passwords: PBKDF2 from the BCL (iteration count per current OWASP guidance, to be set) or an Argon2 library.
- Encryption at rest is a storage-layer responsibility (volume or database); application-level envelope encryption is deferred behind an interface.

### 9.2 In-house security review
STRIDE threat model per trust boundary (SMTP in, SMTP out, DNS, storage, dashboard, key store); OWASP ASVS L2 for API and dashboard, L3 for key and credential handling; written parser-review checklist plus SharpFuzz on every parser with crashers kept as regression tests; attack suites (smtpsmug, SMTP-Smuggling-Tools, EAST for STARTTLS, slowloris, connection flood, oversized DATA, MIME bombs with memory/CPU ceilings); port pen-tests (relay abuse, AUTH brute force, `testssl.sh`, Internet.nl); container hardening (non-root, read-only root filesystem, `cap_drop: ALL`, default seccomp, CIS Docker Benchmark, Trivy/Grype); a non-author reviews every security-relevant PR; quarterly "red hat" week; CVSS 4.0 with fix SLAs (e.g. critical 7 days, high 30, medium 90); every finding becomes a regression test.

An **external audit is recommended before first production-critical use** (2–4 weeks with 2–4 testers is a reasonable scope by inference from comparable audits; no cost figures found, get quotes). Publish `security.txt` and a disclosure policy before launch.

### 9.3 Dashboard supply chain
Preact + Vite recommended. Build in a Node stage of the Dockerfile and copy only `dist/`; `npm ci --ignore-scripts`, a minimum release age (about 7 days), `npm audit signatures`, OSV scanning, a strict CSP (`script-src 'self'`, no inline), and about 10 or fewer direct dependencies. Treat the dashboard as an admin surface with the same review as the SMTP stack.

## 10. Deployment

- **Full:** app + managed Postgres via compose (app + `postgres:17` with a `pg_isready` healthcheck) or a Kubernetes Deployment. More than one replica is safe (no local blobs; `SKIP LOCKED` claims; advisory-locked retention job).
- **Lite:** one container, one volume (ReadWriteOnce, local), one replica, recreate rollout.
- **Image:** one image, chiseled, with ICU (the `-extra` variant) plus a startup Unicode self-test (silent failure in invariant mode is a risk). ReadyToRun; no trimming (EF is not trim-safe). Pin versions.
- **Health:** `--healthcheck`; liveness separate from readiness. When Postgres is down: `451` to SMTP clients, `/readyz` fails, `/healthz` stays alive.
- **Observability:** `System.Diagnostics.Metrics` and `ActivitySource` (BCL, so even the SMTP stack emits metrics), OpenTelemetry with OTLP, JSON console logs. The OTel Prometheus exporter was still beta and prometheus-net had no release since January 2024, so a hand-rolled `/metrics` endpoint (about 150 lines) was suggested as the alternative.
- **Limits (Full):** max message 25 MiB, 50 recipients, 5-day queue lifetime.
- **Deliverability operations** (IP reputation, warm-up, PTR/EHLO, port-25 blocking, abuse desk) are operational, not code, and sit outside the engineering estimate.
