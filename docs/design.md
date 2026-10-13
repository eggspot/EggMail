# EggMail design

Status: design phase, no code. Source of truth for individual choices is [decisions.md](decisions.md); this document explains how they fit together. Items marked **unverified** were not confirmed against a primary source; defaults marked **proposed** are the design authors' choices.

## 1. Goals and scope

EggMail is an open-source, self-hosted outbound email server: SMTP ingress, HTTP API, delivery tracking, webhooks and a dashboard. Primary goal: the fastest SMTP server, claimed only after reproducible measurement ([benchmarks.md](benchmarks.md)). Target runtime: .NET 10 LTS (supported to 2028-11-14), deployed as a Docker image.

"Fastest" is scoped to **SMTP ingest** (accept) throughput and latency, reported separately from outbound delivery.

**Design principle 1: the storage backend changes nothing but storage.** SQLite and PostgreSQL are only a choice of how data is stored persistently and long-term. All features (SMTP/API, DKIM/SPF/DMARC, domain verification, tenants, API keys, suppressions, webhooks, rate limits, warm-up, settings, dashboard pages, ACME/TLS) behave identically on both. How much per-message history is recorded is a separate setting (`History:Mode`), not a property of the backend (§4.1). "Lite" and "Full" are friendly names for the two default presets.

**Design principle 2: performance is a permanent first-class goal on both backends.** The SQLite backend is engineered to perform well for large and high-throughput workloads and is not treated as a toy; optimization work applies to both, and each is benchmarked separately with the identical feature set ([benchmarks.md](benchmarks.md)).

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

As built (the first sketch had no separate Dsn, Tls, Delivery, Webhooks or Portability projects; they were split out when the components were implemented).

```
src/
  Mta.Core              ids (UUIDv7), clock, EmailAddress, log/secret seams       } package-free
  Mta.Dns               packet codec, UDP/TCP transport, cache, MX resolver         } (CI-guarded,
  Mta.Mime              parse/compose, header folding, content extraction           }  decision 4)
  Mta.Dkim              canonicalization, sign/verify
  Mta.Auth              SPF / DMARC / Authentication-Results / ARC
  Mta.Dsn               DSN/ARF generation and parsing, VERP tokens
  Mta.Tls               MTA-STS, DANE, TLS-RPT, outbound TLS policy decision
  Mta.Smtp.Protocol     commands, replies, dot-stuffing, DATA scanner, state machine (pure, no I/O)
  Mta.Smtp.Server       listeners, sessions, pipelines, STARTTLS
  Mta.Smtp.Client       outbound connections, TLS policy, AUTH, DATA/BDAT, connection pool
  Mta.Storage           contracts, options, shared EF model, in-memory backend
  Mta.Storage.Sqlite    SQLite backend (per-file writers)
  Mta.Storage.Postgres  PostgreSQL backend (partitions, SKIP LOCKED claim)
  Mta.Storage.Portability  bundle format, switch engine, verification, secret re-protection
  Mta.Policy            retry schedule, reply classification, throttling, routes, warm-up, sender policy
  Mta.Delivery          scheduler/engine, bounce processing, DKIM signing at delivery
  Mta.Webhooks          Standard Webhooks signing, SSRF guard, dispatcher
  Mta.Observability     metrics (Prometheus text, OTLP), log adapter, health
  Mta.Host              composition root (`mta`), configuration, HTTP API, dashboard hosting, ACME
  Mta.Tools             load generator, sink (`mta-tools`)
dashboard/              Preact + Vite SPA (built in the Docker Node stage)
tests/  bench/
```

Dependencies point downward. The pure libraries do no I/O so they can be fuzzed and benchmarked directly. The package-reference ban applies to `Mta.Smtp.*`, `Mta.Mime`, `Mta.Dkim`, `Mta.Auth` and `Mta.Dns`.

### 2.3 Key interfaces

| Interface | Responsibility |
|---|---|
| `IDnsResolver` / `IDnsTransport` | Resolve with caching; send and receive DNS packets |
| `ISmtpTransport` | Deliver one message to a remote host |
| `IQueueStore` | Enqueue, claim/lease, retry, complete (provider-specific claim SQL) |
| `IMessageBodyStore` | Spool, content and retained-raw tables; partition drop (PostgreSQL) vs batched DELETE (SQLite). Postgres/SQLite implementations only; FS/S3 providers are not built but the interface remains |
| `IEventStore` | Per-message delivery events (`History:Mode=Full`, either backend) |
| `IStatsStore` | Hourly/daily counters, recorded in every history mode; one shared implementation using `INSERT … ON CONFLICT DO UPDATE` |
| `IConfigStore` | Tenants, domains, keys, suppressions, webhook endpoints, settings, certificates and ACME state; one shared implementation over EF for both providers |
| `IPortableStore`, `IBundleWriter` / `IBundleReader` | Export, import, count and checksum contract implemented by the config, stats, queue and history stores; used by the backend-switch engine (§4.6) |
| `ICertificateStore` | Certificates, private keys (Data Protection) and ACME state held in the config store on both backends; serve from memory, reload on change by polling the store (§7.3) |
| `ISpfEvaluator`, `IDmarcEvaluator`, `IDkimSigner`, `IDkimVerifier` | Authentication |
| `IRoutingPolicy` | Routing, rate limits, retry schedule per message |
| `IClock` (and file-system seam) | Test seams for time and crash simulation |

### 2.4 Shared vs provider-specific

Shared (identical on both backends): SMTP server/client, MIME, DKIM/SPF/DMARC, DNS, scheduler logic, routing, rate limits and warm-up, webhook dispatch, API, auth, tenants, domain verification, all dashboard pages, secrets handling, TLS/ACME, observability, config and stats stores, history and content logic, retention policy, and the backend-switch engine.

Provider-specific (storage mechanics only): queue claim SQL and leases, the writer model (per-file writers on SQLite, pooled concurrent writers on PostgreSQL), partition management vs batched-delete executors, sync/WAL tuning, migrations.

Two EF Core providers, one `DbContext`, a separate migrations assembly per provider selected by configuration. Branch on `migrationBuilder.ActiveProvider` for partition DDL, which exists only in the Postgres migration. Isolate provider-specific annotations in a per-provider model hook (the EF docs do not cover them in a shared model; **unverified** which behave). CI runs `has-pending-model-changes` once per provider; `Migrate()` throws on pending changes in EF 9+. The test matrix doubles; SQLite tests are fast and are the default for local development.

## 3. SMTP stack and performance design

- **Pipelines-based server.** Copy Kestrel's zero-byte-read default (`WaitForDataBeforeAllocatingBuffer`) so idle connections hold no buffer; cap read/write buffers explicitly (Kestrel defaults are 1 MiB and 64 KiB). Always call `AdvanceTo(consumed, examined)` and never touch a `ReadOnlySequence` afterwards.
- **DATA path.** Scan for `\r\n.\r\n` incrementally with `SearchValues<byte>`. The body is buffered in memory up to `Smtp:MaxMessageSize` (default 25 MiB on both backends) behind a **global in-flight bytes budget**; when exhausted, reply `452`. Objects of 85,000 bytes or more land on the large object heap. Start with EF `byte[]`; use Npgsql directly for the body insert only if profiling shows LOH pressure (owner permission for raw Npgsql is an open question).
- **Smuggling and STARTTLS hardening.** Only `\r\n` ends a line; reject bare CR/LF and NUL with a 5xx and close; end DATA only on `\r\n.\r\n`. On STARTTLS, if the reader holds any bytes beyond the command line, close the connection; rebuild pipes over `SslStream` and reset session state (RFC 3207 §4.2). The client must re-EHLO after TLS and ignore the pre-TLS capability list. The client never emits a bare CR/LF.
- **Group commit.** One writer per database file drains queued commands into one transaction so the per-commit cost (an fsync under SQLite `Normal`/`Full` or a PostgreSQL commit; transaction overhead under the SQLite default `Off`) is amortized across many messages. `250` is sent only after the commit returns. On PostgreSQL, events are buffered in a channel and flushed every few milliseconds, and claims fetch N rows per round trip.
- **TLS.** One shared `SslServerAuthenticationOptions` and certificate; stable `TargetHost` on outbound so session resumption works.
- **GC.** Start with workstation non-concurrent GC below 2 cores and server GC with DATAS above; decide from benchmarks.
- **EF Core on the hot path.** Use `AddPooledDbContextFactory` with a short-lived context per batch (never per message, never long-lived in a worker); `AsNoTracking`, `ExecuteUpdate`/`ExecuteSql`, `SqlQuery<T>`, compiled queries for fixed lookups. EF costs several KB per operation even when tuned, so the per-message allocation budget applies to the SMTP/protocol path; the database layer has its own proposed budget (see [benchmarks.md](benchmarks.md)).

## 4. Storage

### 4.1 Backends, history level and presets

**Principle: SQLite vs PostgreSQL is only a storage-backend choice.** Every feature behaves identically on both backends: SMTP and API, DKIM/SPF/DMARC and domain verification, tenants, API keys, suppressions, webhooks, rate limits, warm-up, settings, dashboard pages, ACME/TLS, retries, routing. The backend decides only *how data is stored persistently and long-term* (and the operational characteristics that follow from that, §4.2). A feature is never gated on the backend; where a capability depends on what data is recorded, it depends on a separate, orthogonal setting.

Two orthogonal settings:

| Setting | Values | Meaning |
|---|---|---|
| `Storage:Backend` | `Sqlite` \| `Postgres` | Where data is stored. **Default: `Sqlite`** (owner-decided), so the single-container quick start works with no external database; PostgreSQL is selected by configuration in the same image ([release.md](release.md)) |
| `History:Mode` | `StatsOnly` \| `Full` | How much per-message history is recorded |

**Any combination is allowed:** SQLite + `Full` history, PostgreSQL + `StatsOnly`, SQLite + `StatsOnly` and PostgreSQL + `Full`. The default is `History:Mode=Full` on both backends (below).

`History:Mode`:

| | `StatsOnly` | `Full` |
|---|---|---|
| Aggregated statistics (hourly/daily counters per tenant, sending domain, recipient-domain bucket; §4.5) | yes | yes |
| Recent-events ring (`History:RecentEvents`, default 1,000, content-free, recipient domain only) | yes | yes (alongside full events) |
| Per-message events, timeline, search | no | yes (`Retention:MetadataDays`) |
| Stored content, retained raw, view and resend (§5) | no | yes (`Content:*` settings) |
| Bounce correlation | stateless signed VERP token (tenant id, domain id, timestamp, HMAC); the recipient to suppress comes from the DSN's `Final-Recipient` | same token, additionally linked to the message's rows |
| Send response | returns an id, for log correlation only | returns an id that resolves to the message |

Everything not listed in this table (queue, delivery, suppressions, webhooks, domain verification, authentication, all settings) is identical in both history modes. The dashboard shows the same pages on every backend; pages that need per-message history show an explanatory state when `History:Mode=StatsOnly`, and the UI reads `History:Mode` from a capabilities endpoint (never the backend). Per-message API lookups made in `StatsOnly` return `410 Gone` with code `history_not_recorded` (error body and the other cases in §5.2). That reflects data that was never recorded, not a missing feature of the backend.

**Presets (unified defaults, owner-decided).** "Lite" and "Full" remain friendly names, now for the two storage backends' default deployment shapes: **Lite = the SQLite backend (the default backend), Full = the PostgreSQL backend.** They have **exactly the same defaults for every behavioural setting.** Only storage-backend characteristics differ (§4.2), and backend-specific storage tuning defaults (the SQLite sync pragmas, connection-pool sizes, partition granularity) are not behavioural settings.

The single default set, on both backends (names marked proposed; values are the earlier Full-preset values unless noted):

| Setting | Default | Notes |
|---|---|---|
| `History:Mode` | **`Full`** | **DESIGN-DECIDED** (the owner delegated the value). Justification below |
| `History:RecentEvents` | 1,000 | |
| `Retention:MetadataDays` | 30 | `0` = keep forever (§5.1) |
| `Content:Mode` / `Content:RetentionDays` | `Retain` / 7 | subject + text + html + attachment index; range 6–30 |
| `Content:StoreAttachments` | `false` | `Content:AllowAttachmentStorage` master switch also `false` |
| `Content:MaxStoredBodyBytes` | 256 KiB | |
| `Stats:*` | 30 days hourly, 400 days daily, top-20/top-10 domains, 200,000 series | |
| `Queue:MaxLifetime` (proposed name) | 5 days | |
| `Smtp:MaxMessageSize` (proposed name) / recipients | 25 MiB / 50 | |
| `Webhooks:*` | 7-day outbox and attempt-log retention, 15 s timeout, concurrency 4, HTTPS only | |

Backend-specific storage defaults (not behavioural, and not changed by the other backend): SQLite: `Sqlite:SyncMode=Off`, `Sqlite:ConfigSyncMode=Full`, `Sqlite:QueuePersistence=Persistent`; PostgreSQL: `Mail__Database__Migrate=Auto`, pool sizes, day partitions.

**Why `History:Mode=Full` is the default.** (1) EggMail's product is delivery tracking: the dashboard's message search, timeline and resend work out of the box. (2) The owner wanted identical behavior on both backends, so a single default must serve both, and tracking is the behavior users expect from an outbound email service. (3) `StatsOnly`, the lightweight "fire-and-forget, no per-message record" option the owner asked for earlier, stays one setting away and is documented as such. (4) Switching backends then changes nothing. The cost, stated plainly: `Full` writes more per message (events, content, optionally attachments) and stores personal data (subject and body) for the content retention period (7 days by default); operators who do not want that set `History:Mode=StatsOnly` or `Content:Mode=None`. On the SQLite backend `Full` also means more writes and a larger `history.db`. Benchmarks publish both history levels ([benchmarks.md](benchmarks.md)). The value is easy to flip if the owner prefers `StatsOnly` as the single default. **Open question, flagged rather than changed:** now that SQLite is the default backend, `History:Mode=Full` is also the default for the single-container quick start, which writes events and content into `history.db` by default; whether that conflicts with the quick start's size and performance expectations is **unmeasured** ([open-questions.md](open-questions.md)).

Switching backends never changes behavior silently: the migration tool records the *effective* values of all settings in the bundle and writes them explicitly into the target (§4.6).

### 4.2 Backend characteristics (not feature differences)

These are properties of the storage engines. They affect scale and operations, never what EggMail can do.

| Characteristic | SQLite backend | PostgreSQL backend |
|---|---|---|
| Nodes / replicas | Single node, one replica (single process owns the files) | Several replicas (`SKIP LOCKED` claims) |
| High availability | None built in; backups via `VACUUM INTO`, restore returns the last backup | Managed HA is a deployment prerequisite; `451` during an outage |
| Writes | One writer per database file; single-writer throughput ceiling; group commit | MVCC; many concurrent writers; batching |
| Storage location | Local volume only (WAL does not work on network filesystems) | External server |
| Retention mechanism | Batched `DELETE` plus `incremental_vacuum` (no partition drop) | Day partitions dropped with `DETACH … CONCURRENTLY`, then `DROP` |
| Atomicity | Per file, not across files (§4.4): cross-file effects are idempotent and ordered | One transaction across all tables |
| Durability default | `synchronous=OFF`: process-crash-safe, **not** power-loss-safe; corruption possible on OS crash or power loss (§4.4) | WAL synced at commit (Postgres default) |
| Operational footprint | No external dependency | Managed Postgres, roles, pool sizing, partition job |

The advisory dashboard indicators (§4.4) tell an operator when a backend's characteristics are becoming a constraint. They never trigger a switch.

### 4.3 PostgreSQL backend (EF Core + Npgsql only)

One database, one schema, three roles: **owner** (runs migrations, owns objects), **runtime** (the app; default privileges set with `ALTER DEFAULT PRIVILEGES FOR ROLE <owner>`), and **read-only** (dashboard queries, with `statement_timeout`, e.g. 5 s, and `idle_in_transaction_session_timeout`). One database is kept because a transaction cannot span databases: one transaction writes message, delivery rows, content and event together, and splitting would force an outbox. Minimum PostgreSQL 16; default `postgres:17`. **Managed HA is a deployment prerequisite**; `451` during a database outage is accepted.

Tables:

| Table | Partitioning | Holds / lifetime |
|---|---|---|
| `delivery_queue` | none (live rows only, small) | One row per recipient delivery: id, message_id, recipient, domain, due_at, attempt, lease_owner, lease_until, state, last_error. Row deleted on completion. Own autovacuum settings, lower fillfactor (proposed) |
| `message_spool` | none | Full raw `.eml`, byte-for-byte as accepted, until all recipients are final, then deleted |
| `message_content` | day | (`History:Mode=Full`) Subject, text, html, attachment index (name, type, size), extracted at accept time. Dropped after `Content:RetentionDays` |
| `message_raw_retained` | day | (`History:Mode=Full`, attachment storage on) Raw `.eml` including attachments; written by moving the spool row at the final state in one transaction |
| delivery events | day | (`History:Mode=Full`) 30 days of metadata by default |
| stats, config, webhook, tenant, key, domain, suppression, certificate and ACME-state tables | none | See §4.5, §6, §7.3 |

The schema is identical whatever `History:Mode` is; the history tables are simply left empty in `StatsOnly`.

Rules:

- Retention is partition drop: `DETACH PARTITION … CONCURRENTLY`, then `DROP`. A background in-app job creates partitions ahead under a transaction-level advisory lock (`pg_try_advisory_xact_lock`; session-level locks are incompatible with PgBouncer transaction pooling). `pg_partman` is optional.
- Partition constraints must include the partition key, concurrent detach is not allowed with a DEFAULT partition, and foreign keys into partitioned tables must include the partition key, so references to the big tables are soft. Autovacuum does not analyze partitioned parents; schedule a manual `ANALYZE`. The Npgsql provider has no partition API (efcore.pg#1035), so DDL goes in `migrationBuilder.Sql`.
- **Claim:** native `UPDATE … WHERE id IN (SELECT … FOR UPDATE SKIP LOCKED LIMIT @n) RETURNING …` via `Database.SqlQuery<T>`. Do not compose LINQ over it. A pure-LINQ `ExecuteUpdate` claim (three round trips, loses races under contention) exists only as a test double behind the same interface. **Unverified:** that the Npgsql provider does not wrap `UPDATE … RETURNING` in `SqlQuery<T>`; confirm in a spike.
- **Migrations:** `Mail__Database__Migrate=Auto` by default (EF 9+ takes a database-wide lock, so concurrent startup is safe), or `Never` plus an `mta migrate-db` subcommand and an idempotent SQL script for locked-down setups. Two connection strings: schema owner and runtime. *Implemented* as hand-written, versioned SQL (`Schema/V001__initial.sql`, frozen) applied by one idempotent `DO` block under `pg_advisory_xact_lock`, so the same text serves `Auto`, `mta migrate-db` and a DBA; see [components/storage.md](components/storage.md).
- **Connections:** Npgsql's default pool is 100 per connection string; set explicit sizes (roughly 8–16 claim workers, 16 API, 8 dashboard, 2 maintenance; proposed) and keep the total across replicas under about half of `max_connections`. Enforce with `ALTER ROLE … CONNECTION LIMIT`.
- **Split later only if** sustained volume exceeds roughly 1M messages/day or WAL exceeds roughly 50 GB/day (move events or bodies to a separate instance, accepting an outbox), a compliance rule needs secrets in a separate store, or analytics load belongs on a replica. These thresholds are unsourced rules of thumb.
- **No blob store.** Filesystem, S3 and R2 providers were dropped; bodies live in Postgres `bytea` and restore together with metadata. `IMessageBodyStore` stays so a provider could be added later (about 12–14 weeks, if volume demands it).

### 4.4 SQLite backend (Microsoft.Data.Sqlite)

Single node, one replica, local volume only (WAL does not work on network filesystems). Microsoft.Data.Sqlite 10.0.12 bundles SQLite 3.53.3, so `UPDATE … RETURNING` works; the WAL-reset bug (3.7.0–3.51.2) is fixed in 3.51.3. Everything in §4.1 applies: this backend runs every feature, with the same defaults as the PostgreSQL backend (including `History:Mode=Full`).

**Database files, each with its own WAL and its own writer:**

| File | Contents | Sync mode |
|---|---|---|
| `queue.db` | Spool bodies, delivery queue, webhook outbox | `Sqlite:SyncMode`, default **`Off`** |
| `stats.db` | Aggregates, recent-events ring, webhook attempt log | `Sqlite:SyncMode`, default **`Off`** |
| `history.db` | (`History:Mode=Full`, the default; absent under `StatsOnly`) delivery events, content, retained raw | `Sqlite:SyncMode`, default **`Off`** |
| `config.db` | Tenants, API keys, domains, DKIM keys, suppressions, webhook endpoints, settings, certificates and ACME state, Data Protection keys | `Sqlite:ConfigSyncMode`, default `Full` (rarely written) |

The `Off` default for the data files is **owner-decided**. Keeping `config.db` at `Full` is **owner-decided** (it is rarely written and holds DKIM keys, API-key hashes, certificates and ACME state, and the Data Protection key ring, whose loss or corruption would be severe).

**History file layout (DESIGN-DECIDED): one `history.db`, with batched deletes.** SQLite has no partition drop, so retention of events and content cannot be a cheap metadata operation the way it is on PostgreSQL. Options considered:

| | A. Single `history.db` (chosen) | B. Per-day files (`history-YYYYMMDD.db`) | C. Per-day tables in one file |
|---|---|---|---|
| Retention | Batched `DELETE` in short transactions plus `incremental_vacuum`: costs write amplification and WAL churn at high volume | Delete the file: as cheap as a partition drop | `DROP TABLE` per day, then `incremental_vacuum` |
| Writers / WAL | One writer, one WAL | Writer touches only today's file; a WAL per open file | One writer, one WAL |
| Queries across days (search, timelines) | One SQL query | Fan-out over up to retention-window files and merge in the app; or `ATTACH`, whose default limit is 10 databases (compile-time maximum 125; the limit in the bundled SQLite build is **unverified**), too few for a 30-day window | `UNION ALL` views or fan-out; EF cannot map table names that change daily, so raw SQL |
| Schema migrations | One file | Apply to every existing day file, and to a number of files that is unbounded when `Retention:MetadataDays=0` | One file, but daily tables are created dynamically |
| Export and backup | One consistent stream | Old day files are immutable: copy or stream whole files (best for large history) | One file |
| EF Core fit | Plain | One `DbContext` per file, dynamic connection strings | Poor |

Recommendation: **A for v1.** It is the simplest to implement, search and export, keeps the EF model plain and avoids the `ATTACH` limit. Its weakness is retention cost at high volume, mitigated by `WITHOUT ROWID` tables keyed `(day, id)` so expiry is a sequential range delete (proposed), small delete batches off-peak, and `incremental_vacuum`; and at volumes where this still hurts, PostgreSQL's partition drop is the backend characteristic designed for that (§4.2). B is the upgrade path if SQLite history retention proves too expensive: the store interface hides the layout, and day-first keys and UUIDv7 ids (time-ordered, so the day is derivable from an id) keep the move mechanical. C is rejected because of the EF mapping cost. This is a design judgement without measurements; the retention-delete cost under load is a spike item ([open-questions.md](open-questions.md)).

Separate files keep a stats rollup or history retention job from stalling queue commits. That independent-writer property is inferred from per-file WALs; no explicit sqlite.org statement was found (**unverified**). SQLite documents that a transaction across several databases in WAL mode is atomic per file but not as a set, so **every cross-file effect must be idempotent and ordered**. Examples: on a hard bounce, write the suppression to `config.db` first, then complete the queue row (a crash in between just means the retry bounces again); with attachment storage on, write the retained raw to `history.db` first, then delete the spool row (a crash in between leaves a duplicate that a reconcile job removes). On PostgreSQL these are single transactions; the observable behavior is the same.

**Writer design:** one writer thread per file. Callers submit write commands through a bounded channel and await the result; the writer drains up to N commands or T milliseconds (e.g. 2 ms) into one `BEGIN IMMEDIATE … COMMIT`. Under load, batches grow. The `250` is sent after the commit returns (see "Acknowledgement and sync mode" below for what that does and does not guarantee). Reads use separate short connections. Avoid `Cache=Shared` with WAL; one connection per operation. Queue claim is a single-process claim (no `SKIP LOCKED` needed); retention is batched `DELETE` in short transactions with pauses, followed by `incremental_vacuum` (no partition drop).

**There is no rate limiter in the product, on either backend.** The only back-pressure is natural: the bounded channel into the writer (SMTP reads slow through TCP flow control) and `452` for disk full.

**Acknowledgement and sync mode (read this before deploying the SQLite backend).** The earlier design acknowledged after a `synchronous=FULL` commit and called the queue "durable". The owner chose `PRAGMA synchronous=OFF` as the default for speed, so that wording no longer applies and the term "durable queue" is retired. The SQLite backend's default is **process-crash-safe, not power-loss-safe**:

- `250`/`202` now means the data has been **handed to the operating system**, not synced to disk.
- A **process kill or container restart is safe**: per the SQLite docs, "If the application running SQLite crashes, the data will be safe".
- If the **operating system crashes or the host loses power**, the SQLite docs say that with `synchronous=OFF` "the database might become corrupted", and their durability matrix lists WAL mode with `OFF` as "Not consistent". This is **corruption, not just loss of the last commits**: the whole `queue.db` (all queued mail and the webhook outbox, including mail already acknowledged with `250`) or `stats.db`/`history.db` may be unusable. By contrast, `NORMAL` in WAL mode is documented as safe from corruption but may roll back recently committed transactions, and `FULL` is documented as durable (ACID) in WAL mode. Source: [sqlite.org/pragma.html](https://www.sqlite.org/pragma.html#pragma_synchronous).
- A server that acknowledges `250` takes responsibility for the message (RFC 5321). Under the default, that responsibility is not backed by a disk sync. Operators who need it must opt in to `Normal` or `Full`, or use the PostgreSQL backend.

**Loud warnings, no acknowledgement gate (DESIGN-DECIDED; the owner delegated).** `Off` does **not** require an explicit acknowledgement setting. Instead EggMail is deliberately loud about it, every time:

- a **startup log warning** at `Warning` level, naming each file running with `synchronous=OFF` and the safer settings;
- a **persistent dashboard banner** on every page while any data file runs with `Off` (not permanently dismissible; a per-session collapse is acceptable);
- a **metric and health detail**: a gauge for each file's sync mode (name proposed, e.g. `eggmail_sqlite_sync_mode`) and a `warnings` entry (`sqlite_sync_off`) in the health detail. Readiness is not failed by it, because the configuration is a supported choice;
- the **README** text and the quick-start documentation ([release.md](release.md)).

Reason: an acknowledgement gate adds friction to the single-container quick start and, in the owner's judgment, is not what comparable tools do (not independently verified). The documented safer knobs are `Sqlite:SyncMode=Normal` (safe from corruption, may lose recent commits on power loss) and `Sqlite:SyncMode=Full` (durable). The startup integrity check and quarantine recovery below stay.

Knobs (names are proposed; they were `Lite:*` before backends were made feature-identical):

| Knob | Values | Default | Notes |
|---|---|---|---|
| `Sqlite:SyncMode` | `Off` \| `Normal` \| `Full` | `Off` | Applies to `queue.db`, `stats.db` and `history.db`. `Normal`: WAL synced at checkpoints only, safe from corruption, may lose recent commits on power loss. `Full`: WAL synced on every commit, ACID in WAL mode |
| `Sqlite:ConfigSyncMode` | `Off` \| `Normal` \| `Full` | `Full` | Applies to `config.db`. Owner-decided |
| `Sqlite:QueuePersistence` | `Persistent` \| `Memory` | `Persistent` | Renamed from the earlier `QueueDurability = Durable \| Memory` because "durable" is no longer accurate. `Memory` is an explicit opt-in: "accepted means in memory; lost on restart" |

All leases clear on startup (single process) and delivery is at-least-once, so a message in flight at crash time may duplicate.

Cost and benefit versus `Sqlite:SyncMode=Full` (qualitative; no numbers measured): SQLite documents that commits "can be much faster" with `OFF`, and with no fsync per commit the writer is no longer bound by fsync latency. The price is the corruption exposure above. The size of the speedup on our workload is **unmeasured** and must be benchmarked as a pair ([benchmarks.md](benchmarks.md)). Group commit is kept in all sync modes: under `Normal`/`Full` it amortizes fsync; under `Off` it still amortizes per-transaction overhead (inference, to be measured).

**Corruption detection and recovery.**

- At startup, run an integrity check on each file: `PRAGMA quick_check` by default (O(N), skips UNIQUE and index-content checks) or the full `PRAGMA integrity_check` (O(N log N)) by configuration. Startup time grows with file size. A passing check does not prove the file is free of corruption.
- If a file fails: **quarantine** it (move the file and its `-wal`/`-shm` to a timestamped quarantine directory, never delete), **start with an empty file** for that database, and raise an alert (dashboard banner, log, metric). The quarantined file is kept for manual salvage.
- Consequences by file: a quarantined `queue.db` loses all queued mail and pending webhook events; a quarantined `stats.db` loses statistics history and the attempt log; a quarantined `history.db` loses per-message history; `config.db` at `Full` is expected to survive (not guaranteed). If `config.db` is on `Off` and is quarantined, the instance starts without tenants, keys and DKIM keys and must be restored from backup or re-provisioned.
- Optional scheduled backups with `VACUUM INTO` (works while running; `BackupDatabase` blocks writers). A restore returns the state at the last backup; mail accepted since is lost.

**Housekeeping:** `auto_vacuum=INCREMENTAL` must be set before tables exist; `VACUUM` needs up to 2× free space. Set `journal_size_limit`; run `wal_checkpoint(PASSIVE)` after batches and `TRUNCATE` at idle, because long-lived readers starve checkpoints (dashboard reads hit `stats.db`/`history.db`, not `queue.db`). Export WAL size as a metric. Keep the SQLite schema small and stable: AlterColumn/DropColumn need table rebuilds, idempotent scripts are unsupported, a killed migration can leave an abandoned `__EFMigrationsLock`, and `DateTimeOffset`/`decimal`/`TimeSpan` comparisons run client-side (store UTC `DateTime` or `long`).

**Honest ceiling.** This backend is engineered for large, high-throughput workloads; its performance is a first-class goal ([benchmarks.md](benchmarks.md)). With the default `Off` the limit is no longer fsync latency but single-writer CPU, WAL write bandwidth and checkpoint I/O (each body is written to the WAL and again at checkpoint, at least 2× disk writes); with `Normal`/`Full` fsync latency returns as a limit. With `History:Mode=Full` the volume of retained content and events adds file growth and batched-delete cost; the size model in §5 (modeled for PostgreSQL) applies to bytes, not to engine behavior. No credible published commits/s figure for SQLite on SSD with `FULL` was found; one snippet (about 442 inserts/s WAL+FULL vs 33k/s NORMAL) is **unverified** and not our workload. The earlier expectation of thousands of messages/s on local NVMe and hundreds on cloud block storage was an inference made for `FULL`; it is not re-derived for `Off`. Measure it.

**Dashboard indicators (advisory only).** A "storage pressure" indicator for the SQLite backend fed by `sqlite_commit_latency_ms`, `sqlite_writer_batch_size`, `sqlite_writer_queue_depth` and WAL size (equivalent indicators for PostgreSQL, such as pool saturation and claim latency, are proposed). Suggested default signals: writer queue depth over 1,000 for 5 minutes, or p99 commit latency over about 100 ms (both configurable; calibrate after benchmarking, since commit latency will be much lower under `Off`). These are **advisory indicators on the dashboard only**; the system **never switches backend automatically**. Suggested docs wording: *"The SQLite backend has no built-in rate limit. Throughput is bounded by your hardware. If the writer queue stays deep or p99 commit latency is high, you have reached the ceiling; consider faster local disk or switching to PostgreSQL."* Reasons to consider PostgreSQL: more than one node or HA, power-loss safety without the cost of `Sqlite:SyncMode=Full`, scale beyond the single-writer ceiling, or an indicator that stays red. The owner decides whether and when to switch (§4.6).

### 4.5 Statistics (both backends)

Statistics are recorded on every backend and in every history mode, through one shared `IStatsStore` (both engines support `INSERT … ON CONFLICT DO UPDATE`, so the hourly upsert SQL is identical). One row per (period, tenant, sending domain, recipient-domain bucket) with about ten counters (accepted, delivered, deferral attempts, hard bounce, soft bounce, expired, complained, rejected, suppressed), written as upserts. Counters accumulate in memory and flush about every 10 s, so a process crash loses at most that window.

| Knob | Default |
|---|---|
| `Stats:HourlyRetentionDays` | 30 (matches the default `Retention:MetadataDays`); `0` = keep forever, see §5.1 |
| `Stats:DailyRetentionDays` | 400; `0` = keep forever, see §5.1 |
| `Stats:RecipientDomainTopNHourly` | 20 (rest bucketed as "other") |
| `Stats:RecipientDomainTopNDaily` | 10 |
| `Stats:MaxSeriesPerHour` | 200,000 (overflow goes to "other") |
| `History:RecentEvents` | 1,000 (content-free ring, recipient domain only) |

Size model (assumes about 120 B per row plus a similar index, about 250 B per row total, and active series at 30% of the maximum; both assumptions **unverified**): 50 tenants × 2 domains × 21 buckets ≈ 0.45M hourly rows plus 0.25M daily rows ≈ 0.2 GB; 1,000 tenants × 3 domains × 21 buckets ≈ 13.7M hourly rows plus 4M daily rows ≈ 4–5 GB.

**Rollup job** (on SQLite it runs on the stats file's own writer, so it never blocks the queue): hourly, roll each completed day up with `INSERT … SELECT … GROUP BY`, delete expired hourly rows in batches of about 5k with short pauses (and `PRAGMA incremental_vacuum` on SQLite).

### 4.6 Switching backends: manual and symmetric

EggMail never changes backend on its own: no auto-failover, no auto-upgrade, no threshold that triggers a switch. Switching is an **owner-triggered, explicit action** and works **the same in both directions** (SQLite → PostgreSQL and PostgreSQL → SQLite). Because the backend only decides how data is stored, a switch moves data and nothing else changes: every feature, setting and behavior stays as it was (and because the presets share every behavioural default, §4.1, nothing needs translating).

**Two entry points, one engine:** a guided dashboard action, and a CLI, `mta migrate-storage --to postgres|sqlite` (subcommands `export`, `import`, `verify`, `confirm`, `activate`, `rollback`, `finalize`; options such as `--dry-run`, `--bundle <path>`, `--drain` or `--quiesce`, `--skip-history`). Both call the same portable export/import engine.

**One portable, versioned bundle** (NDJSON files plus a `manifest.json`, streamed so memory stays bounded):

- `manifest.json`: switch id (UUIDv7), bundle format version (semantic; the importer accepts older minors and refuses a newer major), source backend and schema version, creation time, counts and SHA-256 per file and per chunk, what is included, the effective values of settings, and secret-protection metadata.
- `config/*.ndjson`: tenants, domains, DKIM keys (protected), API-key hashes, SMTP credential hashes, suppressions, webhook endpoints (secrets protected), relay routes, per-domain TLS policies, settings, warm-up and rate-limit configuration, **certificates and ACME state** (§7.3; private keys and the ACME account key protected), and API idempotency keys.
- `stats/*.ndjson`: hourly and daily aggregates, the recent-events ring, the webhook attempt log.
- `queue/*.ndjson` plus spool bodies: queued deliveries with their retry state, spool bodies and the pending webhook outbox.
- `history/*.ndjson` plus raw files: delivery events, content, retained raw, in checksummed chunks (resumable).
- `secrets/`: the bundle's own Data Protection key ring and its passphrase-protected certificate (below).

Each store (config, stats, queue, history) implements the same export/import contract over the provider-neutral EF model, so adding a table adds it to the bundle in one place. Config is accessed through one shared config-store abstraction implemented once over EF for both providers.

**What moves:**

| Data | Moves? |
|---|---|
| Config: tenants, domains, DKIM keys, API-key hashes, suppressions, webhook endpoints, relay routes, TLS policies, settings, API idempotency keys | Always |
| Certificates and ACME state (account key, certificates, private keys, renewal metadata) | Always (they live in the config store on both backends; secrets protected as below). In-flight ACME orders and DNS-01 challenge state are not moved; the target restarts any pending order |
| Effective values of settings | Always, recorded in the manifest and written explicitly into the target, so behavior does not change |
| Stats and aggregates, recent-events ring, webhook attempt log | Yes |
| Queued messages with bodies and retry state, pending webhook outbox | **In v1, two ways** (below): `--drain` (safe default; waits for an empty queue, nothing to move) or `--quiesce` (does not wait; transfers what remains) |
| Per-message history (events, content, retained raw) | **In v1** when `History:Mode=Full` on both sides: streamed, resumable, skippable with `--skip-history`. If the target is `StatsOnly`, history is not carried to the target and stays in the read-only source; the guided flow states this in the confirmation |
| Data Protection key ring of the deployment | No: the target keeps its own ring; secrets are re-protected (below) |
| Deployment configuration (ports, connection strings, `Storage:Backend`, sync modes, the key-protection certificate or KMS credential) | Not exported; it belongs to the deployment. The tool shows exactly what to change (see "Activation, and orchestrator-managed configuration" below) |

**Secrets: ASP.NET Core Data Protection is the mechanism, and nothing is ever written in clear.** Everything secret in the bundle (DKIM private keys, webhook secrets, the ACME account key, certificate private keys) is protected with Data Protection. In each deployment these secrets are protected at rest by that deployment's own Data Protection key ring, which is persisted in the config store and itself protected by `Secrets:KeyProtection` (`Certificate` or `Kms`; `None` is dev only). Those two settings are *how a deployment protects its ring*; they are independent of the bundle and may differ between source and target.

Across two different key rings the design is (the simplest sound design that still uses Data Protection; **DESIGN-DECIDED**):

1. **Export** (needs a user-supplied *export passphrase*): the source unwraps each secret in memory with its own ring (so the source's certificate or KMS must be reachable during export). The export then creates a **bundle certificate** (a throwaway self-signed RSA certificate) and a **bundle key ring**, a standalone Data Protection key ring written under `secrets/` and protected with that certificate (`ProtectKeysWithCertificate`). Each secret is protected with a purpose string dedicated to the bundle (for example `EggMail.Bundle.v1`) from that ring and written as a protected blob. The bundle certificate's private key is exported as PKCS#12 encrypted under the passphrase (`ExportPkcs12` with PBES2 / AES-256 / SHA-256, available in .NET 9 and later; exact parameters to be confirmed). Plain-text keys are never written to disk.
2. **Import** (same passphrase): load the PKCS#12 to recover the bundle certificate, open the bundle key ring, unprotect each secret in memory, and **re-protect it with the target's own ring** (the target's own `Secrets:KeyProtection`). The target never needs the source's ring, certificate or KMS key, and the bundle certificate and key ring are discarded after import.
3. The only secret that must travel out of band is the passphrase. Its strength is the strength of the bundle (PKCS#12 password-based encryption); the guided flow enforces a minimum length and the bundle should be treated as sensitive and deleted after finalization.

Sub-choices, flagged honestly: (a) Data Protection has no built-in passphrase mode, so the passphrase goes through a PKCS#12 certificate rather than custom crypto; this is a design choice. (b) A "public-key mode" (protect the bundle to the *target's* certificate, so no passphrase is shared) is possible later and is not in v1. (c) RSA is assumed for the bundle certificate because Data Protection's certificate-based key encryption is documented with RSA certificates (**unverified** for other key types). (d) If the target runs with `Secrets:KeyProtection=None` the import warns and requires explicit confirmation, since the re-protected keys are then only as safe as the database.

**Draining and quiescing queued mail (both in v1).** Delivery stays **at-least-once**. The goal is that the switch itself adds as few duplicate sends as possible, and that the ones it cannot avoid are visible.

- **`--drain` (the safe option):** stop accepting, stop starting new deliveries, wait for the queue to empty (the owner can wait, cancel and resume, or let messages expire). Nothing queued moves, so there is nothing to duplicate.
- **`--quiesce` (does not wait for a full drain):**
  1. *Stop accepting:* SMTP listeners reply `421` and the API replies `503` with `Retry-After`; clients retry later (client-side retries are inherently at-least-once).
  2. *Stop starting deliveries:* the scheduler stops claiming new rows. Deliveries already leased (mid-conversation with a remote server) are allowed to **finish**, up to `Switch:QuiesceTimeoutSeconds` (**default 30 seconds**, overridable with `--quiesce-timeout`; DESIGN-DECIDED, the graceful-shutdown pattern). Finished deliveries are recorded final in the source before export.
  3. *Fence:* the source writes a durable **fence record** (`switch_id`, state `Fenced`, time) in its config store. A fenced source never accepts mail and never claims or sends, including after a restart, until the fence is cleared by `rollback`. This is the cutover fence: at most one side is ever allowed to dispatch.
  4. *Requeue what did not finish (no blocking state):* anything still in flight at the timeout is aborted, its lease is cleared, and the delivery is **requeued with the same message id and delivery id and its retry state preserved** (attempt count, `due_at`, last error; the aborted attempt is recorded as `aborted_by_switch`). Delivery stays at-least-once, like Postfix and Exim after a crash or restart. There is no `in_doubt` state and nothing blocks the switch. If the abort happened *after* the terminating `.` of the message body was sent (the remote may have accepted it although we did not see the final reply), the delivery also gets a **`possible_duplicate` flag** and, under `History:Mode=Full`, a `possible_duplicate` event, so operators can see which deliveries might have been sent twice. Aborts before the end of data cannot have been accepted by the remote and are requeued without the flag (reasoning from SMTP acceptance semantics). The flag travels with the row into the target.
  5. *Export and mark:* queued rows (retry state: attempt count, `due_at`, last error), spool bodies and pending webhook outbox rows are exported with their **message ids, delivery ids, webhook event ids and API idempotency keys preserved**, and the source marks each exported row `transferred(switch_id)`. A marked row cannot be claimed even if the fence were cleared by mistake.
  6. *Import:* the target stores the rows with ids preserved, leases cleared and state `queued`, but **does not dispatch** until it is activated. Import is idempotent per `switch_id` and chunk, so repeating it creates no duplicates; the importer refuses a non-empty target that does not carry the same `switch_id`.
  7. *After cutover:* receivers can de-duplicate webhooks by event id, and clients retrying an API send after cutover are de-duplicated by the preserved idempotency keys. SMTP submissions have no idempotency key, so a client that retried because it never saw a `250` can still create a duplicate, as in any SMTP system.
- **Rollback and the fence:** before activation, `rollback` clears the transfer marks and the fence on the source and discards the target's imported data; nothing was sent from the target, so no duplicates are possible. After activation the target may have delivered the rows, so un-fencing the source is refused; going back means running the same flow in reverse (target → source), which fences the target and transfers what is still queued.

**History migration (in v1).** When `History:Mode=Full` on both sides, events, content and retained raw are exported in time-ordered, checksummed chunks (per-day chunks, further split by size) and imported in order with a progress record (`switch_id`, last verified chunk). The job is **streamed** (bounded memory) and **resumable** (restart continues after the last verified chunk; re-sending a chunk is idempotent). `--skip-history` skips it. History is not needed to send mail, so the cutover does not wait for it: the config, stats and queue move in the cutover, and history can be copied **before activation (default for small history) or backfilled after activation** from the read-only source (the target keeps recording new history meanwhile; backfilled rows are older and cannot conflict). The source is kept until the backfill is verified. Size and time are proportional to retained bytes (the modeled example of §5 is about 14 GB at 7 days of content, or about 35–150 GB with attachments) but **no throughput was measured**, so any time estimate is **unverified**; the preflight prints row and byte counts, and the throughput is to be measured in a spike ([open-questions.md](open-questions.md)).

**Steps (identical in both directions; each is a checkpoint the owner can stop at).** Source states: `Active → Quiescing | Draining → Fenced → (Active again on rollback | Finalized)`. Target states: `Importing → Verified → Confirmed → Active`.

1. **Preflight**: target reachable and empty (the importer refuses to merge into a non-empty target), schema/migrations current, target key protection available, bundle format compatible, disk space and size/time estimate from row counts, sync-mode warning if the target is SQLite with `Off`, and a statement of what will not carry over (for example history when the target is `StatsOnly`).
2. **Drain or quiesce** the source, ending with the source `Fenced`.
3. **Export** the bundle (stats flushed first).
4. **Import** into the target (state `Importing`).
5. **Verify**: per-table row counts against the manifest, per-file and per-chunk SHA-256, and a checksum recomputed from the target's tables; report shown to the owner. State `Verified`.
6. **Confirm** (explicit owner action). State `Confirmed`.
7. **Activate**: see "Activation".
8. **Finalize** (separate, explicit): only then may the owner remove the old data. The tool never deletes the source.

**Activation, and orchestrator-managed configuration (DESIGN-DECIDED).** The storage pointer (`Storage:Backend` and its connection) cannot live in the database it points to, so it is always *deployment configuration*. Precedence for every setting is: **command line > environment variables / mounted ConfigMap files > bootstrap file on the data volume > settings persisted in the config store > built-in defaults**. A value supplied by the deployment layer shows in the dashboard as "locked by deployment" and cannot be edited there; settings that are not set by the deployment are editable in the dashboard and persisted in the config store. The storage pointer itself is never persisted in the config store (it would be circular, and a stale override in the old store would conflict after a switch).

The switch **never rewrites environment variables, ConfigMaps or compose files.** The tool detects where `Storage:*` comes from:

- *Bootstrap-file-managed* (typically a single container with a writable data volume): after confirmation the tool writes the new pointer into the bootstrap file and restarts.
- *Orchestrator-managed* (Kubernetes, compose with environment-supplied settings): the tool completes everything up to `Confirmed`, then **produces a cutover patch** with the exact keys to change (an environment diff, a ConfigMap patch or a compose override snippet; secrets are referenced by name, never printed) and stops. The operator applies it and restarts.
- **Startup gate (the same in both cases):** on start, the application reads the `switch_state` of the store it is pointed at. With no switch record, or `Active`, it runs normally. With `Confirmed`, it atomically moves to `Active` and only then starts accepting and dispatching. With `Importing` or `Verified` it starts in a restricted mode (dashboard and API read-only, no accepting, no dispatching) and shows what is pending. A **fenced source** (an old pod, or an instance restarted with the old configuration) shows a banner naming the switch and refuses to accept or dispatch, so a forgotten replica cannot double-send.

Rationale: patching the deployment is the operator's job and cannot be done safely from inside the pod; the persisted state plus the startup gate make the order of operations safe whatever the orchestrator does.

**Rollback.** The source is kept read-only (fenced, files unmodified) until the owner finalizes. Before activation, rollback is `rollback`: discard the target, clear marks and fence, resume the source. After activation, going back is the same flow in reverse. That symmetry is the point of the design.

**Implementation notes (built; details in [components/switch.md](components/switch.md)).** Choices made while building, each **DESIGN-DECIDED**:

- *The bundle row is the EF entity.* One registry (`TransferTables`) lists the 28 tables that move; the relational providers share one implementation of export/import (`EfStorageTransfer`), the in-memory backend has its own. The queue, stats and history stores of SQLite are raw SQL for the hot paths, but export and import go through EF, so adding a table adds it to the bundle in one place. Bundle format 1.1.0 adds per-table checksums, chunk metadata and the history export progress.
- *Chunks and body packs.* Tables are exported in chunk files (5,000 rows or 32 MiB); the raw messages of a chunk are one body pack, not one file per message; history is chunked per day.
- *Order-independent table checksums.* Providers return rows in different orders, so a table checksum is the 256-bit sum of the SHA-256 of each canonical row. Secrets are checked separately by a keyed digest (HMAC) whose key travels protected by the bundle key ring.
- *Hold column and gate.* `delivery_queue` and `webhook_outbox` carry `transfer_switch_id`: a transfer mark on the source, an activation hold on the target; a held row is never claimed. A persisted-state gate in every backend refuses accept, claim, outbox claim and maintenance on a fenced source and on an unactivated target, including after a restart.
- *Progress records.* One `transfer_chunk_<part>` table per model part (a part is one SQLite file): a chunk and its record commit together, which makes import idempotent per switch id and chunk and history resumable. SQLite schema version 3, PostgreSQL migration V003.
- *Drain does not wait for the webhook outbox.* Pending outbox rows move in both modes (receivers de-duplicate by event id); only the delivery queue gates a drain.
- *Effective values travel in the pointer.* They are deployment configuration, not rows, so the activation carries every effective source setting that differs from the built-in default (bootstrap file, or cutover patch), instead of writing them into the `setting` table.
- *One process per SQLite directory.* A lock file proves the server is stopped before the offline `mta migrate-storage` commands open the files.
- *Abort flag precision.* `SmtpClientConnection.EndOfDataStarted` tells the delivery engine whether the end-of-data terminator of the current transaction had begun to be written when a quiesce cancelled it; only then is the requeued delivery flagged `possible_duplicate` (item 4 above).
- Not yet built: the dashboard flow (the admin API endpoints are `StorageSwitchService` over `IStorageSwitchEngine`).

Effort: the switch engine, quiesce and fence, resumable history migration, Data Protection bundle protection, the orchestrator-aware cutover, the CLI and the dashboard flow ([plan.md](plan.md)); engine, fence, history migration, bundle protection, cutover and CLI are built, the dashboard flow is not.

## 5. History and content retention

(`History:Mode=Full`, on either backend.) The raw message is delivered verbatim (apps may DKIM-sign their own mail; rebuilding MIME would break the signature), so it stays untouched in `message_spool` until every recipient is final. Stripping a partitioned row in place would create dead tuples and rewrite TOAST, so content is split into separate tables instead (on SQLite the same split applies, with `history.db` holding the content and retained-raw tables).

- Default stored content: subject + text + html + attachment index. Attachments are **not** stored unless enabled.
- Attachment flag precedence: per-send API flag, then per-tenant setting, then global default (`false`), behind the master switch `Content:AllowAttachmentStorage`. SMTP ingress uses the tenant setting only.
- Config (proposed): `Content:Mode = Retain | None` (default `Retain`; `None` deletes content at the final state), `Content:RetentionDays = 7` (range 6–30, **no unlimited value**; see §5.1), `Content:StoreAttachments = false`, `Content:MaxStoredBodyBytes = 256 KiB` (truncated with a flag), `Content:StoreSubject` configurable (subjects can contain personal data). Event metadata is kept 30 days (`Retention:MetadataDays`, `0` = keep forever, see §5.1); anything content-like (e.g. a preview) follows the content retention.
- Resend: from retained raw when attachment storage was on; for attachment-free messages, "send again from content" re-composes from stored subject/body and is labelled as re-composed (headers not byte-identical); otherwise the dashboard shows "attachments were not stored" and the API returns a clear error. In `StatsOnly` there is nothing to resend from (§5.2).
- The dashboard renders stored HTML only in a sandboxed iframe under a strict CSP, with plain text as the default.
- Size model (illustrative, not measured; 100k messages/day, about 20 KB content per message, an assumption; sizes are bytes, whichever backend): about 2 GB/day and 14 GB at 7 days before TOAST compression (PostgreSQL). Worst case spool (all mail deferred 5 days) about 25 GB. With attachment storage on: about 35 GB at 7 days, about 150 GB at 30 days.
- Revisit the Postgres-only body design if retained content passes roughly 200–300 GB, WAL passes roughly 50 GB/day or restore time becomes unacceptable (rules of thumb, unsourced).

### 5.1 Retention knobs and unlimited retention

**Convention (applies everywhere): a retention value of `0` means "keep forever" (unlimited).** Negative values are invalid. Unlimited means no automatic cleanup: disk grows without bound and the operator must clean up manually or with external tooling. The dashboard shows a warning next to any knob set to `0`. The knobs and their meaning are the same on both backends; only the cleanup mechanism differs (partition drop on PostgreSQL, batched `DELETE` plus `incremental_vacuum` on SQLite).

| Knob | Default | Allowed | Unlimited (`0`)? | Cost / reasoning |
|---|---|---|---|---|
| `Webhooks:OutboxRetentionDays`, `Webhooks:AttemptLogDays` | 7 | any positive integer, or `0` (**owner-decided**; the earlier cap of 30 is removed) | Yes | Rows grow with event volume. On SQLite the outbox lives in `queue.db`, the hot file, so unlimited outbox retention inflates the file the writer commits to and slows vacuum/backup; the attempt log lives in `stats.db`. Prefer a finite outbox value on SQLite |
| `Retention:MetadataDays` (events, `History:Mode=Full`) | 30 | positive integer, or `0` | Yes, with warning | PostgreSQL: partitions are never dropped, so the partition count grows by one per day; PostgreSQL's partitioning docs caution that very many partitions raise planning time and memory (not re-fetched, **unverified**); consider week-sized partitions if used. SQLite: the events table grows without bound. Backup size and restore time grow on both |
| `Stats:HourlyRetentionDays` | 30 | positive integer, or `0` | Yes, with warning | Hourly rows are the bulk of the stats store (about 13.7M rows, 4–5 GB total, in the modeled large case at 30 days); unlimited growth is linear in time. The `Stats:MaxSeriesPerHour` cap still bounds each hour |
| `Stats:DailyRetentionDays` | 400 | positive integer, or `0` | Yes | Daily rows are small (modeled as about 10k rows/day in the large case, top 10 domains), so this is the safest knob to leave unlimited |
| `Content:RetentionDays` (`History:Mode=Full`) | 7 | **6 to 30 only** | **No** | See below |
| Suppressions | no expiry | n/a | Already unlimited | Needed for correctness |
| `History:RecentEvents` | 1,000 | count, not time | n/a | A bounded ring by design |

**Why `Content:RetentionDays` stays 6–30 and has no unlimited value.** The floor of 6 exists because content must outlive the 5-day queue lifetime (otherwise the dashboard view and resend would vanish before the message is final). The ceiling of 30 is a safety bound, not a technical limit: content holds personal data (subjects, bodies, optionally attachments), so unlimited retention is a privacy and compliance liability, and it is the largest storage consumer (about 150 GB at 30 days with attachments in the modeled example, with a revisit threshold of roughly 200–300 GB). For operators who need to keep nothing, `Content:Mode=None` deletes content at the final state, and `History:Mode=StatsOnly` records no content at all. **OWNER-DECIDED:** the range stays 6–30 with no unlimited value and no override; `0` = unlimited is the convention for the other retention knobs only.

### 5.2 API behavior when history is not recorded or has expired (DESIGN-DECIDED)

The rules are the same on both backends. They reuse the earlier `body_expired` state (an expected state, as opposed to `body_missing`, which is an error).

| Situation | Response |
|---|---|
| `History:Mode=StatsOnly`: any per-message resource (`GET /messages/{id}`, `/events`, `/content`, `POST …/resend`) or message search/list | **`410 Gone`**, code `history_not_recorded` |
| `History:Mode=Full`, message found, content past `Content:RetentionDays` | `GET /messages/{id}` returns **`200`** with `content.state = "body_expired"` (metadata and events are still available); `GET /messages/{id}/content` returns **`410 Gone`**, code `body_expired`; resend returns `410` `body_expired` |
| `History:Mode=Full`, message id unknown or past `Retention:MetadataDays` | **`404 Not Found`**, code `message_not_found` |
| Resend of an attachment-free message that has no retained raw | Allowed, labelled as re-composed (§5); with attachments and no retained raw: **`409 Conflict`**, code `attachments_not_stored` |
| Content missing although it should exist | **`500`**, code `body_missing` (an error state, alerted) |

Why `410` and not `404`, `409` or `200`: in `StatsOnly` the server cannot tell an unknown id from a message it never recorded, so `404` would wrongly say "no such message"; `409` implies a conflict the client could resolve by retrying; `410` states that the resource is intentionally not available and will not appear, which is exactly the situation. Expired content is also `410` for the same reason, while the message resource itself stays `200` so dashboards can still show the timeline. `501` is not used because the capability is not missing. Clients can avoid the error by reading the capabilities endpoint (`history.mode`, `content.retentionDays`) first.

Error body: RFC 9457 problem details (`application/problem+json`, supported natively by ASP.NET Core), with extension members:

```json
{
  "type": "https://eggmail.example/problems/history_not_recorded",
  "title": "Per-message history is not recorded",
  "status": 410,
  "detail": "History:Mode is StatsOnly; per-message data is not stored.",
  "code": "history_not_recorded",
  "history_mode": "StatsOnly",
  "request_id": "01J…"
}
```

For `body_expired`, add `"expired_at"` and `"retention_days"`. The `type` URI is a placeholder (a proposal; no domain is registered for it).

## 6. Webhooks (identical on both backends)

- **Format:** [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md): headers `webhook-id`, `webhook-timestamp`, `webhook-signature`; HMAC-SHA256 over `id.timestamp.payload`; signature `v1,<base64>`; secrets `whsec_…`; rotation by signing with old and new keys (space-delimited). The event id is the idempotency key; delivery is at-least-once and unordered. The spec says only "some allowable tolerance" for replay; the default 5-minute window is Stripe's library convention.
- **Retry schedule (default):** immediately, 5 s, 5 min, 30 min, 2 h, 5 h, 10 h, 10 h (about 27 hours), identical to Svix and Resend. Other platforms differ (Postmark 6 retries, Mailgun 8 hours, Stripe up to 3 days).
- **Delivery rules:** success is 2xx within 15 s; `410` disables the endpoint; `429`, `502` or `504` throttle; redirects are not followed; an endpoint is disabled after 5 days of continuous failure and the tenant is notified; per-endpoint concurrency capped (default 4).
- **SSRF protection:** HTTPS required by default (`Webhooks:AllowHttp=false`). Resolve the host, validate resolved IPs against a denylist (loopback, private ranges, link-local, `169.254.169.254`, `fc00::/7`, `fe80::/10`, multicast), connect only to the validated addresses keeping the host name for SNI and `Host` (defeats DNS rebinding). A per-tenant allowlist overrides for internal endpoints.
- **Schema:** `webhook_endpoint` (config DB: id, tenant, url, wrapped secret, event types, enabled, disabled reason); `webhook_outbox` (in the queue store, `queue.db` on SQLite: id, endpoint, tenant, event type, event id, JSON payload, next_attempt_at, attempt count, state, lease), inserted in the same transaction that completes the delivery row so a crash cannot lose an event whose outcome is already durable; `webhook_attempt` (in the stats store, `stats.db` on SQLite: outbox id, time, status code, duration, error class, response snippet of at most 1 KB; losing a few rows on a crash is acceptable).
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

- **Certificates and ACME state live in the database** (the config store, on both backends; owner-decided): the ACME account key, issued certificates and chains, private keys, challenge state and renewal metadata (not-after, last attempt, ARI data, failures). Private keys and the account key are protected with Data Protection (§9.1). They are included in the switch bundle (§4.6). One certificate store serves SMTP and the dashboard through an own `ServerCertificateSelector`; TLS 1.2 minimum (1.3 on).
- **Hot reload from the database:** each replica holds the certificates in memory and polls the store every 30–60 s for a changed version or thumbprint (a cheap query), validates the new certificate (key match, `NotAfter`, SAN, chain) before swapping, and keeps the old one and alerts on failure. This replaces polling files (which was unreliable with Kubernetes' `..data` symlink swap). If the database is briefly unavailable, replicas keep serving the certificates already in memory.
- **Renewal lock for multiple replicas (Full):** renewal must run on one replica at a time. A long-running ACME flow (DNS-01 propagation takes minutes) cannot hold a database transaction or a pooled session-level advisory lock, so the design uses a **renewal lease row** (`lock name, owner, lease_until, fencing token`, renewed while working) that works on both backends; on PostgreSQL a short transaction-level advisory lock (`pg_try_advisory_xact_lock`) guards acquiring the lease. The owner suggested an advisory lock; this is the same idea adapted to a long flow (**DESIGN-DECIDED sub-choice**).
- **Sources and precedence:** certificate in the database (ACME-issued, or imported through the dashboard), self-signed on first run (stored in the database and flagged in the dashboard), or built-in ACME with Certes (pin 4.1.x behind an interface; **DNS-01 by default**, Cloudflare first, pluggable DNS-provider interface; renew using ARI). An **optional file or environment override** (mounted PEM/PFX, e.g. cert-manager under Kubernetes) takes precedence when configured, and the app then only watches those files. Let's Encrypt moves the default profile to 64-day certificates on 2027-02-10 and 45 days on 2028-02-16, and no longer sends expiry emails, so expiry must be monitored. Certes was dormant 2021–2026 with a single recent author; the fallback is an own client (6–12 weeks).
- **Bootstrap problem:** the app needs the database to read its certificates, so it cannot terminate TLS before the database is reachable. Startup order: connect to the database (the database connection has its own TLS, independent of these certificates); start the plain HTTP listener on 8080 (probes; reachable on loopback or the internal network for first setup); load certificates from the store (or the file/environment override); if none exist, generate and store a self-signed certificate so HTTPS (8443) and SMTP STARTTLS come up, and flag it in the dashboard. SMTP does not accept mail while the database is down (`451`), so no certificate is needed in that state. The certificate that protects the Data Protection key ring (`Secrets:KeyProtection=Certificate`) or the KMS credential is *deployment configuration outside the database*, otherwise the secrets could not be opened; it is not one of these TLS certificates.
- **Security note on keys in the database:** TLS private keys and the ACME account key are stored encrypted by Data Protection (AES-256-CBC with HMAC-SHA256 by default), and the key ring is protected by a certificate or KMS held outside the database. Anyone who can read the database *and* the key-protection certificate/KMS can recover the keys, and database backups, replicas and dumps contain the ciphertext, so protect the key-protection secret separately and restrict who can use it. Grant the read-only dashboard role no access to the secret tables. With `Secrets:KeyProtection=None` (dev only) the keys are effectively unprotected in the database.
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
- DKIM private keys, webhook secrets, TLS private keys and the ACME account key are protected with ASP.NET Core Data Protection; the Data Protection key ring is persisted in the config store and itself protected by a certificate or KMS (`Secrets:KeyProtection = Certificate | Kms | None`; `None` is for dev only). That certificate or KMS credential is deployment configuration outside the database and comes from the `*_FILE` secret convention. Never delete old Data Protection keys. Backend switching re-protects secrets under the target's ring through a bundle-specific Data Protection key ring (§4.6).
  *Implemented:* `Kms` is a pluggable key-wrapping provider with a built-in file/environment key and no cloud service (decision 66).
- Dashboard passwords: PBKDF2 from the BCL (iteration count per current OWASP guidance, to be set) or an Argon2 library.
- Encryption at rest is a storage-layer responsibility (volume or database); application-level envelope encryption is deferred behind an interface.

### 9.2 In-house security review
STRIDE threat model per trust boundary (SMTP in, SMTP out, DNS, storage, dashboard, key store); OWASP ASVS L2 for API and dashboard, L3 for key and credential handling; written parser-review checklist plus SharpFuzz on every parser with crashers kept as regression tests; attack suites (smtpsmug, SMTP-Smuggling-Tools, EAST for STARTTLS, slowloris, connection flood, oversized DATA, MIME bombs with memory/CPU ceilings); port pen-tests (relay abuse, AUTH brute force, `testssl.sh`, Internet.nl); container hardening (non-root, read-only root filesystem, `cap_drop: ALL`, default seccomp, CIS Docker Benchmark, Trivy/Grype); a non-author reviews every security-relevant PR; quarterly "red hat" week; CVSS 4.0 with fix SLAs (e.g. critical 7 days, high 30, medium 90); every finding becomes a regression test.

An **external audit is recommended before first production-critical use** (2–4 weeks with 2–4 testers is a reasonable scope by inference from comparable audits; no cost figures found, get quotes). Publish `security.txt` and a disclosure policy before launch.

### 9.3 Dashboard supply chain
Preact + Vite recommended. Build in a Node stage of the Dockerfile and copy only `dist/`; `npm ci --ignore-scripts`, a minimum release age (about 7 days), `npm audit signatures`, OSV scanning, a strict CSP (`script-src 'self'`, no inline), and about 10 or fewer direct dependencies. Treat the dashboard as an admin surface with the same review as the SMTP stack.

## 10. Deployment

- **PostgreSQL backend ("Full"):** app + managed Postgres via compose (app + `postgres:17` with a `pg_isready` healthcheck) or a Kubernetes Deployment. More than one replica is safe (no local blobs; `SKIP LOCKED` claims; advisory-locked retention job).
- **SQLite backend ("Lite"), the default:** one container, one volume mounted at `/data` (ReadWriteOnce, local), one replica, recreate rollout. Characteristics of the backend (§4.2), not missing features.
- **Switching backends** is manual and symmetric (§4.6); the guided action cannot provision Postgres or change container topology.
- **Image:** **a single Docker image** that runs out of the box (SQLite backend, one volume at `/data`, the default ports of §7.1) and selects the PostgreSQL backend by configuration (`Storage:Backend=Postgres`) in the same image. Chiseled, with ICU (the `-extra` variant) plus a startup Unicode self-test (silent failure in invariant mode is a risk). ReadyToRun; no trimming (EF is not trim-safe). Pin versions. Release process, registry, tags and quick-start snippets: [release.md](release.md).
- **Health:** `--healthcheck`; liveness separate from readiness. When the backend is PostgreSQL and it is down: `451` to SMTP clients, `/readyz` fails, `/healthz` stays alive.
- **Observability:** `System.Diagnostics.Metrics` and `ActivitySource` (BCL, so even the SMTP stack emits metrics), OpenTelemetry with OTLP, JSON console logs. The OTel Prometheus exporter was still beta and prometheus-net had no release since January 2024, so a hand-rolled `/metrics` endpoint (about 150 lines) was suggested as the alternative.
- **Limits (settings with identical defaults on both backends):** `Smtp:MaxMessageSize` 25 MiB, 50 recipients, `Queue:MaxLifetime` 5 days.
- **Deliverability operations** (IP reputation, warm-up, PTR/EHLO, port-25 blocking, abuse desk) are operational, not code, and sit outside the engineering estimate.
