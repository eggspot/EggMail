# Storage (`Mta.Storage`, `Mta.Storage.Sqlite`, `Mta.Storage.Postgres`)

One storage model, three implementations behind `IStorage` (decision E: feature-identical backends):

| Project | What it is |
|---|---|
| `Mta.Storage` | The contracts, the shared EF model split into four parts, the logic every backend shares (attempt planning, statistics bucketing and rollup, status rules, lease rules), the EF `IConfigStore`, and `InMemoryStorage` |
| `Mta.Storage.Sqlite` | `SqliteStorage`: four database files, one group-commit writer per file |
| `Mta.Storage.Postgres` | `PostgresStorage`: one database, one transaction across everything, day partitions, owner/runtime roles (see "PostgreSQL backend") |
| `tests/Mta.Storage.Tests` | The conformance suite (abstract classes, one `CreateAsync(StorageOptions)` to plug a backend in) plus unit tests of the shared logic |
| `tests/Mta.Storage.Sqlite.Tests` | The conformance suite against SQLite (history Full and StatsOnly, sync Off/Normal/Full, memory queue) plus SQLite-specific tests |
| `tests/Mta.Storage.Postgres.Tests` | The conformance suite against a real PostgreSQL (throwaway cluster, or `EGGMAIL_TEST_POSTGRES`; skipped when neither exists) plus PostgreSQL-specific, outage and cross-backend equivalence tests |

## Entity overview

The model is four parts. On SQLite each part is its own context and its own file; the PostgreSQL provider composes all four with `StorageModel.ConfigureAll` into one context (see "PostgreSQL backend"). Table and column names are snake_case; there are **no foreign keys** (references are soft so cross-file effects, imports and partial restores never depend on order). Secrets columns hold bytes already protected with Data Protection.

| Part (context, SQLite file) | Tables |
|---|---|
| config (`ConfigDbContext`, `config.db`) | `tenant`, `api_key`, `smtp_credential`, `dashboard_user`, `dashboard_session`, `domain`, `dkim_key`, `suppression`, `webhook_endpoint`, `setting`, `tls_policy`, `relay_route`, `certificate`, `acme_account`, `acme_renewal`, `domain_record_check`, `tls_rpt_bucket`, `sending_counter`, `lease`, `switch_state`, `data_protection_key` (`IDataProtectionKeyContext`) |
| queue (`QueueDbContext`, `queue.db`) | `delivery_queue` (one row per recipient), `message_spool` (verbatim raw message, freed with the last recipient), `webhook_outbox`, `api_idempotency_key` |
| stats (`StatsDbContext`, `stats.db`) | `stat_aggregate` (hourly and daily rows in one table, `WITHOUT ROWID`), `stat_meta` (rollup watermark), `recent_event` (the bounded ring), `webhook_attempt` |
| history (`HistoryDbContext`, `history.db`, only with `History:Mode=Full`) | `message_index`, `message_recipient`, `message_event` (`WITHOUT ROWID`, keyed with a leading `day`), `message_content`, `message_raw_retained` |

Notes on placement:

- `api_idempotency_key` is logically configuration (the switch bundle exports it with config), but on SQLite it lives in `queue.db` so the duplicate check is atomic with the spool insert; a separate file would reopen a crash window between "key stored" and "message queued".
- History keys start with `day` = days since 1970 of the **UUIDv7 message id**, so retention is a key-prefix range delete (decision L) and the day is derived from an id without a lookup. `AcceptAsync` therefore requires a UUIDv7 `MessageId` (`Ids.New`).
- `WITHOUT ROWID` is used for the small-row history and stats tables only. `message_content` and `message_raw_retained` hold large values, where SQLite documents `WITHOUT ROWID` as a loss, so they are ordinary tables with a unique `(day, message_id)` key.
- Provider specifics live in `IStorageModelHooks`. The SQLite hooks store every `DateTimeOffset` as UTC unix milliseconds (`INTEGER`), so comparisons and ordering run in SQLite; Guids use the provider default (upper-case canonical TEXT, whose text order is the UUIDv7 time order). The schema is generated from the model (`GenerateCreateScript`), `WITHOUT ROWID` is applied from a model annotation, and a test compares every table's columns to the model.

## File layout and pragmas (SQLite)

Under `Sqlite:DataDirectory`: `queue.db`, `stats.db`, `config.db`, and `history.db` **only** when `History:Mode=Full`. With `Sqlite:QueuePersistence=Memory` the queue is an in-memory SQLite database owned by the queue writer and `queue.db` is never created (explicit opt-in: accepted means in memory, lost on restart; surfaced as the `queue_persistence_memory` health warning).

| Pragma | Value | Meaning |
|---|---|---|
| `auto_vacuum` | `INCREMENTAL`, set before the first table exists | freed pages go on a free list; `incremental_vacuum` after retention deletes returns them to the OS |
| `journal_mode` | `WAL` | writers append to the log; readers and the writer never block each other; persistent in the file; no network file systems |
| `synchronous` | `Sqlite:SyncMode` (default `Off`) for queue/stats/history, `Sqlite:ConfigSyncMode` (default `Full`) for config | `Off`: no fsync, safe against a **process** kill, an OS crash or power loss can corrupt; `Normal`: fsync at checkpoints, no corruption but recent commits can roll back; `Full`: fsync every commit, durable |
| `busy_timeout` | `Sqlite:BusyTimeout` (5 s) | wait for a lock before `SQLITE_BUSY` |
| `journal_size_limit` | `Sqlite:JournalSizeLimitBytes` (64 MiB) | the WAL is truncated to at most this after a checkpoint |
| `cache_size` | 16 MiB (writer only) | page cache of the writer connection |
| `user_version` | 7 | schema version; versions 1 to 6 are upgraded in place, one step per version, each idempotent (2: dashboard tables and fingerprint; 3: backend switch column and tables; 4: persisted runtime state tables in `config.db`, `message_id_header` and `tags` on `message_index` in `history.db`; 5: `delivery_queue.headers_utf8`; 7: the index on `delivery_queue (message_id)`, which cancelling uses; there is no SQLite version 6: PostgreSQL's `V006` replica tables are PostgreSQL-only and the numbers are kept equal), a newer version is refused, an unversioned database with tables is refused |

`Cache=Shared` is never used. Reads use separate short pooled connections (the only exception is the in-memory queue, whose reads run on its writer). Every connection of a file is private; WAL means readers see a committed snapshot.

**Startup:** per file `PRAGMA quick_check` (or `integrity_check` when `Sqlite:QuickCheck=false`); a failing file (or one that cannot even be opened) is **quarantined**: the file and its `-wal`/`-shm` move to `<DataDirectory>/quarantine/<utc timestamp>/`, nothing is deleted, an empty file is created, and `IStorageMaintenance.GetHealthAsync` reports `sqlite_quarantined:<file>` with the path. Then all leases are cleared (single process; delivery is at-least-once) and the spool is reconciled. A startup log warning names every file running with `synchronous=OFF` (decision P); health carries the `sqlite_sync_off` warning and per-file `sync_mode.*` details; readiness is not failed by it.

## Writer design

One writer per file, `SqliteFileWriter`: a dedicated thread, a **bounded channel** (`Sqlite:WriterQueueCapacity`) and **group commit**. Callers submit a command and await its result; the thread drains up to `Sqlite:WriterMaxBatch` commands into one `BEGIN IMMEDIATE … COMMIT` and completes the callers after the commit returned. Under `Full` it also lingers up to `Sqlite:WriterBatchWindow` for more commands (that is where one fsync is amortized); under `Off`/`Normal` a commit costs no fsync, so it commits when the queue is momentarily empty and batches still grow whenever commands arrive faster than commits finish.

- **Acknowledgement semantics:** `AcceptAsync` returns after the queue transaction committed. `Off` = handed to the OS, `Normal` = in the WAL (fsynced at checkpoint), `Full` = fsynced.
- **Back-pressure:** when the channel is full callers wait (a cancellation token cancels the wait, not a queued command). That is the only throttle; there is no rate limiter.
- **Fault isolation:** if any command of a batch throws, the batch is rolled back and its commands are replayed one by one in their own transactions, so a constraint violation fails only its own caller. Commands therefore keep side effects outside the database out of `Execute`.
- **Allocation:** a submission is one object (the command doubles as the `IValueTaskSource`); statements are prepared once per writer and parameters set by index. The hot paths (intake, claim, record attempt) use ADO.NET on the writer connection; EF is used for schema generation and for the config store (a cold path; shared with PostgreSQL), where config writes run on the config writer's connection and transaction.
- Metrics (`SqliteStorage.WriterMetrics`, also in health details): commits, commands, max/last batch size, queue depth, last and max commit time. These feed the advisory storage-pressure indicator.
- Meter `Mta.Storage.Sqlite` (`SqliteMetrics`, table in [../operations.md](../operations.md#monitoring)): the writer records the commit duration and the batch size of every transaction per file (`file` label: `queue.db`, `stats.db`, `config.db`, `history.db`), failed batches are counted, and gauges report the live writer queue depth, the WAL size, `synchronous=OFF` per file (`sqlite_sync_off`) and files quarantined at start. A storage attaches itself after a successful start and detaches when disposed. The gauges are state, so a quarantine that happened before the exporter started is still visible.
- PostgreSQL has no `Mta.Storage.Postgres` meter: command latency and pool state come from Npgsql's own meter (`db.client.*`), which the Prometheus exporter and OTLP include. The data sources are named (`eggmail-runtime`, `eggmail-owner`, `eggmail-coordination`) so the pool label is a short fixed name instead of the connection string.

### Claim

A single statement through the queue writer: `UPDATE delivery_queue SET lease_owner, lease_until WHERE id IN (SELECT id … WHERE due_at <= now AND lease_until <= now AND expires_at > now ORDER BY due_at, id LIMIT n) RETURNING …`. A lease that is past is simply claimable again (no attempt is counted); `ClaimExpired` takes rows past `expires_at`. Rows are returned oldest-due first.

### Recording an attempt (`AttemptPlanner`)

The consequences of an outcome are computed by one shared function, so SQLite and in-memory cannot drift:

| Outcome | Queue row | Event | Counter |
|---|---|---|---|
| Delivered | deleted | delivered | Delivered |
| Deferred (counted) | attempt+1, new due time, lease released, `last_error` | deferred | Deferred |
| Deferred, `CountAttempt=false` | due time and lease only; no attempt, no event, no statistic, no webhooks | none | none |
| Failed | deleted | bounced | HardBounce |
| Expired / Suppressed / Cancelled | deleted | expired / suppressed / cancelled | Expired / Suppressed / none (`Cancelled` is produced by `CancelAsync`; the delivery processor never records it) |
| AbortedBySwitch | requeued unchanged (lease released) | aborted_by_switch | none |

`Suppress=Complaint` adds a `complained` event and counter; `PossibleDuplicate` adds a `possible_duplicate` event and sets the sticky flag on a surviving row. Webhook events fan out to the tenant's **enabled** endpoints whose list contains the event type or `*` (an empty list receives nothing), in the same transaction as the row completion. The spool counter is decremented in that transaction; the last recipient frees the spool row. Recording an attempt for a delivery that is already gone is a no-op, so reports are safe to repeat.

### Cancelling (`IDeliveryStore.CancelAsync`, decision 84)

One shared decision function (`CancelPlanner`) splits the message's waiting rows into "cancel" (not leased, not marked for a switch), "in flight" (leased), "transfer-held" and "not waiting" (a *named* recipient without a row), so the backends cannot disagree; the result also carries how many rows were waiting (`Waiting`, whatever was requested), which the API uses to tell an unknown or finished message from one whose named recipients are not waiting. Each cancelled row then goes through `AttemptPlanner.Plan` with a `Cancelled` attempt, exactly as a recorded attempt; a row whose lease ran out without a report (`lease_owner` set) or that is flagged `possible_duplicate` is planned with the doubt, so its events say so (`possible_duplicate`). The webhook event of each cancelled row comes from a callback of the caller (storage cannot reference `Mta.Webhooks`) and its outbox rows are written in the same transaction as the deletion.

- **SQLite:** the selection, the deletes, the spool decrement and the outbox rows are one queue-writer command (`CancelCommand`); the fence is checked again inside it. Then, **as for a recorded attempt, the queue (`queue.db`) and the history (`history.db`) are different files and not atomic together**: retained raw, history events and status, and the recent-events ring follow the queue commit, so a crash between the two leaves the queue right and the history without the `cancelled` event (the same window as in the crash table below).
- **PostgreSQL:** everything in one transaction (`SELECT … WHERE message_id AND tenant_id ORDER BY id FOR UPDATE`, the fence re-checked with the rows locked, then the same code as a recorded attempt for each row, including the history), so there is no such window.
- **In-memory:** under the state lock.

The rows are found through an index on `delivery_queue (message_id)` (schema version 7: SQLite `user_version` 7 created for new files and added by the upgrade step from 5; PostgreSQL `V007`, `CREATE INDEX IF NOT EXISTS`, which blocks writes to `delivery_queue` while it builds). Cancelled rows write the `cancelled` event and the message status (the shared `MessageStatus.Next`) only under `History:Mode=Full`, and no statistics counter: `StatCounter` has no cancelled bucket, and adding one would change the statistics API contract for an event that is not a delivery outcome.

## Crash windows (design §4.4)

SQLite is atomic per file, not across files, so every cross-file effect is ordered and idempotent:

| Sequence | Crash between | Result |
|---|---|---|
| hard bounce: suppression (`config.db`) → complete row (`queue.db`) | the two | the delivery is retried and bounces again; the suppression upsert is idempotent |
| retained raw: mark spool `awaiting_retention` (`queue.db`) → raw to `history.db` → delete spool row | after the mark / after the copy | a spool row stays; the reconcile job (start-up and every maintenance run) copies it (idempotent) and deletes the row, so at worst a duplicate exists until then |
| accept: queue transaction → history entry | the two | the message is queued and delivered normally but has no history entry (never the reverse: no ghost history for a message that was never acknowledged); later events for it are stored without an index row |
| record attempt: queue transaction → history events → statistics/ring (memory, flushed ~10 s) | any | events or counters of that attempt can be missing; the queue state is always right |
| webhook complete: outbox update → attempt log (`stats.db`) | the two | one attempt-log row is lost (acceptable, design §6) |

What a kill does per sync mode: a **process** kill (SIGKILL) loses nothing that was acknowledged under `Off`, `Normal` and `Full` (the bytes are in the OS cache and WAL recovery replays them); this is tested by `CrashRecoveryTests`, which kills a child process mid-load in each mode and verifies every acknowledged message after reopening. **Power loss or an OS crash** is not tested here: `Off` can corrupt the database (the startup check then quarantines it and mail is lost), `Normal` cannot corrupt but can lose the latest commits, `Full` is durable. The statistics window (about 10 s) is lost on any crash.

## Maintenance (`RunAsync`)

Idempotent, safe to call repeatedly. In order: flush statistics; metadata retention (`message_event`, `message_recipient`, `message_index` by day key) and content retention (`message_content`, `message_raw_retained`); webhook outbox (finished rows) and attempt log; hourly→daily rollup then retention of hourly and daily rows; expired idempotency keys; spool reconcile; `incremental_vacuum` on files that deleted rows; `wal_checkpoint(PASSIVE)` after the batches and `TRUNCATE` for idle writers. Deletes run in batches of `Sqlite:RetentionDeleteBatchSize` (5,000) in separate short transactions with `Sqlite:RetentionDeletePause` between them. **`0` means keep forever** and skips the job (negative values are rejected at start; `Content:RetentionDays` must be 6..30). Reads also enforce the windows exactly (metadata and content expire at `received + days`), so a lagging maintenance run never exposes expired data; deletion is lazy.

**Rollup:** a day is rolled up one hour after it ends (late flushes still land in its last hour), `DELETE` + `INSERT … SELECT … GROUP BY` with a window function ranking the recipient domains by total volume (ties by name) and folding everything beyond `RecipientDomainTopNDaily` into `other`; a watermark in `stat_meta` prevents re-rolling.

**Statistics:** `Add` is a dictionary lookup and an interlocked add; the buffer is drained into `INSERT … ON CONFLICT DO UPDATE` upserts about every 10 s, on `FlushAsync` and on dispose. While writing, each (hour, tenant, sending domain) group admits the first `RecipientDomainTopNHourly` recipient domains (largest first within a flush) and buckets the rest as `other`; once an hour has `MaxSeriesPerHour` series new domains also go to `other`. This write-time top-N is approximate across flushes of one hour (documented gap); the daily rollup re-ranks by real volume. Reads see flushed data only. The recent-events ring keeps the newest `History:RecentEvents` outcome events (no content; no `queued` events).

**Backup:** `BackupAsync(dir)` creates `dir/eggmail-backup-<utc>/` and runs `VACUUM INTO` per file on its own connection (a consistent snapshot while the writer keeps committing; the memory queue is skipped). Restoring is copying the files into a data directory.

## Backend switch support

Every backend implements `IStorage.Transfer` (`IStorageTransfer`): streaming export of the 31 tables that move, idempotent chunked import with progress records, the persisted switch state with the gate behind it (a fenced source and an unactivated target refuse accept, claims and maintenance), and the transfer marks. The model gained `delivery_queue.transfer_switch_id`, `webhook_outbox.transfer_switch_id` and the four `transfer_chunk_*` tables (SQLite schema version 3 with in-place upgrades from 1 and 2; PostgreSQL migration `V003__backend_switch.sql`). Schema version 4 added three config tables to the registry (`domain_record_check`, `tls_rpt_bucket`, `sending_counter`; see "Persisted runtime state") and two columns to `message_index`; a bundle written before it imports into a version 4 target unchanged (the manifest names the tables it holds, the new columns are null). A provider adds `ITransferDbAccess` (a read context, a write transaction, and for day-partitioned history `PrepareHistoryDaysAsync`) and must exclude held rows in its claim SQL and consult the gate; `TransferConformance` checks all of it. Details in [switch.md](switch.md).

## Persisted runtime state (schema version 4)

State the process used to keep in memory only, and what an asynchronous bounce needs to find its message. Everything below is additive, exists on all three backends with the same observable behavior (shared conformance suites: `RuntimeStateConformance`, `HistoryConformance`, `StatsOnlyHistoryConformance`), and is created by SQLite `user_version` 4 (in-place upgrade from 1 to 3) and PostgreSQL `V004__persisted_runtime_state.sql`.

| Table (part) | What it holds | Writer |
|---|---|---|
| `domain_record_check` (config) | the result of the last DNS check of each record a domain must publish: `(domain_id, record_key = "TYPE\|host")` to `status` (ok, missing, invalid, pending), what was `found`, `checked_at`. The set of a domain is replaced by each check and deleted with the domain | `DomainVerificationService` after each check |
| `tls_rpt_bucket` (config) | an append-only journal of TLS-RPT collector flushes: one row per flush, policy domain and UTC day, with the aggregate as JSON and the number of failed attempts to send that day's report | `TlsReportJournal` (every minute and at shutdown); the report sender merges the rows of a completed day and deletes them once the report is sent |
| `sending_counter` (config) | the hourly and daily counters behind the sending caps and the warm-up: `(scope, tenant_id, domain, window_kind, window_index)` to `count`; the value is the sum of what every replica flushed | `SendingCounterPersistence` (write-behind, every 10 s and at shutdown) |
| `message_index.message_id_header` (history) | the normalized `Message-ID` header of the message (no angle brackets, lower case), indexed with the tenant, so a returned bounce finds the message | intake, `History:Mode=Full` only |
| `message_index.tags` (history) | the tags of an API send as a JSON array; null when there are none | intake, `History:Mode=Full` only |

These sit on the config store (`IRuntimeStateStore`, which `IConfigStore` extends): one EF implementation shared by SQLite and PostgreSQL, one in-memory implementation, writes through the config writer on SQLite and through the advisory-locked transaction on PostgreSQL, so the read-modify-write of a counter is atomic across replicas. DESIGN-DECIDED (decision 55): the tables live in the config part, not the stats part, because the stats writer batches in memory and is lossy by design while these rows are tiny, written in batches (a few rows every 10 s, so even `Sqlite:ConfigSyncMode=Full` costs one fsync per flush), and must move with the switch bundle (which the config part always does). `domain_record_check`, `tls_rpt_bucket` and `sending_counter` are in `TransferTables`; the lease table still does not move.

**Contract.** `IRuntimeStateStore`: `GetDomainRecordChecksAsync` / `ReplaceDomainRecordChecksAsync`; `AddTlsRptBucketsAsync` / `GetTlsRptBucketsAsync(beforeDay, max)` / `ReplaceTlsRptBucketsAsync(removeIds, replacement)`; `GetSendingCountersAsync(minHourIndex, minDayIndex)` / `AddSendingCountersAsync(deltas, pruneBeforeHour, pruneBeforeDay)` (a delta is added to the stored total, never below zero, a negative delta never creates a row, windows older than the previous hour and day are pruned by the next write). `IHistoryStore.AttachReportAsync(tenantId, messageIdHeader, AsyncReport)` appends a `bounced` or `complained` event to the newest message of the tenant with that `Message-ID` and moves the status (`MessageStatus.AfterReport`: a delivered message becomes `bounced`, or `partial` when it had several recipients; a delivered or partial message with a complaint becomes `complained`; anything else keeps its status). It returns the message id, or null when history is not recorded (`StatsOnly`: nothing per message is stored, so nothing is attached), the message is unknown, belongs to another tenant or is past `Retention:MetadataDays`. `MessageSummary.Tags`, `MessageQuery.Tag` (exact match of one whole tag: `json_each` on SQLite, `jsonb_exists` on PostgreSQL), `AcceptedMessage.MessageIdHeader` and `AcceptedMessage.Tags`.

**Crash windows.** Counters and TLS-RPT counts are written behind: a crash loses what was counted since the last flush (at most 10 s of sending counters, at most a minute of TLS-RPT counts); a graceful stop, a switch quiesce and the next start lose nothing. A TLS-RPT report that was sent but not yet deleted is sent again after a crash (at-least-once). An asynchronous report is attached after the suppression and the webhook are decided; a failure to attach is logged and never fails the bounce handling. Repeated delivery of one DSN adds one event per delivery (no de-duplication; the bounce listener always answers 250, so remotes do not retry). Version 5 (PostgreSQL `V005__headers_utf8.sql`) added `delivery_queue.headers_utf8`, the intake-time decision that a message's header section is internationalized (`AcceptedMessage.HeadersUtf8` to `ClaimedDelivery.HeadersUtf8`; it moves with the queued rows in a backend switch; old rows read false).

## Contract additions (all documented in the PR)

`StorageBackend.InMemory`; `QueueOptions.IdempotencyKeyLifetime` (24 h); `SqliteOptions` tuning knobs (`RetentionDeleteBatchSize`, `RetentionDeletePause`, `BusyTimeout`, `JournalSizeLimitBytes`, `StatsFlushInterval`); `StorageConflictException`; `StorageUnavailableException` (PostgreSQL only: the database cannot be reached, answer 451); `PostgresOptions` tuning knobs (`StatsFlushInterval`, `RetentionDeleteBatchSize`, `RetentionDeletePause`, `CommandTimeoutSeconds`); `IConfigDbAccess<T>.TranslateException` (default: none; lets a provider map connectivity failures for the shared config store); `DeliveryAttempt.CountAttempt` (uncounted holds); store-assigned `CertificateRecord.Version`; defined semantics for the settled gaps: `EventTypes` containing `*` subscribes to all, suppression addresses and slugs are lower-cased, settings with `TenantId == null` are global, `QueryAsync` is `[from, to)`.

### Additions for the HTTP API ([api.md](../api.md), [components/api.md](api.md))

All additive; the shared conformance suites cover them on both backends.

- **Dashboard users and sessions** (`DashboardUser`, `DashboardSession`, `DashboardRole`; tables `dashboard_user`, `dashboard_session`; ten `IConfigStore` methods). User names are unique case-insensitively (stored lower-case). A session row stores only the SHA-256 digest of the cookie secret, the user, the CSRF token and created / last-seen / expires. `EfConfigStore` reaches the two tables with `Set<T>()`, so `IConfigDbSets` is unchanged and a provider that implements it needs no new `DbSet` property. `DeleteDashboardUserAsync` removes the user's sessions.
- `IConfigStore.DeleteSmtpCredentialAsync(tenantId, id)` (tenant-checked).
- **Idempotency fingerprint:** `AcceptedMessage.IdempotencyFingerprint` is stored with the key in `api_idempotency_key.fingerprint` (new nullable column) and returned by `IntakeResult.IdempotencyFingerprint` on a duplicate, so the API can answer `409 idempotency_conflict` when the same key arrives with a different body. A provider that does not store it returns null and the API then treats a duplicate as a safe retry.
- `IWebhookOutbox.EnqueueForEndpointAsync(tenantId, endpointId, draft, now)` queues one event for one enabled endpoint regardless of its subscriptions (the "send test event" action). It is a **default interface member that throws `NotSupportedException`**, so a provider written before it compiles unchanged; the API answers 503 `not_ready` until the provider overrides it.
- `IMessageRecipientLookup` (optional interface on `IHistoryStore`): recipients of several messages in one call, so message lists can show them without loading content. Providers without it show lists without recipients.
- `IConfigStore.DeletePendingDkimKeyAsync(domainId, keyId)` (cancels a DKIM rotation: only a key that never signed can be deleted).
- Schema upgrades: SQLite `SchemaVersion` is 2 and a version 1 file is upgraded in place (`config.db` gets the two tables, `queue.db` the `fingerprint` column; tested by taking a current file back to version 1); PostgreSQL has migration `V002__dashboard_users_idempotency_fingerprint.sql`. The PostgreSQL provider implements `EnqueueForEndpointAsync`, `IMessageRecipientLookup` and the fingerprint.

## PostgreSQL backend (`Mta.Storage.Postgres`)

`PostgresStorage` implements the same `IStorage` with the same observable behaviour (decision E); it is the third implementation the conformance suite runs against, and a cross-backend test runs one scenario on InMemory, SQLite and PostgreSQL and compares the results line by line. What differs is only what the engine is: many replicas, one transaction across everything, day partitions, and a WAL that PostgreSQL syncs at commit.

| Piece | What it is |
|---|---|
| `PostgresDbContext` | One EF context implementing the four `I*DbSets` interfaces, composed with `StorageModel.ConfigureAll` + `PostgresModelHooks` (`timestamptz` truncated to UTC milliseconds, `uuid`, `bytea`, text columns in the `"C"` collation so ordering is byte order exactly like SQLite's BINARY, independent of the database's own collation) |
| `PostgresMigrator` + `Schema/V001__initial.sql` | Hand-written, versioned, idempotent migrations (below) |
| `PostgresQueueStore` | Intake, claim, record attempt, leases, queue statistics, webhook outbox |
| `PostgresHistoryStore` | History writes (called inside the queue transactions) and the reads (search, detail, events, retained raw) |
| `PostgresStatsStore` | In-memory aggregation flushed with one `INSERT … ON CONFLICT DO UPDATE` per chunk, the ring, queries |
| `PostgresPartitions` | Day partitions of the five history tables: create ahead, create on demand, `DETACH … CONCURRENTLY` + `DROP` |
| `PostgresMaintenance` | The maintenance jobs, health, `BackupAsync` (returns `null`: use `pg_dump`/PITR) |
| `PostgresConfigAccess` | Plugs the provider-neutral `EfConfigStore<PostgresDbContext>` into PostgreSQL |

### Roles and connection strings

The settings below are named by the option they set (`PostgresOptions.*`); in deployment configuration they are `Storage:Postgres:<name>` (for example `Storage:Postgres:RuntimeConnectionString`, `Storage:Postgres:PartitionsAheadDays`, `Storage:Postgres:CommandTimeoutSeconds`), `AutoMigrate` is `Mail:Database:Migrate` (`Auto` or `Never`), and the SQLite tuning knobs are `Sqlite:StatsFlushInterval`, `Sqlite:RetentionDeleteBatchSize` and `Sqlite:RetentionDeletePause` ([operations.md](../operations.md) lists every key).

| Setting | Role | Used for |
|---|---|---|
| `Postgres:OwnerConnectionString` | schema owner | the migrator, creating and dropping day partitions (DDL needs ownership), `ANALYZE` of the partitioned parents, and the advisory-lock holder connection of every maintenance job. A small pool of its own (4) |
| `Postgres:RuntimeConnectionString` | runtime | everything else: `SELECT/INSERT/UPDATE/DELETE` only. Pool size `Postgres:MaxPoolSize` (32) |

With one connection string given it serves both roles (health carries the warning `postgres_single_role` and the start-up log says so). With two, the migrator grants the runtime role `SELECT/INSERT/UPDATE/DELETE` on all tables and `USAGE` on sequences and sets `ALTER DEFAULT PRIVILEGES FOR ROLE <owner>` so partitions created later are covered; the runtime role cannot create, alter, drop or truncate anything (tested). **Read-only role (design §4.3).** With `Postgres:ReadOnlyConnectionString` (config key `Storage:Postgres:ReadOnlyConnectionString`) the read queries of the dashboard and of the HTTP API (`IHistoryStore`: search, detail, events, retained raw, recipients; `IStatsStore`: `QueryAsync`, `GetRecentEventsAsync`; behind `GET /messages*` and `GET /stats*`) run on a third data source (`PostgresRuntime.Reader`, pool `Postgres:ReadOnlyMaxPoolSize` = 8, application name `eggmail-readonly`) whose connections carry `statement_timeout` (`Postgres:ReadOnlyStatementTimeoutSeconds` = 5) and `idle_in_transaction_session_timeout` (`ReadOnlyIdleInTransactionTimeoutSeconds` = 10) and `default_transaction_read_only=on` as *startup options* (a plain `SET` would be wiped by the pool's `DISCARD ALL` when a connection is returned; tested over repeated use). The role is created by the DBA (`CREATE ROLE eggmail_ro LOGIN PASSWORD '...'`, optionally `ALTER ROLE eggmail_ro SET statement_timeout = '5s'` and `CONNECTION LIMIT 8`); the migration script then grants it `USAGE` on the schema and `SELECT` on exactly `message_index, message_recipient, message_event, message_content, message_raw_retained, stat_aggregate, recent_event` (`PostgresMigrator.ReadOnlyTables`): no write, no secret table, no default privileges (a day partition created later is checked through its parent). `PostgresMigrator.GenerateScript(runtimeRole, readOnlyRole)` and `Postgres:AutoMigrate` both include it. Start-up opens one read-only connection and reads `message_index`, so a wrong password or a role migrated without its grants stops the start with an explanation; health reports `read_only_role` and warns, never failing readiness, `postgres_read_only_unavailable` when the role cannot be used and `postgres_read_only_role_too_privileged` if it can write a history table or read any table outside the seven (secrets, queue, configuration). A statement stopped by the timeout (SQLSTATE `57014`, not cancelled by the caller) is a `StorageQueryTimeoutException`, answered `503 query_too_slow` without `Retry-After` (an outage stays `not_ready`; a statement the caller cancelled stays an `OperationCanceledException`). The role must point at the primary, never a replica that lags. Without a read-only string the reads use the runtime role as before. Behind a pooler in transaction mode, let the `options` startup parameter through (PgBouncer: `ignore_startup_parameters = options`) or set the timeouts on the role.

`Postgres:AutoMigrate` (default `true`): `InitializeAsync` runs the migration script on the owner connection. With `false`, `InitializeAsync` refuses a schema that is not at `PostgresMigrator.CurrentVersion`; produce the script with `PostgresMigrator.GenerateScript(runtimeRole)` (one `DO` block = one transaction, idempotent, takes `pg_advisory_xact_lock` first, so replicas starting together queue up and find the version already recorded) and apply it as the owner role (`psql -f`, or `mta migrate-db`, which migrates even with `Mail:Database:Migrate=Never` and needs the owner connection string).

Npgsql defaults the data source adds unless the connection string already sets them: `Application Name=eggmail`, `Maximum Pool Size`, `Command Timeout` (`Postgres:CommandTimeoutSeconds`, 30), and auto-prepare of hot statements (`Max Auto Prepare=64`, after 2 uses; set `Max Auto Prepare=0` behind a pooler that does not support prepared statements).

### Schema

The schema is the shared model (same tables, snake_case, no foreign keys) frozen in `V001__initial.sql`: generated once from the EF model and then fixed, so a later model change cannot silently change what a fresh database gets. A test compares every table, column type and nullability of a migrated database with the model, so drift fails the build. `message_index`, `message_recipient`, `message_event`, `message_content` and `message_raw_retained` are `PARTITION BY RANGE (day)` (`day` = days since 1970 of the UUIDv7 message id, the first key column of each); `delivery_queue` and `webhook_outbox` get a lower `fillfactor` and aggressive autovacuum settings because their rows are updated on every claim and attempt. Partition names are `<table>_p<yyyyMMdd>`.

### Queue (one transaction per change)

- **Intake** is one implicit-transaction `NpgsqlBatch` (one round trip): spool row, delivery rows (`INSERT … SELECT FROM unnest(…)`), and, with `History:Mode=Full`, the index row, recipients, content and the `queued` event. With an idempotency key it is an explicit transaction that first does the key upsert; a concurrent insert of the same key waits on the unique index and then reads the winner (tested with three replicas). Statistics are counted in memory after the commit.
- **Claim** is `UPDATE delivery_queue SET lease_owner, lease_until WHERE id IN (SELECT id … WHERE due_at <= now AND lease_until <= now AND expires_at > now ORDER BY due_at, id LIMIT n FOR UPDATE SKIP LOCKED) RETURNING …`: any number of workers on any number of replicas take disjoint rows without waiting for each other (tested: 12 workers on 3 replicas, 1,200 deliveries, no duplicates; and a claim that skips a row another session holds locked). A lease that is past is claimable again without counting an attempt. `ClaimExpired` is the same statement over `expires_at`. The webhook outbox claim has the same shape. Unlike SQLite (single process) a start does **not** clear leases: another replica's work is live; leases of dead workers simply expire (`queue.leases` in maintenance clears the stale owner names).
- **Record attempt** is one transaction: lock the delivery row (`FOR UPDATE`, so a repeated report waits and finds it gone), then in one round trip the spool counter, the suppression upsert (hard bounce or complaint; it commits with the completion, so SQLite's "suppression first" ordering is unnecessary here), the queue row action and the webhook fan-out; when the last recipient is final the raw message is copied into `message_raw_retained` (if requested) and the spool row deleted in the same transaction; then the history events, the message status and the content lifecycle. `CountAttempt=false` holds touch the row's due time and lease only.
- **History writes** use the same transaction, so there is no "queued without history" window. A write for a day whose partition is missing fails with "no partition", gives its connection back, and only then is the partition created (owner connection, under an advisory lock) and the write retried once; intake also ensures the day before it opens a connection, so record-attempt normally finds the partitions that intake created. **Rule for the whole provider: no code path holds a pooled connection or an open transaction while it waits for another connection** (the owner/DDL connections are a separate pool of 4 in any case); a regression suite runs 64 callers against a pool of 4 and one of 1. History rows older than the metadata retention (and content older than the content retention) are not written at all; reads would hide them anyway.

### Maintenance

Each job runs under `pg_try_advisory_xact_lock(<job key>)` held by a dedicated owner connection inside an open transaction, while the work uses other connections: `DETACH PARTITION … CONCURRENTLY` cannot run inside a transaction block, and a session-level lock would break behind PgBouncer in transaction mode. (The holder transaction stays open for the duration of the job, so an `idle_in_transaction_session_timeout` on the owner role shorter than the longest job would release the lock early; the jobs are idempotent, so the worst case is two nodes doing the same work.) Calling `RunAsync` from several replicas runs each job once; the others report it as `skipped: another node is running this job`. Job names: `partitions.create`, `retention.metadata`, `retention.content`, `analyze.history`, `retention.webhook_outbox`, `retention.webhook_attempts`, `stats.rollup`, `stats.retention`, `idempotency.expired`, `queue.leases`.

- **Partitions**: partitions are created as a standalone table plus `ATTACH PARTITION` in one transaction, not `CREATE TABLE … PARTITION OF`: the latter takes an `ACCESS EXCLUSIVE` lock on the parent, which queues behind every open transaction that touched the table and blocks every new one (a deadlock with writers that hold history rows; reproduced and tested), while `ATTACH` needs only `SHARE UPDATE EXCLUSIVE`. `partitions.create` makes yesterday..today+`Postgres:PartitionsAheadDays` (7). Retention drops whole partitions: metadata tables (`message_index/recipient/event`) before the metadata cutoff day, content tables (`message_content/raw_retained`) before the content cutoff day; `RowsAffected` is the number of rows that were in them (an exact `count(*)` of each partition just before the detach). An interrupted detach (`inhdetachpending`) is finished with `DETACH … FINALIZE` on the next run. If a `DEFAULT` partition exists (which forbids concurrent detach) the plain, briefly locking detach is used. `ANALYZE` of the partitioned parents runs after a run that dropped partitions (autovacuum never analyzes a partitioned parent).
- **Everything else** (outbox and attempt-log retention, hourly retention, idempotency keys) is batched `DELETE … WHERE ctid IN (SELECT ctid … LIMIT n)` in separate short transactions (`Postgres:RetentionDeleteBatchSize` 5,000, `RetentionDeletePause` 20 ms). The rollup is the same SQL as SQLite (window-function ranking by volume, top-N, the rest as `other`), one transaction per day, with the watermark in `stat_meta`.
- **Health** (`GetHealthAsync`) never throws for an outage: `Ready=false`, warning `postgres_unavailable` and the error in `details`. It also reports the server version, schema version (`postgres_schema_version_mismatch`), the role split, `postgres_partition_missing:<table>` when today's partition is absent, `postgres_read_only_replica`, `retention_unlimited:*` and `postgres_single_role`.

### Statistics

Identical aggregation to SQLite (`StatsAggregator`, `StatsBucketer`, `StatsRollup`): counters accumulate in memory and a timer (`Postgres:StatsFlushInterval`, 10 s), `FlushAsync` and dispose write them. The flush is one transaction: the existing series of each hour are re-read (so other replicas' series count and a rolled-back flush cannot leave a cache ahead of the table), the rows are sorted by key (two replicas flushing the same hour cannot deadlock) and written with `INSERT … SELECT FROM unnest(…) ON CONFLICT DO UPDATE SET c = c + excluded.c`; the recent-events ring is appended in order and trimmed to `History:RecentEvents`. The top-N is approximate across flushes and replicas of one hour, as on SQLite; the daily rollup re-ranks by real volume.

### Configuration store

`EfConfigStore<PostgresDbContext>` unchanged. Its queries are synchronous (shared with SQLite), so `PostgresConfigAccess.ReadAsync` runs them on pool threads, at most `min(4, MaxPoolSize/4)` at a time, on pooled read contexts (`PooledDbContextFactory<PostgresReadContext>`, about 11 KB allocated per `IsSuppressedAsync`). Without that bound a burst of delivery workers (32 workers plus ingest) blocked most of the thread pool inside Npgsql, the async work that frees pooled connections could not run, and new connections failed with `Timeout during connection attempt` about 10 s into a busy start while the server sat idle (found with a pg_stat_activity dump taken at the failure: backends idle waiting for the client, thread pool backlog; chaos test failed about 1 run in 10 before, 0 in 200 after). `PostgresConfigAccess` opens a fresh no-tracking context per read and runs every write in a transaction that first takes `pg_advisory_xact_lock`, which makes the read-modify-write of a lease atomic across replicas (decision K; tested: ten rounds, two replicas asking at once, exactly one wins). Cached webhook endpoints are refreshed when this process changes them and at most every 5 s otherwise (another replica may have); one caller refreshes at a time (the read is synchronous), the others keep using the list they have.

### Outages

Every public method turns a connectivity failure (down, restarting, shutting down, out of connections, network or pool timeout, SQLSTATE class 08, `57P01..03`, `53300`) into `StorageUnavailableException`, so the SMTP layer can answer `451`; constraint violations on intake stay `StorageConflictException`. Tested with a TCP proxy that is cut and restored: every operation reports unavailable while it is cut, health reports not ready, buffered statistics survive the failed flush, and the same storage works again afterwards without a restart. SQLite never raises it.

### Testing

`tests/Mta.Storage.Postgres.Tests` runs the whole shared conformance suite against PostgreSQL (the same abstract classes InMemory and SQLite run, both history modes, a fresh database per test copied from a migrated template) plus: concurrent claims across replicas, partition creation/retention/interrupted detach/advisory-lock guard, the runtime-role permission split, restart and lease recovery, the migrator (idempotent, concurrent, model agreement), outages, cursor paging equality with SQLite on the same data, and the three-backend equivalence scenario.

The server comes from `EGGMAIL_TEST_POSTGRES` (a connection string to an existing server; CI provides one; only `eggmail_test_*` databases are created or dropped), otherwise from a throwaway cluster started from local binaries (`EGGMAIL_TEST_PG_BIN`, Homebrew, `/usr/lib/postgresql/*/bin` or `PATH`): `initdb` into a temp directory, a random free localhost port, trust authentication, no unix socket, `fsync` off. The test host owns the cluster: it is stopped by its own pid at exit, a small detached watchdog stops exactly that pid (and removes exactly that directory) if the host is killed without running exit handlers, and clusters left by a dead earlier run are cleaned at the next start. With neither available every test is reported as **skipped** with the reason (a small xUnit framework extension, because the conformance facts live in another assembly), not failed. `EGGMAIL_TEST_PG_DURABLE=1` keeps `fsync` on (the benchmarks set it).

### Measured on PostgreSQL (one laptop, one run)

`bench/Mta.Benchmarks/Storage/PostgresStorageBenchmarks.cs` (BenchmarkDotNet `ShortRun`: 3 warm-up and 3 measured iterations, **one launch, so the error bars are wide and every 100 KB cell is noisy**; not a release-quality benchmark). It starts the same throwaway cluster as the tests, but with the server's real durability (`fsync`, `full_page_writes` and `synchronous_commit` on) via `EGGMAIL_TEST_PG_DURABLE=1`; the "off" rows set `synchronous_commit=off` for the session (a crash can lose the last fraction of a second of commits, no corruption). One operation is one acknowledged `AcceptAsync` with `History:Mode=Full`: the spool row, the delivery row, the index row, the recipient row, the content row and the `queued` event commit in one transaction and one round trip. The benchmark client and the server share the machine.

- Machine: Apple M4 (10 cores), macOS 26 (Darwin 25.6), local APFS SSD, .NET 10.0.12 arm64, PostgreSQL 18.6 (Homebrew) on 127.0.0.1, Npgsql 10.0.3. Server settings other than durability are the defaults except `shared_buffers=128MB`, `max_wal_size=2GB`.
- Caveat as for SQLite: on macOS `fsync` does not force the drive's write cache to the platter (that needs `F_FULLFSYNC`), so the `synchronous_commit=on` rows are optimistic compared with Linux on a server SSD, and the difference between on and off is small here for that reason. Run the benchmark on the target hardware before quoting anything.
- Messages per second = 1,000,000 / mean time per message; the 100 KB cells use the median because one iteration in each cell was an outlier (checkpoints).

| Callers | `synchronous_commit` | 2 KB msgs/s | 100 KB msgs/s (median, noisy) | 2 KB mean | 100 KB median |
|---:|---|---:|---:|---:|---:|
| 1 | on | 6,300 | 2,400 | 159 us | 421 us |
| 1 | off | 7,200 | 3,100 | 140 us | 325 us |
| 8 | on | 22,600 | 5,400 | 44 us | 183 us |
| 8 | off | 28,700 | 4,200 | 35 us | 239 us |
| 64 | on | 21,600 | 3,000 | 46 us | 335 us |
| 64 | off | 28,700 | 6,500 | 35 us | 153 us |

Accept + claim (100 at once) + record `Delivered` for the same message (2 KB, 8 callers for the accept part): `synchronous_commit=on` 7,800 messages/s (129 us), off 9,300 messages/s (107 us). Allocation per message on the accept path was about 17 KB (the budget in docs/benchmarks.md is about 20 KB per database round trip); 35 KB for the whole accept-claim-record cycle.

Reading the table: with one caller the cost is one round trip plus the commit; with 8 callers PostgreSQL's own commit grouping and the connection pool scale it about 4x and then it flattens at the CPU of one laptop shared by client and server. Compared with the SQLite table above, SQLite `Off`/`Normal` is faster for a single process (no network hop, no separate server process), and PostgreSQL with `synchronous_commit=on` is far faster than SQLite `Full` here for the reason above (the optimistic fsync) as well as group commit; the two must not be compared as engines, only as defaults on this machine, and the PostgreSQL numbers say nothing about a remote server (add the network round trip to every figure). Nothing here has been reproduced by anyone else.


### Differences from SQLite that are characteristics, not features

| | SQLite | PostgreSQL |
|---|---|---|
| Atomicity | per file; cross-file effects ordered and idempotent (table above) | one transaction across queue, history, outbox, suppressions; no crash windows except the in-memory statistics (about 10 s) |
| Start-up | clears all leases (single process) | leaves leases alone (other replicas) |
| Retention | batched `DELETE` + `incremental_vacuum` | `DETACH … CONCURRENTLY` + `DROP` of day partitions; `RowsAffected` counts the rows that were in them |
| Backups | `BackupAsync` = `VACUUM INTO` | `BackupAsync` returns `null`: `pg_dump`, base backups, PITR |
| Reads | synchronous on the caller's thread | asynchronous I/O (except configuration reads, below) |
| Durability | `Sqlite:SyncMode` | `synchronous_commit` of the server (default on) |

## Known gaps

- Power-loss and OS-crash behaviour is documented from the SQLite docs, not tested.
- The write-time recipient-domain top-N is approximate within an hour (above).
- `GetQueueStatsAsync` computes `SpoolBytes` with a scan of `message_spool`; fine for dashboards, not for a tight loop.
- `ReleaseOwnedLeasesAsync` scans `delivery_queue` (no index on the lease owner), acceptable at shutdown.
- Config reads other than the suppression check use a pooled EF context per call; config is otherwise a cold path.
- SQLite statements on the hot paths run through the native API, not `SqliteCommand`: the writers' commands (`PreparedCommand`: prepared once per writer connection, typed `Set`, `RawReader`) and two read sessions (`SqliteReadSessionPool`: open read connections with prepared statements, used for the raw message of a delivery and the suppression check; closed by `SqliteFile.ClearPool`, which is called from the quarantine of a file and from disposing the storage, and nowhere else; at most 64 idle sessions are kept, one idle for more than 60 s is closed, and after the storage is disposed a read still works but keeps no connection open). Guids are stored as upper-case text exactly as before, empty text and empty blobs stay empty (not NULL), errors are the same `SqliteException`. `IConfigDbAccess.TryIsSuppressed` lets a provider answer the per-recipient suppression check without an EF query (PostgreSQL still uses EF). `IWebhookOutbox.MayHaveSubscribers` lets the delivery processor skip building event payloads when the loaded endpoint list says nobody would receive them (never false while the fan-out would queue the event). `StatKey` is a `readonly record struct`. The in-memory backend's claim picks the first `max` due rows in one pass.
- Reads on file-backed databases run synchronously on the caller's thread (SQLite has no asynchronous I/O); long history searches should be called from a thread-pool context.
- Search by subject is a `LIKE '%…%'` scan within the other filters; no full-text index.
- The storage-pressure indicator UI is another task (the export/import engine exists, see [switch.md](switch.md)).
- PostgreSQL: verified against PostgreSQL 18.6 and 16.13 (Homebrew, local) only; not against a managed service, behind PgBouncer, over TLS, with a remote server or with real HA/failover. The minimum supported version (16) is the lowest tested; `DETACH … CONCURRENTLY` and `inhdetachpending` need 14+.
- PostgreSQL: the maintenance partition DDL needs the owner credentials at runtime (or a `RuntimeConnectionString` that is the owner); a deployment that must keep the owner secret away from the application has to run `partitions.create` and retention from a separate maintenance process with the owner string. `mta migrate-db` migrates with whatever credentials the configuration holds; `PostgresMigrator.GenerateScript` is the script form for a DBA.
- PostgreSQL: configuration reads (`EfConfigStore`) are still synchronous queries; they are bounded and moved off the caller's thread (above) rather than truly asynchronous. Converting the ~30 read queries to `ToListAsync`/`FirstOrDefaultAsync` would remove the blocked pool threads altogether.
- PostgreSQL: history rows older than the metadata retention are not written (SQLite writes then hides them); `RowsAffected` of the partition retention is an exact `count(*)` taken just before the drop, which costs a scan of each expiring partition.
- PostgreSQL: recipient-domain top-N is approximate across flushes **and replicas** of one hour; the read-only role and `statement_timeout` for dashboard queries are deployment steps, not enforced by the application.
- PostgreSQL: the per-message transaction takes about six round trips (lock row, one batch, spool free, history events, status, commit); a stored function could make it one, which was not measured or needed yet.
- `Content:RetentionDays` applies to retained raw messages too (they are content-like); this is a design reading, not an owner decision.

## Measured on SQLite (unverified outside this machine)

Measured with `bench/Mta.Benchmarks/Storage/StorageBenchmarks.cs` (BenchmarkDotNet `ShortRun`: 3 warm-up and 3 measured iterations, **one launch, so the error bars are wide and several 100 KB cells are noisy**; raw numbers in the run output, not a release-quality benchmark). One operation is one acknowledged `AcceptAsync` with `History:Mode=Full` (queue transaction, then the history entry), one recipient, a fresh temp directory per cell.

- Machine: Apple M4 (10 cores), macOS 26 (Darwin 25.6), local APFS SSD, .NET 10.0.12 arm64, Workstation concurrent GC. Microsoft.Data.Sqlite 10.0.12 (SQLite 3.53.3).
- Caveat: on macOS `fsync` does not force the drive's write cache to the platter (that needs `F_FULLFSYNC`), so the `Full` rows here are optimistic compared with Linux on a server SSD. Run the benchmark on the target hardware before quoting anything.
- Messages per second = 1,000,000 / mean time per message.

| Callers | Sync mode | 2 KB msgs/s | 100 KB msgs/s | 2 KB mean | 100 KB mean |
|---:|---|---:|---:|---:|---:|
| 1 | Off | 12,800 | 2,700 (noisy; median 4,000) | 78 us | 367 us |
| 1 | Normal | 8,600 | 3,400 | 117 us | 297 us |
| 1 | Full | 276 | 252 | 3.63 ms | 3.96 ms |
| 8 | Off | 32,300 | 3,200 (noisy) | 31 us | 313 us |
| 8 | Normal | 22,900 | 4,100 | 44 us | 246 us |
| 8 | Full | 1,990 | 1,630 | 503 us | 613 us |
| 64 | Off | 52,600 | 1,700 (noisy) | 19 us | 573 us |
| 64 | Normal | 40,900 | 5,100 | 24 us | 198 us |
| 64 | Full | 12,400 | 4,200 | 81 us | 239 us |

Accept + claim + record `Delivered` for the same message (2 KB, 8 callers for the accept part, claims of 100): `Off` 21,600 messages/s (46 us), `Normal` 16,500/s (60 us), `Full` 1,600/s (610 us).

Reading the table: group commit is what makes `Full` usable under concurrency (276/s with one caller, 12,400/s with 64, because many commands share one fsync); under `Off`/`Normal` a commit costs no fsync and the limit is the writer thread (CPU, WAL bandwidth); 100 KB messages are bounded by copying each body into the WAL and again at checkpoint. Allocation per message on the storage path was 10.5 to 16.4 KB including the history write (the EF-free hot path; the budget in docs/benchmarks.md is about 20 KB per database round trip). The headline `Off` numbers must always be quoted next to `Normal` and `Full` (docs/benchmarks.md, fairness rule 1). Nothing here has been reproduced by anyone else.

## Replica coordination (PostgreSQL schema version 6)

`IStorage.Replicas` (`IReplicaCoordination`, DESIGN-DECIDED, decision 82) is what replicas on one database exchange (*replica coordination*): `HeartbeatAsync` (who is alive, ordinally sorted, so every replica derives the same rank), `LeaveAsync`, `PublishSignalsAsync`/`GetSignalsAsync` (what a replica learned about a remote destination, as a duration: `PeerSignal.ValidFor` counted from publishing, read back as what is left, `Cooldown` for an opened circuit), and the failed-login counts (`AddAuthFailuresAsync`, `GetAuthFailuresAsync`, `ClearAuthFailuresAsync`, per keyed digest and time bucket). Time is the database's own clock (`clock_timestamp()`); the in-memory implementation uses the storage's clock. PostgreSQL implements it with three tables created by `V006__replica_coordination.sql`: `replica_heartbeat`, `replica_signal` and `auth_failure`, written with single atomic statements (`INSERT ... ON CONFLICT`, no advisory lock; keys of one statement are sorted, and deletes lock their rows in key order or skip locked ones, so two replicas cannot deadlock) on a data source of their own with two connections. Columns: `replica_heartbeat(replica_name, beat_at)`, `replica_signal(signal_kind, signal_key, replica_name, raised_at, valid_until, cooldown_ms)`, `auth_failure(key_digest, bucket_index, failure_count)`. The in-memory backend implements it so that several runtimes sharing one `InMemoryStorage` behave like replicas. SQLite returns `null`: one process by design, the in-process state is exact. The tables are not in the EF model, not in the SQLite schema and not in the backend switch bundle (ephemeral, rebuilt within seconds); `MigrationTests` names them as the tables outside the model. Replicas silent for five minutes are forgotten with their signals, signals expired for an hour are deleted, failed-login buckets older than the window are deleted by the next failure. Conformance: `ReplicaCoordinationConformance` (in-memory and PostgreSQL).
