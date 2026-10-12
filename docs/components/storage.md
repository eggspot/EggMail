# Storage (`Mta.Storage`, `Mta.Storage.Sqlite`)

One storage model, three implementations behind `IStorage` (decision E: feature-identical backends):

| Project | What it is |
|---|---|
| `Mta.Storage` | The contracts, the shared EF model split into four parts, the logic every backend shares (attempt planning, statistics bucketing and rollup, status rules, lease rules), the EF `IConfigStore`, and `InMemoryStorage` |
| `Mta.Storage.Sqlite` | `SqliteStorage`: four database files, one group-commit writer per file |
| `tests/Mta.Storage.Tests` | The conformance suite (abstract classes, one `CreateAsync(StorageOptions)` to plug a backend in) plus unit tests of the shared logic |
| `tests/Mta.Storage.Sqlite.Tests` | The conformance suite against SQLite (history Full and StatsOnly, sync Off/Normal/Full, memory queue) plus SQLite-specific tests |

## Entity overview

The model is four parts. On SQLite each part is its own context and its own file; the PostgreSQL provider composes all four with `StorageModel.ConfigureAll` into one context (see below). Table and column names are snake_case; there are **no foreign keys** (references are soft so cross-file effects, imports and partial restores never depend on order). Secrets columns hold bytes already protected with Data Protection.

| Part (context, SQLite file) | Tables |
|---|---|
| config (`ConfigDbContext`, `config.db`) | `tenant`, `api_key`, `smtp_credential`, `domain`, `dkim_key`, `suppression`, `webhook_endpoint`, `setting`, `tls_policy`, `relay_route`, `certificate`, `acme_account`, `acme_renewal`, `lease`, `switch_state`, `data_protection_key` (`IDataProtectionKeyContext`) |
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
| `user_version` | 1 | schema version; a newer version is refused, an unversioned database with tables is refused |

`Cache=Shared` is never used. Reads use separate short pooled connections (the only exception is the in-memory queue, whose reads run on its writer). Every connection of a file is private; WAL means readers see a committed snapshot.

**Startup:** per file `PRAGMA quick_check` (or `integrity_check` when `Sqlite:QuickCheck=false`); a failing file (or one that cannot even be opened) is **quarantined**: the file and its `-wal`/`-shm` move to `<DataDirectory>/quarantine/<utc timestamp>/`, nothing is deleted, an empty file is created, and `IStorageMaintenance.GetHealthAsync` reports `sqlite_quarantined:<file>` with the path. Then all leases are cleared (single process; delivery is at-least-once) and the spool is reconciled. A startup log warning names every file running with `synchronous=OFF` (decision P); health carries the `sqlite_sync_off` warning and per-file `sync_mode.*` details; readiness is not failed by it.

## Writer design

One writer per file, `SqliteFileWriter`: a dedicated thread, a **bounded channel** (`Sqlite:WriterQueueCapacity`) and **group commit**. Callers submit a command and await its result; the thread drains up to `Sqlite:WriterMaxBatch` commands into one `BEGIN IMMEDIATE … COMMIT` and completes the callers after the commit returned. Under `Full` it also lingers up to `Sqlite:WriterBatchWindow` for more commands (that is where one fsync is amortized); under `Off`/`Normal` a commit costs no fsync, so it commits when the queue is momentarily empty and batches still grow whenever commands arrive faster than commits finish.

- **Acknowledgement semantics:** `AcceptAsync` returns after the queue transaction committed. `Off` = handed to the OS, `Normal` = in the WAL (fsynced at checkpoint), `Full` = fsynced.
- **Back-pressure:** when the channel is full callers wait (a cancellation token cancels the wait, not a queued command). That is the only throttle; there is no rate limiter.
- **Fault isolation:** if any command of a batch throws, the batch is rolled back and its commands are replayed one by one in their own transactions, so a constraint violation fails only its own caller. Commands therefore keep side effects outside the database out of `Execute`.
- **Allocation:** a submission is one object (the command doubles as the `IValueTaskSource`); statements are prepared once per writer and parameters set by index. The hot paths (intake, claim, record attempt) use ADO.NET on the writer connection; EF is used for schema generation and for the config store (a cold path; shared with PostgreSQL), where config writes run on the config writer's connection and transaction.
- Metrics (`SqliteStorage.WriterMetrics`, also in health details): commits, commands, max/last batch size, queue depth, last and max commit time. These feed the advisory storage-pressure indicator.

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
| Expired / Suppressed / Cancelled | deleted | expired / suppressed / cancelled | Expired / Suppressed / none |
| AbortedBySwitch | requeued unchanged (lease released) | aborted_by_switch | none |

`Suppress=Complaint` adds a `complained` event and counter; `PossibleDuplicate` adds a `possible_duplicate` event and sets the sticky flag on a surviving row. Webhook events fan out to the tenant's **enabled** endpoints whose list contains the event type or `*` (an empty list receives nothing), in the same transaction as the row completion. The spool counter is decremented in that transaction; the last recipient frees the spool row. Recording an attempt for a delivery that is already gone is a no-op, so reports are safe to repeat.

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

## Contract additions (all documented in the PR)

`StorageBackend.InMemory`; `QueueOptions.IdempotencyKeyLifetime` (24 h); `SqliteOptions` tuning knobs (`RetentionDeleteBatchSize`, `RetentionDeletePause`, `BusyTimeout`, `JournalSizeLimitBytes`, `StatsFlushInterval`); `StorageConflictException`; `DeliveryAttempt.CountAttempt` (uncounted holds); store-assigned `CertificateRecord.Version`; defined semantics for the settled gaps: `EventTypes` containing `*` subscribes to all, suppression addresses and slugs are lower-cased, settings with `TenantId == null` are global, `QueryAsync` is `[from, to)`.

## Extending to PostgreSQL

The Postgres provider (later task) should:

1. Define one context implementing `IConfigDbSets`, `IQueueDbSets`, `IStatsDbSets`, `IHistoryDbSets` and call `StorageModel.ConfigureAll` plus its own `IStorageModelHooks` (native `timestamptz`, `uuid`, `bytea`; day partitions for the history tables via `migrationBuilder.Sql` as design §4.3).
2. Reuse `EfConfigStore<TContext>` by implementing `IConfigDbAccess<TContext>` (a context per call; atomic lease acquisition guarded by `pg_try_advisory_xact_lock`).
3. Write provider-specific hot-path stores (claim with `FOR UPDATE SKIP LOCKED … RETURNING`, record attempt in one transaction) and reuse the shared logic classes: `AttemptPlanner`, `StatsAggregator`/`StatsBucketer`/`StatsRollup`, `MessageStatus`, `ContentRules`, `LeaseRules`, `RetentionCutoffs`, `Cursors`, `EventIds`.
4. Run the conformance suite: derive the abstract classes in `Mta.Storage.Tests` (`IntakeConformance`, `DeliveryConformance`, `HistoryConformance`, `StatsOnlyHistoryConformance`, `StatsConformance`, `WebhookConformance`, `ConfigConformance`, `MaintenanceConformance`) and implement `CreateAsync(StorageOptions)` using the provided `Clock`. Tests that depend on text ordering use ASCII names/ids so a database collation does not change results.

## Known gaps

- Power-loss and OS-crash behaviour is documented from the SQLite docs, not tested.
- The write-time recipient-domain top-N is approximate within an hour (above).
- `GetQueueStatsAsync` computes `SpoolBytes` with a scan of `message_spool`; fine for dashboards, not for a tight loop.
- `ReleaseOwnedLeasesAsync` scans `delivery_queue` (no index on the lease owner), acceptable at shutdown.
- Config reads create a short-lived EF context per call (no pooled factory); config is a cold path.
- Reads on file-backed databases run synchronously on the caller's thread (SQLite has no asynchronous I/O); long history searches should be called from a thread-pool context.
- Search by subject is a `LIKE '%…%'` scan within the other filters; no full-text index.
- Export/import (Portability), PostgreSQL, and the storage-pressure indicator UI are other tasks.
- `Content:RetentionDays` applies to retained raw messages too (they are content-like); this is a design reading, not an owner decision.

## Measured (unverified outside this machine)

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

