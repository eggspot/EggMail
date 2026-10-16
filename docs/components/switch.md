# Backend switch (`Mta.Storage.Portability`, `Mta.Storage` transfer layer, `Mta.Host/Switching`)

The implementation of [design §4.6](../design.md#46-switching-backends-manual-and-symmetric): moving a deployment from one storage backend to another (SQLite, PostgreSQL, and the in-memory test backend), in either direction, by an explicit owner action. This page describes what was built, the decisions that were made while building it, and what was measured. Where this differs from the design text it says **DESIGN-DECIDED** and why.

## Pieces

| Piece | Where | What it does |
|---|---|---|
| Transfer contract | `Mta.Storage/Transfer` | `IStorageTransfer` (on `IStorage.Transfer`): stream every table as provider-neutral entity rows, apply a chunk idempotently, the switch state, the fence, transfer marks and activation holds. `TransferTables` is the registry of the 31 tables that move: adding a table to the bundle is one entry there |
| EF implementation | `EfStorageTransfer` | Written once over the shared EF model for every relational provider. SQLite and PostgreSQL only supply `ITransferDbAccess` (how to get a read context and a write transaction) |
| In-memory implementation | `MemoryTransfer` | The same contract straight over the in-memory dictionaries |
| Bundle | `Mta.Storage.Portability` | Chunked NDJSON files, body packs, `manifest.json`, `secrets/` (see Bundle layout) |
| Engine | `StorageSwitchEngine` : `IStorageSwitchEngine` | The orchestrator: preflight, start (drain or quiesce), export, import, verify, confirm, activate, rollback, finalize, status, cancel |
| Startup gate | `Mta.Host/Switching/StartupGate` | Reads the switch state at start: normal, draining, restricted or fenced |
| Activation | `SwitchActivator` | Writes the bootstrap file, or produces the cutover patch |
| Process control | `HostSwitchControl`, `SwitchStateWatcher`, `SwitchRuntimeState` | Stops the listeners, the API flag and the scheduler; follows state written by another process |
| CLI | `mta migrate-storage` (`MigrateStorageCommand`) | `preflight`, `export`, `import`, `verify`, `confirm`, `activate`, `rollback`, `finalize`, `status` |

`IStorageSwitchEngine` is the interface the admin API layer calls through `StorageSwitchService` (see Admin API) (`/admin/storage/switch/*`, [api.md](../api.md)). The API layer defines its own `IStorageSwitchService` interface (answering 503 `not_ready` when no engine is registered); `StorageSwitchService` adapts it with a thin mapping (`preflight` to `PreflightAsync`, `start` to `StartAsync`, `GET` to `GetStatusAsync`, `confirm`/`activate`/`rollback`/`finalize` one to one; `export` and `import` run as part of the guided flow; progress comes from the `IProgress<SwitchProgress>` argument and `SwitchStatus.Progress`). The engine is stateless between calls: everything durable lives in the stores, so a new instance in another process continues a switch.

## Admin API

`StorageSwitchService` (`Mta.Host/Switching`) implements `IStorageSwitchService` of the API over the engine and is registered by `ApiHosting`. The source is the storage the process runs on. `POST /admin/storage/switch/start` validates, opens the target (resolved by `ISwitchTargetResolver` from the deployment configuration: `SwitchTarget:Connections:<name>` for a named PostgreSQL connection, host/port/database applied to `SwitchTarget:Storage:Postgres:RuntimeConnectionString`, or a SQLite directory), runs preflight (a failed check is `400 validation_failed` on `target`) and returns `202`; a background job quiesces or drains (polling until the queue is empty), exports, imports and verifies, and `GET` shows `quiescing`/`draining`, `exporting`, `importing`, then `verified` (or `failed` with the error). The export passphrase stays in memory for the job and is never echoed. `confirm`, `activate`, `rollback`, `finalize` are single engine steps; a step in the wrong state is `409 conflict`, a target that cannot be opened `503 not_ready`, admin only. `activate` returns state `active` with the cutover patch (or the bootstrap file note); the target really becomes Active when the application restarts on it. While the instance is fenced or draining the storage refuses accepts, which the API maps to `503 not_ready` with `Retry-After`. A target that does not protect its key ring is accepted only if this instance does not either.

## States

Source: `Active` → `Draining` | `Quiescing` → `Fenced` → (`Active` on rollback | `Finalized`). Target: `Importing` → `Verified` → `Confirmed` → `Active`. The state, the role (`Source` or `Target`), the switch id and a small JSON detail (mode, bundle path, whether the pointer was rewritten; never a secret) are one row in `switch_state` of each store.

The **gate** (`SwitchGate`) is derived from that row when a store is opened and every time the state is set or read: it is closed for a `Fenced`/`Finalized` source and for a target that is `Importing`, `Verified` or `Confirmed`. A closed store throws `StorageFencedException` from `AcceptAsync`, returns nothing from `ClaimAsync`, `ClaimExpiredAsync` and the webhook `ClaimDueAsync`, runs no maintenance, and (SQLite) does not clear leases or reconcile the spool at open. This is enforced in the storage layer of all three backends, so it holds whatever the host does and across restarts. `Draining` and `Quiescing` are not enforced by the store (the host stops accepting and dispatching; a drain must keep delivering).

## Transfer marks and the activation hold

`delivery_queue`, `webhook_outbox` and `inbound_message` have a nullable `transfer_switch_id` (for received mail only a row whose action is **pending** is marked and held: only a pending action can be claimed, a message that is done or failed is just data; the manifest records the held count per table, `heldRows`, and the import verification expects exactly that many held). A row with a value is never claimed (the claim SQL says `transfer_switch_id IS NULL`), on every backend. On the source the export marks every row `transferred(switch_id)` after writing it; the fence alone would already stop dispatch, the mark makes it hold even if the fence were cleared by mistake, and it also protects against a replica that has not noticed the fence yet (tested on PostgreSQL). On the target the imported rows carry the same column as an activation hold; activation releases them first and sets the state `Active` second, so a crash in between is repeated by the next start and a row is never left held under an Active store. Rollback clears the marks of the source and deletes the imported rows of the target.

## Bundle layout

```
manifest.json                      format 1.3.0: switch id, source, effective settings, per-file SHA-256, per-table rows + checksum,
                                   mode, history export progress, the protected digest key
config/<table>.NNNNN.ndjson        tenants, domains, DKIM keys, API keys, SMTP credentials, suppressions, webhook endpoints, settings,
                                   TLS policies, relay routes, certificates, ACME accounts and renewals, domain_record_check
                                   (last DNS check results), tls_rpt_bucket (unsent TLS-RPT counters), sending_counter (hour/day windows)
stats/<table>.NNNNN.ndjson         stat_aggregate, stat_meta, recent_event, webhook_attempt
queue/<table>.NNNNN.ndjson         delivery_queue, message_spool, webhook_outbox, api_idempotency_key
queue/message_spool.NNNNN.bodies   the raw messages of the chunk with the same stem (body pack: magic, then length + bytes per row)
history/<table>/<yyyy-MM-dd>.NNNNN.ndjson (+ .bodies for message_raw_retained)   one set per day
secrets/bundle-cert.pfx, secrets/keyring/   the bundle's own Data Protection ring and its passphrase-protected certificate
```

A chunk is closed after 5,000 rows or 32 MiB (`SwitchOptions`). The rows are the EF entities serialized with camelCase names, enum names and UTC millisecond timestamps; the hold column and the body column are not part of the row. Unknown members are ignored on read (forward compatibility inside a major version); `manifest.json` carries the format version `1.3.0`, readers accept any 1.x (a bundle of an older minor imports and simply has no data for the tables added since; the reverse, a 1.3 bundle read by a binary that predates it, is not supported: that binary does not know the inbound tables, and the import stops with `the manifest names a table this version does not know ('inbound_message')` before anything is applied to the target; it is refused, never silently reduced. The importer of an older minor reads `heldRows` as absent (every row of a table with a hold). Import with the version that wrote the bundle or a newer one, so an upgrade of the target precedes a switch to it). **A bundle carries the mail bodies of the spool and of received mail in the clear** (only the secrets are re-protected with the export passphrase), like the database files it is copied from: treat the bundle directory like a backup. Format 1.2 (persisted runtime state, schema version 4) added the three config tables above and the `messageIdHeader` and `tags` members of `message_index`; a 1.1 bundle imports into a current target (the tables are absent from its manifest, the members null), and a bundle with the new tables is refused by a build that does not know them (`'name' is not a transferable table`), which is why the switch is meant to run between the same version on both sides. Format 1.3 (inbound mail, schema version 8, decision 95) added the config tables `inbound_domain_settings` and `inbound_route` and the queue tables `inbound_message` (with the hold column) and `inbound_message_raw` (a body pack like the spool's); a 1.2 bundle imports into a current target and leaves the inbound tables empty. Received mail is user data, not history: `--skip-history` does not skip it, and its pending actions are held on the source like deliveries, so none runs on both sides.

**What carries over of the runtime state (DESIGN-DECIDED, decision 55).** The last DNS check results, the unsent TLS-RPT counters and reports, and the sending counters of the current windows move with the config part: a switch must not show a verified domain's records as `pending`, lose the day's TLS report or reset the hour's and day's sending caps. The source process flushes its in-memory counters when it quiesces (`HostSwitchControl.QuiesceDeliveriesAsync` calls `EggMailRuntime.FlushRuntimeStateAsync` after the in-flight deliveries finished), so the bundle holds the last counts; the offline CLI (`mta migrate-storage`) has nothing in memory to flush. The sending counters are imported as an upsert (a value already in the target is replaced, not added to). Not carried: leases, and the in-memory state that is rebuilt by itself (throttles, circuit breakers, route health).

**DESIGN-DECIDED: the bundle row is the EF entity** (the design says each store implements the export/import contract "over the provider-neutral EF model"). The consequence is that the bundle format follows the model: a change to a table is a bundle format change and must bump the format version. A test (`TransferConformance`) round-trips every table through its bundle form.

**DESIGN-DECIDED: bodies are packed per chunk** instead of one file per message (the design says "spool bodies"): a spool of a hundred thousand messages would otherwise be a hundred thousand files and manifest entries.

## Verification

Per-file and per-chunk SHA-256 come from the manifest and are checked before a chunk's first row is applied (core files all up front, history chunk by chunk). The table check is a row count plus a **checksum that does not depend on row order**: the 256-bit sum of the SHA-256 of every row's canonical text. Order independence is required because SQLite (text), PostgreSQL (uuid and `C` collation) and the in-memory backend return the same rows in different orders. The canonical text is independent of the provider (UTC millisecond instants, no hold column, no re-assigned sequence numbers, a body contributes its SHA-256) and leaves the secret columns out.

**DESIGN-DECIDED: secrets are verified by a keyed digest.** Re-protection changes every secret blob, so the secret columns cannot be part of the table checksum. The export computes, per secret, an HMAC-SHA256 over the row's canonical text, the column name and the plaintext, keyed with a random 32-byte digest key that is stored in the manifest *protected by the bundle key ring* (opening it needs the passphrase), and sums them per table. `verify` (with the passphrase) unprotects every secret in the target with the target's ring and recomputes the sum; a secret that was swapped or damaged fails even though the row looks right. Without the key the digest reveals nothing about a low-entropy secret.

## Secrets

Export: each secret column is unprotected with the source's `ISecretProtector` (its certificate or KMS must be reachable), protected again with the bundle key ring (`BundleSecretProtector`, passphrase-protected PKCS#12), and only that blob is written. Import: unprotected with the bundle ring (passphrase), protected with the target's own protector. The purposes are `SecretPurposes` (`DkimKey`, `WebhookSecret`, `TlsPrivateKey`, `AcmeAccountKey`, `RelayPassword`; relay route passwords are included because they are secrets too). The Data Protection key ring settings (`dataprotection.key.*`) never move. Tests check that no secret appears in clear in any bundle file, that the two sides can use different rings (one certificate-protected, one `None`), that a wrong passphrase is refused before anything is written, and that a target with `Secrets:KeyProtection=None` is refused unless acknowledged (`--accept-unprotected-keys`).

## Resumability and cancellation

- **Import:** every chunk and its progress record (`transfer_chunk_<part>`: switch id, chunk id = the bundle file path, rows, checksum) commit in one transaction. Re-running skips applied chunks; a chunk id applied with a different checksum is refused. Cancel (`Cancel()` or the token) or kill the process and run `import` again. Tests: cancel after N history chunks, resume; a chunk applied by a process that died before reporting; a corrupted chunk mid-history stops the import after the earlier chunks and a repaired bundle resumes.
- **Export of history:** days are appended to the bundle; the manifest is replaced atomically (temporary file, move) after each complete day, so it always lists exactly the complete days. A resumed export deletes unlisted files under `history/` and continues after `LastHistoryDay`. The queue marks are idempotent, so a resume re-applies them.
- **History timing:** before activation (default) or as a backfill after it (`--history-after-activation`, then `import --history-only` on the running target). The backfill never touches rows the target recorded meanwhile (ids are unique). `finalize` refuses until every history chunk is applied.

## Drain, quiesce, fence

`start --drain` stops accepting (host control), sets `Draining` and watches the delivery queue; the source is fenced when queued + leased + deferred deliveries are zero (a background monitor in the process that started it, `AdvanceAsync`, or the first `export`; the `SwitchStateWatcher` of a running server does the same for a switch started by the CLI). The webhook outbox does not hold the drain; its pending rows move (receivers de-duplicate by event id). `start --quiesce` stops accepting, pauses the scheduler, calls `DeliveryEngine.QuiesceAsync(timeout)` (default `Switch:QuiesceTimeoutSeconds` = 30), and fences. What `QuiesceAsync` aborts is requeued unchanged with `aborted_by_switch` recorded.

**Abort flag.** `SmtpClientConnection.EndOfDataStarted` is true once the `.` line (or the `BDAT … LAST` chunk) of the current transaction began to be written; `DeliveryProcessor` uses it when a quiesce cancels an attempt, so a delivery cancelled before the end of data (for example while the peer has not answered `RCPT`) is requeued without `possible_duplicate`, and one cancelled while waiting for the final reply is flagged (tests in `Mta.Smtp.Client.Tests` and `Mta.Delivery.Tests`).

## Activation and the cutover pointer

`activate` needs the target `Confirmed` and the source `Fenced`. `SwitchActivator` computes the new pointer from the target options (`Storage:Backend`, the Postgres connection strings or `Sqlite:DataDirectory` and sync settings, `History:Mode`) plus the **effective source settings that differ from the built-in defaults** (retention, content, queue lifetime, stats) so behavior does not change silently. For each pointer key it asks the layered configuration which provider supplies it:

- every key free above the bootstrap file: the pointer is merged into `bootstrap.json` on the data volume (mode 0600; other keys stay), the old file is kept as `bootstrap.json.pre-<switch id>` (or a `.none-` marker when there was none) for rollback, and the application is restarted;
- any key supplied by an environment variable, the command line or a mounted file: nothing is written; the output is a **cutover patch** with an environment diff (old and new value, secrets as `<value of secret eggmail-storage/runtime-connectionstring>`), a ConfigMap patch with `secretKeyRef` instructions and a compose override using `${EGGMAIL_…}`. Secret values are never printed (tested).

**DESIGN-DECIDED: "effective values written explicitly into the target" is realized in the pointer, not in the `setting` table.** Retention, content and similar values are deployment configuration (environment or bootstrap), not rows of the config store, so the manifest records them and the activation carries them; settings that live in the config store (`setting` rows, including dashboard edits) move as data.

After `activate` the bootstrap file points at the target, so the later `rollback`, `finalize` and `status` read the pointer from the kept copy (`PendingOriginalBootstrap`); `finalize` forgets the copy.

## Startup gate and the running process

`StartupGate.EvaluateAsync` (called by `Cli.ServeAsync` right after the storage is initialized): no record or `Active` → normal; target `Confirmed` → atomically `Active` (holds released first), then normal; `Importing`/`Verified` → restricted; source `Fenced`/`Finalized` → fenced with a banner naming the switch; `Draining` → no accepting but delivery continues; `Quiescing` (interrupted) → restricted. In every non-normal mode the SMTP listeners still start and answer `421`, `SwitchRuntimeState.AcceptingApi` is false (the API answers `503` with `Retry-After`; the API layer reads it), and the hosted services that dispatch, run maintenance or renew certificates are not registered, so a fenced source stays exactly as it was until it is finalized or rolled back. In normal mode a `SwitchStateWatcher` polls the stored state every 5 s so that a switch started by another process (the CLI against a shared PostgreSQL, another replica) is followed: it stops accepting, pauses and quiesces, completes a drain, and resumes after a rollback. Reading the state also refreshes the store's own gate, which is what closes a replica that did not restart.

**One process per SQLite directory.** The server holds an exclusive lock file (`.eggmail.lock`, `DataDirectoryLock`) in the data directory; the offline `migrate-storage` commands take it too, which proves the server is stopped before they open the files (opening also clears leases). Against a SQLite deployment the CLI therefore runs with the server stopped; a drain started that way ends with `Draining` and the instruction to start the server, which delivers and fences itself. For PostgreSQL the CLI can run while the application runs.

## CLI

```
mta migrate-storage preflight --to postgres|sqlite [--bundle <dir>] [--SwitchTarget:...=...]
mta migrate-storage export    --to ... --bundle <dir> [--drain|--quiesce] [--quiesce-timeout <s>] [--wait <s>] [--skip-history] [--dry-run]
mta migrate-storage import    [--to ...] --bundle <dir> [--skip-history|--history-only] [--accept-unprotected-keys]
mta migrate-storage verify | confirm | activate | rollback [--source-only] | finalize [--delete-bundle] | status
```

The source is the configured storage; the target is `--to` plus `SwitchTarget:*` (any key, for example `--SwitchTarget:Storage:Postgres:RuntimeConnectionString=…` or the environment variable `SwitchTarget__Storage__Postgres__RuntimeConnectionString`; `--target-dir` is shorthand for `SwitchTarget:Sqlite:DataDirectory`); everything not overridden is the source's own value. The passphrase comes from `--passphrase-file` or the environment variable named by `--passphrase-env` (default `EGGMAIL_BUNDLE_PASSPHRASE`), never from an argument (an argument named `--passphrase` is refused). Configuration overrides must be written `--Key=value`. Exit codes: 0 ok, 2 configuration error, 3 not ready (draining), 4 refused, 5 integrity failure (tampered bundle, failed verification), 64 usage, 130 cancelled.

## Backend notes

- **SQLite:** schema versions up to 7 (the bundle manifest records the version; versions 5 and 7 add a column and an index, which a bundle does not carry; upgrades from 1 to 3; the step to 3 adds the hold column and the four progress tables; the step to 4 adds the runtime state tables and the history index columns, none of which a bundle needs to know about: the three config tables are listed in the manifest like any other, and a bundle from before them imports with those tables simply absent). Writes go through the file's writer thread (one chunk is one writer command); reads stream on pooled read connections. With `Sqlite:QueuePersistence=Memory` the queue part is read in pages on its writer.
- **PostgreSQL:** schema `V003__backend_switch.sql`; one transaction per chunk; `PostgresTransferAccess.PrepareHistoryDaysAsync` creates the day partitions an imported chunk needs, including days older than the application would create (tested with a 25-day-old message). The claim SQL excludes held rows; a replica that has not yet read the fence claims nothing because of the marks.
- **In-memory:** full implementation, used by the conformance suite and as a source/target in the end-to-end tests.

## Tests

`TransferConformance` (every backend: in-memory, SQLite incl. memory queue, PostgreSQL; both history modes): export of all tables, wipe and re-import restores the store, idempotent chunks, marks, holds, the gate, the data-protection ring exclusion, history by day. `Mta.Storage.Portability.Tests`: full drain flow and quiesce flow InMemory↔SQLite and SQLite↔SQLite in both history modes, quiesce with a real `DeliveryEngine` and a loopback MX holding a delivery in flight (the in-flight message is requeued flagged and reaches the MX twice, every other message once), fence after restart, activation gate with a live engine, rollback before and refused after activation, tamper detection (chunk, body pack, missing file, manifest, modified target, swapped secret), resumable history export and import, different key protection, preflight refusals, StatsOnly target and source, reverse switch. `Mta.Storage.Postgres.Tests`: the same flows SQLite↔PostgreSQL both ways and both history modes, replicas, old-day partitions, resume. `Mta.Host.Tests`: startup gate, activator (bootstrap and patch, no secret printed, restore), data directory lock, and the whole CLI flow over two SQLite directories. `Mta.Integration.Tests`: the listeners answer `421`, the scheduler pauses and resumes, the watcher logic.

## Measured (this machine; unverified elsewhere)

Apple M4, macOS, local SSD, .NET 10, debug build of the test project, `EGGMAIL_SWITCH_BENCH=1 EGGMAIL_SWITCH_BENCH_N=30000` (`SwitchThroughput`): 30,000 queued messages (2 KB each, 2 recipients' worth of rows: spool, delivery, idempotency) plus 30,000 delivered messages with history (index, recipient, events, content, retained raw), stats, config; 331,007 rows, a 150.9 MiB bundle. One run each, no repetition; the PostgreSQL cluster of the test fixture runs with `fsync` off, so its import figure is optimistic.

| Direction | Export | Import | Verify |
|---|---:|---:|---:|
| SQLite → SQLite | 3.5 s (96k rows/s, 44 MiB/s) | 8.5 s (39k rows/s) | 1.8 s |
| SQLite → in-memory | 2.5 s (132k rows/s) | 1.3 s (263k rows/s) | 1.7 s |
| SQLite → PostgreSQL | 2.4 s (138k rows/s, 63 MiB/s) | 18.9 s (18k rows/s) | 2.0 s |
| PostgreSQL → SQLite | 4.6 s (72k rows/s, 33 MiB/s) | 9.4 s (35k rows/s) | 2.2 s |

The import dominates, and it is the EF change tracker plus one transaction per 5,000-row chunk, not the disk. Extrapolating these figures to the design's modeled 14 GB of history (rows are about 400 bytes on average here) gives hours, not minutes; that extrapolation is **unverified**, and a bulk-copy path (`COPY` for PostgreSQL, prepared multi-row inserts for SQLite) is the obvious next step if it matters. Export memory is bounded by one chunk (a test streams a 100,000-row file; a chunk is capped by rows and bytes). Fence time (stop accepting, pause, flush stats, write the state) was 60 to 250 ms.

## Known gaps

- Not verified against a real orchestrator (the patch text is generated and tested, not applied to a cluster) and not run with a real cloud KMS (`Secrets:KeyProtection=Kms` is implemented with the built-in `LocalKey` wrapping key and an `IKeyWrapProvider` extension point; no cloud service is included).
- The dashboard flow exists ([dashboard.md](dashboard.md); driven end to end in a browser against a real server and PostgreSQL by the Playwright tests). It switches between backends only (the API refuses `to` equal to the running backend) and has no bundle download. `finalize` through the API after the restart needs the old store described as `SwitchSource:*`; otherwise use `mta migrate-storage finalize`. A switch started by the CLI and still pending after a restart is rolled back or finalized with the CLI.
- A switch started by the CLI against a running SQLite server is not supported (the lock refuses it); online switching of a SQLite source goes through the admin API of the running process, which owns the files.
- Webhook deliveries in flight on a replica of a shared PostgreSQL store at the moment of the fence can complete and record on the source after the export; receivers de-duplicate by event id, and the attempt record on the source is not moved.
- Bundle chunks are read fully into memory one at a time (bounded by the chunk caps, but a chunk of 32 MiB plus one message of up to the SMTP maximum can be about 60 MiB).
