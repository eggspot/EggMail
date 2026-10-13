# Operations guide

How to run EggMail. Everything here is about behaviour that exists in the code; items that are not built yet are marked.

## Configuration

Settings come from (highest precedence first): command line, environment variables, the bootstrap file on the data volume (`bootstrap.json`, written by a backend switch), `appsettings.json`, built-in defaults. Environment variables use `__` for nesting (`Delivery__RemotePort=25`). Values supplied by the deployment cannot be edited in the dashboard.

| Key | Default | Meaning |
|---|---|---|
| `Hostname` | machine name | Name in SMTP greetings, `Received` headers and EHLO; should match the PTR record of the sending IP |
| `Storage:Backend` | `Sqlite` | `Sqlite` or `Postgres` (same image) |
| `Sqlite:DataDirectory` | `/data` | Where the database files live (mount a volume here) |
| `Sqlite:SyncMode` | `Off` | `Off`, `Normal`, `Full` for queue and stats files. **`Off` is safe against a process kill but not against power loss or an OS crash**: files can corrupt and acknowledged mail can be lost. Use `Normal` or `Full`, or PostgreSQL, if you need that |
| `Sqlite:ConfigSyncMode` | `Full` | Same for `config.db` (tenants, keys, certificates) |
| `Storage:Postgres:OwnerConnectionString` / `RuntimeConnectionString` | none | Owner role runs migrations and partition DDL; runtime role does normal work |
| `History:Mode` | `Full` | `Full` keeps per-message history; `StatsOnly` keeps aggregates only |
| `Content:RetentionDays` | 7 | 6 to 30; message bodies kept for the dashboard and resend |
| `Retention:MetadataDays` | 30 | Per-message events; `0` keeps forever |
| `Queue:MaxLifetime` | 5 days | After this a deferred delivery expires and bounces |
| `Smtp:Listeners:<name>:*` | see below | Port, mode, role, auth, bind address, enabled |
| `Smtp:MaxMessageSize`, `MaxRecipients`, `MaxConnections`, `MaxConnectionsPerIp` | 25 MiB, 50, 2000, 100 | Limits |
| `Delivery:BounceDomain` | none | Domain of signed bounce addresses (`b+token@...`). Needs an MX record pointing at this server's bounce listener (public port 25 → container 2526). Without it, bounces go to the original sender address |
| `Delivery:Workers` | 8 × cores (min 32) | Concurrent delivery groups |
| `Delivery:RetryDelays` | built-in ladder | Delays between retries; the last repeats |
| `Delivery:Throttle:*` | 20 connections, 600 msg/min ceilings | Per-destination limits; they start lower and grow while the destination accepts |
| `Delivery:RemotePort`, `Delivery:AllowPrivateMxAddresses` | 25, false | Lab settings only |
| `Dns:Servers` | system resolvers | Resolvers (IP with optional port) |
| `Dns:RequestDnssec`, `Dns:TrustAuthenticatedData` | true, false | DANE needs DNSSEC answers from a trusted validating resolver |
| `Tls:CertificatePath`, `KeyPath`, `PfxPasswordFile` | none | Optional file override (for example cert-manager) |
| `Tls:ReportingEnabled`, `ReportContact` | true | Daily TLS-RPT reports |
| `Acme:Enabled`, `DirectoryUrl`, `Email`, `Domains`, `CloudflareApiToken(File)` | off | ACME with Cloudflare DNS-01 (verified against the Pebble test CA, not yet against a production CA; see [TLS certificates and ACME](#tls-certificates-and-acme)) |
| `Acme:CertificateName`, `PropagationDelay`, `RenewAtRemainingFraction`, `CheckInterval` | `default`, 30 s, 1/3, 1 h | Name of the configured certificate row, wait after creating the TXT records, renew when this fraction of the lifetime is left, how often the renewal check runs |
| `Tls:PollInterval` | 30 s | How often each replica polls the database for a changed certificate |
| `Secrets:KeyProtection` | `None` | `Certificate` (with `CertificatePath`) for production. `None` stores the key ring unprotected and logs a warning |
| `Backup:Enabled`, `IntervalHours`, `Keep`, `Directory` | true, 24, 3, `<data>/backups` | Scheduled SQLite backups |
| `Dashboard:HttpPort`, `HttpsPort`, `HttpsEnabled` | 8080, 8443, true | Dashboard / API listeners |
| `Observability:OtlpEndpoint` | none | OTLP endpoint (for example `http://collector:4317`); when set, metrics, traces and logs are exported there. Empty: no exporter, and no span is ever created |
| `Observability:OtlpProtocol` | `Grpc` | `Grpc` (port 4317) or `HttpProtobuf` (port 4318; EggMail appends `/v1/metrics`, `/v1/traces`, `/v1/logs`) |
| `Observability:TraceSampleRatio` | 0.1 | Share of messages whose trace is exported, 0 to 1. A message is traced completely or not at all |
| `Observability:MetricsEndpointEnabled` | true | Serve `/metrics` |
| `Observability:QueueSampleSeconds` | 15 | Seconds between samples of the queue for the `mta_delivery_queue_*` gauges; `0` turns them off |
| `Webhooks:*` | see `WebhookOptions` | Timeouts, SSRF allow-list, retention |

Default listeners (container ports, publish them as 587, 465, 2525 and 25):

| Name | Port | Mode | Role |
|---|---|---|---|
| `submission` | 5587 | STARTTLS | submission, AUTH required |
| `submissions` | 4465 | implicit TLS | submission |
| `alternate` | 2525 | STARTTLS | submission |
| `bounce` | 2526 | STARTTLS offered | bounce: signed bounce addresses only, no AUTH |
| `alternate-587`, `alternate-465` | 2587, 2465 | | off by default |

## First administrator

Set `Dashboard:BootstrapAdminPasswordFile` (a file holding the password, for example a mounted secret) and `Dashboard:BootstrapAdminUser`: when no administrator exists the server creates one at start. Or, with the server stopped (SQLite allows one process per data directory), run `mta admin create --user NAME --password-file FILE` (`--role tenant --tenant SLUG` for a tenant user; the password can also come from `MTA_ADMIN_PASSWORD`, never from the command line). Passwords need at least 10 characters.

## DNS records for a sending domain

For each domain the dashboard/API shows the exact records: a DKIM TXT at `<selector>._domainkey.<domain>` (required), a CNAME `bounce.<domain>` to your bounce domain (required when `Delivery:BounceDomain` is set), plus advice for SPF (`v=spf1 ... ~all`) and DMARC. Sending is allowed once DKIM (and the return-path record) verify.

Your sending IP also needs a PTR record that matches `Hostname`, and outbound port 25 must not be blocked by your provider. Deliverability work (IP reputation, warm-up, abuse handling) is operational and not done by the software.

## TLS certificates and ACME

Certificates live in the database and are served by SMTP (STARTTLS and implicit TLS) and by the dashboard/API HTTPS listener. A new instance starts with a self-signed certificate for `Hostname` (the dashboard flags it); import a certificate in the dashboard, mount one with `Tls:CertificatePath`/`KeyPath` (it takes precedence), or let EggMail order one.

**Built-in ACME** (`Acme:Enabled=true`) orders one certificate for `Acme:Domains` (the SMTP and dashboard host names) from the CA at `Acme:DirectoryUrl`, using the **DNS-01** challenge only. DNS-01 needs no inbound port 80 or 443; the only supported DNS provider is Cloudflare, with a token that has Zone:Read and DNS:Edit for the zone (`Acme:CloudflareApiToken` or `Acme:CloudflareApiTokenFile`). Wildcard names work. The ACME account is created on the first order and kept (encrypted) in the database for that directory; it is part of a backend switch bundle. Email addresses given to the CA (`Acme:Email`) get no expiry notices from Let's Encrypt any more, so monitor expiry yourself.

Renewal runs hourly and renews when a third of the lifetime is left. A failed attempt (DNS provider error, CA error, validation failed, CA unreachable) is recorded and retried after 10 minutes, then 20, 40, … up to 6 hours; the certificate in use keeps being served. Status, failure count, last error and next attempt are in the admin API (`GET /api/v1/admin/certificates/acme`). With several replicas only one orders at a time (a lease row); the others pick the new certificate up from the database within `Tls:PollInterval` without a restart.

**Use the staging CA first.** Production Let's Encrypt rate-limits failed validations and new accounts. Set `Acme:DirectoryUrl=https://acme-staging-v02.api.letsencrypt.org/directory`, check that a certificate is issued (it is not trusted by clients), then switch to `https://acme-v02.api.letsencrypt.org/directory`. Accounts are per directory, so switching the directory registers a second account; the existing certificate is not re-ordered until it is due or you request one (`POST /api/v1/admin/certificates/acme`).

What has been verified: the whole flow (order, DNS-01 validation, finalize, encrypted storage, renewal, back-off, hot swap into SMTP and HTTPS) runs in CI against the Pebble test CA ([components/acme.md](components/acme.md)). What has not: a real CA, the real Cloudflare API (the provider is unit-tested only against a fake), and real DNS propagation (`Acme:PropagationDelay` of 30 s is a guess; Let's Encrypt validates from several vantage points, so raise it if validation fails right after the records were created).

Checklist for the first real-CA run: a domain whose zone is in Cloudflare and a host name inside it that you will use as `Hostname`/`Acme:Domains`; the API token; outbound HTTPS to the CA and to `api.cloudflare.com`; the staging run above. Afterwards verify from outside that the certificate is served on port 587/465 (`openssl s_client -starttls smtp -connect <host>:587 -servername <host>`) and on the dashboard port, with the intermediate certificate included.

## Backups and restore (SQLite)

Backups run while the server runs (`VACUUM INTO` per file) every `Backup:IntervalHours` into `<data>/backups/eggmail-backup-<UTC>/`; the newest `Backup:Keep` are kept. Put `Backup:Directory` on another disk when possible and copy backups off the host.

To restore: stop EggMail, copy the files of one backup directory over the data directory (replace `config.db`, `queue.db`, `stats.db`, `history.db` together), start. The state returns to the moment of the backup; mail accepted since is lost. If a file is found corrupt at start (possible after power loss with `Sqlite:SyncMode=Off`) it is moved aside (quarantined), the instance starts with a fresh file, and a warning is shown. If `config.db` is quarantined the instance starts without tenants and keys: restore it from a backup. PostgreSQL: use `pg_dump` or your platform's backups.

## Monitoring

`/healthz` (liveness), `/readyz` (readiness and warnings) and `/metrics` (Prometheus text, loopback and private networks only, never behind a proxy header) are served by the HTTP layer. The same instruments go to OTLP when `Observability:OtlpEndpoint` is set. Prometheus names are below; in OTLP the names are the dotted forms (`mta.delivery.queue.depth`).

**Cost.** Counters and histograms are recorded where the work happens and cost a few nanoseconds; nothing queries the database when `/metrics` is scraped. The queue gauges read a sample that a background task refreshes every `Observability:QueueSampleSeconds` (each sample reads the whole queue table, so raise the interval on a very large queue); `mta_delivery_queue_sample_age_seconds` tells you when the sample is stale. Labels are small fixed sets (outcome, state, file, reason, certificate name): never a recipient, a message or a tenant, and a metric keeps at most 1000 label combinations.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `mta_smtp_server_connections_total` | counter | none | Connections accepted |
| `mta_smtp_server_connections_refused_total` | counter | none | Connections refused by a limit or policy |
| `mta_smtp_server_sessions_active` | gauge | none | Open SMTP sessions |
| `mta_smtp_server_commands_total` | counter | none | SMTP commands processed |
| `mta_smtp_server_messages_total` | counter | none | Messages accepted (`250` after DATA) |
| `mta_smtp_server_messages_rejected_total` | counter | none | Messages refused after DATA |
| `mta_smtp_server_bytes_total` | counter | none | Message bytes accepted |
| `mta_smtp_server_transaction_duration_seconds` | histogram | none | Time from the end of DATA to the final reply: what a submitting client waits for, including the queue commit |
| `mta_smtp_server_protocol_errors_total` | counter | none | Protocol violations (bad syntax or sequence, smuggling attempts) |
| `mta_smtp_server_auth_failures_total` | counter | none | Failed AUTH attempts |
| `mta_smtp_server_tls_handshakes_total` | counter | none | Completed TLS handshakes on the listeners |
| `mta_smtp_server_tls_failures_total` | counter | none | Failed TLS handshakes on the listeners |
| `mta_smtp_client_connections_total` | counter | none | Outbound connections established |
| `mta_smtp_client_pool_hits_total` | counter | none | Outbound connections reused from the pool |
| `mta_smtp_client_tls_handshakes_total` | counter | none | Completed outbound TLS handshakes |
| `mta_smtp_client_tls_failures_total` | counter | none | Failed outbound TLS handshakes |
| `mta_delivery_claimed_total` | counter | none | Deliveries leased from the queue |
| `mta_delivery_claim_duration_seconds` | histogram | `result` (`claimed`, `empty`) | One queue claim; `empty` is the idle poll |
| `mta_delivery_attempts_total` | counter | `outcome` (`delivered`, `deferred`, `failed`, `expired`, `suppressed`...) | Recipients finished or rescheduled by an attempt. Alert on a growing share of `deferred` |
| `mta_delivery_group_duration_seconds` | histogram | none | One delivery group (a message's recipients at one destination domain), claim to recorded result |
| `mta_delivery_record_duration_seconds` | histogram | none | Storing the results of one delivery transaction (queue update, history, statistics, webhook fan-out) |
| `mta_delivery_held_total` | counter | none | Deliveries held back by a local sending limit or destination throttle (nothing was sent) |
| `mta_delivery_bounces_generated_total` | counter | none | Bounce messages generated |
| `mta_delivery_queue_depth` | gauge | `state` (`queued`, `deferred`, `leased`) | Deliveries in the queue: never tried, waiting for a retry, being delivered. Sampled in the background |
| `mta_delivery_queue_oldest_due_age_seconds` | gauge | none | How long the oldest due delivery has waited; 0 when nothing is overdue. Alert when it grows |
| `mta_delivery_queue_spool_size_bytes` | gauge | none | Bytes of queued message bodies |
| `mta_delivery_queue_sample_age_seconds` | gauge | none | Age of the last successful queue sample; the queue gauges are stale when this keeps growing |
| `mta_delivery_queue_sample_failures_total` | counter | none | Queue samples that failed (storage unavailable) |
| `mta_webhooks_claimed_total` | counter | none | Webhook outbox items picked up for delivery |
| `mta_webhooks_deliveries_total` | counter | `outcome` (`delivered`, `retry`, `failed`) | Webhook attempts: `retry` will be tried again, `failed` is final |
| `mta_webhooks_failures_total` | counter | `reason` (`timeout`, `connect_failed`, `ssrf_blocked`, `throttled`, `gone`, `redirect`, `http_4xx`, `http_5xx`, `endpoint_unavailable`, `secret_unreadable`, `other`) | Failed webhook attempts by cause |
| `mta_webhooks_delivery_duration_seconds` | histogram | none | One HTTP call to a receiver |
| `mta_webhooks_endpoints_disabled_total` | counter | none | Endpoints switched off after `410 Gone` or a continuous failure period |
| `mta_storage_sqlite_commit_duration_seconds` | histogram | `file` (`queue.db`, `stats.db`, `config.db`, `history.db`) | COMMIT of one writer transaction (`sqlite_commit_latency` in [benchmarks.md](benchmarks.md)); with `Sqlite:SyncMode=Full` this is the fsync |
| `mta_storage_sqlite_writer_batch_size` | histogram | `file` | Commands per committed transaction: how well the group commit batches (`sqlite_writer_batch_size`) |
| `mta_storage_sqlite_writer_batch_failures_total` | counter | `file` | Transactions that failed as a whole and were replayed command by command |
| `mta_storage_sqlite_writer_queue_depth` | gauge | `file` | Commands waiting for the writer right now (`sqlite_writer_queue_depth`) |
| `mta_storage_sqlite_wal_size_bytes` | gauge | `file` | Size of the write-ahead log |
| `mta_storage_sqlite_sync_off` | gauge | `file` | 1 for a file running with `synchronous=OFF`, else 0 (`sqlite_sync_off`) |
| `mta_storage_sqlite_quarantined` | gauge | `file` | 1 for a file that failed its start-up integrity check and was moved aside when this process started, else 0 |
| `mta_tls_certificate_expiry_seconds` | gauge | `name`, `source` | Seconds until each served certificate expires |
| `mta_tls_certificates` | gauge | none | Certificates served; an expired one is no longer served, so alert on 0 as well |
| `mta_backup_runs_total` | counter | `outcome` (`success`, `failed`) | Scheduled backup runs |
| `mta_backup_last_success_timestamp_seconds` | gauge | none | Unix time of the newest good backup (also after a restart, from the backups on disk); absent until there is one |

PostgreSQL command latency and pool state come from the Npgsql driver's own meter, exported unchanged next to the `mta_` metrics. The pool label (`db_client_connection_pool_name`) is `eggmail-runtime` or `eggmail-owner`; saturation is `used / max` of `db_client_connection_count` and `db_client_connection_max`.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `db_client_operation_duration_seconds` | histogram | pool name, server | Duration of each command, as seen by the driver |
| `db_client_operation_failed_total` | counter | pool name | Commands that failed |
| `db_client_operation_npgsql_executing` | gauge | pool name | Commands executing right now |
| `db_client_operation_npgsql_prepared_ratio` | gauge | pool name | Share of commands that ran as prepared statements; the hot paths should be near 1 |
| `db_client_connection_count` | gauge | pool name, `db_client_connection_state` (`idle`, `used`) | Pooled connections by state |
| `db_client_connection_max` | gauge | pool name | Pool size limit (`Storage:Postgres:MaxPoolSize`) |
| `db_client_connection_npgsql_pending_requests` | gauge | pool name | Callers waiting for a free connection; above 0 for long means the pool is too small |
| `db_client_connection_npgsql_timeouts_total` | counter | pool name | Connection requests that timed out |
| `db_client_connection_npgsql_create_time_seconds` | histogram | pool name | Time to open a new connection |

**What to alert on.**

- Queue backlog: `mta_delivery_queue_oldest_due_age_seconds` above a few minutes for more than a few scrapes, or `mta_delivery_queue_depth{state="queued"}` growing steadily. `mta_delivery_queue_sample_age_seconds` above a minute means both are stale.
- Repeated deferrals to one domain: the metrics carry no domain label (it is unbounded); the dashboard's per-domain statistics and the message events show which one. Alert on the `deferred` share of `mta_delivery_attempts_total`.
- Certificates: `mta_tls_certificate_expiry_seconds` below 14 days (ACME renews with a third of the lifetime left) or `mta_tls_certificates == 0`.
- Durability warnings: `mta_storage_sqlite_sync_off == 1` when you did not choose `Sqlite:SyncMode=Off`, and `mta_storage_sqlite_quarantined == 1` (a file was found corrupt and replaced by an empty one; the evidence is in `<data>/quarantine/`).
- Backups: `mta_backup_runs_total{outcome="failed"}` increasing, or `time() - mta_backup_last_success_timestamp_seconds` above two backup intervals.
- SQLite write pressure (advisory; switching backends is manual): `mta_storage_sqlite_writer_queue_depth{file="queue.db"}` high for minutes, or the p99 of `mta_storage_sqlite_commit_duration_seconds` above about 100 ms.
- PostgreSQL: `db_client_connection_npgsql_pending_requests > 0`, `db_client_connection_npgsql_timeouts_total` or `db_client_operation_failed_total` increasing.

**Traces.** With `Observability:OtlpEndpoint` set, there is one trace per message and its trace id is the message id (the id in the `250 Queued as` reply and in the API): search your tracing backend for it. The spans are `mta.submit` (accepting the message into the queue), `mta.queue.wait` (acceptance to the first claim), `mta.delivery.attempt` (one per attempt and destination domain, with one event per recipient holding the outcome and SMTP code) and `mta.webhook.deliver` (one per webhook call; the message is found from the event's `message_id`). Nothing is stored for this: every span derives its trace from the message id, so a retry days later, or on another replica, joins the same trace. The spans hang under one shared parent id that is not itself exported, which tracing UIs show as a missing root. Only `Observability:TraceSampleRatio` of the messages are exported, chosen by message id, so a message is traced completely or not at all. Without an endpoint no span is created and nothing is allocated for tracing.

**Logs.** With an endpoint set, the structured log (the same records as the JSON console log) is exported over OTLP as well. Records written before the logging pipeline exists (configuration errors) are console only.

Alert also on the readiness warnings of `/readyz` (`sqlite_sync_off`, `sqlite_quarantined:<file>`, `queue_persistence_memory`), which carry the same facts as the gauges.

## Upgrades

Take a backup, pull the new image, restart. Schema changes run at start (SQLite: automatic; PostgreSQL: `Mail:Database:Migrate`, owner role). Schema version 4 builds an index on the history index (`message_index`) of every partition on PostgreSQL, which blocks intake writes for the duration; on a large history run `mta migrate-db` in a quiet moment before the rollout. Roll back by restoring the backup and starting the old image. Backend switching (SQLite ⇄ PostgreSQL) is a separate, manual procedure (`docs/design.md` section 4.6; the engine is being built).

## State kept across restarts

Four things the server counts or learns while running are written to the database in the background, so a restart (and, on PostgreSQL, another replica) sees them: the last DNS check result of every record of a domain, the hourly and daily sending counters behind `Sending:*` caps and the warm-up, the TLS-RPT counters, and the reports that could not be delivered yet. They are flushed every 10 seconds (counters) and every minute (TLS-RPT) and when the process stops, so a graceful restart loses nothing and a crash loses at most that last interval (the caps may then be overshot by what was sent in those seconds). With several replicas on one PostgreSQL database the caps are shared with a lag of one flush interval and each daily TLS report is sent once. Global settings changed in the dashboard (`/admin/settings`) are stored at once and applied at the next start.

## Graceful shutdown

On SIGTERM the SMTP listeners stop accepting, running deliveries are given time to finish, the rest are returned to the queue unchanged (a delivery that may already have been sent is flagged `possible_duplicate`), then the process exits. Give the container at least 60 s of termination grace.
