# Operations guide

How to run EggMail. Everything here is about behaviour that exists in the code; items that are not built yet are marked.

## Configuration

Settings come from (highest precedence first): command line, environment variables, the bootstrap file on the data volume (`bootstrap.json`, written by a backend switch), `appsettings.json` next to the executable (`/app/appsettings.json` in the image; mount one there), the global settings saved through the dashboard (`/admin/settings`, stored in the database), built-in defaults. Environment variables use `__` for nesting (`Delivery__RemotePort=25`). Values supplied by the deployment cannot be edited in the dashboard. A value of the wrong type (`Smtp__MaxRecipients=many`) or out of range stops the start with a message naming the key; a saved dashboard setting that does not validate is ignored with a warning.

Formats: durations are `[d.]hh:mm:ss` (`00:00:30`, `2.00:00:00`); sizes are bytes; lists are indexed (`Acme__Domains__0=a.example`) or, for the lists marked *list*, one value with entries separated by commas.

The tables below list every key; the test `ConfigurationDocumentationTests` fails when a key the code reads is missing here, or a key named here is not read.

### General, storage and retention

| Key | Default | Meaning |
|---|---|---|
| `Hostname` | machine name | Name in SMTP greetings, `Received` headers and EHLO; should match the PTR record of the sending IP |
| `Storage:Backend` | `Sqlite` | `Sqlite` or `Postgres` (same image) |
| `Sqlite:DataDirectory` | `/data` | Where the database files live (mount a volume here) |
| `Sqlite:SyncMode` | `Off` | `Off`, `Normal`, `Full` for queue and stats files. **`Off` is safe against a process kill but not against power loss or an OS crash**: files can corrupt and acknowledged mail can be lost. Use `Normal` or `Full`, or PostgreSQL, if you need that |
| `Sqlite:ConfigSyncMode` | `Full` | Same for `config.db` (tenants, keys, certificates) |
| `Sqlite:QueuePersistence` | `Persistent` | `Memory` keeps the queue only in memory (a restart loses queued mail; the dashboard warns) |
| `Sqlite:QuickCheck` | true | Run `PRAGMA quick_check` at start; `false` runs the slower full `integrity_check` |
| `Sqlite:StatsFlushInterval` | `00:00:10` | How often the in-memory statistics are written; a crash loses at most this window. `00:00:00` disables the timer |
| `Sqlite:RetentionDeleteBatchSize` | 5000 | Rows per batched retention `DELETE` |
| `Sqlite:RetentionDeletePause` | `00:00:00.020` | Pause between those batches so intake stays responsive |
| `Storage:Postgres:OwnerConnectionString` | none | Owner role: runs migrations and partition DDL |
| `Storage:Postgres:RuntimeConnectionString` | none | Runtime role: normal work (required for PostgreSQL). With only one of the two set it serves both roles and health warns |
| `Storage:Postgres:ReadOnlyConnectionString` | none | Optional read-only role for the read queries of the dashboard and the API (message search, detail, events, statistics); must name a `Username` and point at the primary; the migration grants it `SELECT` on the history and statistics tables only. Without it those queries use the runtime role |
| `Storage:Postgres:ReadOnlyStatementTimeoutSeconds` | 5 | `statement_timeout` of the read-only connections; a query that runs longer is cancelled and answered `503 query_too_slow` |
| `Storage:Postgres:ReadOnlyIdleInTransactionTimeoutSeconds` | 10 | `idle_in_transaction_session_timeout` of the read-only connections |
| `Storage:Postgres:ReadOnlyMaxPoolSize` | 8 | Connection pool of the read-only role |
| `Storage:Postgres:MaxPoolSize` | 32 | Connection pool of the runtime role (the owner role has a small pool of its own) |
| `Storage:Postgres:PartitionsAheadDays` | 7 | Day partitions of the history tables created ahead by maintenance |
| `Storage:Postgres:StatsFlushInterval` | `00:00:10` | As `Sqlite:StatsFlushInterval` |
| `Storage:Postgres:RetentionDeleteBatchSize` | 5000 | Rows per batched `DELETE` (tables that are not day partitioned) |
| `Storage:Postgres:RetentionDeletePause` | `00:00:00.020` | Pause between those batches |
| `Storage:Postgres:CommandTimeoutSeconds` | 30 | Command timeout of the hot-path statements (a `Command Timeout` in the connection string wins) |
| `Mail:Database:Migrate` | `Auto` | `Auto` migrates the PostgreSQL schema at start (owner role); `Never` leaves it to `mta migrate-db` or the generated script |
| `History:Mode` | `Full` | `Full` keeps per-message history; `StatsOnly` keeps aggregates only |
| `History:RecentEvents` | 1000 | Size of the content-free recent-events ring behind the dashboard's live view (both modes) |
| `Content:Mode` | `Retain` | `None` deletes message content at the final state |
| `Content:RetentionDays` | 7 | 6 to 30; message bodies kept for the dashboard and resend |
| `Content:StoreAttachments` | false | Default for keeping the raw message with its attachments (a tenant or a send can override it); has an effect only with `Content:AllowAttachmentStorage` |
| `Content:AllowAttachmentStorage` | false | Master switch: without it no attachment is ever stored |
| `Content:MaxStoredBodyBytes` | 262144 | Stored text/HTML bodies are truncated (and flagged) beyond this |
| `Content:StoreSubject` | true | `false` stores no subject (subjects can contain personal data) |
| `Retention:MetadataDays` | 30 | Per-message events; `0` keeps forever |
| `Stats:HourlyRetentionDays` | 30 | Hourly statistics; `0` keeps forever |
| `Stats:DailyRetentionDays` | 400 | Daily statistics; `0` keeps forever |
| `Stats:RecipientDomainTopNHourly` | 20 | Recipient domains kept per hour and sending domain; the rest is counted as `other` |
| `Stats:RecipientDomainTopNDaily` | 10 | The same for the daily rollup |
| `Stats:MaxSeriesPerHour` | 200000 | Cap on distinct statistic series in one hour; the overflow goes to `other` |
| `Queue:MaxLifetime` | `5.00:00:00` | After this a deferred delivery expires and bounces. Must be shorter than `Content:RetentionDays` while history is recorded |
| `Queue:MaxLifetimeDays` | 5 | The same in whole days: the form the dashboard's settings page stores. If both are set, `Queue:MaxLifetime` wins |

### SMTP and delivery

| Key | Default | Meaning |
|---|---|---|
| `Smtp:Listeners:<name>:Port` | see below | Listener port (0 lets the system pick one) |
| `Smtp:Listeners:<name>:BindAddress` | `::` | IP address to bind |
| `Smtp:Listeners:<name>:Mode` | `StartTls` | `StartTls`, `Implicit` (TLS from the first byte) or `Plain` |
| `Smtp:Listeners:<name>:Role` | `Submission` | `Submission` (tenant mail, AUTH) or `Bounce` (signed bounce addresses only) |
| `Smtp:Listeners:<name>:AuthRequired` | true | |
| `Smtp:Listeners:<name>:Enabled` | true | |
| `Smtp:Listeners:<name>:AllowInsecureAuth` | false | Allow AUTH without TLS (loopback or internal networks only) |
| `Smtp:MaxMessageSize` | 26214400 | Bytes (25 MiB); also the limit of a message sent through the API |
| `Smtp:MaxRecipients` | 50 | Recipients per message (1 to 1000); also the API limit |
| `Smtp:MaxConnections` | 2000 | Concurrent SMTP connections |
| `Smtp:MaxConnectionsPerIp` | 100 | Concurrent connections from one address |
| `Smtp:MaxInFlightBytes` | 536870912 | Message bytes the server holds in memory at once across all connections (512 MiB); beyond it a sender gets `452` and retries later |
| `Smtp:Chunking` | true | Advertise `CHUNKING`/`BDAT` |
| `Smtp:SmtpUtf8` | true | Advertise and accept `SMTPUTF8` |
| `Delivery:BounceDomain` | none | Domain of signed bounce addresses (`b+token@...`). Needs an MX record pointing at this server's bounce listener (public port 25 → container 2526). Without it, bounces go to the original sender address |
| `Delivery:HeloName` | `Hostname` | EHLO name of outbound connections |
| `Delivery:Workers` | 8 × cores (min 32) | Concurrent delivery groups |
| `Delivery:ClaimBatchSize` | 100 | Deliveries claimed from the queue at once |
| `Delivery:ClaimLease` | `00:15:00` | A claimed delivery that is not reported back within this is handed out again (flagged `possible_duplicate`) |
| `Delivery:PollInterval` | `00:00:00.250` | How often an idle engine looks for due deliveries |
| `Delivery:MaxRecipientsPerTransaction` | 100 | Recipients of one destination domain sent in one SMTP transaction |
| `Delivery:PreferChunking` | false | Use `BDAT` when the remote server offers it |
| `Delivery:RetryDelays` | built-in ladder | Delays between retries (2 m, 5 m, 15 m, 30 m, 1 h, 2 h, 4 h); the last repeats |
| `Delivery:Throttle:MaxConnections` | 20 | Ceiling of concurrent connections to one destination domain |
| `Delivery:Throttle:MaxMessagesPerMinute` | 600 | Ceiling of messages per minute to one destination domain |
| `Delivery:Throttle:MaxMessagesPerConnection` | 100 | Messages over one connection before it is closed |
| `Delivery:Throttle:InitialConnections` | 5 | Connections allowed at first; grows while the destination keeps accepting |
| `Delivery:Throttle:InitialMessagesPerMinute` | 120 | Messages per minute allowed at first; grows the same way |
| `Delivery:RemotePort` | 25 | Destination port for direct MX delivery; lab setups only |
| `Delivery:AllowPrivateMxAddresses` | false | Allow MX hosts that resolve to loopback or private addresses; lab setups only |
| `Delivery:PublicSendingIp` | none | The address receiving servers see for our connections; reported as `sending-mta-ip` in TLS-RPT reports. Set it when EggMail is behind NAT or a proxy. Without it only a public local address of the connection is reported; private, loopback and link-local addresses are left out |
| `Dns:Servers` | system resolvers | Resolvers (IP with optional port) |
| `Dns:RequestDnssec` | true | Ask for DNSSEC records (needed for DANE) |
| `Dns:TrustAuthenticatedData` | false | Trust the AD bit; only behind a local validating resolver |
| `Sending:GlobalPerHour` | 0 | Most messages the server sends per UTC hour (0 = unlimited). Counters are in memory: a restart starts the hour at zero |
| `Sending:GlobalPerDay` | 0 | The same per UTC day |
| `Sending:TenantPerHour` | 0 | Default cap per tenant and hour; a tenant setting `Sending:PerHour` overrides it |
| `Sending:TenantPerDay` | 0 | Default cap per tenant and day; tenant setting `Sending:PerDay` |
| `Sending:DomainPerHour` | 0 | Default cap per sending domain and hour |
| `Sending:DomainPerDay` | 0 | Default cap per sending domain and day |
| `Sending:WarmupEnabled` | false | Limit each sending domain by the warm-up ramp (50, 100, 200 ... a day) from the day it was added |

### TLS, certificates and secrets

| Key | Default | Meaning |
|---|---|---|
| `Tls:CertificatePath` | none | Optional file override (for example cert-manager): PEM chain, or a PFX when `Tls:KeyPath` is empty. Wins over the database certificates for the same names |
| `Tls:KeyPath` | none | PEM private key of the override |
| `Tls:PfxPasswordFile` | none | File holding the PFX password |
| `Tls:PollInterval` | `00:00:30` | How often replicas look for a changed certificate (database and override files) |
| `Tls:ReportingEnabled` | true | Collect outbound TLS results and send daily TLS-RPT reports (RFC 8460) to domains that ask |
| `Tls:ReportContact` | `postmaster@<Hostname>` | Contact in the reports |
| `Acme:Enabled` | false | ACME with Cloudflare DNS-01 (verified against the Pebble test CA in CI, not yet against a production CA; see [TLS certificates and ACME](#tls-certificates-and-acme)). Needs `Acme:CloudflareApiToken` or `Acme:CloudflareApiTokenFile` |
| `Acme:DirectoryUrl` | Let's Encrypt production | Use the staging directory while testing |
| `Acme:Email` | none | Contact for the ACME account |
| `Acme:Domains` | none | *List.* Names for the certificate renewed from configuration (wildcards need DNS-01, the only method). Certificates requested through the API are renewed as well |
| `Acme:CertificateName` | `default` | Name of that certificate in the database |
| `Acme:DnsProvider` | `Cloudflare` | The only provider so far |
| `Acme:CloudflareApiToken` | none | API token with DNS edit rights (prefer the file form) |
| `Acme:CloudflareApiTokenFile` | none | File holding that token |
| `Acme:PropagationDelay` | `00:00:30` | Wait after publishing the challenge record |
| `Acme:RenewAtRemainingFraction` | 0.3333 | Renew when this fraction of the lifetime remains (between 0 and 1) |
| `Acme:CheckInterval` | `01:00:00` | How often the renewal service looks |
| `Secrets:KeyProtection` | `None` | `Certificate` (with `Secrets:CertificatePath`) for production. `None` stores the key ring unprotected and logs a warning |
| `Secrets:CertificatePath` | none | PFX that protects the Data Protection key ring (deployment configuration, never in the database) |
| `Secrets:CertificatePasswordFile` | none | File holding its password |

### HTTP API and dashboard

| Key | Default | Meaning |
|---|---|---|
| `Dashboard:BindAddress` | `::` | IP address of the HTTP and HTTPS listeners |
| `Dashboard:HttpPort` | 8080 | Plain HTTP (probes, internal) |
| `Dashboard:HttpsPort` | 8443 | HTTPS with the certificate store; TLS 1.2 minimum, 1.3 on |
| `Dashboard:HttpsEnabled` | true | |
| `Dashboard:BootstrapAdminUser` | `admin` | User name created at start when no administrator exists |
| `Dashboard:BootstrapAdminPasswordFile` | none | File holding that user's password (see below) |
| `Api:MaxBodyBytes` | 1048576 | Largest JSON body of every endpoint except sending (checked while streaming) |
| `Api:MaxSendBodyBytes` | 41943040 | Largest JSON body of `POST /messages` and `/messages/raw` (40 MiB; attachments are base64). The server request limit follows it (at least 64 MiB) |
| `Api:MaxInFlightSendBytes` | 536870912 | Send-request bytes held in memory at once; beyond it the API answers `429` |
| `Api:MaxAttachments` | 50 | Attachments per message |
| `Api:MaxCustomHeaders` | 50 | Custom headers per message |
| `Api:MaxTags` | 10 | Tags per message |
| `Api:SessionLifetime` | `12:00:00` | Absolute lifetime of a dashboard session |
| `Api:SessionIdleTimeout` | `02:00:00` | A session unused for this long ends |
| `Api:CookieSecure` | `Auto` | `Auto` marks the session cookie `Secure` unless the request is plain HTTP from loopback; `Always`; `Never` |
| `Api:MaxDomainsPerTenant` | 200 | |
| `Api:MaxApiKeysPerTenant` | 100 | Active API keys |
| `Api:MaxSmtpCredentialsPerTenant` | 100 | |
| `Api:MaxWebhooksPerTenant` | 50 | |
| `Api:MaxStatsRows` | 50000 | Rows one statistics query may return |
| `Api:MetricsAllowedNetworks` | loopback and private ranges | *List.* Networks (CIDR) allowed to read `/metrics`; it carries no credentials, so keep it off the public internet |
| `Api:SpfInclude` | none | `include:` host suggested to customers in their SPF record |
| `Observability:MetricsEndpointEnabled` | true | Serve `/metrics`. Off also removes the Prometheus exporter itself (no meter listener of ours); OTLP is unaffected |
| `Observability:OtlpEndpoint` | none | OTLP endpoint, an `http://` or `https://` URL (for example `http://collector:4317`); `collector:4317` is refused at start. When set, metrics, traces and logs are exported there. Empty: no exporter, and no span is ever created |
| `Observability:OtlpProtocol` | `Grpc` | `Grpc` (port 4317) or `HttpProtobuf` (port 4318; EggMail appends `/v1/metrics`, `/v1/traces`, `/v1/logs`) |
| `Observability:TraceSampleRatio` | 0.1 | Share of messages whose trace is exported, 0 to 1. A message is traced completely or not at all |
| `Observability:QueueSampleSeconds` | 15 | Seconds between samples of the queue for the `mta_delivery_queue_*` gauges; `0` turns them off |
| `Webhooks:AllowHttp` | false | Allow plain `http` webhook endpoints (HTTPS only otherwise) |
| `Webhooks:Timeout` | `00:00:15` | One delivery attempt |
| `Webhooks:MaxConcurrency` | 32 | Concurrent webhook deliveries |
| `Webhooks:MaxConcurrencyPerEndpoint` | 4 | So one slow endpoint cannot take all workers |
| `Webhooks:BatchSize` | 64 | Deliveries claimed at once |
| `Webhooks:PollInterval` | `00:00:00.500` | |
| `Webhooks:Lease` | `00:02:00` | |
| `Webhooks:DisableAfter` | `5.00:00:00` | An endpoint failing for this long is disabled and the tenant notified |
| `Webhooks:RetrySchedule` | 5 s, 5 m, 30 m, 2 h, 5 h, 10 h, 10 h | Delays after attempt 1, 2, ... |
| `Webhooks:ThrottleExtraDelay` | `00:01:00` | Extra delay when the receiver answers 429/502/504 |
| `Webhooks:MaxResponseSnippetBytes` | 1024 | Response bytes kept in the attempt log |
| `Webhooks:UserAgent` | `EggMail-Webhooks/1.0` | |
| `Webhooks:OutboxRetentionDays` | 7 | Finished deliveries; `0` keeps forever |
| `Webhooks:AttemptLogDays` | 7 | Attempt log; `0` keeps forever |

### Backups and backend switch

| Key | Default | Meaning |
|---|---|---|
| `Backup:Enabled` | true | Scheduled SQLite backups |
| `Backup:IntervalHours` | 24 | |
| `Backup:Keep` | 3 | Newest backups kept |
| `Backup:Directory` | `<data>/backups` | Put it on another disk than the data |
| `Switch:QuiesceTimeoutSeconds` | 30 | Seconds to wait for in-flight deliveries when a backend switch quiesces |
| `Switch:BundleDirectory` | `<data>/switch` (or the temp directory) | Where the admin API writes switch bundles |
| `SwitchTarget:*` | none | Overlay for the target of a backend switch, for example `SwitchTarget:Connections:<name>` (a named PostgreSQL connection) or `SwitchTarget:Storage:Postgres:RuntimeConnectionString`; the API never carries credentials |
| `SwitchSource:*` | none | The same for the store an instance was switched away from (rollback) |

Default listeners (container ports, publish them as 587, 465, 2525 and 25):

| Name | Port | Mode | Role |
|---|---|---|---|
| `submission` | 5587 | STARTTLS | submission, AUTH required |
| `submissions` | 4465 | implicit TLS | submission |
| `alternate` | 2525 | STARTTLS | submission |
| `bounce` | 2526 | STARTTLS offered | bounce: signed bounce addresses only, no AUTH |
| `alternate-587`, `alternate-465` | 2587, 2465 | | off by default |

A listener named in configuration replaces the default of the same name member by member (`Smtp__Listeners__submission__Port=587`); a new name adds a listener.

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

## PostgreSQL roles

Three logins are supported (design section 4.3): the **owner** (migrations and partition DDL: `Storage:Postgres:OwnerConnectionString`), the **runtime** role (everything the application does: `Storage:Postgres:RuntimeConnectionString`), and an optional **read-only** role for the read queries of the dashboard and the API. To use the read-only role create it once, then restart (the start applies the grants, or run `mta migrate-db` when `Mail:Database:Migrate=Never`):

```sql
CREATE ROLE eggmail_ro LOGIN PASSWORD '...';
ALTER ROLE eggmail_ro CONNECTION LIMIT 8;                  -- matches Storage:Postgres:ReadOnlyMaxPoolSize
ALTER ROLE eggmail_ro SET statement_timeout = '5s';        -- optional: the application sets the same timeouts itself
REVOKE CREATE ON SCHEMA public FROM PUBLIC;                -- PostgreSQL before 15 lets everyone create tables in public (15 and later do not)
```

and set `Storage:Postgres:ReadOnlyConnectionString` to a connection string for it, pointing at the primary (not a replica: reads would lag the writes). The connections are also started `read-only` (`default_transaction_read_only=on`). The role can read the history and statistics tables and nothing else: no write, no secrets, no queue. If it cannot, or the password is wrong or the role does not exist, the start stops with the reason; later, an unusable or too privileged role shows as a health warning without taking the instance out of service. A query that runs past the timeout answers `503 query_too_slow`. Behind a pooler in transaction mode let the `options` startup parameter through (PgBouncer: `ignore_startup_parameters = options`).

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
- Backups: `mta_backup_runs_total{outcome="failed"}` increasing, or `time() - mta_backup_last_success_timestamp_seconds` above two backup intervals. The gauge exists from start when a backup is already on disk, and is absent on a fresh install until the first one: with backups enabled on SQLite also alert on `absent(mta_backup_last_success_timestamp_seconds)` for longer than the interval (a PostgreSQL deployment has no such series, since backups are the database's own).
- SQLite write pressure (advisory; switching backends is manual): `mta_storage_sqlite_writer_queue_depth{file="queue.db"}` high for minutes, or the p99 of `mta_storage_sqlite_commit_duration_seconds` above about 100 ms.
- PostgreSQL: `db_client_connection_npgsql_pending_requests > 0`, `db_client_connection_npgsql_timeouts_total` or `db_client_operation_failed_total` increasing.

**Traces.** With `Observability:OtlpEndpoint` set, there is one trace per message and its trace id is the message id (the id in the `250 Queued as` reply and in the API): search your tracing backend for it. The spans are `mta.submit` (accepting the message into the queue), `mta.queue.wait` (acceptance to the first claim), `mta.delivery.attempt` (one per attempt and destination domain, with one event per recipient holding the outcome, SMTP code, enhanced code, MX host and whether TLS was used) and `mta.webhook.deliver` (one per webhook call; the message is found from the event's `message_id`). Nothing is stored for this: every span derives its trace from the message id, so a retry days later, or on another replica, joins the same trace. The spans hang under one shared parent id that is not itself exported, which tracing UIs show as a missing root. Only `Observability:TraceSampleRatio` of the messages are exported, chosen by message id, so a message is traced completely or not at all (a webhook span that is not about a message follows the ratio per span). Without an endpoint no span is created and nothing is allocated for tracing. A failed attempt's span status carries the enhanced status code (`5.1.1`) or `smtp <code>`, never the remote server's reply text, because that text echoes recipient addresses.

**What leaves the box over OTLP.** Treat the collector as part of your trust boundary.

- Span attributes: the message id, the tenant id (an opaque id, kept so a tenant's traces can be found when supporting them), the recipient count, message size, source (`Smtp`/`Api`), the attempt number, the **recipient domain** of each delivery attempt, the MX host name, SMTP and enhanced codes, the webhook event type and the HTTP status code. No recipient or sender address, subject, body, webhook URL or endpoint id is exported in spans. Webhook calls to your customers carry no `traceparent` or other trace header either.
- Metrics: labels are the small fixed sets in the tables. The one label that can contain a customer's name is the certificate `name` of `mta_tls_certificate_expiry_seconds` (`selfsigned:<hostname>`, `default`, or the name given to an ACME or uploaded certificate, which may be a domain). The Prometheus exporter keeps at most 1000 label combinations per metric and counts what it refuses in `eggmail_exporter_dropped_series_total` (only rendered once above 0: it means some label is unbounded); the OpenTelemetry SDK's own per-metric limit (2000 by default) applies to the OTLP export.
- Logs: the same records as the JSON console log, with their formatted message text (deliberately: raw templates are hard to read in a log backend). Log messages can contain recipient addresses and remote server error text, for example in delivery failures. If that must not leave the host, leave `Observability:OtlpEndpoint` empty and ship the JSON console log through your own pipeline, where you can filter it.

**Logs.** With an endpoint set, the structured log (the same records as the JSON console log) is exported over OTLP as well. Records written before the logging pipeline exists (configuration errors) are console only.

Alert also on the readiness warnings of `/readyz` (`sqlite_sync_off`, `sqlite_quarantined:<file>`, `queue_persistence_memory`), which carry the same facts as the gauges.

## Bounces caused by the receiving server's capabilities

EggMail sends 8-bit bodies with `BODY=8BITMIME` and internationalized mail with `SMTPUTF8` when the receiving server offers them, and converts or refuses when it does not. Three permanent failures name this in the bounce text (none of them suppresses the recipient): `5.6.1` the server has no 8BITMIME and the message could not be converted to 7-bit (the text says why, for example 8-bit header fields in an attached message); `5.6.9` the message has UTF-8 header fields and the server has no SMTPUTF8 (a change from earlier versions, which sent such mail as is; headers are not downgraded, RFC 6857); `5.6.7` the sender or recipient address has non-ASCII characters before the `@` and the server has no SMTPUTF8 (when only some recipients are affected the others are delivered, and the affected ones are offered to the domain's other mail hosts first). A configured `Delivery:BounceDomain` makes the envelope sender an ASCII bounce address, which avoids `5.6.7` for the sender. Bounce reports about internationalized recipients are RFC 6533 reports (`message/global-delivery-status`).

## Upgrades

Take a backup, pull the new image, restart. Schema changes run at start (SQLite: automatic; PostgreSQL: `Mail:Database:Migrate`, owner role). Schema version 4 builds an index on the history index (`message_index`) of every partition on PostgreSQL, which blocks intake writes for the duration; on a large history run `mta migrate-db` in a quiet moment before the rollout. Roll back by restoring the backup and starting the old image. Backend switching (SQLite ⇄ PostgreSQL) is a separate, manual procedure (`docs/design.md` section 4.6; the engine is being built).

## State kept across restarts

Four things the server counts or learns while running are written to the database in the background, so a restart (and, on PostgreSQL, another replica) sees them: the last DNS check result of every record of a domain, the hourly and daily sending counters behind the sending caps (`Sending:GlobalPerHour` and the others) and the warm-up, the TLS-RPT counters, and the reports that could not be delivered yet. They are flushed every 10 seconds (counters) and every minute (TLS-RPT) and when the process stops, so a graceful restart loses nothing and a crash loses at most that last interval (the caps may then be overshot by what was sent in those seconds). With several replicas on one PostgreSQL database the caps are shared with a lag of one flush interval and each daily TLS report is sent once. Global settings changed in the dashboard (`/admin/settings`) are stored at once and applied at the next start.

## Graceful shutdown

On SIGTERM the SMTP listeners stop accepting, running deliveries are given time to finish, the rest are returned to the queue unchanged (a delivery that may already have been sent is flagged `possible_duplicate`), then the process exits. Give the container at least 60 s of termination grace.
