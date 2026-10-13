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
| `Secrets:KeyProtection` | `None` | `Certificate` (with `Secrets:CertificatePath`) or `Kms` (see "Protecting the key ring" below) for production. `None` stores the key ring unprotected and logs a warning |
| `Secrets:CertificatePath` | none | PFX that protects the Data Protection key ring (deployment configuration, never in the database) |
| `Secrets:CertificatePasswordFile` | none | File holding its password |
| `Secrets:KmsProvider` | `LocalKey` | With `Kms`: the key service that wraps the key ring. Only `LocalKey` is built in |
| `Secrets:KmsKeyFile` | none | `LocalKey`: file with the 32-byte wrapping key (base64, hex or raw). A mounted secret; preferred |
| `Secrets:KmsKey` | none | `LocalKey`: the same key as base64 or hex in a value, for platforms that only pass environment variables |

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
| `Observability:MetricsEndpointEnabled` | true | Serve `/metrics` |
| `Observability:OtlpEndpoint` | none | OTLP endpoint for metrics and traces |
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

## Monitoring

`/healthz` (liveness), `/readyz` (readiness and warnings) and `/metrics` (Prometheus text, admin network only) are served by the HTTP layer *(the API pull request provides `/readyz` and `/metrics`; `/healthz` exists already)*. Meters: `Mta.Smtp.Server`, `Mta.Smtp.Client`, `Mta.Delivery` (attempts by outcome, holds, bounces, group duration), `Mta.Webhooks`, and storage meters. Alert on queue depth and oldest due delivery, repeated `deferred` outcomes to one domain, certificate expiry, the `sqlite_sync_off` warning being unintended, and failed backups.

## Protecting the key ring (`Secrets:KeyProtection`)

DKIM keys, webhook secrets, TLS private keys and the ACME account key are encrypted with ASP.NET Core Data Protection; the key ring itself lives in the database. `Certificate` encrypts the ring with a PFX held outside the database. `Kms` wraps every ring element with a key that is kept outside the database: with `Secrets:KmsProvider=LocalKey` that is a random 32-byte key from a mounted file (`openssl rand -base64 32 > eggmail-keyring.key`, `Secrets:KmsKeyFile=/run/secrets/eggmail-keyring.key`) or an environment value (`Secrets:KmsKey`, less safe: it is visible in the process environment). Elements are sealed with AES-256-GCM and record the provider and a fingerprint of the key, so starting with another key stops with a message naming both instead of failing on the first secret. **Keep the key: without it the ring, and with it every secret in the database, cannot be opened, and a rotated key cannot open an existing ring** (key rotation is not implemented; restore a backup of the database and the old key to go back). A cloud key service (AWS KMS, Azure Key Vault, Google Cloud KMS) is not included: it plugs in as an `IKeyWrapProvider` registered with `KeyWrapProviders.Register` and selected by `Secrets:KmsProvider`; see [open-questions.md](open-questions.md). Backend switching works with any of the modes (the source's key must be reachable during the export).

## Upgrades

Take a backup, pull the new image, restart. Schema changes run at start (SQLite: automatic; PostgreSQL: `Mail:Database:Migrate`, owner role). Schema version 4 builds an index on the history index (`message_index`) of every partition on PostgreSQL, which blocks intake writes for the duration; on a large history run `mta migrate-db` in a quiet moment before the rollout. Roll back by restoring the backup and starting the old image. Backend switching (SQLite ⇄ PostgreSQL) is a separate, manual procedure (`docs/design.md` section 4.6; the engine is being built).

## State kept across restarts

Four things the server counts or learns while running are written to the database in the background, so a restart (and, on PostgreSQL, another replica) sees them: the last DNS check result of every record of a domain, the hourly and daily sending counters behind the sending caps (`Sending:GlobalPerHour` and the others) and the warm-up, the TLS-RPT counters, and the reports that could not be delivered yet. They are flushed every 10 seconds (counters) and every minute (TLS-RPT) and when the process stops, so a graceful restart loses nothing and a crash loses at most that last interval (the caps may then be overshot by what was sent in those seconds). With several replicas on one PostgreSQL database the caps are shared with a lag of one flush interval and each daily TLS report is sent once. Global settings changed in the dashboard (`/admin/settings`) are stored at once and applied at the next start.

## Graceful shutdown

On SIGTERM the SMTP listeners stop accepting, running deliveries are given time to finish, the rest are returned to the queue unchanged (a delivery that may already have been sent is flagged `possible_duplicate`), then the process exits. Give the container at least 60 s of termination grace.
