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
| `Acme:Enabled`, `DirectoryUrl`, `Email`, `Domains`, `CloudflareApiToken(File)` | off | ACME with Cloudflare DNS-01 (not verified against a real CA) |
| `Secrets:KeyProtection` | `None` | `Certificate` (with `CertificatePath`) for production. `None` stores the key ring unprotected and logs a warning |
| `Backup:Enabled`, `IntervalHours`, `Keep`, `Directory` | true, 24, 3, `<data>/backups` | Scheduled SQLite backups |
| `Dashboard:HttpPort`, `HttpsPort`, `HttpsEnabled` | 8080, 8443, true | Dashboard / API listeners |
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

## Backups and restore (SQLite)

Backups run while the server runs (`VACUUM INTO` per file) every `Backup:IntervalHours` into `<data>/backups/eggmail-backup-<UTC>/`; the newest `Backup:Keep` are kept. Put `Backup:Directory` on another disk when possible and copy backups off the host.

To restore: stop EggMail, copy the files of one backup directory over the data directory (replace `config.db`, `queue.db`, `stats.db`, `history.db` together), start. The state returns to the moment of the backup; mail accepted since is lost. If a file is found corrupt at start (possible after power loss with `Sqlite:SyncMode=Off`) it is moved aside (quarantined), the instance starts with a fresh file, and a warning is shown. If `config.db` is quarantined the instance starts without tenants and keys: restore it from a backup. PostgreSQL: use `pg_dump` or your platform's backups.

## Monitoring

`/healthz` (liveness), `/readyz` (readiness and warnings) and `/metrics` (Prometheus text, admin network only) are served by the HTTP layer *(the API pull request provides `/readyz` and `/metrics`; `/healthz` exists already)*. Meters: `Mta.Smtp.Server`, `Mta.Smtp.Client`, `Mta.Delivery` (attempts by outcome, holds, bounces, group duration), `Mta.Webhooks`, and storage meters. Alert on queue depth and oldest due delivery, repeated `deferred` outcomes to one domain, certificate expiry, the `sqlite_sync_off` warning being unintended, and failed backups.

## Bounces caused by the receiving server's capabilities

EggMail sends 8-bit bodies with `BODY=8BITMIME` and internationalized mail with `SMTPUTF8` when the receiving server offers them, and converts or refuses when it does not. Three permanent failures name this in the bounce text (none of them suppresses the recipient): `5.6.1` the server has no 8BITMIME and the message could not be converted to 7-bit (the text says why, for example 8-bit header fields in an attached message); `5.6.9` the message has UTF-8 header fields and the server has no SMTPUTF8; `5.6.7` the sender or recipient address has non-ASCII characters before the `@` and the server has no SMTPUTF8 (when only some recipients are affected the others are delivered). A configured `Delivery:BounceDomain` makes the envelope sender an ASCII bounce address, which avoids `5.6.7` for the sender. Bounce reports about internationalized recipients are RFC 6533 reports (`message/global-delivery-status`).

## Upgrades

Take a backup, pull the new image, restart. Schema changes run at start (SQLite: automatic; PostgreSQL: `Mail:Database:Migrate`, owner role). Roll back by restoring the backup and starting the old image. Backend switching (SQLite ⇄ PostgreSQL) is a separate, manual procedure (`docs/design.md` section 4.6; the engine is being built).

## Graceful shutdown

On SIGTERM the SMTP listeners stop accepting, running deliveries are given time to finish, the rest are returned to the queue unchanged (a delivery that may already have been sent is flagged `possible_duplicate`), then the process exits. Give the container at least 60 s of termination grace.
