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
| `Secrets:KeyProtection` | `None` | `Certificate` (with `Secrets:CertificatePath`) or `Kms` (see below) for production. `None` stores the key ring unprotected and logs a warning |
| `Secrets:CertificatePath`, `Secrets:CertificatePasswordFile` | none | PFX (and a file with its password) that protects the Data Protection key ring; deployment configuration, never in the database |
| `Secrets:KmsProvider` | `LocalKey` | With `Kms`: the key service that wraps the key ring. Only `LocalKey` is built in |
| `Secrets:KmsKeyFile` | none | `LocalKey`: file with the 32-byte wrapping key (base64, hex or raw). A mounted secret; preferred |
| `Secrets:KmsKey` | none | `LocalKey`: the same key as base64 or hex in a value, for platforms that only pass environment variables |
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

Take a backup, pull the new image, restart. Schema changes run at start (SQLite: automatic; PostgreSQL: `Mail:Database:Migrate`, owner role). Roll back by restoring the backup and starting the old image. Backend switching (SQLite ⇄ PostgreSQL) is a separate, manual procedure (`docs/design.md` section 4.6; the engine is being built).

## Graceful shutdown

On SIGTERM the SMTP listeners stop accepting, running deliveries are given time to finish, the rest are returned to the queue unchanged (a delivery that may already have been sent is flagged `possible_duplicate`), then the process exits. Give the container at least 60 s of termination grace.
