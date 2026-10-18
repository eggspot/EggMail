# Operations guide

How to run EggMail. Everything here is about behaviour that exists in the code; items that are not built yet are marked.

## Deploying

Tested deployment files are in `deploy/` (the release workflow tests them against the image it builds: the PostgreSQL compose file on every build, the SQLite compose file, the Unbound sidecar and the Kubernetes manifests on tags and manual runs, not on the daily nightly; [release.md](release.md)):

| Deployment | Files | Notes |
|---|---|---|
| Docker Compose, SQLite (default) | `deploy/compose/compose.yaml` | The quick start with `EGGMAIL_*` variables: one container, one volume at `/data`, one replica. Read-only root filesystem, no capabilities, 60 s stop grace |
| Docker Compose, PostgreSQL | `deploy/compose/compose.postgres.yaml` | The quick start plus one variable, `EGGMAIL_DATABASE`: EggMail plus `postgres:17`; one database role for both duties (use a managed PostgreSQL with an owner and a runtime role in production) |
| DANE: local validating resolver | `deploy/compose/compose.unbound.yaml` (add with a second `-f`), `deploy/kubernetes/components/unbound` | Unbound sidecar, sets `Dns:Servers`, `Dns:RequestDnssec` and `Dns:TrustAuthenticatedData` together |
| Kubernetes, SQLite | `deploy/kubernetes/sqlite` | StatefulSet (one replica, ReadWriteOnce claim), `fsGroup` for the volume, startup/liveness (`/healthz`) and readiness (`/readyz`) probes |
| Kubernetes, PostgreSQL | `deploy/kubernetes/postgres` | Deployment (raise `replicas` for availability; read [Running more than one replica](#running-more-than-one-replica) first), connection strings from a Secret |
| Both Kubernetes variants | `deploy/kubernetes/base` | Services (SMTP as a LoadBalancer with `externalTrafficPolicy: Local` so client addresses survive), NetworkPolicy of design 7.1, ConfigMap |

Things that are easy to get wrong:

- **Healthcheck command.** The chiseled image has no shell and `/app` is not on `PATH`: use `["CMD", "/app/mta", "--healthcheck"]` (the `HEALTHCHECK` of the image does). `["CMD", "mta", "--healthcheck"]` fails with "executable file not found in $PATH". The release workflow checks this on every build (`deploy/smoke/image.sh` prints the image's `PATH` and tries `mta`).
- **First administrator.** Docker and Compose: nothing to do, a password is generated and printed once (see [Quick start](#quick-start-and-the-minimal-environment)); `EGGMAIL_ADMIN_PASSWORD` in the compose file chooses it, or a file secret through `EGGMAIL_ADMIN_PASSWORD_FILE` (the file must be readable by uid 1654: Compose does not apply `uid` or `mode` to file secrets outside Swarm). Kubernetes: a Secret mounted at `/run/secrets/eggmail` (`Dashboard__BootstrapAdminPasswordFile`). Or `mta admin create` while the SQLite server is stopped. Further users are made in the dashboard or the API while the server runs (see "Users while the server runs").
- **First sending domain.** Set `Domains__Bootstrap=example.com`: the first start registers the domain, generates its DKIM key and writes the DNS records to create into the log (one JSON line per line of the zone file, category `Mta.domains`: `docker compose logs eggmail | grep Mta.domains`); the dashboard shows them with a **Check DNS** button (see "Adding a sending domain and its DNS records").
- **Volume ownership.** The image prepares `/data` for uid 1654; a new Kubernetes volume is owned by root, hence `fsGroup: 1654` in the StatefulSet.
- **Inbound port 25** (bounces now, received mail once the receive path ships) needs a public MX record and a platform that offers inbound 25 (many load balancers do not). It maps to the port-25 listener 2526 of the container, which accepts nothing but the signed bounce addresses (and, with inbound mail on, the recipients of the domains tenants enabled); it is not a submission port, see [Ports](#ports). **Check that the client address survives:** `-p 25:2526` on Docker Desktop (macOS, Windows), with the rootless engine, or through the userland proxy delivers every connection from the gateway or loopback address, which makes SPF and the per-address limits of inbound mail meaningless; use host networking or a setup without source NAT ([Inbound mail](#inbound-mail)).
- **Kubernetes NetworkPolicy** is enforced only by a CNI that implements it; the smoke test applies the policy on kind but does not test enforcement.

## Quick start and the minimal environment

### One command, no configuration

```sh
docker run -d --name eggmail -p 587:5587 -p 465:4465 -p 2525:2525 -p 8443:8443 \
  -v eggmail-data:/data ghcr.io/eggspot/eggmail:nightly
docker logs eggmail          # the generated dashboard password, printed once (see below)
```

That is a working mail server: SMTP submission with AUTH on 587 (STARTTLS), 465 (implicit TLS) and 2525, the API and dashboard on `https://<host>:8443`, SQLite in the volume. The first start creates everything it needs by itself and says what it did in the log:

- the data directory and the SQLite files in `/data` (a data directory that cannot be written stops the start with the reason: in Docker use a named volume, or `chown 1654:1654` a bind-mounted directory);
- the Data Protection key ring and the VERP key, kept in the config database (the key ring is unprotected until you set `Secrets:KeyProtection`; the log says so);
- the **first dashboard administrator** `admin` with a **generated password**, printed once in a block delimited by `==== EGGMAIL FIRST START: DASHBOARD ADMINISTRATOR ====` and `==== END OF THE ONE-TIME PASSWORD (it is never shown again) ====`. It goes to the console only (never into the structured log that an OTLP exporter might ship), only the first time, and only if no administrator exists. It is a **temporary** password: the dashboard accepts nothing but a new password at the first sign-in (the API answers `403 password_change_required` to everything else), and the generated one stops working with that. Until someone signs in, **it is as readable as the container log**: Docker's log files and drivers, a Kubernetes log shipper or a collector all keep the console output, and the password has no expiry and stays valid until it is changed, so sign in right after the first start (or choose the password yourself, below, and nothing is printed). To choose the password yourself set `EGGMAIL_ADMIN_PASSWORD_FILE` (a mounted secret, preferred) or `EGGMAIL_ADMIN_PASSWORD` before the first start: then nothing is printed and the password you set is the one that stays. **If you lose the password** see [Lost password](#lost-password);
- a **self-signed certificate** for `Hostname`, used by STARTTLS, implicit TLS and the dashboard. Every start says so in the log (`Serving a SELF-SIGNED certificate ...`), the API reports the warning `self_signed_certificate`, and the dashboard shows a persistent banner on every page, including the sign-in page. Clients that verify certificates (browsers, most mail clients) will complain until you set up a real one (`EGGMAIL_HOSTNAME` with `EGGMAIL_ACME_EMAIL`, or upload one). Mail servers that receive your mail do not require a trusted certificate from a sender;
- a **DKIM key per sending domain**, generated when the domain is added (dashboard, API, or `EGGMAIL_DOMAINS`); the dashboard then shows the DNS records to publish.

What is left to do in the dashboard: add each **sending domain** (it shows the DNS records to publish; the domain sends once its DKIM record verifies), create an **SMTP credential** or an **API key** (Credentials), and point the application at port 587 or `POST /api/v1/messages`.

A start that cannot work is refused: the exit code is 2 and the message names the variable and says what to set (`configuration error: EGGMAIL_ACME_EMAIL needs EGGMAIL_HOSTNAME: ...`).

### The simple environment variables

A small, fixed set of variables for the common cases. They are **documented aliases** for configuration keys, not a second configuration system: the keys of [Configuration](#configuration) stay authoritative. Precedence, highest first: command line, `EGGMAIL_HOSTNAME`, long-form environment variables (`Acme__Email`, ...), the other `EGGMAIL_*` variables, the bootstrap file and `appsettings.json`, settings stored in the database, built-in defaults. `EGGMAIL_HOSTNAME` is the one alias above the long-form environment: configuration keys are not case sensitive, so the `HOSTNAME` variable that Docker and Kubernetes set in every container (the container id or pod name) is the key `Hostname` and would otherwise beat it. So a key set the long way is never changed by an alias, and the dashboard shows a key set by an alias as set by the deployment. A blank value counts as unset. A list (`Acme:Domains`) belongs to the highest layer that mentions it, as a whole: `EGGMAIL_HOSTNAME` with `EGGMAIL_ACME_EMAIL` gives exactly that one domain, whatever a mounted `appsettings.json` lists. The test `EnvironmentAliasesTests` keeps this table and the code identical; a value that is wrong is reported by the name of its variable and never repeated (a relay address or a connection string can contain a password).

| Variable | Stands for | Meaning |
|---|---|---|
| `EGGMAIL_HOSTNAME` | `Hostname`, `Acme:Domains` | The DNS name of this server, for example `mail.example.com`: the name in SMTP greetings (HELO/EHLO), `Received` headers and generated `Message-ID`s, in the first-run certificate and the name an ACME certificate is ordered for (the dashboard on 8443 serves the same certificate, so browse to this name). It must be the name in the reverse DNS (PTR) of the sending IP address. Refused when it is a URL, has a port, or is an IP address; the log warns about an underscore or a single label, which receiving servers dislike. `docker run --hostname` and the Compose `hostname:` set the container's own name, which is **not** read as a chosen name (the log still says nobody chose one): use `EGGMAIL_HOSTNAME`. When it differs from a `Hostname` in a mounted file or the long-form environment the log says that it overrides it (only `--Hostname=` on the command line is above it). Without it the machine name is used (in Docker a random container id) and the log says to set it; the self-signed certificate then keeps the first name instead of being replaced each time a container is recreated. Setting it replaces a self-signed certificate made for another name |
| `EGGMAIL_ACME_EMAIL` | `Acme:Enabled`, `Acme:Email`, `Acme:Domains` | Contact for the certificate account. **With `EGGMAIL_HOSTNAME` it turns ACME on** for that name (see [TLS certificates and ACME](#tls-certificates-and-acme)); without a host name it is refused |
| `EGGMAIL_ACME_STAGING` | `Acme:Directory` | `true`: order from the Let's Encrypt staging CA (certificates that clients do not trust; use while testing, production rate-limits failures) |
| `EGGMAIL_ACME_DIRECTORY` | `Acme:Directory` | ACME directory URL of any other CA, or a name (`LetsEncrypt`, `LetsEncryptStaging`, `ZeroSsl`). Both CA variables write `Acme:Directory`, the key that wins over `Acme:DirectoryUrl`, so a `DirectoryUrl` in a mounted file cannot override them silently (a long-form `Acme:Directory` in the environment or on the command line still wins, as always). Not together with `EGGMAIL_ACME_STAGING=true` |
| `CLOUDFLARE_API_TOKEN` | `Acme:CloudflareApiToken`, `Acme:Challenge` | Cloudflare token with DNS edit rights; **selects the DNS-01 challenge** (works without inbound port 80, allows wildcard names). Unprefixed on purpose: it is the name Cloudflare's own tooling and the common ACME clients (lego, certbot's plugin, acme.sh) read, so a token you already have works unchanged |
| `CLOUDFLARE_API_TOKEN_FILE` | `Acme:CloudflareApiTokenFile`, `Acme:Challenge` | The same, read from a file (a mounted secret) |
| `EGGMAIL_ADMIN_USER` | `Dashboard:BootstrapAdminUser` | User name of the first administrator (default `admin`). Checked when the administrator is created, so a wrong value does not stop `--healthcheck` or `mta admin create` |
| `EGGMAIL_ADMIN_PASSWORD` | `Dashboard:BootstrapAdminPassword` | Password of the first administrator, 10 to 1,024 characters, white space at both ends trimmed like the contents of the file. Visible to whoever can inspect the container: prefer the file form. Unset (and no file): a password is generated and printed once. Checked only when the administrator is created (while none exists) |
| `EGGMAIL_ADMIN_PASSWORD_FILE` | `Dashboard:BootstrapAdminPasswordFile` | The same password read from a file. A file that cannot be read, or holds a password that is too short, stops the start (while no administrator exists yet). Not together with `EGGMAIL_ADMIN_PASSWORD` |
| `EGGMAIL_DOMAINS` | `Domains:Bootstrap` | Sending domains to register at the start, separated by commas. The registration itself and the DNS records it leads to are described in [DNS records for a sending domain](#dns-records-for-a-sending-domain) |
| `EGGMAIL_DATABASE` | `Storage:Backend`, `Storage:Postgres:RuntimeConnectionString` | **One variable switches from SQLite to PostgreSQL**: a connection string (`Host=db;Database=eggmail;Username=eggmail;Password=...`) or a URL (`postgres://user:password@db:5432/eggmail?sslmode=require`; percent-encode special characters in the password; only `sslmode` is read from the URL). One role serves as schema owner and runtime role, and health warns `postgres_single_role`: for production set `Storage:Postgres:OwnerConnectionString` and `Storage:Postgres:RuntimeConnectionString` separately (the long forms win over this variable). For a database on another host use `sslmode=require` (or `verify-full`; in the Npgsql form `SSL Mode=Require`): without it the password and the data cross the network in clear text. The schema is created at the start. `/data` still holds the bootstrap file. **If `/data` already holds the SQLite files of an earlier run** (and no bootstrap file from a deliberate switch), the start logs a warning that their content is not used: move it with the Storage switch or `mta migrate-storage` first ([Backend switch](design.md#46-switching-backends-manual-and-symmetric)) |
| `EGGMAIL_RELAY` | `Delivery:Relay:Address` | Optional `host:port` of a smarthost (a name, not an IP address), for networks that block outbound port 25. Kept as the relay route `configuration-relay` for every recipient domain, tried **after** direct delivery fails ([Relay routes and per-domain TLS](#relay-routes-and-per-domain-tls)). TLS mode `implicit` on port 465, `verify` otherwise (`Delivery:Relay:TlsMode` changes it). The route follows the configuration at every start (host, port, TLS mode, login); priority, domains and the enabled flag stay as set in the dashboard; unsetting the variable removes the route |
| `EGGMAIL_RELAY_USER` | `Delivery:Relay:User` | Login on that relay; needs a password |
| `EGGMAIL_RELAY_PASSWORD` | `Delivery:Relay:Password` | Its password (stored encrypted like every relay password) |
| `EGGMAIL_RELAY_PASSWORD_FILE` | `Delivery:Relay:PasswordFile` | The same, read from a file |

Not covered by an alias, because they are rarely needed on a first start: everything else in [Configuration](#configuration) (use `Name__With__Underscores` environment variables, a mounted `appsettings.json`, or the command line).

**Minimal sets**

| Goal | Variables |
|---|---|
| Try it | none |
| A real server with a trusted certificate | `EGGMAIL_HOSTNAME`, `EGGMAIL_ACME_EMAIL` and port 80 published (HTTP-01), or add `CLOUDFLARE_API_TOKEN` instead of port 80 (DNS-01, also for wildcards) |
| ... and your domain ready at the first start | add `EGGMAIL_DOMAINS` |
| Your own administrator password | add `EGGMAIL_ADMIN_PASSWORD_FILE` |
| PostgreSQL | add `EGGMAIL_DATABASE` (one variable) |
| Behind a provider that blocks port 25 | add `EGGMAIL_RELAY` (+ `EGGMAIL_RELAY_USER` and `EGGMAIL_RELAY_PASSWORD_FILE`) |

With Compose the same variables go under `environment:` (the shipped `deploy/compose/compose.yaml` and `compose.postgres.yaml` do exactly that); PostgreSQL needs a database server, so its compose file also has one.

### Ports

| Container port | Publish as | Purpose |
|---|---|---|
| 5587 | 587 | Submission, STARTTLS, AUTH required |
| 4465 | 465 | Submission over implicit TLS |
| 2525 | 2525 | Alternate submission, STARTTLS, for networks that block 587 |
| 2526 | **25**, only if you want bounces (or inbound mail) | The **port-25 listener**: today it accepts nothing but mail addressed to the signed bounce addresses (`b+token@<Delivery:BounceDomain>`, and `postmaster`/`abuse` there), so that asynchronous bounces and complaints reach EggMail; with inbound mail on (a later change) it also accepts the recipients of the domains tenants enabled, and still nothing else. It is not a submission or open relay port. Publish it so that the **client address is kept**: plain `-p 25:2526` does not on Docker Desktop, the rootless engine or the userland proxy (see [Inbound mail](#inbound-mail)). The container runs without privileges and cannot bind port 25 itself, hence `-p 25:2526` maps the public port to it. **Outbound** mail to other servers also uses port 25, but that is a connection the container opens: nothing to publish. Without `Delivery:BounceDomain` no bounce address exists and nothing needs inbound 25 |
| 80 | 80, only for ACME HTTP-01 | The built-in challenge listener (`Acme:Http01ListenPort`, default 80). The certificate authority must reach port 80 of `EGGMAIL_HOSTNAME` when `EGGMAIL_ACME_EMAIL` is used without a Cloudflare token, so add `-p 80:80`. It answers `/.well-known/acme-challenge/<token>` and nothing else. Docker lets the non-root image bind port 80; under Kubernetes or rootless Podman set `Acme__Http01ListenPort=8081` and publish `-p 80:8081` ([TLS certificates and ACME](#tls-certificates-and-acme)) |
| 8443 | 8443 | Dashboard and API over HTTPS. Restrict who can reach it: it is an administration surface |
| 8080 | do not publish, or `127.0.0.1:8080:8080` | Plain HTTP: `/healthz`, `/readyz`, `/metrics` for probes and first set-up on the host itself |

### What only you can do outside the container

None of this can be done by the software, and mail does not reach inboxes without it:

1. **DNS for the server**: an `A` (and `AAAA`) record for `EGGMAIL_HOSTNAME` pointing at the server.
2. **Reverse DNS (PTR)** of the sending IP address pointing back at `EGGMAIL_HOSTNAME`. It is set at the provider that owns the address (a control panel setting or a support ticket), not in your zone.
3. **Outbound port 25 must be open.** Many cloud providers block it by default (and unblock it on request); EggMail delivers directly to the recipients' servers on port 25. If you cannot get it opened, set `EGGMAIL_RELAY`.
4. **DNS for every sending domain**: the DKIM `TXT` record the dashboard shows when you add the domain (required), an SPF record that authorizes the sending IP (or the relay) and a DMARC record (advice), plus the `bounce.<domain>` CNAME when `Delivery:BounceDomain` is set. See [DNS records for a sending domain](#dns-records-for-a-sending-domain).
5. **Firewall**: inbound 587/465/2525 for your senders, 8443 for administrators only, 80 for ACME HTTP-01, 25 for bounces (and an `MX` record for the bounce domain).
6. **Reputation**: a new IP address starts without one. Warm up (`Sending:WarmupEnabled`), send wanted mail, watch the complaint rate; blocklists and mailbox providers decide, not EggMail.
7. **For DNS-01 with Cloudflare**: the zone of `EGGMAIL_HOSTNAME` must be in Cloudflare and the token needs Zone:Read and the DNS edit permission for that zone (a token restricted to that one zone is enough). A line end or blanks around the token (an environment variable, a file) are ignored; a token with blanks inside or non-ASCII characters stops the start with a message that does not repeat it. Cloudflare errors are shown with their code and message in the ACME renewals of the admin view (`could not look up the zone (HTTP 403, 9109: Invalid access token)`), and rate limits and server errors are retried three times within seconds before the order counts as failed.

## Configuration

Settings come from (highest precedence first): command line, environment variables, the bootstrap file in the data directory (`bootstrap.json`, written by a backend switch; the directory is `--Sqlite:DataDirectory` on the command line, else `Sqlite__DataDirectory`, else `/data`), `appsettings.json` next to the executable (`/app/appsettings.json` in the image; mount one there), the global settings saved through the dashboard (`/admin/settings`, stored in the database), built-in defaults. Environment variables use `__` for nesting (`Delivery__RemotePort=25`). Values supplied by the deployment cannot be edited in the dashboard. A value of the wrong type (`Smtp__MaxRecipients=many`) or out of range stops the start with a message naming the key; a saved dashboard setting that does not validate is ignored with a warning.

Formats: durations are `[d.]hh:mm:ss` (`00:00:30`, `2.00:00:00`); sizes are bytes; lists are indexed (`Acme__Domains__0=a.example`) or, for the lists marked *list*, one value with entries separated by commas.

The tables below list every key; the test `ConfigurationDocumentationTests` fails when a key the code reads is missing here, or a key named here is not read.

### General, storage and retention

| Key | Default | Meaning |
|---|---|---|
| `Hostname` | machine name | Name in SMTP greetings, `Received` headers and EHLO; should match the PTR record of the sending IP |
| `Startup:RequireUnicodeSupport` | true | Refuse to run `serve`, `migrate-db`, `migrate-storage`, `admin`, `domains` and `secrets` when the Unicode self-test fails (see "Unicode support" below); `false` only logs a warning |
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
| `Inbound:RetentionDays` | 7 | Days received mail (row and body) is kept when its domain sets no value; `0` keeps forever unless `Inbound:MaxRetentionDays` is set (see [Inbound mail](#inbound-mail)) |
| `Inbound:MaxRetentionDays` | 0 | **Ceiling:** the longest retention any domain gets. A domain's own value (and the default) is cut to it and "forever" becomes it; the API refuses a longer value. `0`: no ceiling |
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
| `Delivery:MaxIdleConnectionsPerTarget` | 2 | Idle outbound connections kept per destination for the next delivery (0 to 256; 256 idle in total). More concurrent deliveries to one destination than this reconnect (and handshake TLS) again and again; raise it towards `Delivery:Throttle:MaxConnections` to reuse more, at the price of more idle sockets to the same server |
| `Delivery:RetryDelays` | built-in ladder | Delays between retries (2 m, 5 m, 15 m, 30 m, 1 h, 2 h, 4 h); the last repeats |
| `Delivery:Throttle:MaxConnections` | 20 | Ceiling of concurrent connections to one destination domain |
| `Delivery:Throttle:MaxMessagesPerMinute` | 600 | Ceiling of messages per minute to one destination domain |
| `Delivery:Throttle:MaxMessagesPerConnection` | 100 | Reserved: read and validated, but **not enforced yet** (a connection is closed when it goes idle, and a transaction carries one message group); only `MaxConnections` and `MaxMessagesPerMinute` limit a destination today |
| `Delivery:Throttle:InitialConnections` | 5 | Connections allowed at first; grows while the destination keeps accepting |
| `Delivery:Throttle:InitialMessagesPerMinute` | 120 | Messages per minute allowed at first; grows the same way |
| `Delivery:RemotePort` | 25 | Destination port for direct MX delivery; lab setups only |
| `Delivery:AllowPrivateMxAddresses` | false | Allow MX hosts that resolve to loopback or private addresses; lab setups only |
| `Delivery:Relay:Address` | none | `host:port` of a relay (smarthost) kept as the relay route `configuration-relay` for every recipient domain, tried after direct delivery (`EGGMAIL_RELAY`; see [Relay routes and per-domain TLS](#relay-routes-and-per-domain-tls)) |
| `Delivery:Relay:User` | none | Login on that relay (needs a password) |
| `Delivery:Relay:Password` | none | Its password; prefer the file |
| `Delivery:Relay:PasswordFile` | none | File holding it |
| `Delivery:Relay:TlsMode` | `implicit` on port 465, else `verify` | `verify`, `implicit`, `required`, `starttls` or `none` (refused together with a login) |
| `Delivery:PublicSendingIp` | none | The address receiving servers see for our connections; reported as `sending-mta-ip` in TLS-RPT reports. Set it when EggMail is behind NAT or a proxy. Without it only a public local address of the connection is reported; private, loopback and link-local addresses are left out |
| `Dns:Servers` | system resolvers | Resolvers (IP with optional port) |
| `Dns:RequestDnssec` | true | Ask for DNSSEC records (needed for DANE) |
| `Dns:TrustAuthenticatedData` | false | Trust the AD bit; only behind a local validating resolver. With the default DANE never applies. `deploy/compose/compose.unbound.yaml` (Compose) and `deploy/kubernetes/components/unbound` (Kubernetes) add an Unbound sidecar and set `Dns:Servers`, `Dns:RequestDnssec` and this key together |
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
| `Acme:Enabled` | false | Get and renew a certificate from an ACME CA (Let's Encrypt by default) automatically; with `Hostname` and `Acme:Email` set that is all it takes (HTTP-01 on port 80). Verified against the Pebble test CA in CI, not yet against a production CA; see [TLS certificates and ACME](#tls-certificates-and-acme) |
| `Acme:Email` | none | Contact for the ACME account (some CAs, such as ZeroSSL, require it) |
| `Acme:Domains` | the `Hostname` | *List.* Names for the certificate renewed from configuration. Wildcard names (`*.example.com`) need DNS-01. Internationalized names are sent in their ASCII (`xn--`) form. Certificates requested through the API are renewed as well |
| `Acme:Challenge` | `Auto` | `Auto`: DNS-01 when a Cloudflare token is configured, otherwise HTTP-01. `Http01`: HTTP-01 on the built-in listener (no DNS access needed). `Dns01`: DNS-01 through the DNS provider (needs the token; wildcards; no inbound port) |
| `Acme:Http01ListenPort` | 80 | HTTP-01: the port of the built-in challenge listener. The CA always connects to port 80 of the name, so leave it at 80 or map port 80 to this one (container, load balancer). It answers `GET /.well-known/acme-challenge/<token>` and nothing else |
| `Acme:Http01BindAddress` | `::` | HTTP-01: the address of that listener (`::` is every IPv4 and IPv6 address) |
| `Acme:Directory` | Let's Encrypt production | The CA by name (`LetsEncrypt`, `LetsEncryptStaging`, `ZeroSsl`) or the ACME directory URL of any CA. Wins over `Acme:DirectoryUrl` when set. Use `LetsEncryptStaging` while testing |
| `Acme:DirectoryUrl` | Let's Encrypt production | The same as a URL only (kept for compatibility; prefer `Acme:Directory`) |
| `Acme:EabKeyId` | none | External account binding (needed by ZeroSSL and some other CAs, not by Let's Encrypt): the key identifier the CA gave you. Used when the account is registered |
| `Acme:EabHmacKey` | none | The base64url HMAC key of the binding (prefer the file form) |
| `Acme:EabHmacKeyFile` | none | File holding that key |
| `Acme:CertificateName` | `default` | Name of that certificate in the database |
| `Acme:DnsProvider` | `Cloudflare` | The only provider so far (used by DNS-01) |
| `Acme:CloudflareApiToken` | none | DNS-01: API token with DNS edit rights (prefer the file form). Its presence selects DNS-01 under `Acme:Challenge=Auto` |
| `Acme:CloudflareApiTokenFile` | none | File holding that token |
| `Acme:PropagationDelay` | `00:00:30` | DNS-01: wait after publishing the challenge record (HTTP-01 has no propagation) |
| `Acme:RenewAtRemainingFraction` | 0.3333 | Renew when this fraction of the lifetime remains (between 0 and 1); used when the CA gives no renewal information |
| `Acme:UseRenewalInfo` | true | Ask the CA when to renew (ACME Renewal Information, RFC 9773) and follow its suggested window; falls back to the lifetime rule when the CA has none or fails |
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
| `Dashboard:BootstrapAdminPassword` | none | That password itself, for platforms that only pass environment variables (prefer the file: it is visible to whoever can inspect the container). With neither this nor the file the server generates a password and prints it once. Not together with the file |
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
| `Api:MaxInboundRoutesPerDomain` | 100 | Inbound routes per domain (never more than 100) |
| `Api:MaxStatsRows` | 50000 | Rows one statistics query may return |
| `Api:MetricsAllowedNetworks` | loopback and private ranges | *List.* Networks (CIDR) allowed to read `/metrics`; it carries no credentials, so keep it off the public internet |
| `Api:SpfInclude` | none | `include:` host suggested to customers in their SPF record (see [Sending domains](#sending-domains-and-their-dns-records)) |
| `Observability:MetricsEndpointEnabled` | true | Serve `/metrics`. Off also removes the Prometheus exporter itself (no meter listener of ours); OTLP is unaffected |
| `Observability:OtlpEndpoint` | none | OTLP endpoint, an `http://` or `https://` URL (for example `http://collector:4317`); `collector:4317` is refused at start. When set, metrics, traces and logs are exported there. Empty: no exporter, and no span is ever created |
| `Observability:OtlpProtocol` | `Grpc` | `Grpc` (port 4317) or `HttpProtobuf` (port 4318; EggMail appends `/v1/metrics`, `/v1/traces`, `/v1/logs`) |
| `Observability:TraceSampleRatio` | 0.1 | Share of messages whose trace is exported, 0 to 1. A message is traced completely or not at all |
| `Observability:QueueSampleSeconds` | 15 | Seconds between samples of the queue for the `mta_delivery_queue_*` gauges; `0` turns them off |
| `Webhooks:AllowHttp` | false | Allow plain `http` webhook endpoints (HTTPS only otherwise). Deliveries are made **directly**: `HTTP_PROXY`/`HTTPS_PROXY` are ignored on purpose, because the SSRF guard checks the address it connects to and through a proxy that is the proxy. The host needs outbound access to the receivers (in Kubernetes the NetworkPolicy allows TCP 443 to the public Internet) |
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

### Inbound mail

Server defaults for the domains that receive mail; a domain's own settings override them (see [Inbound mail](#inbound-mail)).

| Key | Default | Meaning |
|---|---|---|
| `Inbound:MaxMessageSize` | `Smtp:MaxMessageSize` | **Ceiling and default:** largest inbound message in bytes; a domain can lower it, never raise it |
| `Inbound:MaxMessagesPerMinute` | 600 | **Ceiling and default:** messages per minute accepted for one domain |
| `Inbound:MaxMessagesPerMinutePerRemote` | 60 | **Ceiling and default:** messages per minute accepted from one client address (an IPv6 /64) for one domain |
| `Inbound:MaxStoredBytesPerDomain` | 2147483648 | **Ceiling and default:** message bytes kept for one domain, each recipient's copy counted; at the limit new mail is refused with `452 4.2.2`; `0` is unlimited (a finite ceiling also refuses "unlimited" in a domain's settings) |
| `Inbound:MaxStoredBytesPerTenant` | 10737418240 | Message bytes kept for all domains of one tenant together (a tenant cannot multiply the per-domain limit by adding domains); `0` is unlimited |
| `Inbound:Enabled` | false | Master switch of inbound mail. Off, nothing is received and the route action runner **defers** whatever it finds (`inbound_disabled`), which counts against the retry ladder, so pending actions end `failed` after about 27 hours if it stays off. `GET /capabilities` reports it as `inbound.enabled` |
| `Inbound:ApiBaseUrl` | none | Prefix of the attachment and raw-message paths in webhook payloads (`https://mail.example.com`); without it the payload carries the bare paths (`/api/v1/inbound/messages/<id>/raw`) and the receiver knows its server. An absolute `http(s)` URL without user information, query or fragment |
| `Inbound:Action:Concurrency` | 4 | Route actions (webhook, forward) carried out at the same time on this replica |
| `Inbound:Action:MaxConcurrencyPerTenant` | 2 | Of those, how many one tenant may use at once on this replica: a claim takes at most this many rows of a tenant and nothing of a tenant that has attempts in flight, so one tenant with a slow receiver and a large backlog cannot take every worker or hold claims while it waits |
| `Inbound:Action:PollInterval` | `00:00:01` | Wait before asking for work again when nothing is due (30 seconds at least while `Inbound:Enabled` is off) |
| `Inbound:Action:Lease` | `00:02:00` | How long a claimed action belongs to the replica that claimed it before another may take it over |
| `Inbound:Action:RetrySchedule` | 5 s, 5 m, 30 m, 2 h, 5 h, 10 h, 10 h | *List* of delays before attempt 2, 3, ...; an action has one attempt more than the list has delays (eight by default, about 27 hours); an empty list is the default ladder |
| `Inbound:Webhook:MaxTextBytes` | 262144 | The text part and the HTML part of the JSON webhook payload are each cut at this many bytes (`truncated: true`) |
| `Inbound:Webhook:MaxRawMessageBytes` | 10485760 | The largest message sent in the `raw_mime` webhook format; a bigger one fails at once with `too_large_for_raw_webhook` (use the `json` format or the download endpoint) |

### Sending domains and their DNS records

| Key | Default | Meaning |
|---|---|---|
| `Domains:Bootstrap` | none | *List* of domain names to register at start for the first tenant (in an environment variable `Domains__Bootstrap`; commas, semicolons or spaces separate several). Idempotent and safe with several replicas; a new domain gets its DKIM key and the DNS records to create are written to the log ([below](#adding-a-sending-domain-and-its-dns-records)). An entry that is not a domain name stops the start |
| `Domains:DmarcPolicy` | `none` | Policy of the suggested DMARC record: `none` (monitor only), `quarantine` or `reject` |
| `Domains:DmarcReportAddress` | `dmarc@{domain}` | E-mail address in the `rua` of the suggested DMARC record; `{domain}` stands for the sending domain. The address has to receive mail, and reports for a domain whose `rua` is on another domain are only sent if that domain publishes an authorization record (below). One address; `;`, `,`, white space and control characters stop the start, because the value is written into a DNS record |
| `Domains:TlsReportAddress` | `tls-rpt@{domain}` | Destination in the `rua` of the suggested TLS-RPT record: one e-mail address or one `https://` URL (same rules as above) |
| `Domains:MtaStsMode` | `Off` | `None`, `Testing` or `Enforce`: EggMail serves the MTA-STS policy file (`mode: none`, `testing` or `enforce`) of every registered domain and suggests the MTA-STS and TLS-RPT records. Global, not per domain. Needs a fully qualified `Hostname`. Read the warning [below](#mta-sts) first |
| `Domains:MtaStsMaxAge` | `7.00:00:00` | `max_age` of the served policy (1 minute to 31557600 seconds) |
| `Domains:MtaStsMx` | `Hostname` | *List.* The `mx:` lines of the served policy: fully qualified host names in lower case with no trailing dot; `*.example.net` is allowed, `*.*.example.net` is not. Anything else stops the start |

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

When no administrator exists the server creates one at start, in this order of preference: the password in `Dashboard:BootstrapAdminPasswordFile` (a file, for example a mounted secret; `EGGMAIL_ADMIN_PASSWORD_FILE`), the password in `Dashboard:BootstrapAdminPassword` (`EGGMAIL_ADMIN_PASSWORD`; not together with the file), or, when neither is set, a **generated password printed once** ([Quick start](#quick-start-and-the-minimal-environment)). The user name is `Dashboard:BootstrapAdminUser` (`EGGMAIL_ADMIN_USER`, default `admin`). Passwords need 10 to 1,024 characters. A configured password that cannot be used (file unreadable or empty, too short, both forms set, the name already taken by a user who is not an administrator) stops the start with the reason, instead of starting a server nobody can sign in to. Several replicas on one PostgreSQL race harmlessly: exactly one creates the administrator, and only that one prints a generated password, so read the log of the replica that was started first on the empty database (or set `EGGMAIL_ADMIN_PASSWORD_FILE` on all of them).

Or, with the server stopped (SQLite allows one process per data directory), run `mta admin create --user NAME --password-file FILE` (`--role tenant --tenant SLUG` for a tenant user; the password can also come from `MTA_ADMIN_PASSWORD`, never from the command line).

A generated password is **temporary**: the first dashboard sign-in asks for a new one before anything else (`403 password_change_required` for every other call of that session). A password you set with `EGGMAIL_ADMIN_PASSWORD(_FILE)` is yours and is not marked. The mark lives in the stored hash, so no setting has to be remembered and any new password clears it.

### Lost password

Another administrator can **Reset password** in the dashboard. If there is none, create one from the command line. The image's entry point is `/app/mta`, so the arguments after the image name are the command; the name must be new (`rescue` here), and the password at least 10 characters:

```sh
# SQLite (the default): the server container must be stopped, one process owns the data directory
docker stop eggmail
docker run --rm -v eggmail-data:/data -e MTA_ADMIN_PASSWORD='a-new-password-1' ghcr.io/eggspot/eggmail:nightly admin create --user rescue
docker start eggmail

# PostgreSQL (EGGMAIL_DATABASE): the server can keep running; give the command the same database
docker run --rm -e EGGMAIL_DATABASE='Host=db;Database=eggmail;Username=eggmail;Password=...' -e MTA_ADMIN_PASSWORD='a-new-password-1' ghcr.io/eggspot/eggmail:nightly admin create --user rescue

# Docker Compose
docker compose stop eggmail && docker compose run --rm -e MTA_ADMIN_PASSWORD='a-new-password-1' eggmail admin create --user rescue && docker compose start eggmail
```

Sign in as `rescue`, then reset or delete the account whose password was lost. The first-start notice prints the SQLite form.


### Users while the server runs

Once one administrator exists, the others are made in the dashboard (**Users**, administrators only) or with the API (`POST /api/v1/admin/users`, [api.md](api.md#dashboard-users-role-admin-addition)): no restart and no stopped server are needed, on either backend. What to know:

- **Create** a user as an administrator or as a user of one active tenant. Leave the password empty and the server generates one (shown once; pass it on over a safe channel and ask the person to change it on the **Account** page). Names are not case sensitive.
- **Disable** a user (a leaver) and they are signed out at once and cannot sign in; **enable** brings the account back (the old sessions do not return). A role or tenant change also signs the user out. **Delete** removes the account.
- **Forgotten password:** an administrator resets it (**Reset password**, generated or chosen); all of that person's sessions end. If the only administrator forgot theirs, there is no one to reset it: stop the server and run `mta admin create` for a new administrator (SQLite), or use the bootstrap file when no administrator exists at all.
- **You cannot lock the installation out through the dashboard:** the last enabled administrator cannot be disabled, demoted or deleted (`409`, "only enabled administrator"). Create or enable a second administrator first. A disabled administrator does not count.
- **Own password:** the **Account** page (`POST /api/v1/me/password`) asks for the current password, signs the user's other sessions out and keeps the current one. Ten wrong attempts from one address or for one user name within 15 minutes lock that address or name out of sign-in, SMTP AUTH and this form alike (`429`, `Retry-After`).
- **Trail:** there is no audit table. Every user change writes one log line at information level, for example `Dashboard user updated: actor root, user 0192..., enabled=False role=tenant ...`, with no password or hash; keep the server log if you need to answer "who disabled this account".

## Adding a sending domain and its DNS records

A domain can send once EggMail has found its **required** records in DNS. There are three ways to add one, and each ends at the same list of exact records to create:

1. **At start**, for a new installation: `Domains__Bootstrap=example.com` (or `--Domains:Bootstrap=example.com`; several names separated by commas). EggMail creates a tenant named `Default` when there is none, registers each domain that is missing in the oldest tenant, generates its DKIM key and **writes the DNS records to the log, once, when the domain is registered** (one log line per line of the zone file). Starting again changes nothing and prints nothing new; several replicas starting together register each domain once (a lease in the database, `domains-bootstrap`). A name another tenant has registered is left alone with a warning.
2. **In the dashboard**: Domains, enter the name, Add domain. The page of the domain shows everything below.
3. **With the API**: `POST /api/v1/domains` `{ "name": "example.com" }`; `GET /api/v1/domains/{id}/records` returns the records and the same text as a zone file ([api.md](api.md#domains-domains-scope)).

**Printing the records again:** `mta domains records example.com` writes the zone-file text to the standard output, and `mta domains check example.com` looks every record up in DNS and prints its status with what was found next to what is expected (it saves nothing). Both read the database, so with SQLite the server must be stopped (one process owns the data directory); while it runs, use the dashboard or `GET /api/v1/domains/{id}/records?format=zone`, which returns plain text, for example `curl -H "Authorization: Bearer $KEY" "$URL/api/v1/domains/$ID/records?format=zone"`.

### The records

For `example.com`, with `Hostname=mta.example.net`, `Delivery:BounceDomain=bounces.example.net`, `Delivery:PublicSendingIp=203.0.113.25` and `Domains:MtaStsMode=Testing`, the page, the API, the log and `mta domains records` give this (the DKIM key is shortened here; the real value is a 392 character key, written as two quoted strings because one string holds at most 255 characters):

```
; DNS records for example.com
; Required records decide whether the domain can send; recommended ones improve delivery and give you reports.
; SPF and DMARC are shown as comments: add them only if the domain has none, otherwise merge them into the record that exists (two SPF records break SPF).

; DKIM (required): Lets receivers verify that mail from this domain is signed by EggMail.
egg202610._domainkey.example.com. 3600 IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..." "...IDAQAB"

; Return-path (required): Makes bounce messages for this domain reach EggMail.
bounce.example.com. 3600 IN CNAME bounces.example.net.

; SPF (recommended): Authorizes this server to send for the domain. Keep a single SPF record per domain: merge this into an existing one.
; example.com. 3600 IN TXT "v=spf1 ip4:203.0.113.25 ~all"

; DMARC (recommended): Tells receivers what to do with mail that fails authentication and where to send reports. The default only monitors (p=none).
; _dmarc.example.com. 3600 IN TXT "v=DMARC1; p=none; rua=mailto:dmarc@example.com"

; TLS-RPT (recommended): Asks receivers to send daily TLS reports (RFC 8460) to the address in rua. Publish it only if this server receives the domain's mail.
_smtp._tls.example.com. 3600 IN TXT "v=TLSRPTv1; rua=mailto:tls-rpt@example.com"

; MTA-STS (recommended): Announces the MTA-STS policy that EggMail serves at https://mta-sts.example.com/.well-known/mta-sts.txt. The id changes when the policy changes. Publish it only if this server receives the domain's mail.
_mta-sts.example.com. 3600 IN TXT "v=STSv1; id=3f6c1d0a9b2e4f57"

; MTA-STS host (recommended): Must lead to this server (mta.example.net) so it can serve the policy over HTTPS; its certificate has to cover mta-sts.example.com.
mta-sts.example.com. 3600 IN CNAME mta.example.net.

; Bounce MX (recommended): Published once by the operator for all domains: delivers bounces for the bounce domain to this server (port 25 reaches the bounce listener).
; MX bounces.example.net -> 10 mta.example.net (published once by whoever runs EggMail, not in this zone)

; Reverse DNS (recommended): Advice: the reverse DNS of the sending IP should be this server's host name. It is set at whoever owns the IP address (your hosting provider), not in your zone.
; PTR 25.113.0.203.in-addr.arpa -> mta.example.net
```

| Record | What it does | Where it comes from |
|---|---|---|
| **DKIM** TXT `<selector>._domainkey.<domain>` (required) | receivers verify the signature EggMail adds | the domain's RSA-2048 key, generated when the domain is added; the selector is `egg<YYYYMM>` |
| **Return-path** CNAME `bounce.<domain>` (required when `Delivery:BounceDomain` is set) | bounces for the domain reach EggMail | `Delivery:BounceDomain` |
| **SPF** TXT on the domain | authorizes this server | `include:` of `Api:SpfInclude`, `ip4:`/`ip6:` of `Delivery:PublicSendingIp`, or else `a:` of `Hostname`; then `~all`. Nothing of these configured: no SPF record |
| **DMARC** TXT `_dmarc.<domain>` | policy and report address | `Domains:DmarcPolicy` (default `p=none`, monitoring only), `Domains:DmarcReportAddress` |
| **TLS-RPT** TXT `_smtp._tls.<domain>` | where receivers send TLS reports about mail to this domain (only with `Domains:MtaStsMode`) | `Domains:TlsReportAddress` |
| **MTA-STS** TXT `_mta-sts.<domain>` and CNAME `mta-sts.<domain>` | announce and locate the policy file (only with `Domains:MtaStsMode`) | the id is a hash of the policy file, so it changes exactly when the policy does; the CNAME points at `Hostname` |
| **Bounce MX** MX on the bounce domain | the receiving side of the return-path CNAME: bounces are delivered to this server | `Hostname`; one record for all domains, published once by whoever runs EggMail, not by each customer |
| **Reverse DNS** PTR | receivers compare the sending IP's reverse name with the EHLO name | advice only: it is set at whoever owns the IP address, so it is a comment in the zone file, not a line |

A record that cannot be created in the customer's zone is a comment in the zone file instead of a line: the reverse DNS, and the bounce MX when the bounce domain is not inside the domain (with `Delivery:BounceDomain=bounces.example.com` the MX for `example.com` is a real line). **SPF and DMARC are comments in the zone file.** Most domains have both already, and a second record of either kind breaks it (two SPF records are a permanent error, two DMARC records are ignored), so importing the file must never add one: copy the value into the record that exists, or uncomment the line when the domain has none. When there is nothing to authorize (no `Api:SpfInclude`, no `Delivery:PublicSendingIp`, no fully qualified `Hostname`) no SPF record is suggested at all, because `v=spf1 ~all` authorizes nothing, and the file says so. **TLS-RPT and the two MTA-STS records appear only with `Domains:MtaStsMode`** (they concern mail the domain *receives*); their notes and the zone-file comments repeat that they are to be published only if this server receives the domain's mail.

Only the two required records decide whether the domain can send; everything else is recommended and never blocks sending. When `Hostname` is not a fully qualified name (the machine-name default), the bounce MX, the MTA-STS records and the reverse-DNS advice are left out because they would name a host nobody can reach.

**The bounce path.** Port 25 of the host (`Hostname`) has to reach the bounce listener (the listener named `bounce`, container port 2526 by default, `Smtp:Listeners:<name>:Port`), and the bounce domain's MX record has to name that host. Without the MX record no bounce, complaint report or delayed-delivery notice ever arrives. Which of the two names carries the envelope sender of outgoing mail (the shared bounce domain, or the verified `bounce.<domain>` of the sending domain) is a delivery matter, described in [components/delivery.md](components/delivery.md); the MX of the bounce domain is needed either way, because the per-domain CNAME leads to it.

**Reverse DNS.** Your sending IP needs a PTR record that matches `Hostname`, and outbound port 25 must not be blocked by your provider. `Delivery:PublicSendingIp` makes the check look at exactly that IP; without it EggMail looks up the addresses of `Hostname` and reverses each one. Deliverability work (IP reputation, warm-up, abuse handling) is operational and not done by the software.

### Check DNS and what the statuses mean

The **Check DNS** button of the domain page (`POST /api/v1/domains/{id}/verify`) looks every record up at once, stores the result, and shows for each record its status and, when it is not OK, what was found next to what is expected. At most one check per 30 seconds per domain; EggMail also re-checks on its own (every 90 seconds at first, then less often, daily once verified). The top of the page says **Ready to send** or **Not ready to send** and counts the published records ("Required records: 2 of 2 published. Recommended records: 3 of 4 published."). The count leaves out what the customer cannot publish in the domain's zone: the reverse DNS, and the operator's bounce MX when the bounce domain is outside the domain; those rows are still checked and shown.

| Status | Meaning |
|---|---|
| OK | found as expected. SPF is judged by what the record authorizes (RFC 7208 evaluation of the sending address: CIDR ranges, `include:`, `a:` and `mx` count), DMARC also by the record of the organizational domain for a subdomain, and a CNAME may lead through other names |
| Missing | nothing of that kind at the name |
| Invalid | a record exists but is malformed, or there are several where one is allowed (two SPF records make SPF fail; two DMARC records are ignored) |
| Mismatch | a well-formed record with another value: another DKIM key, another CNAME target, an SPF record without our mechanism, an older MTA-STS id, an MX or PTR naming another host |
| Pending | not looked up yet, or the DNS server did not answer (a DNS outage never changes a domain's state) |

DMARC and TLS-RPT accept any valid record: the policy and report address are the customer's to choose, so a stricter DMARC policy is OK. An SPF record that holds other senders is OK as long as it contains the mechanism EggMail asked for. DNS changes can take a while to spread; a record that was just published may show as missing for the length of its previous TTL. A check looks records up four at a time and gives each record 20 seconds; a record that does not answer in time is Pending. What DNS returned is kept per record up to 2,048 characters.

**Reports sent to another domain (RFC 7489 section 7.1).** If the `rua` address of the DMARC record is on a different domain than the sending domain (for example `Domains:DmarcReportAddress=reports@ops.example.net` for `example.com`), receivers send the reports only if `ops.example.net` publishes an authorization record: a TXT record `example.com._report._dmarc.ops.example.net` with the value `v=DMARC1`. EggMail does not create or check that record, because it belongs to the zone of the report address; without it the reports are silently dropped. TLS-RPT has no such rule.

### MTA-STS

MTA-STS (RFC 8461) protects mail **sent to** a domain: it tells other servers to deliver to your MX hosts only over verified TLS. EggMail is an outbound server, so this only makes sense for a domain whose MX records point at this server (for example a domain used only for sending and bounces). **Do not turn it on for a domain whose mail is received somewhere else** (Google Workspace, Microsoft 365, another MTA): in `Enforce` mode senders would refuse to deliver to your real MX hosts, and even in `Testing` the policy is wrong for that domain. Use `Domains:MtaStsMx` for the hosts that do receive the domain's mail, and `Testing` first. The switch is global: all registered domains get the policy.

With `Domains:MtaStsMode=Testing` or `Enforce`:

- EggMail answers `GET https://mta-sts.<domain>/.well-known/mta-sts.txt` itself, on the dashboard listeners, for every registered domain, with `version: STSv1`, the mode, one `mx:` line per `Domains:MtaStsMx` entry (default: `Hostname`) and `max_age:`. Any other path on a `mta-sts.<domain>` host, and the policy path of a domain that is not registered, is 404; the dashboard is not offered under that name.
- **`mta-sts.<domain>` must point at this server** (the CNAME shown on the domain page, to `Hostname`), and the HTTPS port 443 of that name must reach the HTTPS listener (container port 8443, `Dashboard:HttpsPort`).
- **The certificate must cover `mta-sts.<domain>`**: senders refuse a policy served with a certificate for another name. The listener presents the stored certificate that matches the requested name (or the default one); list `mta-sts.<domain>` in `Acme:Domains` (HTTP-01 proves it on port 80 like any other name, once the name points at this server; a `*.<domain>` wildcard needs DNS-01), or upload a certificate that has it ([TLS certificates and ACME](#tls-certificates-and-acme)). Until it does, the page shows the records as OK and senders still ignore the policy.
- **Turning it off properly.** Senders keep a policy until its `max_age` runs out (7 days by default; it can be up to a year), and an `enforce` policy keeps blocking delivery for that long if the file simply disappears. To retire MTA-STS, first set `Domains:MtaStsMode=None`: the served file says `mode: none`, the `_mta-sts` id changes (update the TXT record), senders fetch it and forget the old policy; keep it for at least the old `max_age`, and only then set `Off` and remove the records.
- Probes and the CA's HTTP-01 challenge (`/healthz`, `/readyz`, `/.well-known/acme-challenge/`) are answered on every host name, also on `mta-sts.<domain>`; nothing else of the dashboard is.
- The `id` in the `_mta-sts` TXT record is a hash of the policy file. When you change the mode, the max age or the `mx:` lines the id changes, and the domain page shows the record as **Mismatch** until the TXT record is updated to the new value.

### Bounce addresses and the return path

Once the return-path CNAME is verified, the envelope sender of the mail of that domain is `b+<token>@bounce.<domain>` instead of `b+<token>@<Delivery:BounceDomain>` (a domain whose CNAME is missing keeps using the shared bounce domain). Receivers check SPF against that name: the CNAME makes `bounce.<domain>` resolve the TXT record of your bounce domain, so publish **one SPF record at the bounce domain** that names your sending IP (`v=spf1 ip4:203.0.113.10 ~all`), and the check passes and aligns (relaxed) with the `From` domain, which is what makes DMARC pass through SPF as well as through DKIM. The MX of the bounce domain (`Delivery:BounceDomain` → `Hostname`) receives the bounces for both forms of address: a mail server resolving the MX of `bounce.<domain>` follows the CNAME. The bounce listener (port 25) accepts a valid token at the shared bounce domain, or at a registered domain's `bounce.<domain>` once that domain's CNAME is verified, and refuses everything else. Bounce addresses are bound to the destination domain of the message: a report (bounce or complaint) is acted on only for addresses in that domain (or the `Original-Recipient` it names), so someone who received one message cannot get another address suppressed by sending a forged report to the address in the `Return-Path`. Tokens issued before this binding existed keep working until they expire (14 days). **Rolling upgrade:** a replica of an older build cannot read the new bounce addresses and answers `550` for them, so run mixed versions only for the length of a rollout. When the receiving server offers DSN, EggMail sends the address it used as `ORCPT`, so a bounce for a forwarded address still names it (`Original-Recipient`); a report that names only a forwarding target is ignored and counted in `mta_bounce_reports_ignored_total`. A sending domain so long that `b+<token>@bounce.<domain>` would exceed 254 characters uses the shared bounce domain (a warning in the log).

## TLS certificates and ACME

Certificates live in the database and are served by SMTP (STARTTLS and implicit TLS) and by the dashboard/API HTTPS listener. A new instance starts with a self-signed certificate for `Hostname` (every start says so in the log and the dashboard flags it with a persistent banner; a certificate made for another host name, before `EGGMAIL_HOSTNAME` was set, is replaced by one for the new name, and one that expires within 30 days is replaced at the next start; any other certificate wins over it); import a certificate in the dashboard, mount one with `Tls:CertificatePath`/`KeyPath` (it takes precedence), or let EggMail order one.

**Built-in ACME** (`Acme:Enabled=true`) orders one certificate for `Acme:Domains` (the SMTP and dashboard host names; by default the `Hostname`) from the CA of `Acme:Directory`, Let's Encrypt production unless you say otherwise. The ACME account is created on the first order and kept (encrypted) in the database for that directory; it is part of a backend switch bundle. Email addresses given to the CA (`Acme:Email`) get no expiry notices from Let's Encrypt any more, so monitor expiry yourself.

**The two-setting start.** Set `Hostname=mail.example.com` and `Acme:Enabled=true` and `Acme:Email=you@example.com` (in a container: `Hostname`, `Acme__Enabled`, `Acme__Email`, or the short environment names of the deployment files) and publish port 80. The server starts with its self-signed certificate, asks Let's Encrypt for a real one over HTTP-01 within a minute, and renews it by itself. No DNS access is needed; the name only has to resolve to this server and the CA must be able to reach its port 80 from the internet.

* **HTTP-01** (the default without a DNS token). The CA fetches `http://<name>/.well-known/acme-challenge/<token>` and EggMail's **own tiny listener** answers it: it is a separate socket server (not the dashboard, not Kestrel) that serves exactly that path for a token an order is waiting for and refuses everything else (404, 405 or 400, no body, connection closed; at most 8 KiB of request head within 2 seconds, 5 seconds in all, 128 connections and 8 per client address), so port 80 never exposes the dashboard or API. It is bound only while ACME with HTTP-01 is enabled, on **every** replica (see below). `Acme:Http01ListenPort` is 80; the image runs as a non-root user, which Docker allows to bind port 80 (its default `net.ipv4.ip_unprivileged_port_start=0`); under Kubernetes or rootless Podman set `Acme__Http01ListenPort=8081` and publish or route port 80 to 8081 (`docker run -p 80:8081`, a Service with `targetPort: 8081`). Allow the CA's inbound connections to that port in your firewall and in the network policy.
* **DNS-01** (with `Acme:CloudflareApiToken` or `Acme:CloudflareApiTokenFile`, or `Acme:Challenge=Dns01`). Needs no inbound port; the only supported DNS provider is Cloudflare, with a token that has Zone:Read and DNS:Edit for the zone. Wildcard names work only with DNS-01 (RFC 8555): a wildcard in `Acme:Domains` without a DNS token is a configuration error at start, and a wildcard requested later through the API is a recorded failure that says so.
* **No port 80?** If the listener cannot bind its port (in use by another web server, not allowed), the server says so in the log (`ACME HTTP-01: ... already in use ...`, once, and again when the problem changes), no order is started (the CA is not asked, so no failed validation counts against the name), the failure is recorded, the listener tries again every minute and the order follows within five minutes of the port becoming free. Free the port, change `Acme:Http01ListenPort` and forward port 80 to it, or switch to DNS-01.
* **While there is no certificate** the self-signed certificate keeps serving SMTP and the dashboard, and the dashboard shows a banner: `acme_pending` while the first order is awaited, `acme_failing` (with the failure count, a category such as "the port for the HTTP-01 challenge could not be bound", "the CA could not validate the challenge" or "the CA could not be reached", and the time of the next attempt) while orders fail, in the capabilities warnings and `/readyz` like the other warnings. A failing **renewal** raises the same warning and says until when the current certificate is still good. Both clear as soon as a certificate is issued. Anybody who can read `/api/v1/capabilities` sees that text, so it holds a category and never the error: the full last error, with what the CA said, is in the server log and in the admin view (`GET /api/v1/admin/certificates/acme`, the dashboard's Certificates page, ACME renewals). `Acme:Directory` and `Acme:DirectoryUrl` are the same setting in two spellings (the name or URL form and the URL-only form; `Acme:Directory` wins when both are set); neither may contain credentials, a query string or a fragment.
* **Several replicas** share one certificate: only the replica holding the lease orders, but the CA connects to whichever replica the load balancer picks. Every replica therefore runs the listener, and the ordering replica publishes each token in the config store (`challenge_state_json` of the certificate's renewal row; removed when the order ends, ignored after two hours); a replica that did not order reads it from there (one read at most every 50 ms, whatever arrives on port 80). Route port 80 of the host name to all replicas (or any of them). A load balancer that terminates port 80 itself must forward `/.well-known/acme-challenge/` to them unchanged.
* **Other CAs and external account binding.** `Acme:Directory=ZeroSsl` (or any ACME directory URL) selects another CA. CAs that require external account binding refuse the registration without it: set `Acme:EabKeyId` and `Acme:EabHmacKey` or `Acme:EabHmacKeyFile` to what the CA's account page gives you (ZeroSSL: a key id and a base64url HMAC key); without them the failure says so. The binding is only used to register the account; it is stored once per directory like any account.

Renewal is checked hourly (`Acme:CheckInterval`). When the CA supports ACME Renewal Information (ARI; Let's Encrypt does) EggMail asks it when to renew and renews at a random time inside the window it suggests (when that time falls before the next hourly check), and never later than when a sixth of the lifetime is left. A window that has passed, for example after a revocation or an incident, means renew at the next check, but a certificate younger than a day (or a twentieth of its lifetime if longer; 4.5 days for 90 days) is never renewed on advice alone, so a CA that keeps saying "now" cannot make EggMail order at every check. The CA is asked about once per its `Retry-After` (between a minute and a day, 6 hours without one). After a server error or a network failure it is asked again after 5 minutes, doubling up to 6 hours; after any other error after 6 hours. A CA without ARI (asked again daily), an ARI request that fails, or `Acme:UseRenewalInfo=false` falls back to renewing when a third of the lifetime is left. The renewal order names the certificate it replaces. The last advice (window, chosen time, errors, failure count) is stored in the certificate's renewal row (`ari_json`) and logged; it is not shown in the API yet. A failed order, a DNS provider error, validation failure or an unreachable CA is recorded and retried after 10 minutes, then 20, 40, … up to 6 hours, or when the CA's refusal carried a longer `Retry-After` (a rate limit) after that, at most a day; the certificate in use keeps being served. What the CA sends is checked before it is stored: a certificate that is empty, cut off, for other names, for another key or already expired is a recorded failure like any other, with the old certificate still served. Status, failure count, last error and next attempt are in the admin API (`GET /api/v1/admin/certificates/acme`). With several replicas only one orders at a time (a lease row); the others pick the new certificate up from the database within `Tls:PollInterval` without a restart.

**Use the staging CA first.** Production Let's Encrypt rate-limits failed validations and new accounts. Set `Acme:Directory=LetsEncryptStaging`, check that a certificate is issued (it is not trusted by clients), then remove the setting (production is the default). Accounts are per directory, so switching the directory registers a second account; the existing certificate is not re-ordered until it is due or you request one (`POST /api/v1/admin/certificates/acme`).

What has been verified: the whole flow (order, HTTP-01 and DNS-01 validation, external account binding, finalize, encrypted storage, renewal, back-off, hot swap into SMTP and HTTPS) runs in CI against the Pebble test CA, which really connects to the built-in listener ([components/acme.md](components/acme.md)); the failures a CA or Cloudflare can cause (rate limits, bad nonces, damaged or wrong certificate chains, expired orders, validation that fails or never ends, accounts that went away, replicas racing for the lease) run in every build against a scriptable mock CA and a fake Cloudflare ([testing-offline-coverage.md](testing-offline-coverage.md) lists what that does and does not prove). What has not: a real CA (rate limits, CAA, the real validation from several vantage points), ZeroSSL's EAB, the real Cloudflare API (the provider is tested against a fake written from its documentation), real DNS propagation (`Acme:PropagationDelay` of 30 s is a guess; Let's Encrypt validates from several vantage points, so raise it if validation fails right after the records were created), and binding port 80 inside a real container as the non-root user.

Checklist for the first real-CA run, HTTP-01: a public host name whose A/AAAA record points to this server (the CA tries IPv6 first when there is an AAAA record, so make sure it works over both or has none), port 80 reachable from the internet and published to the container, outbound HTTPS to the CA, the staging run above. For DNS-01 instead: a domain whose zone is in Cloudflare and a host name inside it; the API token; outbound HTTPS to `api.cloudflare.com`. Afterwards verify from outside that the certificate is served on port 587/465 (`openssl s_client -starttls smtp -connect <host>:587 -servername <host>`) and on the dashboard port, with the intermediate certificate included.

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
| `mta_inbound_actions_total` | counter | `kind` (`webhook`, `forward`, `store`, `discard`: the kind of the route when the attempt ran), `outcome` (`done`, `retry`, `failed`) | Attempts at inbound route actions: `retry` goes to the next rung of the ladder (a deferral counts), `failed` is final |
| `mta_inbound_forward_loops_total` | counter | none | Forwards refused because the message had been forwarded by this server three times already (`loop_detected`) |
| `mta_inbound_srs_bounces_dropped_total` | counter | none | Bounces to the SRS address of a forwarded message that were accepted and dropped (never relayed to the original sender) |
| `mta_inbound_action_duration_seconds` | histogram | `kind` | Claim to recorded result of one attempt |
| `mta_inbound_actions` | gauge | `state` (`pending`, `failed`) | Inbound route actions waiting and given up, sampled while `Inbound:Enabled` is on: `pending` every 15 seconds from an indexed count, `failed` every 5 minutes (it has no index of its own). A growing `pending` is a receiver that does not answer, or `Inbound:Enabled` off; `failed` is what the tenants should retry |
| `mta_storage_sqlite_commit_duration_seconds` | histogram | `file` (`queue.db`, `stats.db`, `config.db`, `history.db`) | COMMIT of one writer transaction (`sqlite_commit_latency` in [benchmarks.md](benchmarks.md)); with `Sqlite:SyncMode=Full` this is the fsync |
| `mta_storage_sqlite_writer_batch_size` | histogram | `file` | Commands per committed transaction: how well the group commit batches (`sqlite_writer_batch_size`) |
| `mta_storage_sqlite_writer_batch_failures_total` | counter | `file` | Transactions that failed as a whole and were replayed command by command |
| `mta_storage_sqlite_writer_queue_depth` | gauge | `file` | Commands waiting for the writer right now (`sqlite_writer_queue_depth`) |
| `mta_storage_sqlite_wal_size_bytes` | gauge | `file` | Size of the write-ahead log |
| `mta_storage_sqlite_sync_off` | gauge | `file` | 1 for a file running with `synchronous=OFF`, else 0 (`sqlite_sync_off`) |
| `mta_storage_sqlite_quarantined` | gauge | `file` | 1 for a file that failed its start-up integrity check and was moved aside when this process started, else 0 |
| `mta_process_open_fds` | gauge | none | Open file descriptors (sockets and files), Linux only (no series elsewhere). Returns to its idle value when load stops; a climb is a leak |
| `mta_process_threads` | gauge | none | Operating-system threads of the process (not only the thread pool's) |
| `mta_bounce_reports_ignored_total` | counter | `kind` (`bounce`, `complaint`) | Reports that arrived under a valid bounce address and were not acted on because they name an address outside the domain the bounce address was issued for (no suppression, no webhook). A trickle is forwarded mail whose server does not return the Original-Recipient; a burst is somebody trying to get addresses suppressed |
| `mta_tls_certificate_expiry_seconds` | gauge | `name`, `source` | Seconds until each served certificate expires |
| `mta_tls_certificates` | gauge | none | Certificates served; an expired one is no longer served, so alert on 0 as well |
| `mta_backup_runs_total` | counter | `outcome` (`success`, `failed`) | Scheduled backup runs |
| `mta_backup_last_success_timestamp_seconds` | gauge | none | Unix time of the newest good backup (also after a restart, from the backups on disk); absent until there is one |

PostgreSQL command latency and pool state come from the Npgsql driver's own meter, exported unchanged next to the `mta_` metrics. The pool label (`db_client_connection_pool_name`) is `eggmail-runtime`, `eggmail-owner` or, with several replicas, `eggmail-coordination` (two connections); saturation is `used / max` of `db_client_connection_count` and `db_client_connection_max`.

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

The .NET runtime's own meter (`System.Runtime`) is exported unchanged too, so memory growth, garbage collections and thread-pool pressure can be watched without a profiler (the soak test of [soak.md](soak.md) reads them). Only the ones below are documented and pinned by a test; the runtime publishes a few more (`dotnet_jit_*`, `dotnet_assembly_count`, `dotnet_timer_count`, `dotnet_process_cpu_count`). The names and types are exactly what the runtime declares: `dotnet_thread_pool_thread_count_total` and `dotnet_thread_pool_queue_length_total` carry the **current** number although the runtime declares them as counters, so read them as gauges.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `dotnet_gc_collections_total` | counter | `gc_heap_generation` (`gen0`, `gen1`, `gen2`) | Garbage collections since the process started. A steadily rising `gen2` rate under constant load is a sign of heap growth |
| `dotnet_gc_heap_total_allocated_bytes_total` | counter | none | Managed bytes allocated since the process started (the allocation rate is its derivative) |
| `dotnet_gc_pause_time_seconds_total` | counter | none | Time the process was paused by garbage collections |
| `dotnet_gc_last_collection_heap_size_bytes` | gauge | `gc_heap_generation` (`gen0`, `gen1`, `gen2`, `loh`, `poh`) | Managed heap size by generation as of the latest collection (`loh` is the large object heap: where message bodies of 85 KB and more live) |
| `dotnet_process_memory_working_set_bytes` | gauge | none | Physical memory mapped to the process (close to the resident set size) |
| `dotnet_process_cpu_time_seconds_total` | counter | `cpu_mode` (`user`, `system`) | CPU time used by the process |
| `dotnet_thread_pool_thread_count_total` | counter | none | Thread-pool threads that exist now (see the note above) |
| `dotnet_thread_pool_queue_length_total` | counter | none | Work items waiting for a thread-pool thread now (see the note above); above zero for long means the pool is starved |
| `dotnet_thread_pool_work_item_count_total` | counter | none | Work items the thread pool has completed |
| `dotnet_monitor_lock_contentions_total` | counter | none | Contended monitor lock acquisitions |
| `dotnet_exceptions_total` | counter | `error_type` | Exceptions thrown in managed code |

**What to alert on.**

- Queue backlog: `mta_delivery_queue_oldest_due_age_seconds` above a few minutes for more than a few scrapes, or `mta_delivery_queue_depth{state="queued"}` growing steadily. `mta_delivery_queue_sample_age_seconds` above a minute means both are stale.
- Repeated deferrals to one domain: the metrics carry no domain label (it is unbounded); the dashboard's per-domain statistics and the message events show which one. Alert on the `deferred` share of `mta_delivery_attempts_total`.
- Certificates: `mta_tls_certificate_expiry_seconds` below 14 days (ACME renews with a third of the lifetime left) or `mta_tls_certificates == 0`.
- Leaks over days: `mta_process_open_fds` and `mta_process_threads` should settle under constant load and return to their idle values when it stops; alert on a slope (for example `deriv(mta_process_open_fds[6h]) > 0` for a day). Memory comes from the platform (`docker stats`, the cgroup) or from the .NET runtime meter where the host exports it.
- Disk full on the SQLite backend: submissions are answered `452 4.3.1 Insufficient system storage` (clients retry; other storage failures are `451 4.3.0`) and the log has "the disk is full" at error level. Free space (or move `Sqlite:DataDirectory`) and intake resumes by itself; nothing needs a restart. Watch the free space of the volume yourself: the process does not export it.
- Durability warnings: `mta_storage_sqlite_sync_off == 1` when you did not choose `Sqlite:SyncMode=Off`, and `mta_storage_sqlite_quarantined == 1` (a file was found corrupt and replaced by an empty one; the evidence is in `<data>/quarantine/`).
- Backups: `mta_backup_runs_total{outcome="failed"}` increasing, or `time() - mta_backup_last_success_timestamp_seconds` above two backup intervals. The gauge exists from start when a backup is already on disk, and is absent on a fresh install until the first one: with backups enabled on SQLite also alert on `absent(mta_backup_last_success_timestamp_seconds)` for longer than the interval (a PostgreSQL deployment has no such series, since backups are the database's own).
- SQLite write pressure (advisory; switching backends is manual): `mta_storage_sqlite_writer_queue_depth{file="queue.db"}` high for minutes, or the p99 of `mta_storage_sqlite_commit_duration_seconds` above about 100 ms.
- PostgreSQL: `db_client_connection_npgsql_pending_requests > 0`, `db_client_connection_npgsql_timeouts_total` or `db_client_operation_failed_total` increasing.

**Traces.** With `Observability:OtlpEndpoint` set, there is one trace per message and its trace id is the message id (the id in the `250 Queued as` reply and in the API): search your tracing backend for it. The spans are `mta.submit` (accepting the message into the queue), `mta.queue.wait` (acceptance to the first claim), `mta.delivery.attempt` (one per attempt and destination domain, with one event per recipient holding the outcome, SMTP code, enhanced code, MX host and whether TLS was used) and `mta.webhook.deliver` (one per webhook call; the message is found from the event's `message_id`). Nothing is stored for this: every span derives its trace from the message id, so a retry days later, or on another replica, joins the same trace. The spans hang under one shared parent id that is not itself exported, which tracing UIs show as a missing root. Only `Observability:TraceSampleRatio` of the messages are exported, chosen by message id, so a message is traced completely or not at all (a webhook span that is not about a message follows the ratio per span). Without an endpoint no span is created and nothing is allocated for tracing. A failed attempt's span status carries the enhanced status code (`5.1.1`) or `smtp <code>`, never the remote server's reply text, because that text echoes recipient addresses.

**What leaves the box over OTLP.** Treat the collector as part of your trust boundary.

- Span attributes: the message id, the tenant id (an opaque id, kept so a tenant's traces can be found when supporting them), the recipient count, message size, source (`Smtp`/`Api`), the attempt number, the **recipient domain** of each delivery attempt, the MX host name, SMTP and enhanced codes, the webhook event type and the HTTP status code. No recipient or sender address, subject, body, webhook URL or endpoint id is exported in spans. Webhook calls to your customers carry no `traceparent` or other trace header either.
- Metrics: labels are the small fixed sets in the tables. The one label that can contain a customer's name is the certificate `name` of `mta_tls_certificate_expiry_seconds` (`selfsigned:<hostname>:<thumbprint prefix>`, `default`, or the name given to an ACME or uploaded certificate, which may be a domain). The Prometheus exporter keeps at most 1000 label combinations per metric and counts what it refuses in `eggmail_exporter_dropped_series_total` (only rendered once above 0: it means some label is unbounded); the OpenTelemetry SDK's own per-metric limit (2000 by default) applies to the OTLP export.
- Logs: the same records as the JSON console log, with their formatted message text (deliberately: raw templates are hard to read in a log backend). Log messages can contain recipient addresses and remote server error text, for example in delivery failures. If that must not leave the host, leave `Observability:OtlpEndpoint` empty and ship the JSON console log through your own pipeline, where you can filter it.

**Logs.** With an endpoint set, the structured log (the same records as the JSON console log) is exported over OTLP as well. Records written before the logging pipeline exists (configuration errors) are console only.

Alert also on the readiness warnings of `/readyz` (`sqlite_sync_off`, `sqlite_quarantined:<file>`, `queue_persistence_memory`), which carry the same facts as the gauges.

## Relay routes and per-domain TLS

**Direct delivery is the default.** Every message goes straight to the recipient's mail server on port 25. A relay (a smarthost or provider on 587, 465 or 2525) is an **opt-in fallback for the recipient domains you list**, for a network that blocks outbound port 25 or for a destination that only accepts mail from a known relay. It changes what the destination sees (the relay's IP, so SPF and the bounce path are the relay's business), which is why nothing is rerouted by default and the delivery history records the route of each delivery.

Manage both in the dashboard (administrators: **Relay routes**, **TLS policies**) or through the admin API ([api.md](api.md#relay-routes-and-tls-policies-role-admin-addition)). The one exception is a single relay from the deployment configuration (`EGGMAIL_RELAY` and the keys of the `Delivery:Relay:Address` family): the server keeps it as the route `configuration-relay`, updates its host, port, TLS mode and login from the configuration at every start and removes it when the configuration is gone; do not use that name for a route of your own. Both are server-wide, stored in the config part of the database (so they move with a backend switch) and reloaded by the delivery engine within 30 seconds on every replica, and at once on the replica that took the change.

* **A relay route** names the host, port, TLS mode, optional login, a priority and the recipient domains it carries (`example.com`; `*.example.com` for every subdomain at any depth, which does **not** include `example.com` itself, so list both to cover both; or `*`). Order of attempts: direct delivery, then the matching relays by priority. A connect timeout or refusal moves on to the next route; a 4xx, a TLS failure or a dropped connection is retried on the same route; a 5xx rejection is final and never sent through another route; a route that keeps failing to connect is skipped for a cooldown (circuit breaker) and tried again afterwards. To make a relay the only way out, list `*` and keep in mind that direct delivery is still tried first; there is no switch that disables direct delivery in the dashboard. A relay host is a host name, not an IP address (the engine resolves it in DNS). If the relay refuses the login (a rotated password, a mistyped one) the affected mail waits and is retried (`454 4.7.0 relay authentication failed`) instead of bouncing: fix the route and it goes out. **Mail sent through a relay is not covered by TLS policies, MTA-STS or DANE of the destination**; the dashboard and the API warn when an `encrypt` or `verify` policy overlaps a relay's domains.
* **The relay password** is encrypted with the same key ring as DKIM and webhook secrets (`Secrets:KeyProtection`) before it is stored, is never returned by the API or shown by the dashboard (only "password set"), and is not written to the log. To change it, type a new one; to drop it, "Remove the stored user name and password". Changing the host, port or TLS mode of a route that keeps its login needs the password typed again (a stored secret is never sent somewhere new on its own). Use TLS mode `verify` (STARTTLS, usually 587) or `implicit` (port 465) with a login: both validate the relay's certificate and host name. `required` only encrypts and `starttls` is opportunistic, so a password would go to whoever answers; the dashboard and the API warn, and `none` with a login is refused.
* **A TLS policy** sets the level for a recipient domain (exact name, `*.suffix` or `*`; the most specific pattern wins; no policy means `may`). `may`: TLS when the server offers it, any certificate. `encrypt`: TLS required, certificate not checked. `verify`: TLS required and the certificate must be valid for the MX name. A server that cannot satisfy `encrypt` or `verify` gets nothing: the mail is retried and finally bounces after `Queue:MaxLifetimeDays`, so set them for domains you have checked, and think twice before a strict `*`. `none` switches TLS off for those destinations and **also skips MTA-STS and DANE**, so it can send in plaintext to a destination that publishes an enforcing policy; use it only for a destination you know cannot do TLS. `none` for `*` (everything) needs an explicit acknowledgement in the form and in the API (`acknowledgeInsecure`), and every `none` is logged at warning level. `*.example.com` covers the subdomains of `example.com` and not `example.com`: add a policy for the bare domain as well. For all other levels, DANE (when `Dns:TrustAuthenticatedData` is on behind a validating resolver) and an enforcing MTA-STS policy of the destination still apply on top and win over the level.
* **Audit.** The API has no audit table. Each change writes one log line from `Mta.Host.Api.RoutingAdminApi` such as `Relay route office (...) updated by root: host smtp.relay.example:587, tlsMode verify, user relay-user, password set, ...` (never the password); ship the logs somewhere that keeps them if you need a trail.
* **Backups and bundles.** Routes and policies are in the config part: a SQLite or PostgreSQL backup has them, the relay password stays encrypted and needs the same key ring to be usable ([storage.md](components/storage.md)).

* **Concurrent changes.** An update reads the record, merges the request and writes it back: two administrators saving the same record at the same moment get last write wins on the whole record. Relay names are unique by a check before the write, not by an index.
* **Private addresses.** An MX or relay host name that resolves to a loopback or reserved address is not used unless `Delivery:AllowPrivateMxAddresses` is `true`; the API warns when a relay host would be refused for this. Turning it on is for lab setups: it lets whoever can create relay routes (administrators) point mail, and a stored relay login, at services on the server's own host.
* **Upgrade note.** Earlier builds accepted any certificate for relay TLS modes `verify` and `implicit` (and nothing could create a route through the API, so only routes inserted straight into the database were affected). They now validate the chain and the host name: a route whose relay presents a self-signed or mismatching certificate stops carrying mail (retried, then expired) until the certificate is fixed or the mode is set to `required` (encryption without validation).

Not verified: delivery through a real relay provider (the engine tests use loopback servers, including STARTTLS with a self-signed certificate that `required` accepts and `verify` refuses).

## Inbound mail

Received mail, the settings and routes of the domains that receive it, and the state of the route actions are stored like the rest of the data ([design.md section 11](design.md#11-inbound-mail), decision 95). What an operator should know about the storage and the API (the SMTP receive path, the route actions and the dashboard pages are separate changes; until the receive path ships no mail arrives and the tables stay empty):

- **Where it lives.** Settings and routes in the config part (`config.db`), messages and their bodies in the queue part (`queue.db`): `inbound_domain_settings`, `inbound_route`, `inbound_message`, `inbound_message_raw` (a body is a separate row so lists and claims never read it). One row and one body per accepted recipient. On PostgreSQL they are ordinary tables in the one database. Stored mail grows the hot `queue.db`: a deployment that stores a lot of mail should use a finite `Inbound:RetentionDays` (or per-domain `retentionDays`) and the per-domain `maxStoredBytes`, or PostgreSQL.
- **Retention.** A message (row and body) is deleted when it is older than its domain's `retentionDays`, else `Inbound:RetentionDays` (default 7); **`0` keeps forever**, which shows as the health warning `retention_unlimited:Inbound:RetentionDays` and as `retention_unlimited` in the settings API. The job is `inbound_retention` of the storage maintenance (every five minutes with the other jobs, safe on several replicas): batched deletes on both backends (at most 100 messages and 64 MiB of bodies per write, fewer when `Sqlite:RetentionDeleteBatchSize` or `Storage:Postgres:RetentionDeleteBatchSize` is lower, with the configured pause between batches; the message row goes first, then its body). The cutoff is read from the current settings when the job runs, so shortening a domain's retention frees old mail at the next run. **A message whose action is still pending is never deleted by retention.** A forward that completed has no body; a discarded message never had one.
- **The operator's limits** are ceilings, and the API shows what applies as `effective` values: `Inbound:MaxMessageSize` (default `Smtp:MaxMessageSize`; a domain can lower it, never raise it), `Inbound:MaxMessagesPerMinute`, `Inbound:MaxMessagesPerMinutePerRemote`, `Inbound:MaxStoredBytesPerDomain`. The receive path applies the same ones; a domain's own settings override them.
- **API.** Scopes `inbound:read` (list, search, show, download, usage) and `inbound:write` (change settings and routes, delete, retry, erase) ([api.md](api.md#inbound-mail-inboundread-and-inboundwrite-scopes)); a key may hold both, and neither implies the other. Create the keys with `POST /api-keys` (`"scopes": ["inbound:read"]`) for the application that reads received mail. Raw messages and attachments are only ever served as downloads (`Content-Disposition: attachment`, `nosniff`, no caching). **A tenant can only lower the limits above, never raise them**; the API refuses a larger value. `DELETE /inbound/messages?sender=...` erases everything of a tenant that matches (a data-subject request); it needs at least one filter.
- **Deleting a webhook endpoint** that an inbound route uses is refused with `409` (`webhook_endpoint_in_use`, enforced by the storage write itself, and a route cannot name an endpoint that does not exist for its tenant); deleting a domain deletes its inbound settings and routes, and is refused with `409` while the domain still has received mail unless `purgeInbound=true` is given.
- **The client address must reach the server (for the receive path).** SPF, the DNSBL and the per-remote limit use the address the sender connected from. Behind source NAT every sender looks like the NAT address: SPF passes or fails for the wrong reasons and one sender can use up everyone's per-remote budget. What works: `network_mode: host` (Compose) or `hostNetwork` with the port set to 25; a Kubernetes `Service` with `externalTrafficPolicy: Local`; a layer-4 load balancer that keeps the client address. What does not: `-p 25:2526` under **Docker Desktop**, the **rootless** engine and the **userland proxy** (`docker-proxy`, which a Linux host falls back to when it cannot do the NAT in the kernel; check with `docker info` and `iptables -t nat -S DOCKER`): they connect to the container from the gateway or loopback. A default Docker engine on Linux keeps the address. The server warns once an hour when inbound connections arrive from a private, loopback or link-local address on a listener that is not loopback-bound; PROXY protocol support is an open question ([open-questions.md](open-questions.md)).
- **`inbound:write` decides where future mail goes.** A route sends every matching message to the endpoint or addresses the key names, so a leaked key with `inbound:write` reads the mailbox from then on without ever calling `inbound:read`; treat the two scopes as equally sensitive. A `forward` route needs the `send` scope as well. Deleting a domain that still has received mail needs `?purgeInbound=true` (and `inbound:write`), which deletes the mail first.
- **Large deletes are batched.** An erasure (`DELETE /inbound/messages?...`), the retention job and `purgeInbound` delete at most 100 messages and 64 MiB of bodies per write, with a short pause between, so they do not stall intake or deliveries on SQLite (one writer) or hold long transactions on PostgreSQL. A ceiling that the operator lowers later is applied at run time (`min(domain value, ceiling)`), and a request that only turns a domain off is never refused because of it.
- **Backups and the backend switch.** A SQLite backup or `pg_dump` has all of it. The switch bundle (format 1.3) carries the four tables: settings and routes with the config part, messages and bodies with the queue part (the body in a body pack, like the spool). Pending actions are held on the source until the switch finishes, so none runs twice. `--skip-history` does not skip received mail (it is not history), so a deployment that keeps a lot of it makes the bundle, the export and the verification that large. A bundle of format 1.2 (without inbound tables) imports into a build that has them and starts with no inbound data; a bundle with the tables is refused by a build that does not know them (the import stops at the first unknown table before anything is applied), so upgrade the target before switching to it.
- **Route actions (webhook, forward, store, discard).** A pool of `Inbound:Action:Concurrency` workers per replica claims the pending actions (several replicas on PostgreSQL split them with `FOR UPDATE SKIP LOCKED`; SQLite has one process), counts the attempt at the claim, and records the result. A failed attempt moves to the next rung of `Inbound:Action:RetrySchedule` (eight attempts over about 27 hours) and then the action is `failed` with a short code in `actionLastError` (`webhook_http_503`, `webhook_timeout`, `webhook_ssrf_blocked`, `endpoint_disabled`, `route_deleted`, `too_large_for_raw_webhook`, ...; never a URL, an address or the receiver's answer) and the tenant's endpoints that subscribe to `inbound.action.failed` (or `*`) are told. **Anything that stops an attempt for a reason that is not the message's counts as an attempt too** (a disabled endpoint, a suspended tenant, `Inbound:Enabled` off): nothing stays pending for longer than the ladder, and `retry` (API or dashboard) starts a new ladder after the cause is fixed. A runner that dies in the middle of an attempt has used the attempt up, so a message that kills its runner every time ends `failed` (`attempts_exhausted`) instead of being claimed for ever. The action that runs is the route's **current** one: a route that became `store` or `discard` while mail waited completes it as `done` with the note `route_is_now_store` / `route_is_now_discard` (nothing is delivered, nothing is deleted); a deleted route fails it with `route_deleted`. Webhook calls use the same HTTP stack as every other webhook (Standard Webhooks signature, the SSRF guard with the tenants' allowlists, no redirects, no proxy, `Webhooks:Timeout`), and the endpoint's failing streak, the `410` switch-off and the `Webhooks:DisableAfter` rule apply to inbound calls too. `webhook-id` is `evt_<inbound id>` and stays the same across automatic retries; a manual `retry` makes it `evt_<inbound id>-<n>`. **One tenant cannot take the whole pool or starve the others** (`Inbound:Action:MaxConcurrencyPerTenant`): the claim itself limits a tenant's rows per call and leaves out tenants that already have attempts in flight on the replica, so another tenant's actions are claimed even behind a backlog of a dead receiver, and no claimed action waits for a slot. Replicas apply the limit independently, so the cluster-wide share of a tenant is at most the limit times the number of replicas.
- **Upgrade note.** Schema version 8 (SQLite files are upgraded at the first start; PostgreSQL `V008`) adds the four tables and an index on `inbound_message`; no existing table changes and nothing is rewritten, so the upgrade is quick on any size of database.

## Cancelling queued mail

A message that has not been delivered yet can be stopped from the message page of the dashboard (**Cancel delivery**) or with `POST /api/v1/messages/{id}/cancel` ([api.md](api.md)); the caller needs the `send` scope. What an operator should know:

- It works on recipients that are *waiting*: queued, or deferred until their next retry. A recipient whose delivery attempt is running at that moment (it holds a lease) is left alone and reported as `inFlight`; try again after the attempt, which lasts seconds. A recipient held by a backend switch is reported as `transferHeld` until the switch is finished or rolled back. A stuck lease (a worker that died) runs out after `Delivery:ClaimLease` (15 minutes by default), and the recipient is cancellable from then on; because the outcome of that attempt is unknown, the cancel is recorded with a `possible_duplicate` event.
- A cancelled recipient is final: `cancelled` event, no retry, no bounce message to the sender, no suppression and no statistics counter (the "recent events" list shows it). The accepted count of the statistics stays, so accepted minus the other counters includes cancelled mail. A `message.cancelled` webhook event is published to the tenant's subscribed endpoints.
- It does not need per-message history: with `History:Mode=StatsOnly` it still works (no events or status are recorded, and the answer carries no status).
- There is no audit log of who cancelled: the `cancelled` events in the message history are the record. Cancelling during a backend switch is refused with `503` like every queue write.
- **Upgrade note:** schema version 7 adds an index on `delivery_queue (message_id)` so that cancelling does not scan the queue. SQLite builds it at the first start (the queue file is locked meanwhile); on PostgreSQL the migration's `CREATE INDEX` blocks writes to `delivery_queue` while it builds. Both are quick for a queue of some hundred thousand rows; on a much larger queue run the migration (`mta migrate-db`) in a quiet moment. The build time on very large queues was not measured.

## Bounces caused by the receiving server's capabilities

EggMail sends 8-bit bodies with `BODY=8BITMIME` and internationalized mail with `SMTPUTF8` when the receiving server offers them, and converts or refuses when it does not. Three permanent failures name this in the bounce text (none of them suppresses the recipient): `5.6.1` the server has no 8BITMIME and the message could not be converted to 7-bit (the text says why, for example 8-bit header fields in an attached message); `5.6.9` the message has UTF-8 header fields and the server has no SMTPUTF8 (a change from earlier versions, which sent such mail as is; headers are not downgraded, RFC 6857); `5.6.7` the sender or recipient address has non-ASCII characters before the `@` and the server has no SMTPUTF8 (when only some recipients are affected the others are delivered, and the affected ones are offered to the domain's other mail hosts first). A configured `Delivery:BounceDomain` makes the envelope sender an ASCII bounce address, which avoids `5.6.7` for the sender. Bounce reports about internationalized recipients are RFC 6533 reports (`message/global-delivery-status`).

## Protecting the key ring (`Secrets:KeyProtection`)

DKIM keys, webhook secrets, TLS private keys and the ACME account key are encrypted with ASP.NET Core Data Protection; the key ring itself lives in the database. `Certificate` encrypts the ring with a PFX held outside the database. `Kms` wraps every ring element with a key that is kept outside the database: with `Secrets:KmsProvider=LocalKey` that is a random 32-byte key from a mounted file or an environment value.

```sh
umask 077 && openssl rand -base64 32 > /run/secrets/eggmail-keyring.key     # readable by the EggMail user only
# Secrets__KeyProtection=Kms  Secrets__KmsKeyFile=/run/secrets/eggmail-keyring.key
```

`Secrets:KmsKey` (the key in an environment value) works but is visible in the process environment; the start logs a warning, as it does for a key file that other users can read. Elements are sealed with AES-256-GCM and record the provider and a key id, so starting with another key stops with a message naming both. A missing or unusable key is a configuration error at start (exit 2).

**The stored ring must fit the configuration.** At start the ring is inspected before Data Protection touches it (otherwise a key it cannot read would be treated as missing and a new one created, stranding everything protected by the old ring). The start is refused, with a message, when the key is not the one the ring was wrapped with, when the ring holds keys encrypted with a certificate but `Secrets:KeyProtection` is not `Certificate`, or keys wrapped by `Kms` while it is not `Kms`. A ring that still holds keys written in the clear (from before protection was switched on) starts with a warning, and the backend switch does not count the instance as protected. **Changing `Secrets:KeyProtection`, or the key, on a ring that already holds keys is only supported with `mta secrets rewrap`**: with the server stopped and after a backup, `mta secrets rewrap` shows what it would change, `mta secrets rewrap --apply` protects keys stored in the clear and, with `--from-kms-key-file OLD`, moves keys wrapped by the previous key to the configured one. Keys encrypted with a certificate are not converted.

**Keep the key: without it the ring, and with it every secret in the database, cannot be opened.** There is no other key rotation. A cloud key service (AWS KMS, Azure Key Vault, Google Cloud KMS) is not included: it is an `IKeyWrapProvider` registered with `KeyWrapProviders.Register` in a custom build of the host and selected by `Secrets:KmsProvider`; see [open-questions.md](open-questions.md). Backend switching works with any of the modes (the source's key must be reachable during the export).

## Unicode support

Internationalized domain names and Unicode normalization depend on ICU. In invariant globalization mode (`DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1`, `InvariantGlobalization=true`, or a host without `libicu`) .NET gives wrong answers for anything outside ASCII without any error: an upper case or decomposed IDN becomes the wrong A-label, so a sender domain no longer matches the one that was registered. Before `mta serve`, `migrate-db`, `migrate-storage`, `admin` and `secrets` do anything they therefore run a self-test (A-labels of a precomposed, an upper case, a decomposed and a CJK name, U-label round trip, NFC normalization) and, if it fails, print what was wrong and how to fix it and exit with code 71 before opening any storage (`--version`, `--healthcheck` and `self-test` itself are exempt). The probes go through the same code the mail pipeline uses for domain names (`DnsName`, the address parser). `mta self-test` runs the same test and prints the result (exit 0 or 71): use it to check an image or a host. The published image is the chiseled `-extra` variant with ICU. `Startup:RequireUnicodeSupport=false` starts anyway with a warning in the log (not recommended).

## Upgrades

**Attachment storage on SMTP.** SMTP submissions now follow the tenant's `Content:StoreAttachments` setting, and the operator default when the tenant never chose (they used to ignore both), so where `Content:AllowAttachmentStorage` is on and the default or a tenant says yes, SMTP mail with attachments is kept after delivery and uses disk for `Content:RetentionDays`. Check the tenants' settings and `Content:StoreAttachments` before upgrading if that is not wanted.

Take a backup, pull the new image, restart. Schema changes run at start (SQLite: automatic; PostgreSQL: `Mail:Database:Migrate`, owner role). Schema version 4 builds an index on the history index (`message_index`) of every partition on PostgreSQL, which blocks intake writes for the duration; on a large history run `mta migrate-db` in a quiet moment before the rollout. Schema version 7 does the same for the index on `delivery_queue (message_id)` (see Cancelling queued mail above). Roll back by restoring the backup and starting the old image. Backend switching (SQLite ⇄ PostgreSQL) is a separate, manual procedure (`docs/design.md` section 4.6; engine, CLI, admin API and dashboard wizard are built, see [components/switch.md](components/switch.md)).

## State kept across restarts

Four things the server counts or learns while running are written to the database in the background, so a restart (and, on PostgreSQL, another replica) sees them: the last DNS check result of every record of a domain, the hourly and daily sending counters behind the sending caps (`Sending:GlobalPerHour` and the others) and the warm-up, the TLS-RPT counters, and the reports that could not be delivered yet. They are flushed every 10 seconds (counters) and every minute (TLS-RPT) and when the process stops, so a graceful restart loses nothing and a crash loses at most that last interval (the caps may then be overshot by what was sent in those seconds). With several replicas on one PostgreSQL database the caps are shared with a lag of one flush interval and each daily TLS report is sent once ([Running more than one replica](#running-more-than-one-replica)). Global settings changed in the dashboard (`/admin/settings`) are stored at once and applied at the next start.

## Running more than one replica

Only with the PostgreSQL backend (SQLite is one process on one volume, by design). Point every replica at the same database with the same `Secrets` configuration; each replica generates a unique name for itself at start. Nothing needs to be configured for the replicas to find each other: they beat in the database every 5 seconds.

What is shared between replicas, and what is not (decision 82):

| What | With N replicas |
|---|---|
| Queue, history, suppressions, configuration, certificates and ACME renewal, domain verification, `Domains:Bootstrap` | One copy in the database; claims use `SKIP LOCKED`, renewals, checks and the start-up registration of domains take leases (a replica that finds the `domains-bootstrap` lease taken skips it; each domain is registered and its records are logged once) |
| Failed-login lockout (`SMTP AUTH` and the API/dashboard sign-in) | One budget for all replicas (10 failures per address and per user name in 15 minutes), counted in the database as keyed digests. Costs one small read per login attempt, one write per failed attempt, and a delete after a success that follows failures. If the database cannot be reached or is slow each replica counts on its own until it is back |
| Connections and messages per minute to one destination (`Delivery:Throttle:MaxConnections`, `Delivery:Throttle:MaxMessagesPerMinute`) | The ceiling holds for all replicas together: each takes its share (a ceiling of 20 connections is 7, 7 and 6 on three replicas). A replica that joins or leaves is noticed within about 5 s (a replica that dies within 20 s); until then the sum of the shares can be above a ceiling for a few seconds. Set `Delivery:Throttle:MaxConnections` at least as high as the number of replicas, otherwise every replica still gets one |
| A destination that throttled one replica, a mail server found down | The other replicas slow down or skip an MX host within about 5 s, for at most the base cool-down (5 minutes) and not if they connected to it in the last 2 minutes; relay routes are never opened by another replica. Each replica still probes a down server itself once its cool-down is over |
| Sending caps and warm-up (`Sending:GlobalPerHour` and the others) | Shared through the database with a lag of one flush interval (10 s): a cap can be overshot by what the other replicas send in those seconds. Set a hard ceiling lower by that amount |
| TLS reports | One report per domain and day, with every replica's counts |
| Inbound connection limits (`Smtp:MaxConnections`, `MaxConnectionsPerIp`, `MaxInFlightBytes`), the API request memory budget | Per replica (they protect that process); behind a load balancer the per-address limit is per replica |

Things to get right:

- **Clocks.** The replica set and what replicas tell each other about destinations are timed by the database's clock, so replica clocks do not enter. Leases (renewals, domain checks, the TLS report job) and the failed-login buckets use each replica's own clock: keep them within a minute of each other (NTP).
- **Rolling updates.** A new replica joins the set before it delivers; the old one leaves when it stops (SIGTERM; give it the 60 s grace). A replica killed without leaving is dropped by the others after 20 seconds, and in the meantime it holds a share that nobody uses.
- **Rolling updates across a schema version.** The first new replica migrates the schema at start (`Mail:Database:Migrate=Auto`; otherwise apply `mta migrate-db` first). Replicas of the old build that are already running keep working, because the migrations are additive; but an old build that restarts after the migration refuses to start (the schema is newer than it knows), so roll forward and do not restart old replicas in between; to go back, restore the backup and start the old image ([Upgrades](#upgrades)). Builds before schema version 6 take no part in the coordination: while they run, the new replicas share the destination ceilings and the failed-login budget among themselves only, so the old ones come on top of the ceilings, and failed logins at an old replica are not counted by the new ones.
- **A database that cannot be reached for a while.** A replica that cannot beat for 20 seconds is dropped by the others while it keeps its old share, so for that time the shares add up to more than a ceiling; it rejoins at its next successful beat. Its claims are failing too, so it sends little in that time. The coordination uses two database connections of its own (pool `eggmail-coordination`), so a busy queue does not delay the beat.
- **A delivery that was being sent when its replica died** is picked up by another replica when its lease (`Delivery:ClaimLease`, 15 minutes) runs out and is flagged `possible_duplicate`. Lower the lease only if remote conversations are short: a delivery that takes longer than the lease is sent by two replicas, both flagged.
- **Connections.** Keep the sum of the pool sizes of all replicas below about half of `max_connections` of the database (design section 4.2). The coordination adds a handful of tiny statements per replica every 5 seconds, on its own two connections, and one read per login attempt.

## Graceful shutdown

On SIGTERM the SMTP listeners stop accepting, running deliveries are given time to finish, the rest are returned to the queue unchanged (a delivery that may already have been sent is flagged `possible_duplicate`), then the process exits. Give the container at least 60 s of termination grace.

## Load, benchmark and soak tests

Before trusting a configuration with real mail, measure it on your hardware. `bench/run-local-matrix.sh` runs the throughput matrix (both backends, durable and non-durable, ingest and delivery) on the machine you are on and writes a table ([benchmarks.md](benchmarks.md#the-same-matrix-on-a-laptop-or-a-server-of-your-own)). `bench/soak/run-soak.sh` runs the real `mta serve` for hours under mixed load, kills it with `kill -9` on a schedule, restores backups into a second instance, and ends with a PASS/FAIL verdict on lost messages, unflagged duplicates, memory, descriptor and thread growth, error rate and queue drain ([soak.md](soak.md)). Both run on a laptop or a server without Docker (PostgreSQL from the binaries on `PATH`); the matching GitHub Actions workflows are `bench-throughput` and `soak`, dispatched by hand because they bill by the minute.
