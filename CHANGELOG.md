# Changelog

All notable changes to EggMail are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Nothing is released yet. The first release will be `0.1.0` (the version in `Directory.Build.props`); everything under `Unreleased` is what
it will contain, and [docs/progress.md](docs/progress.md) states exactly what is verified and what is not.

How it is used: every pull request that changes behaviour adds a line under `Unreleased`. Cutting a release moves the `Unreleased`
entries to a new `## [X.Y.Z] - YYYY-MM-DD` section in the same pull request that bumps `<Version>` in `Directory.Build.props`. The release
workflow refuses a stable tag without a non-empty section for that exact version and publishes the section as the GitHub Release notes
(see [docs/release.md](docs/release.md)).

## [Unreleased]

### Added

- Inbound mail, design and storage contracts (decision 95, [design.md section 11](docs/design.md#11-inbound-mail)): receiving for domains a tenant enables, SPF/DKIM/DMARC/ARC verification, per-domain routes (webhook, forward with SRS, store, discard), retention, the `inbound` API scope. This change is the design and the contracts; the implementation follows in later changes.
- Outbound SMTP server and client written on the .NET base class library only (STARTTLS, implicit TLS, AUTH, pipelining, BDAT, request
  smuggling and STARTTLS-injection defences), with a CI guard that the protocol assemblies have no package references.
- Message handling: MIME parser/builder/editor, DKIM signing and verification, SPF, DMARC, Authentication-Results, ARC, DSN/ARF, VERP,
  DNS client with DNSSEC data (AD bit honoured only with `Dns:TrustAuthenticatedData`), MTA-STS, DANE, TLS-RPT.
- Delivery engine: grouping, MX and relay routes, TLS policy per domain, retry ladder, circuit breakers, per-destination throttles,
  bounce and complaint processing, signed webhooks (Standard Webhooks), sending caps and domain warm-up.
- Storage backends with the same feature set: SQLite (default, `Sqlite:SyncMode=Off` with a loud warning) and PostgreSQL (EF Core +
  Npgsql, day partitions, `SKIP LOCKED` claims, owner and runtime roles). Shared conformance suites run against both.
- Replica coordination on PostgreSQL: replicas share the failed-login budget, the per-destination connection and rate ceilings (each takes its share from the live replica set) and, bounded, what remote destinations told a replica (throttling, an unreachable MX host). A delivery whose lease another replica took over is flagged `possible_duplicate` when its first holder reports (schema version 6).
- Automatic TLS certificates: with `Hostname`, `Acme:Enabled` and `Acme:Email` set the server gets and renews a Let's Encrypt certificate over HTTP-01
  on a built-in port 80 listener that serves nothing but the challenge; DNS-01 (Cloudflare) for wildcards or when a token is configured; any CA by
  name or URL (staging, ZeroSSL) with external account binding; the self-signed certificate keeps serving, with a log and dashboard banner
  (`acme_pending`, `acme_failing`), while issuing is pending or failing; several replicas answer each other's challenges through the config
  store. Verified against the Pebble test CA (decision 87).
- Backend switch in both directions (`mta migrate-storage`, `/api/v1/admin/storage/switch/*` and the dashboard wizard): drain or
  quiesce, fence, symmetric bundle, verification, activation, rollback, resumable history migration, secrets re-protected with Data
  Protection.
- HTTP API (`/api/v1`) and the dashboard (Preact + Vite) with API keys, SMTP credentials, tenants, domains with DNS verification, DKIM
  rotation, suppressions, webhooks, statistics and settings. `/healthz`, `/readyz`, `/metrics`.
- Dashboard user management while the server runs: `/api/v1/admin/users` (create, list, enable, disable, role and tenant, reset
  password, delete) and `POST /api/v1/me/password`, with the matching Users and Account pages. Disabling, role changes, resets and
  deletes end the user's sessions in the same write, and the last enabled administrator cannot be removed.
- `mta` command line: `serve`, `--healthcheck`, `--version`, `migrate-db`, `migrate-storage`, `admin create`.
- One multi-architecture container image (`ghcr.io/eggspot/eggmail`, `linux/amd64` and `linux/arm64`, chiseled .NET 10 base, non-root)
  with SBOM and provenance attestations.
- Deployment artifacts under `deploy/`: Compose files for SQLite and PostgreSQL, an optional Unbound (DNSSEC-validating resolver)
  sidecar so DANE works, Kubernetes manifests (StatefulSet for SQLite, Deployment for PostgreSQL, Services, NetworkPolicy, probes)
  and an end-to-end smoke test that the release workflow runs against the pushed image.
- Benchmark harness (`bench/`) and a scheduled allocation-regression gate with a checked-in baseline.
- Throughput matrix for both backends, each durable and non-durable, reported in pairs (`bench/run-local-matrix.sh` on a laptop, the `bench-throughput` workflow on a runner), and a soak test of the real published host (`bench/soak/run-soak.sh`, the `soak` workflow): hours of load, `kill -9` and backup/restore drills, PASS/FAIL criteria for lost messages, unflagged duplicates, memory, descriptor and thread growth, error rate and queue drain. `/metrics` also exports the .NET runtime meter (garbage collections, working set, thread pool).
- Allocation round 3: the ingest path allocates about 1.7 KB per 200-byte message and 3.5 KB per 2 KB message on SQLite (was 5.1 and 10.7 KB), the
  SMTP server path alone 0.1 KB (was 1 KB); delivery about 25 KB per recipient (was 28 KB). New setting `Delivery:MaxIdleConnectionsPerTarget`
  (default 2, unchanged behaviour) for the idle outbound connections kept per destination (decision 89).
- Zero-configuration start: `docker run -p 587:5587 -p 465:4465 -p 2525:2525 -p 8443:8443 -v eggmail-data:/data ghcr.io/eggspot/eggmail` is a usable server. The first start creates the data
  directory, the key ring, the VERP key, a self-signed certificate (said in the log at every start and as a persistent dashboard banner) and the first dashboard administrator with a
  generated password printed once. A small set of documented `EGGMAIL_*` environment variables maps onto the existing configuration (`EGGMAIL_HOSTNAME`, `EGGMAIL_ACME_EMAIL` with the
  host name turns ACME on, `EGGMAIL_ACME_STAGING`, `EGGMAIL_ACME_DIRECTORY`, `CLOUDFLARE_API_TOKEN`, `EGGMAIL_ADMIN_USER`, `EGGMAIL_ADMIN_PASSWORD(_FILE)`, `EGGMAIL_DOMAINS`, `EGGMAIL_DATABASE`
  for PostgreSQL with one variable, `EGGMAIL_RELAY`); combinations that cannot work stop the start with a message that names the variable. New keys `Dashboard:BootstrapAdminPassword`
  and `Delivery:Relay:*`. The generated administrator password is temporary: the dashboard (and the API, with `403 password_change_required`) allows nothing but choosing a new one at the first sign-in. The shipped Compose files use the new variables. A browser-and-SMTP end-to-end test starts the real host with nothing configured, and the release smoke test does
  the same with the pushed image.
- Cancelling queued mail: `POST /api/v1/messages/{id}/cancel` and a "Cancel delivery" action on the dashboard's message page stop delivery
  to the recipients that are still waiting (all of them, or the ones named); a recipient whose delivery attempt is running is left alone and
  reported as in flight. Works with and without per-message history, publishes a `message.cancelled` webhook event and is implemented on every storage backend (decision 86; adds the index `delivery_queue (message_id)`, schema version 7).
- Descriptor and thread metrics on `/metrics` and OTLP (`mta_process_open_fds` on Linux, `mta_process_threads`) so a long run can be judged for leaks without access to the host.
- `mta_bounce_reports_ignored_total{kind}` counts bounce and complaint reports that were not acted on because they name an address outside the destination domain of their bounce address.
- The outbound client sends `ORCPT` when the receiving server offers DSN, so bounces for forwarded addresses still name the address EggMail used.

### Changed

- The container image no longer sets `Storage__Backend` and `Sqlite__DataDirectory` (the defaults are the same): an environment variable counts as supplied by the deployment, which made a backend switch from the one-container quick start print a cutover patch instead of writing the bootstrap file.
- `ci` starts on every pull request and skips its work for documentation-only changes inside the job, so a branch rule that requires the `build-test` check never waits for a documentation-only pull request; a missing PostgreSQL or Pebble in CI now fails the run instead of silently skipping their tests.

### Fixed

- The envelope sender (and so SPF) uses the sending domain's own `bounce.<domain>` host once its return-path CNAME is verified; before, the record was required and verified but never used, and the bounce listener now accepts bounces addressed to it.

### Fixed

- `BDAT` bodies are held to the same line-ending rule as `DATA` (bare LF, bare CR and NUL are refused with `500 5.5.2` and the connection is closed) instead of being acknowledged and bounced at delivery.
- A full disk on the SQLite backend is answered `452 4.3.1` instead of `451 4.3.0`.

### Changed

- `Delivery:Throttle:MaxMessagesPerConnection` is documented as reserved: it is read and validated but the delivery engine never enforces it.
- Webhook deliveries need direct network access to the receivers: a proxy configured through `HTTP_PROXY`/`HTTPS_PROXY` is ignored (see Security).

### Security

- A forged bounce or complaint report could get any address suppressed for a tenant: every message carries a valid bounce address in its Return-Path and the report body decided which address was suppressed. Bounce addresses are now bound to the destination domain of the message and reports naming addresses elsewhere are ignored (decision 92). Bounce addresses issued before the change keep their old behaviour until they expire (14 days). Residual risk: the binding is to the destination domain, not the address, so someone who received one message to `gmail.com` can still get another `gmail.com` address suppressed for that tenant. Upgrading: replicas of an older build refuse the new bounce addresses (`550`), so run mixed versions only during a rollout; new builds accept old ones for 14 days.
- Webhook deliveries never go through a proxy, so `HTTP_PROXY`/`HTTPS_PROXY` in the environment cannot bypass the SSRF guard (the guard checks the address it connects to, which through a proxy is the proxy). Deployments that could only reach receivers through a proxy must allow direct egress for the webhook port range instead.
- No known vulnerabilities; no independent security audit has been done yet. Report problems as described in [SECURITY.md](SECURITY.md).

[Unreleased]: https://github.com/eggspot/EggMail/commits/main
