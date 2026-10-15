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

- Outbound SMTP server and client written on the .NET base class library only (STARTTLS, implicit TLS, AUTH, pipelining, BDAT, request
  smuggling and STARTTLS-injection defences), with a CI guard that the protocol assemblies have no package references.
- Message handling: MIME parser/builder/editor, DKIM signing and verification, SPF, DMARC, Authentication-Results, ARC, DSN/ARF, VERP,
  DNS client with DNSSEC data (AD bit honoured only with `Dns:TrustAuthenticatedData`), MTA-STS, DANE, TLS-RPT.
- Delivery engine: grouping, MX and relay routes, TLS policy per domain, retry ladder, circuit breakers, per-destination throttles,
  bounce and complaint processing, signed webhooks (Standard Webhooks), sending caps and domain warm-up.
- Storage backends with the same feature set: SQLite (default, `Sqlite:SyncMode=Off` with a loud warning) and PostgreSQL (EF Core +
  Npgsql, day partitions, `SKIP LOCKED` claims, owner and runtime roles). Shared conformance suites run against both.
- Replica coordination on PostgreSQL: replicas share the failed-login budget, the per-destination connection and rate ceilings (each takes its share from the live replica set) and, bounded, what remote destinations told a replica (throttling, an unreachable MX host). A delivery whose lease another replica took over is flagged `possible_duplicate` when its first holder reports (schema version 6).
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
- Zero-configuration start: `docker run -p 587:5587 -p 465:4465 -p 2525:2525 -p 8443:8443 -v eggmail-data:/data ghcr.io/eggspot/eggmail` is a usable server. The first start creates the data
  directory, the key ring, the VERP key, a self-signed certificate (said in the log at every start and as a persistent dashboard banner) and the first dashboard administrator with a
  generated password printed once. A small set of documented `EGGMAIL_*` environment variables maps onto the existing configuration (`EGGMAIL_HOSTNAME`, `EGGMAIL_ACME_EMAIL` with the
  host name turns ACME on, `EGGMAIL_ACME_STAGING`, `EGGMAIL_ACME_DIRECTORY`, `CLOUDFLARE_API_TOKEN`, `EGGMAIL_ADMIN_USER`, `EGGMAIL_ADMIN_PASSWORD(_FILE)`, `EGGMAIL_DOMAINS`, `EGGMAIL_DATABASE`
  for PostgreSQL with one variable, `EGGMAIL_RELAY`); combinations that cannot work stop the start with a message that names the variable. New keys `Dashboard:BootstrapAdminPassword`
  and `Delivery:Relay:*`. The shipped Compose files use the new variables. A browser-and-SMTP end-to-end test starts the real host with nothing configured, and the release smoke test does
  the same with the pushed image.
- Cancelling queued mail: `POST /api/v1/messages/{id}/cancel` and a "Cancel delivery" action on the dashboard's message page stop delivery
  to the recipients that are still waiting (all of them, or the ones named); a recipient whose delivery attempt is running is left alone and
  reported as in flight. Works with and without per-message history, publishes a `message.cancelled` webhook event and is implemented on every storage backend (decision 86; adds the index `delivery_queue (message_id)`, schema version 7).

### Security

- No known vulnerabilities; no independent security audit has been done yet. Report problems as described in [SECURITY.md](SECURITY.md).

[Unreleased]: https://github.com/eggspot/EggMail/commits/main
