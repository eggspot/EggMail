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

- Inbound mail, end-to-end tests on SQLite and PostgreSQL (decision 105, [docs/testing-offline-coverage.md](docs/testing-offline-coverage.md)): a lab over the real runtime with real stores, scripted DNS, a clock the tests move and fake remote MTAs; the receive path, the route actions, retention, crash and restart, the backend switch and tenant isolation, with the open-relay, backscatter, smuggling, STARTTLS and limit regressions; threat table in [docs/security.md](docs/security.md), abuse handling in [docs/operations.md](docs/operations.md).
- Inbound mail, route actions (decisions 97 and 98): a worker pool per replica carries out the action of the route that matched (webhook as JSON or raw MIME through the shared signed webhook transport, forward, store, discard) with the webhook retry ladder, a per-tenant share of the pool taken in the claim, `inbound.action.failed` events, `Inbound:Action:*`, `Inbound:Webhook:*` and `mta_inbound_actions*` metrics (schema version 9).
- Inbound mail, forward (decision 98): the copy is queued through the outbound queue as source `Forward` with an SRS0 envelope at the route's domain, a signed hop marker (three hops), an ARC set sealed with the route domain's key, original DKIM signatures untouched, byte-exact delivery, the route domain's DKIM signature only and never a bounce. A message whose From is in the route's own organization and did not pass DMARC is not forwarded (`unauthenticated_local_sender`). What a tenant may have waiting is capped (`Inbound:Forward:MaxQueuedMessagesPerTenant`, `MaxQueuedBytesPerTenant`, `MaxQueuedMessagesPerDomain`; `forward_backlog_full` keeps the message and retries), the `Idempotency-Key` prefixes `inbound:` and `eggmail-` (any case) are reserved for the server and the public API answers `400 validation_failed` for them (a visible change: `eggmail-order-1` is now refused), and `mta_inbound_forward_refused_total{reason}` counts what was not forwarded and why (schema version 10).
- Inbound mail, receive path (decision 103): with `Inbound:Enabled` the port-25 listener (container port 2526) is an MX receiver for the domains tenants enabled. RCPT-time classification (signed bounce, SRS, inbound domain with a route, else refused: no open relay, no backscatter), size, recipient, transaction-budget, rate and quota limits, SPF/DKIM/DMARC/ARC verification with the per-domain DMARC action, `Authentication-Results` and `Received`, optional DNSBL, one stored copy per recipient, `mta_inbound_*` metrics, `inbound.enabled` in capabilities. New server hooks (`OnDataStartAsync`, per-transaction size limit, per-listener limits), `SrsCodec` and `ForwardHopMarker`. Route actions are a separate change.
- Inbound mail, design and storage contracts (decision 95, [design.md section 11](docs/design.md#11-inbound-mail)): receiving for domains a tenant enables, SPF/DKIM/DMARC/ARC verification, per-domain routes (webhook, forward with SRS, store, discard), retention, the `inbound:read` and `inbound:write` API scopes. Storage on all backends (schema version 8, bundle format 1.3), the retention job `inbound_retention`, and the HTTP API (settings, routes, received messages, downloads, retry; scopes `inbound:read` and `inbound:write`, `Inbound:*` and `Api:MaxInboundRoutesPerDomain` keys) are in; the SMTP receive path, the route actions and the dashboard pages follow in later changes.
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

- Inbound mail: a `From` field that two parsers read as different addresses is unusable and its DMARC verdict is `permerror` (it was evaluated, and shown as `pass`, for the domain the strict parser chose); a per-minute rate limit is counted in one step with its check (simultaneous connections all passed it); the lookup budget of the bounce listener loses no count at the turn of a second; the route test of the API says `250` for `postmaster`.
- Inbound mail: two shapes of `From` slipped past the unusable-field check and were evaluated for the domain in the angle brackets while Python's `email.policy` reads another: a backslash before an `@` outside quotes (`ceo\@victim.test <x@evil.test>`) and text after `<@` that is not a source route (`<@evil.test,ceo@victim.test:x@evil.test>`); both are unusable now.
- The envelope sender (and so SPF) uses the sending domain's own `bounce.<domain>` host once its return-path CNAME is verified; before, the record was required and verified but never used, and the bounce listener now accepts bounces addressed to it.

### Fixed

- `BDAT` bodies are held to the same line-ending rule as `DATA` (bare LF, bare CR and NUL are refused with `500 5.5.2` and the connection is closed) instead of being acknowledged and bounced at delivery.
- A full disk on the SQLite backend is answered `452 4.3.1` instead of `451 4.3.0`.

### Changed

- `Delivery:Throttle:MaxMessagesPerConnection` is documented as reserved: it is read and validated but the delivery engine never enforces it.
- Webhook deliveries need direct network access to the receivers: a proxy configured through `HTTP_PROXY`/`HTTPS_PROXY` is ignored (see Security).

### Fixed

- ACME: a certificate the CA sends for other names, for another key, empty, cut off or already expired is no longer stored (it is a recorded failure and the old certificate keeps serving); a chain in the wrong order is corrected. A rate limit's `Retry-After` lengthens the wait before the next order (at most a day). An account the CA no longer knows is replaced once instead of failing every order. A registration the CA refused (rate limit, wrong external account binding) is reported as the CA's refusal, not as "could not be reached". A refused certificate download is the CA's refusal, not a `NullReferenceException`, and the wait for a finalizing order is bounded (decision 99).
- ACME with several replicas: replica names were the first 12 hex digits of a version 7 id (a millisecond timestamp), so two replicas started in the same millisecond shared a lease owner; the webhook dispatcher had the same line. A replica whose renewal lease was taken over while its order ran no longer overwrites the other replica's certificate or its renewal row (neither a result nor a failure is written without the lease).
- A damaged replacement of a certificate row no longer takes the working certificate of the same name out of the served set, and a DNS provider that fails to delete a challenge record in any way no longer turns an issued certificate into a failure.
- Cloudflare DNS-01: rate limits, server errors and timeouts are retried, Cloudflare's error codes and messages are shown, an identical record that is already there is adopted, a token with a line end works, and the token is in no message.

### Added

- Offline tests for ACME and Cloudflare (a scriptable mock CA and a fake Cloudflare in `tests/Mta.Host.Tests/Acme`) and [docs/testing-offline-coverage.md](docs/testing-offline-coverage.md), which says what they prove and what they do not.

### Security

- The MX host of a recipient domain can no longer point the SMTP client into your network: addresses that are not public (internal networks: private, link-local including 169.254.169.254, carrier-grade NAT, IPv6 unique-local; multicast and reserved space; Teredo and the IPv6 forms that embed those; the documentation ranges are kept) are dropped unless `Delivery:AllowPrivateMxAddresses` is true, which re-admits all of them, loopback and the metadata address included. A domain left with no usable address is held with a temporary `451 4.4.4` that names the setting (retried until the message expires, never a bounce at once, never a suppression). Upgrading: a deployment that delivers to a mail server on a private address through MX records must set it or use a relay route for that domain (relay hosts may still be private). One address classification now serves the webhook, MTA-STS, TLS-RPT and MX guards (decision 101).
- PostgreSQL refused NUL characters and unpaired surrogates in text, so a hostile query value, user name or remote certificate name could cause a 500 or a delivery result that could not be recorded. A filter or lookup with such text now matches nothing, on every backend, and a write of it no longer fails (PostgreSQL stores U+FFFD in place of the characters it cannot hold; SQLite keeps NUL as it is).
- Webhook URLs with a trailing dot on a blocked address, `*.localhost`, spaces or control characters are refused at registration; names, tags, user names, relay logins and attachment file names refuse control characters, line and paragraph separators, text direction overrides and unpaired surrogates; internationalized local parts refuse the same; the switch bundle reader checks path containment for every caller.
- Added `docs/security-test-map.md`: every threat and review finding mapped to its regression test (in-house review, not an independent audit).
- A forged bounce or complaint report could get any address suppressed for a tenant: every message carries a valid bounce address in its Return-Path and the report body decided which address was suppressed. Bounce addresses are now bound to the destination domain of the message and reports naming addresses elsewhere are ignored (decision 92). Bounce addresses issued before the change keep their old behaviour until they expire (14 days). Residual risk: the binding is to the destination domain, not the address, so someone who received one message to `gmail.com` can still get another `gmail.com` address suppressed for that tenant. Upgrading: replicas of an older build refuse the new bounce addresses (`550`), so run mixed versions only during a rollout; new builds accept old ones for 14 days.
- Webhook deliveries never go through a proxy, so `HTTP_PROXY`/`HTTPS_PROXY` in the environment cannot bypass the SSRF guard (the guard checks the address it connects to, which through a proxy is the proxy). Deployments that could only reach receivers through a proxy must allow direct egress for the webhook port range instead.
- No known vulnerabilities; no independent security audit has been done yet. Report problems as described in [SECURITY.md](SECURITY.md).

[Unreleased]: https://github.com/eggspot/EggMail/commits/main
