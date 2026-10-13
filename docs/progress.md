# Implementation progress

Running status of the implementation, updated in every pull request. **Production readiness is not claimed until every feature in [plan.md](plan.md) is implemented and its quality gate passes.** This file says exactly what is done, what is verified and how, and what is not.

## Milestones

| Area | Status | Verified by |
|---|---|---|
| Foundations: solution, shared contracts, package-free guard | merged | architecture tests (31) |
| SMTP protocol library and server (STARTTLS, implicit TLS, AUTH, BDAT, pipelining, smuggling and STARTTLS-injection defenses) | merged | 90 + 32 tests, MailKit interop |
| Outbound SMTP client (STARTTLS policy, AUTH, pipelining, DATA/BDAT, pool) | merged | 21 loopback tests |
| MIME (parse, build, edit, validate, extract) | merged | 783 tests incl. MimeKit differential and fuzzing |
| DNS client and MX resolver | merged | 203 tests |
| TLS policy: MTA-STS, DANE, TLS-RPT, certificate validation | merged | 471 tests |
| DKIM sign/verify | merged | 339 tests incl. MimeKit differential |
| SPF, DMARC, Authentication-Results, aggregate reports, ARC | merged | 905 tests incl. MimeKit ARC cross-check |
| VERP tokens, DSN builder, inbound DSN/ARF parser | merged | 22 tests |
| Delivery policy: reply classifier, retry schedule, throttle, circuit breakers, route planner, limits, warm-up, sender policy | merged | 343 tests |
| Webhooks library (Standard Webhooks signing, SSRF guard, dispatcher) | merged | 63 tests |
| Storage contracts, in-memory backend, SQLite backend, shared conformance suite | merged | 240 + 417 tests incl. SIGKILL crash recovery in every sync mode |
| Observability (meters, Prometheus text, health) | merged | 4 tests |
| Bundle format and secret protection | merged | 12 tests |
| Certificates in the database, ACME renewal service | merged (ACME **not verified against a real server**) | host tests |
| Host primitives: configuration loader, password hashing, API keys, auth throttle, domain record planner and checker | merged | 47 tests |
| Dashboard SPA (Preact + Vite) | merged (**not run in a real browser**) | 371 tests against a mock API |
| Delivery engine: grouping, MX/relay routes, TLS policy, DKIM signing at delivery, VERP return path, retry/hold/expiry, DSN generation, quiesce | this PR | 13 end-to-end tests over loopback with in-memory storage |
| SMTP ingest (AUTH, sender policy, submission service, bounce listener, bounce/complaint processing) | this PR | 8 loopback tests with MailKit |
| Host composition: Data Protection key ring in the config store, runtime wiring (SMTP, delivery, webhooks, certificates/ACME, maintenance), `mta` CLI (`serve`, `migrate-db`, `--healthcheck`, `--version`), dashboard static hosting with strict headers | this PR | 3 secrets tests, 2 full-pipeline integration tests on the SQLite backend, manual smoke run of the real process (healthz, SMTP banner, graceful shutdown) |
| PostgreSQL backend (EF Core + Npgsql: day partitions, `SKIP LOCKED` claim, owner/runtime roles, advisory-locked maintenance, outage handling) | this PR | 266 tests against a real PostgreSQL 18.6 and 16.13: the whole shared conformance suite, three-backend equivalence, multi-replica claims, partitions and interrupted detach, role-permission split, migrator, outages |
| HTTP API (docs/api.md): auth (API keys, dashboard sessions, CSRF, roles), errors, sending, messages, domains, suppressions, webhooks, credentials, statistics, settings, admin, operational endpoints | this PR, wired into `mta serve` (`Hosting/ApiHosting.cs`) (**not run against a real dashboard in a browser; DNS, ACME and the switch engine are faked in tests**) | 287 host tests over TestHost with in-memory and SQLite storage, incl. contract tests against `dashboard/src/api/types.ts`; manual smoke run of `mta serve` on Kestrel with curl (sign-in, CSRF, tenant, key, domain, 403/413 problems, `/readyz`, `/metrics`) |
| Domain verification service (scheduler over the planner/checker and `VerificationSchedule`, DKIM rotation, sending-paused semantics) | this PR (hosted service registered by `AddEggMailApi`) | host tests with a controllable clock and DNS |
| TLS-RPT: session recording in the delivery engine (MTA-STS/DANE domains only), daily report sender (HTTPS POST or mailto through the normal queue; retries in memory) | this PR | 7 recorder tests, 2 sender tests; **not verified against a real reporting endpoint** |
| Chaos pipeline test: randomized refusals, greylisting and cut connections after end-of-data against an unreliable remote; invariants: one final state per recipient, no loss, duplicates only when flagged `possible_duplicate`, bounces explained and suppressed | this PR | runs in `dotnet test` (about 150 messages, 3 s); `EGGMAIL_CHAOS_MESSAGES` / `EGGMAIL_CHAOS_SEED` scale it (25 consecutive 1,000-message runs passed) |
| Scheduled SQLite backups with retention (`Backup:*`), operations guide | this PR | 3 backup tests (consistent copy opens, interval and retention, unrelated directories untouched) |
| Pipeline benchmark harness (`bench/Mta.Bench.Pipeline`) with allocation sampler; first profile fixed two hot spots (domain query per message, extra copies) | this PR | development-time numbers only (noisy machine); allocation budget **not met** yet, see `docs/benchmarks.md` |
| Stored settings layer (decision N layer 4): global settings from `/admin/settings` apply at the next start below every deployment layer; the storage is reopened when they change its options | this PR | 4 tests (filtering, precedence, reopen, invalid stored value ignored) |
| `mta admin create` and `mta migrate-storage` commands (`admin create` can now use `DashboardAccounts`; `migrate-storage` needs the switch engine) | not started | |
| Backend switch engine (export/import, quiesce, fence, activation, rollback, history migration) | not started | |
| DMARC aggregate report sending | not started | |
| Soak, fuzz and benchmark gates; external security audit | not started | |

## Not verified / known gaps

- HTTP API: tested in process only (TestHost); no real browser, no Kestrel, no reverse proxy. Per-record DNS check results are remembered in memory only (after a restart, or on another replica, a verified domain shows its required records as `ok` and the rest as `pending` until the next check). Global settings written through `/admin/settings` are stored but not yet applied by the runtime at startup (it reads deployment configuration only); the webhook allowlist is the exception and is read live (cached 30 s). Message `tags` are validated but not stored (no storage for them yet). `IStorageSwitchService` has no engine: the endpoints answer 503 `not_ready`. Domain verification and key rotation are serialized per process only (several replicas can race).
- AcmeRenewalService: a renewal used to insert a second row with the same unique certificate name and fail; it now replaces the row (found while testing the API; no test existed for renewal).
- **GitHub Actions is disabled for the repository by the organization**, so the CI workflow and the release workflow cannot run. Pull requests are merged after a full local `dotnet test` and review passes; the workflows are written but unproven on GitHub. Owner action: allow Actions for `eggspot/EggMail` ([open-questions.md](open-questions.md)).
- Docker image build and GHCR publish can only run in GitHub Actions (no Docker is used locally).
- No real-internet MX delivery has been tested; no independent security audit has been done.
- Delivery engine: state of throttles, circuit breakers and sending counters is per process (documented in [components/policy.md](components/policy.md)); sending counters and warm-up are in memory.
- TLS-RPT: pending reports are retried from memory only (a restart loses them); the collected counters are in memory too.
- Async bounces are correlated to the tenant through the VERP token and to the message through the `Message-ID` in the returned headers only for the webhook payload; they are not attached to the message's history events.
- One flaky test was seen once under heavy parallel load (`Mta.Dkim` timing-sensitive test); not reproduced when run alone.

## Design-forced changes recorded in code

- `DeliveryAttempt.CountAttempt` (local holds do not count as attempts).
- `IWebhookOutbox.EnqueueAsync` (events that are not tied to a delivery attempt: asynchronous bounces, complaints).
- The VERP token carries the sending domain's id; the bounce domain and per-domain return-path host are configuration.
- API keys have a fixed positional layout (`egm_` + 8 character id + `_` + 43 character secret); a syntax check by counting underscores was wrong because base64url can contain `_`.
