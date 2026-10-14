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
| Dashboard SPA (Preact + Vite) | merged (real headless Chrome smoke run: pages render under the strict CSP and sign-in works; write flows and the switch wizard were not driven) | 371 tests against a mock API |
| Delivery engine: grouping, MX/relay routes, TLS policy, DKIM signing at delivery, VERP return path, retry/hold/expiry, DSN generation, quiesce | merged | 13 end-to-end tests over loopback with in-memory storage |
| SMTP ingest (AUTH, sender policy, submission service, bounce listener, bounce/complaint processing) | merged | 8 loopback tests with MailKit |
| Host composition: Data Protection key ring in the config store, runtime wiring (SMTP, delivery, webhooks, certificates/ACME, maintenance), `mta` CLI (`serve`, `migrate-db`, `--healthcheck`, `--version`), dashboard static hosting with strict headers | merged | 3 secrets tests, 2 full-pipeline integration tests on the SQLite backend, manual smoke run of the real process (healthz, SMTP banner, graceful shutdown) |
| PostgreSQL backend (EF Core + Npgsql: day partitions, `SKIP LOCKED` claim, owner/runtime roles, advisory-locked maintenance, outage handling) | merged | 266 tests against a real PostgreSQL 18.6 and 16.13: the whole shared conformance suite, three-backend equivalence, multi-replica claims, partitions and interrupted detach, role-permission split, migrator, outages |
| HTTP API (docs/api.md): auth (API keys, dashboard sessions, CSRF, roles), errors, sending, messages, domains, suppressions, webhooks, credentials, statistics, settings, admin, operational endpoints | this PR, wired into `mta serve` (`Hosting/ApiHosting.cs`) (**not run against a real dashboard in a browser; DNS, ACME and the switch engine are faked in tests**) | 287 host tests over TestHost with in-memory and SQLite storage, incl. contract tests against `dashboard/src/api/types.ts`; manual smoke run of `mta serve` on Kestrel with curl (sign-in, CSRF, tenant, key, domain, 403/413 problems, `/readyz`, `/metrics`) |
| Domain verification service (scheduler over the planner/checker and `VerificationSchedule`, DKIM rotation, sending-paused semantics) | merged | host tests with a controllable clock and DNS |
| TLS-RPT: session recording in the delivery engine (MTA-STS/DANE domains only), daily report sender (HTTPS POST or mailto through the normal queue; retries in memory) | merged | 7 recorder tests, 2 sender tests; **not verified against a real reporting endpoint** |
| Chaos pipeline test: randomized refusals, greylisting and cut connections after end-of-data against an unreliable remote; invariants: one final state per recipient, no loss, duplicates only when flagged `possible_duplicate`, bounces explained and suppressed | merged | runs in `dotnet test` (about 150 messages, 3 s); `EGGMAIL_CHAOS_MESSAGES` / `EGGMAIL_CHAOS_SEED` scale it (25 consecutive 1,000-message runs passed) |
| Scheduled SQLite backups with retention (`Backup:*`), operations guide | merged | 3 backup tests (consistent copy opens, interval and retention, unrelated directories untouched) |
| Pipeline benchmark harness (`bench/Mta.Bench.Pipeline`) with allocation sampler; first profile fixed two hot spots (domain query per message, extra copies) | merged | development-time numbers only (noisy machine); allocation budget **not met** yet, see `docs/benchmarks.md` |
| Stored settings layer (decision N layer 4): global settings from `/admin/settings` apply at the next start below every deployment layer; the storage is reopened when they change its options | merged | 4 tests (filtering, precedence, reopen, invalid stored value ignored) |
| Sending caps from configuration (`Sending:*`, tenant overrides `Sending:PerHour/PerDay`, optional domain warm-up from the day a domain was added), refreshed every 30 s | merged | 2 tests; counters stay in memory (a restart resets the current hour/day) |
| `mta admin create` command (offline account creation); CI runs the dashboard checks in the same job (**CI has never run**) | merged | 2 tests |
| DMARC aggregate report sending | not applicable: EggMail is an outbound sender and receives no mail to report on (the report writer exists in `Mta.Auth`) | |
| Backend switch engine (export/import, drain/quiesce, fence, marks, activation gate, bootstrap/cutover-patch activation, rollback, resumable history migration, secrets re-protection) for in-memory, SQLite and PostgreSQL; startup gate; `mta migrate-storage` | merged | transfer conformance on all backends, end-to-end switches InMemory/SQLite/PostgreSQL in both directions and both history modes, quiesce with a real delivery engine, tamper and resume tests, CLI flow, process-control tests; throughput measured ([components/switch.md](components/switch.md)); admin API endpoints (`/admin/storage/switch/*`) over the engine; **no dashboard flow yet; not applied to a real orchestrator** |
| 14-minute soak, DoS probes, crash and restore drills, independent-client interop (see the section below) | done once on one laptop | manual runs, results below |
| 7-day soak, real-internet delivery, Gmail DKIM check, ACME against a real CA, external security audit, publishable benchmarks | **not done** (owner or external systems) | see "Not verified" |

## Not verified / known gaps

Verified by GitHub Actions now (run `ci` on every pull request and on `main`): build with warnings as errors, all test projects against a PostgreSQL 17 container, the ACME tests against the Pebble test CA, the Playwright end-to-end tests of the dashboard against the real server, the dashboard unit tests, CSP and package-free checks, the deployment manifests (`kustomize` + `kubeconform`). `release` builds and pushes the multi-arch image (digest first, then tags), smoke-tests the pushed digest (container health, `--version`, authenticated SMTP submission to the queue, API, PostgreSQL compose, SQLite compose, Unbound sidecar, a kind cluster), and attests it. `fuzz` (weekly and on demand) runs coverage-guided fuzzers for the parsers; `bench-gate` compares allocation per message against a checked-in baseline.

What is still not verified or not done:

- **Needs the owner or a real external system (cannot be done by the build):** delivery to real internet MX servers and Gmail/Outlook DKIM/SPF/DMARC acceptance; ACME against a real CA (Pebble only) and the real Cloudflare API; an independent security audit; the 7-day soak (one 14-minute soak was run); a real cloud KMS provider (a pluggable key-wrap interface and a local-key provider exist); publishable benchmark numbers on a quiet dedicated Linux host (GitHub-hosted runner numbers are labelled noisy); creating a real GitHub Release (needs a tag); the first scheduled `nightly` run. See [open-questions.md](open-questions.md).
- **Allocation budget:** the whole ingest path allocates about 4.8 KB per message with a tiny body and about 10 KB with a 2 KB body, against the 2 KB budget (the SMTP server path alone is 1.1 KB). Further savings need structural changes listed in [benchmarks.md](benchmarks.md).
- **Per-process state:** throttles, circuit breakers and the failed-login budget are per process (several replicas multiply them). Sending counters, TLS-RPT state, DNS check results, and domain/key operations are persisted and coordinated through the storage (leases); see [components/policy.md](components/policy.md).
- **Outbound mail:** 8BITMIME and SMTPUTF8 are handled (conversion with DKIM over the transmitted bytes, refusals as 5.6.x). RFC 6857 header downgrading, BINARYMIME (RFC 3030), REQUIRETLS and a capability-driven fall back to a relay route are not implemented ([components/delivery.md](components/delivery.md)).
- **Admin surface not yet built:** write paths (API and dashboard) for relay routes and per-domain TLS policy, management of dashboard users while the server runs, and cancelling a queued message; ACME Renewal Information (ARI), HTTP-01/TLS-ALPN-01 challenges, other DNS providers and EAB (DNS-01 with Cloudflare only, by design decision 19).
- **Not driven in a browser:** the domain states `temporary_failure` and `failed` (unit-tested only); other browsers than Chromium.
- Header downgrade and the other items above are recorded in the component documents.

## Design-forced changes recorded in code

- `DeliveryAttempt.CountAttempt` (local holds do not count as attempts).
- `IWebhookOutbox.EnqueueAsync` (events that are not tied to a delivery attempt: asynchronous bounces, complaints).
- The VERP token carries the sending domain's id; the bounce domain and per-domain return-path host are configuration.
- API keys have a fixed positional layout (`egm_` + 8 character id + `_` + 43 character secret); a syntax check by counting underscores was wrong because base64url can contain `_`.

## Hardening done after interop and drills (2026-10-13)

- **Interop with independent clients found a real bug:** Python's `smtplib` failed its first STARTTLS after every cold start (8 of 8 on `main`) because the 220 reply was sent while the plaintext reader was still running; fixed and covered by a deterministic regression test (PRs #46, #54). `openssl s_client -starttls smtp` and `smtplib` (AUTH, 2.4 MB attachment, UTF-8 subject, spoofed From refused) now pass; outbound delivery was checked against Python's `smtpd` as the remote peer (DKIM-signed, VERP sender, one transaction for two recipients).
- **Soak, 14 minutes, real process, SQLite `Off`, history `Full`:** 3.17 million messages accepted at about 3,770 msg/s (P99 8.3 ms) and delivered to a sink at the same time; the sink received exactly what was accepted; memory stayed at 396 to 412 MB, file descriptors and threads flat, no errors in the log. This is a short run on one laptop, not the 7-day soak of the plan.
- **DoS probes against the real process:** 400 connections from one address (100 greeted, 300 refused), a 100 KB command line (`500 Line too long`), 150 slow-loris connections, a stranger recipient on the bounce listener (`550`): memory flat (191 to 197 MB), the server stayed healthy.
- **Crash drill:** `kill -9` during load, restart: every acknowledged message was delivered; deliveries in flight at the kill were sent again (at-least-once). They were **not** flagged `possible_duplicate`; now a delivery reclaimed from a lease whose holder never reported is flagged (storage conformance on all three backends).
- **Delivery robustness:** a group that fails before sending is handed back at once instead of waiting out a 15 minute lease; recording a result is retried; a result that cannot be recorded is never handed back (it would be sent twice).

## Final verification of this session

A fresh clone of `main` builds with 0 warnings and all 21 test projects pass (including the PostgreSQL suite against a local PostgreSQL 18). Several tests are timing-sensitive under heavy parallel load; failures seen once and not reproduced are noted in the PR descriptions.

## CI, release and review hardening (2026-10-14)

- GitHub Actions is enabled and green on `main`. Root causes found and fixed from the first failing runs: a test proxy that parsed a host name as an IP, a race between a bounce and its recorded suppression, PostgreSQL `max_connections` exhausted by parallel test projects, two test assemblies dropping each other's template database, heap-size and back-pressure tests that raced, switch tests too slow for a loaded runner, a flaky Dkim performance test (wall-clock assertion), and a real ACME bug (a valid authorization reused by the CA was challenged again and refused).
- The first release dispatch failed on an invalid build version (`nightly-<sha>`); fixed, and a branch dispatch published `ghcr.io/eggspot/eggmail:nightly-<sha>`. The package is public (anonymous pull works).
- Every large pull request was reviewed by an independent reviewer in two passes; findings fixed before merge included a MIME boundary forgery in the 8-bit downgrade, recipient addresses leaking into exported spans, a KMS-key mismatch surfacing only at first use, user cancellation reported as database outage, and a tag run able to publish `latest` from a dispatch.
