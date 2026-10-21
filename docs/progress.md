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
| DMARC aggregate report sending | to be wired by the inbound work: the report writer exists in `Mta.Auth`, but the data is the outcome of evaluating received mail, which EggMail does not receive yet | |
| Backend switch engine (export/import, drain/quiesce, fence, marks, activation gate, bootstrap/cutover-patch activation, rollback, resumable history migration, secrets re-protection) for in-memory, SQLite and PostgreSQL; startup gate; `mta migrate-storage` | merged | transfer conformance on all backends, end-to-end switches InMemory/SQLite/PostgreSQL in both directions and both history modes, quiesce with a real delivery engine, tamper and resume tests, CLI flow, process-control tests; throughput measured ([components/switch.md](components/switch.md)); admin API endpoints (`/admin/storage/switch/*`) over the engine; **no dashboard flow yet; not applied to a real orchestrator** |
| 14-minute soak, DoS probes, crash and restore drills, independent-client interop (see the section below) | done once on one laptop | manual runs, results below |
| Soak harness (`bench/soak`, `.github/workflows/soak.yml`, [soak.md](soak.md)): real host, sink, `kill -9` and backup drills, 19 criteria | merged; short runs only | runs of 6 to 20 minutes per backend, locally and on a hosted runner, all PASS; **no multi-hour run yet** |
| Offline test families: fake remote MTAs, ACME and Cloudflare doubles, independent DKIM/SPF/DMARC fixtures, accelerated lifecycle and leak tests, the in-house security review as tests ([testing-offline-coverage.md](testing-offline-coverage.md), [security-test-map.md](security-test-map.md)) | merged | `Mta.RemoteMta.Tests`, `Mta.Authentication.Tests`, `Lifecycle`/`Leak` families, security regression tests; they found and fixed real defects (5 delivery bugs, 12 lifecycle defects, the security-map findings); they prove behaviour against doubles, not against the real internet |
| 7-day soak, real-internet delivery, Gmail DKIM check, ACME against a real CA, external security audit, publishable benchmarks | **not done** (owner or external systems) | see "Not verified"; the steps are in [go-live-checklist.md](go-live-checklist.md) (the soak step uses `bench/soak` and [soak.md](soak.md)) |
| Plan coverage audit (every plan component, delta, gate and cut item against code and tests) | done 2026-10-15 | see [Plan coverage](#plan-coverage): found libraries not wired into the runtime, a forged-bounce suppression hole and four smaller gaps; fixed in PRs 89, 90, 91 (decisions 91 to 93) |

## Not verified / known gaps

Verified by GitHub Actions now (run `ci` on every pull request and on `main`): build with warnings as errors, all test projects against a PostgreSQL 17 container, the ACME tests against the Pebble test CA, the Playwright end-to-end tests of the dashboard against the real server, the dashboard unit tests, CSP and package-free checks, the deployment manifests (`kustomize` + `kubeconform`). `release` builds and pushes the multi-arch image (digest first, then tags), smoke-tests the pushed digest (container health, `--version`, authenticated SMTP submission to the queue, API, PostgreSQL compose, SQLite compose, Unbound sidecar, a kind cluster), and attests it. `fuzz` (weekly and on demand) runs coverage-guided fuzzers for the parsers; `bench-gate` compares allocation per message against a checked-in baseline.

What is still not verified or not done:

- **Needs the owner or a real external system (cannot be done by the build):** delivery to real internet MX servers and Gmail/Outlook DKIM/SPF/DMARC acceptance; ACME against a real CA (Pebble only) and the real Cloudflare API; an independent security audit; the 7-day soak (one 14-minute soak was run); a real cloud KMS provider (a pluggable key-wrap interface and a local-key provider exist); publishable benchmark numbers on a quiet dedicated Linux host (GitHub-hosted runner numbers are labelled noisy); creating a real GitHub Release (needs a tag); the first scheduled `nightly` run. See [open-questions.md](open-questions.md).
- **Allocation budget:** the whole ingest path allocates about 4.8 KB per message with a tiny body and about 10 KB with a 2 KB body, against the 2 KB budget (the SMTP server path alone is 1.1 KB). Further savings need structural changes listed in [benchmarks.md](benchmarks.md).
- **Replicas (PostgreSQL):** the failed-login budget, per-destination connection/rate ceilings and peer circuit/back-off signals are shared between live replicas through the database (decision 82, proven by multi-runtime tests including a two-replica chaos run); sending counters are eventually consistent (about one flush interval); `SendBudget` and SMTP connection limits stay per process by design. The timings (5 s heartbeat, 20 s liveness) are proposals, not tuned against a real multi-node deployment. Builds older than schema version 6 take no part in the coordination during a rolling update.
- **Outbound mail:** 8BITMIME and SMTPUTF8 are handled (conversion with DKIM over the transmitted bytes, refusals as 5.6.x). RFC 6857 header downgrading, BINARYMIME (RFC 3030), REQUIRETLS and a capability-driven fall back to a relay route are not implemented ([components/delivery.md](components/delivery.md)).
- **Admin surface (done, merged):** relay routes and per-domain TLS policy (API and dashboard), dashboard user management with last-admin protection, cancelling a queued message or recipient (`message.cancelled` webhook), ACME Renewal Information (ARI). Not built: a "must change password at next sign-in" flag, an audit table (changes are structured log lines), HTTP-01/TLS-ALPN-01 challenges, other DNS providers than Cloudflare and EAB (DNS-01 with Cloudflare only, by design decision 19). Cancel latency and `CREATE INDEX` time on a queue of millions of rows at upgrade are unmeasured.
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

## Plan coverage

An audit of [plan.md](plan.md) against the **code and the tests** (first written 2026-10-15, brought up to date with `main` on 2026-10-18), not against the claims above. Method: for every component, delta and quality gate of the plan, find the code that implements it, check that the runtime actually calls it (a library with unit tests that nothing in `Mta.Host` or `Mta.Delivery` uses is "library only"), and name what verifies it. Nothing here was assumed from earlier progress notes; where the audit disagreed with them, the audit wins. *Verified by* names a test project (all run in the `ci` job `build-test` unless noted), a workflow, or says "manual" or "not verified". PR numbers are the fixes made as part of this audit (all merged; decisions 91 to 93 record them) or the changes by others that closed a gap since.

**Result in one paragraph.** The delivery pipeline, both storage backends, the switch engine, the API and the dashboard are implemented and exercised end to end by tests. Three families of gaps were found: (1) code that exists and is tested but is **not wired into the runtime** (SPF, DKIM verification, DMARC, ARC, Authentication-Results and DMARC reports are libraries only until the inbound mail support the owner has asked for gives them a caller; the MIME validator has none either; the per-domain return path was dead until PR 90; the storage-pressure indicator has no production source); (2) **behaviour the plan promised that was missing or wrong** (a forged bounce could suppress any address, BDAT bypassed the smuggling rule, disk-full was `451` not `452`, process-level metrics for the soak were absent); (3) **verification that cannot happen in CI** (real internet, real CA, real Cloudflare, power loss, the 7-day soak, the audit). The first two were fixed where they could be from a Mac and Actions; the third is the owner's list in [go-live-checklist.md](go-live-checklist.md).

Legend: **yes** implemented and wired; **partial** implemented with the gap named; **library only** has no caller in the runtime today (the ones marked *to be wired by the inbound work* get their caller from the inbound mail support the owner asked for); **no** not built.

### Components

| Plan item | Implemented? | Verified by | Gap |
|---|---|---|---|
| SMTP server: STARTTLS, implicit TLS, injection guard | yes | `Mta.Smtp.Server.Tests` (`TlsAndAuthTests`, `StarttlsRaceTests`), MailKit interop in `Mta.Host.Tests`, fuzz `smtp-session`; manual: `openssl`, Python `smtplib` | Real-network behaviour manual only |
| SMTP server: AUTH, SIZE, 8BITMIME, SMTPUTF8, PIPELINING | yes | `Mta.Smtp.Server.Tests`, `Mta.Smtp.Protocol.Tests` | AUTH is PLAIN and LOGIN only. PIPELINING is advertised and tolerated, not a setting. BINARYMIME is refused. `AllowInsecureAuth` untested |
| SMTP server: CHUNKING/BDAT | yes | `ServerProtocolTests` | **BDAT bodies skipped the bare CR/LF/NUL rule that DATA has: fixed in PR 91** (`LineEndingValidator`). No `Chunking=false` test, no BDAT oversize or timeout test |
| SMTP smuggling and STARTTLS-injection defence | yes | `DataScannerTests`, `ServerProtocolTests` (smuggling shapes, injection), `SmtpSmuggling` (PR 106: ten forged end-of-data variants, byte-per-write), fuzz `smtp-protocol`/`smtp-session`; mapped row by row in [security-test-map.md](security-test-map.md) | The design's external attack tools (smtpsmug, EAST) were not run against a deployed instance; the map is not an audit |
| SMTP server limits and timeouts | partial | `Overlong_line…`, `Command_timeout…`, `Data_timeout…`, per-IP and recipient limits | No test for `MaxDataDuration`, `TlsHandshakeTimeout`, `MaxInFlightBytes`, `MaxMessagesPerSession` or the global cap. Limits are shared across listeners (bounce traffic can use up the submission budget). The per-address limit keys on the exact address (no IPv6 /64). Several `SmtpServerOptions` have no configuration key |
| Bounce listener on port 25 | yes | `IngestTests`, `BounceTrustTests` | Default container port is 2526 (publish as 25). **A forged DSN or complaint could get any address suppressed for a tenant: fixed in PR 90** (token bound to the destination domain). Residual: per domain, not per address (decision 92) |
| **Inbound mail** (design section 11, decision 95): storage on all backends, retention, switch bundle 1.3, HTTP API with scopes `inbound:read`/`inbound:write` | yes (PRs 99, 100, 107, 103, 108, 110; schema version 10) | storage conformance on SQLite and PostgreSQL, API matrix and tenant-isolation tests, `InjectionConformance`, receive-path and route-action tests, dashboard unit and e2e tests (`inbound.spec.mjs`) | The receive path (PR 107), the route actions (PRs 103 and 108) and the dashboard pages with the advisory inbound MX record (PR 110) are in. The end-to-end tests on both backends (PR 112) are open. Never received mail from the real internet. Go-live: [go-live-checklist.md step 11](go-live-checklist.md#11-inbound-mail-go-live-once-the-inbound-pull-requests-are-merged). No IMAP or POP3 (open question) |
| Submission service, sender policy | yes | `SubmissionServiceTests`, `IngestTests`, `ApiMessagesTests` | None |
| SMTP client: STARTTLS policy, downgrade detection, AUTH, pipelining, BDAT, pool | yes | `Mta.Smtp.Client.Tests`, `Mta.Integration.Tests`, and since PR 105 `Mta.RemoteMta.Tests` (194 tests: the real delivery engine against a fake MTA with Gmail, Outlook, Postfix and Exim personalities, greylisting, throttling, 16 refusal shapes, garbage, silence, FIN and RST) | The personalities follow public documentation; they are **not captured traffic**, and no real Postfix, Exim or Haraka was used in CI (manual Python `smtpd` once). No REQUIRETLS, no RFC 6857 header downgrade. `SmtpRemoteTarget.LocalAddress` is never set, so no multi-IP sending |
| MIME: parse, build, edit, extract | yes | `Mta.Mime.Tests` (26 files; MimeKit differential on 15 messages plus random structures), fuzz `mime` | `MessageValidator` is library only (used by tests and the fuzz target) |
| DKIM: RSA-2048 signing at delivery, rotation | yes | `Mta.Dkim.Tests` (MimeKit interop), `Mta.Authentication.Tests/DkimCrossCheckTests` (PR 105: 15 message shapes x 4 canonicalizations judged by four independent readers including `openssl` and a from-scratch RFC 6376 implementation that must reproduce `b=` byte for byte), `DeliveryDkimAndLimitsTests`, `ApiDomainsTests` | A key that cannot be read sends the message **unsigned** with a warning (G14). Retired signers are not purged from the cache. Bounce and TLS-RPT mail is unsigned. "Verifies at Gmail" is manual (go-live step 3) |
| DKIM verify, `l=` handling | library only, to be wired by the inbound work | `VerifierTests`, fuzz `dkim` | No inbound mail to verify yet |
| DKIM Ed25519 (cut item 1) | no | none | RSA only, by decision |
| SPF | library only, being wired by the inbound work (PR 107 reads it on the receive path) | `SpfEvaluatorTests`, `Rfc7208AppendixATests` (the RFC's own DNS and verdicts, PR 105), fuzz `spf` | Not called by the runtime on `main` until PR 107 merges |
| DMARC evaluate, public suffix list | library only, being wired by the inbound work (PR 107) | `DmarcEvaluatorTests`, `Rfc7489ExampleTests` (RFC 7489 section 3 examples), `PublicSuffixListTests` | Static suffix list without refresh; not called by the runtime on `main` until PR 107 merges |
| DMARC aggregate reports (cut item 3) | library only, to be wired by the inbound work | `Mta.Auth.Tests/Reports`, fuzz `dmarc-aggregate` | Nothing feeds the collector or sends a report: the data is the outcome of evaluating inbound mail, which the inbound work will produce |
| ARC (cut item 1) | library only, to be wired by the inbound work | `ArcRoundTripTests`, `ArcTamperTests`, MimeKit cross-check | Not called at ingest or delivery yet |
| Authentication-Results builder and parser | library only, being wired by the inbound work (PR 107) | tests, `AuthenticationResultsFixtureTests` (17 receive-side scenarios, PR 105), fuzz `auth-headers` | Not called by the runtime on `main` until PR 107 merges |
| DSN generation | partial | `DsnBuilderTests`, `DeliveryEndToEndTests` | Failure DSNs only (no delayed DSN). NOTIFY, RET, ORCPT, ENVID are parsed and ignored |
| DSN/ARF parse, suppression on bounce or complaint, VERP | yes | `InboundReportParserTests`, `IngestTests`, `AsyncReportHistoryTests`, `VerpTests`, fuzz `dsn-arf` | VERP key has no rotation and is stored as plain JSON in settings. No fuzz target for `VerpCodec.TryDecode`. "Bounces correlate end to end" has no single test through a real remote's DSN |
| Per-domain return path (`bounce.<domain>`) | **yes since PR 90** | `DeliveryDkimAndLimitsTests`, `IngestTests` | Was required and verified but ignored on the wire (`SelectReturnPath` had no caller), so SPF could never align with the From domain. Real MX resolution through the CNAME is manual |
| List-Unsubscribe, RFC 8058 one-click | no | none | Not in the plan. Gmail and Yahoo require it from bulk senders: set the headers per message through the API (go-live step 3) |
| DNS client: codec, resolver, EDNS, TCP fallback, cache, MX | yes | `Mta.Dns.Tests` (203), fuzz `dns-message` | Packets are hand-built; "round-trips real packets" (phase 1 gate) is not met. A live-DNS test is skipped unless `EGGMAIL_TEST_LIVE_DNS=1`, which CI never sets. Three different `IdnMapping` settings in three assemblies |
| DNSSEC AD bit, Unbound sidecar (cut item 8) | partial | `DnsClientTests`; `release.yml` smoke (AD flag for a signed name, SERVFAIL for a broken one) | Off by default (`Dns:TrustAuthenticatedData=false`); no end-to-end DANE delivery test |
| IDN, UTS#46 tables (cut item 10) | no own tables | `UnicodeSelfTestTests` | ICU only; no IdnaTest corpus |
| MTA-STS (consume and serve) | yes | `Mta.Tls.Tests`, fuzz `mta-sts`; since PR 105 `Mta.RemoteMta.Tests` runs the real policy fetcher against a TLS policy web server with a private CA (enforce delivers over verified TLS, defers on a bad certificate or no STARTTLS, never contacts an unlisted MX, never falls back to plaintext); serving a policy for a registered domain (`Domains:MtaStsMode`, PR 96) is tested over `TestHost` (`MtaStsPolicyServingTests`) | Cache is in memory. Real senders' and real receivers' policies are manual. The bounce domain is not a registered domain, so its policy is published by hand (go-live 2.5) |
| TLS-RPT (record, collect, journal, daily send, cut item 2) | yes | `TlsRptTests` (29), `TlsReportSenderTests`, `MultiReplicaTlsReportTests` | **Not verified against a real reporting endpoint** (go-live step 5). Report mail is unsigned |
| DANE (cut item 8) | yes, behind a flag | `DaneTlsaLookupTests`, `DaneVerifierTests`, and since PR 105 end to end against the fake MTA (DANE-EE on a self-signed certificate, no DANE when the MX set is not DNSSEC-validated, DANE taking precedence over MTA-STS) | Off by default (`Dns:TrustAuthenticatedData`); no real TLSA records; the AD bit comes from the fake resolver in tests |
| Delivery scheduler: claim, lease, retry, classify, `possible_duplicate`, quiesce | yes | `DeliveryEndToEndTests`, `ChaosPipelineTests`, `MultiReplicaTests`, `RetryScheduleTests` | `ReplyClassifier.Default` only |
| Destination throttle | partial | `DestinationThrottleTests`, `MultiReplicaTests` | `MaxMessagesPerConnection` is read but never enforced (documented as reserved in PR 91). One token per message group rather than per message. No engine-level throttle-hold test |
| Circuit breakers, route planner, relay routes | yes | `RoutePlannerTests`, `RouteHealthTests`, `RoutingConfigDeliveryTests` | No engine-level breaker test; breaker and throttle state are not exposed |
| Warm-up | partial | `SendingLimitsTests`, `SendingConfiguratorTests` | Default schedule only; old domains graduate at once; usage not visible |
| Operator hold, release, retry-now | no | none | Only cancel exists |
| Webhooks: outbox, dispatcher, signing, endpoint disabling | yes | `WebhookConformance` on all three backends, `Mta.Webhooks.Tests`, PW `webhooks.spec` | The 5-day `DisableAfter` branch is untested; retry delays are checked by binding only |
| Webhook SSRF guard | yes | `SsrfGuardTests`, `UrlValidatorTests` | **A proxy in the environment would have bypassed it: fixed in PR 91.** A real connect to a blocked address ending as `ssrf_blocked` is untested. `AllowHttp` is enforced at registration only |
| Webhook replay: API and UI (cut item 5) | yes | `ApiSuppressionsAndWebhooksTests`, PW | The attempts API returns `eventType` null, so that column never shows against a real server |
| HTTP API | yes | `Mta.Host.Tests/Api` (20 classes incl. TypeScript contract), PW | No test compares `docs/api.md` with the mapped routes. No per-key request throttle. No forwarded-header handling behind a TLS-terminating proxy |
| Domain verification | yes | `DomainVerificationTests`, `ApiDomainsTests`, PR 96's record tests | Since PR 96 SPF is judged by evaluating the record against the sending address, and the zone file, `mta domains check` and `Domains:Bootstrap` exist; DNS itself is still faked in tests |
| Security: hashing, throttle, secrets, headers, CSP | yes | `SecurityTests`, `SecretsTests`, `KeyWrappingTests`, `DashboardHostingTests`, CI `check-csp`, PW `csp-pages.spec` | Only a local-key KMS provider. No Permissions-Policy header |
| OWASP ASVS L2 checklist (phase 4 gate) | no | not verified | No checklist and no mapped tests: part of the external audit scope (go-live step 6) |
| Observability: meters, Prometheus, OTLP, health | yes | `PrometheusTests`, `ApiMetricsScrapeTests`, `MetricsDocumentationTests` | **No process-level metrics for the soak: added in PR 89.** No API request metrics; no webhook outbox depth gauge; `soft_bounce` and `rejected` statistics are never incremented but are returned as zero columns |
| Storage-pressure indicator | UI only | stub in `ApiAdminTests` | `IStoragePressureSource` has no production implementation, so `/admin/status` never carries `pressure` and the dashboard shows nothing. Open, size S-M |
| `synchronous=OFF` warning (log, banner, metric, health) | yes | `Mta.Storage.Sqlite.Tests`, `warningBanner.test.tsx`, PW `auth.spec` | None |
| Dashboard | yes | 35 vitest files, 13 Playwright specs in CI | Domain states `temporary_failure` and `failed` unit-tested only; Chromium only; the guided switch flow (cut item 4) and polish (11) were not cut |
| Storage: content split, spool, `history.db`, retention, `0` = unlimited | yes | conformance suites on three backends, `LogicTests`, `MaintenanceConformance` | Writer tuning keys are not bound to configuration |
| `IStatsStore`, rollups, caps, tenant views | partial | `StatsConformance` on three backends | `soft_bounce`/`rejected` never counted; the all-tenants query is never called |
| `History:Mode` gating, `410 history_not_recorded` | yes | `ApiMessagesTests`, `EquivalenceTests` | None |
| Corruption detection, quarantine, `VACUUM INTO` backups | yes | `QuarantineTests`, `MaintenanceAndBackupTests`, `BackupSchedulerTests` | Corruption is simulated by garbling files; **OS-crash and power-loss fault injection does not exist** (only SIGKILL). No restore command, only the documented copy |
| Writer and crash tests | partial | `WriterTests` (800 concurrent accepts), `CrashRecoveryTests` (SIGKILL in Off, Normal, Full) | Modest scale; nothing kills a process during delivery |
| Disk-full behaviour (risk 14) | yes since PR 91 | `StorageFullTests`, `IngestDiskFullTests` | Was `451`; now `452 4.3.1`. A real full disk and a free-space metric are not built |
| PostgreSQL provider | yes | `Mta.Storage.Postgres.Tests` (266, PostgreSQL 17 in CI), `MultiReplicaTests` | Postgres tests skip when no server is found; **CI now fails instead (PR 89)** |
| Switch engine, CLI, admin API, history migration, quiesce, secrets, cutover | yes | `Mta.Storage.Portability.Tests`, `SwitchActivatorTests`, `ApiStorageSwitchTests`, PW `storage-switch.spec` | Postgres round trip, CLI on Postgres and the Postgres-to-SQLite UI path are not covered. **The image pinned the storage pointer through `ENV`, so the quick start could only print a cutover patch: fixed in PR 89** |
| Guided dashboard switch (cut item 4) | yes | vitest, PW (SQLite to PostgreSQL, drain) | Not cut. No quiesce or Postgres-to-SQLite through the UI |
| Certificates and ACME in the database, hot reload, ARI, HTTP-01 and EAB (decision 87, PR 94) | yes | `Mta.Integration.Tests.Acme` against Pebble in CI (DNS-01, HTTP-01, a second Pebble that requires EAB), `Mta.Host.Tests/Acme` (PR 104: a mock CA and a fake Cloudflare; the bugs they found are fixed, listed in [testing-offline-coverage.md](testing-offline-coverage.md)), `AcmeHotSwapTests`, `TlsMaterialTests`, `AcmeRenewalInfoTests` | **No real CA, no real Cloudflare, no real port 80** (go-live step 4). Renewal is tested by advancing the clock, not by real expiry. A 5xx on the order that carries `replaces` falls back to a plain order (PR 97, after the Pebble ordering race found while fixing CI) |
| Packaging: Dockerfile, Compose, Kubernetes | yes | CI static checks (`compose config`, `kustomize`, `kubeconform`), `release.yml` smoke tests | Runtime smoke tests run in `release.yml`, not on pull requests |
| Release automation | yes | `release.yml` manual run published `nightly-<sha>` | **No tag has ever been pushed**: GitHub Release creation, `latest` and the scheduled nightly have never run |
| Glue: configuration loader, layers, CLI | yes | `ConfigTests`, `ConfigurationDocumentationTests`, `CliTests` | Some options are fixed at defaults (DSN switches, `DefaultTls`, many SMTP server options, SQLite writer tuning) |
| Test infrastructure | yes | 22 test projects, `Mta.ArchitectureTests` (package-free guard over 10 projects) | `Mta.Policy` and `Mta.Delivery` are outside the guard (they are allowed packages) |
| Performance: harness, load generator, allocation gate | partial | `bench-gate.yml` (weekly), `bench-throughput.yml` (manual) | Since PR 98 (decision 89) the 2 KB budget is **met for the SQLite ingest path** (1.72 KB per 200-byte message, stored copy of the message excluded) and its wording is exact; it is not met for PostgreSQL (22 KB, no gate) or the delivery path. Gate covers SQLite ingest only. Postfix and KumoMTA comparison was never run |
| Docs and runbooks | partial | `MetricsDocumentationTests`, `ConfigurationDocumentationTests` | Runbooks were single paragraphs; [go-live-checklist.md](go-live-checklist.md) now holds deploy, restore, rollback and release procedures. No ASVS document |

### Phase quality gates

| Phase | Gate | Status |
|---|---|---|
| 0 | Smuggling and STARTTLS-injection suites pass | Met for DATA; BDAT met by PR 91 |
| 0 | Benchmark baseline recorded | Allocations only (no throughput or competitor baseline) |
| 0 | CI guard on package references | Met |
| 1 | Fuzzers clean for a time budget | Workflow exists (weekly); no recorded clean run; the client assembly is not instrumented; no target for `VerpCodec`, `DaneVerifier`, `EightBitDowngrader`, `MessageBuilder` |
| 1 | DNS codec round-trips real packets | Not met (hand-built packets) |
| 1 | Interop with Postfix, Exim, Haraka | Not verified against real servers; the fake-MTA lab (PR 105) reproduces documented Gmail, Outlook, Postfix and Exim behaviours, not captured traffic |
| 2 | Allocation and throughput budgets | Allocation: met for SQLite ingest since PR 98, not for PostgreSQL or delivery. Throughput: no published budget; numbers from a hosted runner are noisy |
| 2 | Interop matrix; DKIM verifies at Gmail | Not verified (owner: go-live step 3) |
| 3 | SPF, DMARC, DKIM match a reference implementation | DKIM against MimeKit, an independent RFC 6376 reader and `openssl` (PR 105); ARC against MimeKit; SPF and DMARC against the RFCs' own appendix examples (PR 105), not against a second implementation |
| 3 | MTA-STS and DANE against real policies | Against a fake MTA, a fake policy host and fake DNS (PR 105); not against real policies or records |
| 3 | Bounces correlate end to end | Partial |
| 4 | ASVS L2 checklist | Not done |
| 4 | Strict CSP verified | Met |
| 4 | ACME renewal through a forced expiry | Partial (clock advanced, Pebble) |
| 5 | Upgrade, restore, rollback drills | Rollback met (`SwitchSafetyTests`); SQLite restore tested; upgrade drill not automated; Postgres restore documented only; manual drill in go-live step 10 |
| 5 | Fresh single-container start | `release.yml` smoke only |
| 5 | Backend-switch drills both directions | Partial (see switch row) |
| 6 | No open critical or high findings | Not verified: no external audit |
| 6 | 7-day soak | Not done: the harness and its 19 criteria exist ([soak.md](soak.md)); runs so far are 6 to 20 minutes per backend |
| 6 | DoS suite within memory and CPU ceilings | Not verified: per-limit tests only |
| 6 | Runbooks reviewed | Written in the go-live checklist, not yet reviewed by anyone but the author |

### Cut order

| # | Item | State |
|---|---|---|
| 1 | ARC and Ed25519 | ARC library only (to be wired by the inbound work); Ed25519 not built |
| 2 | TLS-RPT sending | Built and wired |
| 3 | DMARC aggregate reports | Library only (to be wired by the inbound work) |
| 4 | Guided dashboard switch | Built |
| 5 | Webhook replay UI | Built |
| 6 | Benchmark baselines beyond Postfix and KumoMTA | Not built; Postfix and KumoMTA compose files never run |
| 7 | Per-send attachment flag | Built |
| 8 | DANE and Unbound | Built, off by default |
| 9 | Message view and resend | Built |
| 10 | UTS#46 tables | Not built (ICU) |
| 11 | Dashboard polish | Built |
| 12 | BDAT/CHUNKING | Built, on by default |

### What this audit fixed

| Gap | Fix | PR |
|---|---|---|
| A required `build-test` check would wait forever on a documentation-only pull request | `ci` always starts; documentation-only changes skip the work inside the job (decision 91) | 89 |
| PostgreSQL or Pebble missing in CI turned their tests into silent skips | `EGGMAIL_REQUIRE_EXTERNAL_TESTS=1` makes `ExternalDependenciesTests` fail | 89 |
| No process-level metrics for the 7-day soak | `Mta.Process` meter on `/metrics` and OTLP | 89 |
| Image `ENV` pinned the storage pointer; the quick start could never switch automatically | `ENV` removed (defaults identical), pinned by `DockerfileTests` | 89 |
| Flaky dashboard end-to-end stack: two listeners could get the same port | all ports allocated together (seen failing PR 89's first run) | 89, 90, 91 |
| Forged DSN or complaint suppressed any address for a tenant | VERP v2 bound to the destination domain (decision 92) | 90 |
| Per-domain return path required but unused on the wire | `SelectReturnPath` used by delivery; bounce listener accepts the verified host | 90 |
| BDAT bypassed the bare CR/LF/NUL rule | `LineEndingValidator` | 91 |
| Disk full answered `451` | `452 4.3.1` through `StorageFullException` | 91 |
| Webhook SSRF guard bypassable through a proxy environment | `UseProxy = false` | 91 |
| `MaxMessagesPerConnection` documented as working | documented as reserved | 91 |
| The `changed-code.sh` self-test failed on `main` because `GITHUB_EVENT_NAME=push` leaked into every case | the self-test is hermetic (clean environment per case, isolated repository configuration) and CI runs it a second time under the push environment | 101 |
| CI flakes seen on the way: the replica-liveness test used a 100 ms window, the outage test a 3 s connect timeout, ARI tests raced Pebble's order index | windows of seconds; 30 s timeout; PR 97 fixes the Pebble race at its source | 89, 91, 97 |
| G11: webhook attempts API returned `eventType` null | read from the outbox item when the log is listed (decision 106), conformance test on all backends | 116 |
| G15: `docs/api.md` not compared with the mapped routes | Route index in api.md checked in both directions by `ApiDocumentationTests`; three shorthand entries named routes that do not exist | 116 |

### What remains

Fixable from a Mac and Actions, **not yet done** (each is an entry in [open-questions.md](open-questions.md#plan-gaps-found-by-the-audit-open)): production storage-pressure source (S-M); configuration keys for the fixed-at-default options (M); engine-level tests for breaker skip and warm-up hold (M; the MTA-STS enforce, throttle ladder and greylisting scenarios exist since PR 105); Postgres switch coverage (M); fuzz targets for `VerpCodec`, `DaneVerifier`, `EightBitDowngrader`, `MessageBuilder` and the client assembly (S-M); VERP key rotation and protection (S-M); history-based confirmation of the recipient of a report (S-M, closes the residual of decision 92 for `History:Mode=Full`); ASVS L2 checklist (M-L; [security-test-map.md](security-test-map.md) maps threats to tests but is not an ASVS checklist); power-loss simulation (M-L); Ed25519 (M, cut item); List-Unsubscribe generation and one-click endpoint (M); delayed DSN and NOTIFY (M); the allocation budget (L); runtime use of SPF, DKIM verification, DMARC, ARC and Authentication-Results (L: this is the inbound work the owner has asked for, not a separate item).

Owner or external system only: everything in [go-live-checklist.md](go-live-checklist.md) (real-internet delivery and Gmail/Outlook/Yahoo results, PTR and port 25, ACME against a real CA and Cloudflare, TLS-RPT against a real endpoint, interop with real Postfix/Exim/Haraka, the independent security audit, the 7-day soak, the first tag and release, GitHub settings, cloud KMS, publishable benchmarks on a quiet host).
