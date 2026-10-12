# Plan

All numbers are the design authors' **estimates**, not measurements, built from one effort model with a roughly 2× spread. Nothing here is a commitment. Units are engineer-weeks unless stated.

## Current totals

**About 279 engineer-weeks central (range about 206–410).** This is the earlier 264 (196–385) plus four sets of new author estimates (not from the earlier effort model): the owner decisions of 2026-10-12 (+2.5), the owner correction that makes the storage backends feature-identical with a symmetric switch (+5.5, range +3.5 to +8.5), and the answers to the open questions that grew the scope (+6.5, range +4.5 to +10.5; quiesce and history migration are now in the first release, plus Data Protection bundle protection, an orchestrator-aware cutover and certificates in the database), and the release automation (+0.5, range +0.5 to +1; see [release.md](release.md)). The owner answers of the third round (SQLite default backend, quiesce requeue, loud warnings) change no effort. Re-estimate before committing.

Calendar uses the same capacity assumptions throughout: 4 engineers ≈ 3.1 effective weeks per week, 2 engineers ≈ 1.7.

| Team | Low | Central | High |
|---|---|---|---|
| 4 engineers | about 15 months | about 21 months | about 30 months |
| 2 engineers | about 28 months | about 38 months | about 55 months |

Outside the estimate: deliverability operations (IP reputation, warm-up, abuse desk) and the external security audit.

## How the total got here

| Step | Change | Total (central) |
|---|---|---|
| Baseline component table (below) | | 236 |
| Owner decisions on attachments, retention, S3 targets, secrets (S3 suite, FS self-test, secrets handling, `body_expired` state) | about +5 (range +3 to +8) | 241 |
| Blob store dropped; bodies in Postgres `bytea` | −12 | 229 |
| Content split (+4), Lite mode on SQLite (+18) | +22 (range +16 to +29.5) | 251 |
| Lite webhooks, multi-tenant stats, three SQLite files, stress tests, benchmark harness | +13 (range +10 to +19.5) | 264 |
| Owner decisions of 2026-10-12: corruption detection/recovery for `synchronous=OFF`, guided manual mode switch (the switch part is replaced by the next row) | +2.5 (range +1.5 to +4.5) | 267 |
| Owner correction: feature-identical backends, `History:Mode`, symmetric Lite ↔ Full switch (net of the replaced items) | +5.5 (range +3.5 to +8.5) | 272 |
| Answers to the open questions: quiesce and history migration in v1, Data Protection bundle protection, orchestrator-aware cutover, certificates and ACME state in the database | +6.5 (range +4.5 to +10.5) | 278.5, about 279 |
| Release automation (tag-driven multi-arch GHCR publish, attestations, GitHub Release, nightly); not enumerated in the baseline Packaging component | +0.5 (range +0.5 to +1) | 279 |

## Component list (baseline of 236)

This is the last per-component table recorded. Later steps are listed as deltas below it; the table has not been re-baselined.

| Component | Weeks |
|---|---|
| SMTP server | 22 |
| SMTP client | 12 |
| MIME | 25 |
| DKIM | 8 |
| SPF | 6 |
| DMARC | 8 |
| ARC | 4 |
| DSN/ARF | 5 |
| DNS | 11 |
| MTA-STS | 3 |
| TLS-RPT | 5 |
| DANE | 3 |
| Delivery scheduler | 18 |
| Webhooks | 2 |
| API | 10 |
| Domain verification | 5 |
| Security | 12 |
| Docs | 4 |
| Glue | 18 |
| Observability | 3 |
| Dashboard | 9 |
| Packaging | 4 |
| Test infrastructure | 9 |
| Performance | 5 |
| ACME, cert store, hot reload, DNS-01 (Certes) | 4 |
| Postgres provider (EF model, queue claim, batching, partition-retention job) | 9 |
| Blob providers, FS + S3 (later dropped, see decision 11) | 12 |
| **Total** | **236** |

The hand-written protocol stack plus scheduler is about 130 of 236 weeks (55%). The range at the baseline was 177–343. The −12 step that dropped the blob store is net of the added body-table work, so it is not simply the 12 weeks in the last row.

### Deltas applied after the baseline

Historical rows keep the earlier "Lite mode" wording from when the SQLite backend was planned as a reduced mode; the owner correction below makes the backends feature-identical.

Content split and Lite mode (+22, versus 229):

| Item | Central | Range |
|---|---|---|
| Content split, flags, resend rules | +4 | 3–6 |
| SQLite stores: queue, claim, spool, retention, crash tests | +6 | 4–8 |
| `IStatsStore` plus dashboard overview on it | +2 | 1.5–3 |
| Second EF provider: migrations assembly, model hooks, CI matrix | +3 | 2–4 |
| Stateless signed VERP plus DSN attribution | +0.5 | 0.5 |
| Lite semantics: mode gating, capabilities, API errors, dashboard variant (re-scoped to `History:Mode` gating by the owner correction below) | +2.5 | 2–3 |
| Drain mode, config and stats export/import (replaced by the symmetric switch engine below) | +1.5 | 1–2 |
| Test matrix hardening for both modes | +2.5 | 2–3 |
| **Total** | **+22** | **+16 to +29.5** |

Lite webhooks, tenancy and benchmarks (+13, versus 251):

| Item | Central | Range |
|---|---|---|
| Webhook outbox, dispatcher, signing, SSRF guard, endpoint disabling | +3.5 | 2.5–5 |
| Multi-tenant stats: caps, rollups, per-tenant views | +2 | 1.5–3 |
| Three SQLite files, per-file writers, ordering rules, checkpoint management | +2.5 | 2–4 |
| Writer/group-commit stress and crash tests, storage-pressure indicator | +2 | 1.5–3 |
| Benchmark harness, load generator, baseline compose, CI regression gate | +2.5 | 2–4 |
| Multi-tenant scoping in Lite | +0.5 | 0.5 |
| **Total** | **+13** | **+10 to +19.5** |

### Owner decisions of 2026-10-12 (new, +2.5)

These are new author estimates (not from the earlier effort model), rounded; re-estimate before committing.

| Item | Central | Range |
|---|---|---|
| Lite corruption handling for `synchronous=OFF`: startup integrity check, quarantine and start-empty, alerting, `VACUUM INTO` backup schedule, OS-crash/power-loss fault-injection tests | +1 | 0.5–2 |
| Guided manual mode switch: preflight, confirmations, drain orchestration, config-only Full → Lite export, dashboard UI (replaced by the symmetric switch below) | +1.5 | 1–2.5 |
| **Total** | **+2.5** | **+1.5 to +4.5** |

The switch and drain items above are superseded by the owner correction below. No change from the other owner decisions: MIT license (docs only), unlimited-retention `0` convention (a "skip deletion" branch in retention jobs plus dashboard warnings, assumed within the existing retention-job estimates), and advisory-only indicators (the storage-pressure indicator was already in scope). Choosing `OFF` as the default does not remove the crash and writer stress tests; it adds the power-loss/OS-crash cases counted above.

### Owner correction: feature-identical backends and symmetric switch (net +5.5)

The owner's correction removes every backend-dependent feature and makes switching easy in both directions. New author estimates, rounded:

| Item | Central | Range |
|---|---|---|
| Switch engine: bundle format and manifest/checksums, export/import contract on the config, stats and queue stores, streaming, one shared config-store abstraction, key re-wrapping, preflight and verification, rollback handling, `mta migrate-storage` CLI | +3.5 | 2.5–5 |
| Guided dashboard flow over the engine (both directions) | +1.5 | 1–2 |
| *Subtotal: replaces the earlier drain/export/import (+1.5) and guided switch (+1.5)* | *+5.0 (was +3.0)* | *3.5–7 (was 2–4.5)* |
| History migration across backends (events, content, retained raw; streamed). Estimated here as optional; made mandatory and resumable by the answers below | +1.5 | 1–2.5 |
| SQLite history stores: events, content, retained raw in `history.db`, batched-delete retention, cross-file ordering | +2.5 | 1.5–4 |
| `History:Mode` gating replacing backend gating (capabilities, `history_not_recorded`, dashboard states; no per-backend dashboard variant) | −0.5 | −0.5 |
| **Net change** | **+5.5** | **+3.5 to +8.5** |

Is it more or less than before? **More:** the switch itself costs about 2 weeks more (5.0 vs 3.0) because it is symmetric, can carry queued mail, re-wraps secrets, verifies checksums and supports rollback, plus 1.5 for history migration (since made mandatory, see below). SQLite now also implements history stores (+2.5), partly offset by dropping the per-backend dashboard variant (−0.5). The earlier "Lite → Full stats import" cut item disappears: stats are one more store in the same bundle, so there is nothing separate to cut. Benchmark and test matrices already covered both backends; no additional change. 

### Answers to the open questions (+6.5, range +4.5 to +10.5)

Scope grew: quiesce and history migration are in the first release (they were optional or deferred), and three further design answers add work. New author estimates, rounded; **the first release now includes all of these, none is an optional or cuttable item**.

| Item | Central | Range |
|---|---|---|
| Quiesce in v1: in-flight handling with requeue and a `possible_duplicate` flag (no blocking `in_doubt` state), durable source fence, transfer marks, transfer of queue rows, spool bodies, pending webhook outbox and API idempotency keys with ids preserved, target activation gate, no-duplicate and rollback tests | +2.0 | 1.5–3.5 |
| History migration made mandatory, streamed, resumable and checksummed per chunk, with backfill after activation (was +1.5 as an optional item; now 3.0 in total) | +1.5 | 1–2 |
| Secrets in the bundle through Data Protection: bundle key ring, passphrase-protected PKCS#12, re-protection under the target's ring, tests across differing `Secrets:KeyProtection` settings (the generic re-wrapping was already in the engine estimate) | +0.5 | 0.5–1 |
| Orchestrator-aware cutover: config-source detection, precedence rules, cutover patch generation, startup gate on `switch_state` | +1.0 | 0.5–1.5 |
| Certificates and ACME state in the database: tables, Data Protection-protected keys, renewal lease, hot reload by database polling, file/environment override, bootstrap flow, inclusion in the bundle | +1.5 | 1–2.5 |
| Unified preset defaults, SQLite history layout (single `history.db`), `410`/problem-details history errors | 0 | 0 |
| **Total** | **+6.5** | **+4.5 to +10.5** |

New central total: 272 + 6.5 = 278.5, about **279** (278.5 + 0.5 for the release automation = 279.0) (about 206–410 after the release automation below). Calendar on the same capacity assumptions (4 engineers ≈ 3.1 effective weeks per week, 2 ≈ 1.7): **4 engineers about 21 months** (low about 15, high about 30); **2 engineers about 38 months** (low about 28, high about 55).

Cut candidates that remain from the switch: only the guided *dashboard* flow, which could fall back to the `mta migrate-storage` CLI alone. History migration, quiesce, the secrets protection and certificates in the database are in scope. History throughput is unmeasured, so any time estimate for moving large histories is **unverified**.

### Release automation (+0.5)

The baseline **Packaging (4 weeks)** component was defined as one image with no second variant, plus compose and Kubernetes manifests; it does not enumerate release automation. The tag-driven multi-arch build, GHCR publishing with `GITHUB_TOKEN`, SBOM/provenance and attestation steps, GitHub Release with changelog and checksums, the nightly build, smoke tests and the one-time package-visibility step ([release.md](release.md)) are therefore **not clearly covered** and are added here as **+0.5 week (range 0.5–1)**, a new author estimate. Not covered either way: a Docker Hub mirror (a later decision).

## Phases

Phase scope at the 236 baseline, with later deltas applied. Per-phase totals below are **derived by summing the recorded phase deltas**; they sum to 274, not 279, because the +5 step above was not assigned to phases in the sources.

| Phase | Scope | Baseline | Deltas since | Derived |
|---|---|---|---|---|
| 0 Foundations | Seams, SMTP parser skeleton, DNS codec, EF/Postgres spike, threat model, CI guard for package-free stack, two-provider skeleton and `Storage:Backend` / `History:Mode` settings | 18 | −2 (no FS blob spike), +1.5, +1 | 18.5 |
| 1 Core engines | SMTP server, DNS, MIME, Postgres and SQLite stores (queue claim, retention job, spool/content/history tables on both backends), `IStatsStore`, `IConfigStore` | 64 | −0.5, +9, +4.5, +2.5 (SQLite history stores) | 79.5 |
| 2 Outbound | SMTP client, scheduler, DKIM, DSN; SQLite-backend crash tests (process kill, OS crash/power loss), corruption detection/recovery, terminal-state strip/move job | 47 | −6 (no S3 provider or suite), +3, +2.5, +1 | 47.5 |
| 3 Authentication and policy | SPF, DMARC, MTA-STS, TLS-RPT, DANE, ARC; stateless VERP | 33 | −4 (no blob reconciliation), +1, +0.5 | 30.5 |
| 4 Product surface | API, webhooks, domain verification, dashboard (same pages on both backends, `History:Mode` states), observability, ACME with certificate and ACME state in the config store, per-tenant/per-send flags, extraction | 33 | +1 (message view/resend UI), +4.5, +3, −0.5, +1.5 (certificates in the database) | 42.5 |
| 5 Deployment | Compose and Kubernetes, packaging, glue; symmetric backend-switch engine with quiesce and fence, resumable history migration, Data Protection bundle protection, orchestrator-aware cutover, CLI and guided flow, release automation | 14 | +5.0 (replaces +1.5 and +1.5), +1.5, +5.0 (quiesce +2.0, history +1.5, Data Protection +0.5, cutover +1.0), +0.5 (release automation) | 26 |
| 6 Hardening | Final security pass, soak, performance tuning, warm-up playbook, runbooks, limited real-traffic pilot; test matrix | 27 | −0.5 (no FS self-test), +1.5, +1.5 | 29.5 |

Baseline calendar at 4 engineers was about 77 weeks (6 / 21 / 15 / 11 / 11 / 4.5 / 9 per phase); it has not been recomputed per phase.

Suggestions from the sources:
- Start a real-sending pilot through a relay as early as Phase 2, because deliverability learning needs real traffic.
- Build order: bring the SMTP/delivery core up against the SQLite stores first (fast local development, no external database), then complete Postgres. This also lets a release on the SQLite backend reach production earlier; the saving of roughly 15–20 weeks versus the full central total is an **unsourced estimate**.
- Do not advertise PIPELINING or CHUNKING until the smuggling suite passes (a deliberate caution, not an RFC requirement). Delay the public bounce listener on port 25 until fuzzing is in CI: it is the one unauthenticated surface on the open internet.

### Quality gates

Carried from the earlier plan version (storage-engine-specific gates dropped); to be re-confirmed.

| Phase | Gate to leave |
|---|---|
| 0 | Smuggling and STARTTLS-injection suites pass on the skeleton; benchmark baseline recorded; CI guard on package references active |
| 1 | Fuzzers (SharpFuzz) run clean for a set time budget on every parser; DNS codec round-trips real packets; interop with Postfix/Exim/Haraka as peers |
| 2 | Delivery to a sink meets the allocation and throughput budgets; interop matrix passes; DKIM signatures verify at Gmail (`Authentication-Results`) |
| 3 | SPF/DMARC/DKIM results match a reference implementation on a shared corpus; MTA-STS and DANE tested against real policies; bounces correlate end to end |
| 4 | OWASP ASVS L2 checklist on API and dashboard; strict CSP verified; ACME renewal tested through a forced expiry |
| 5 | Upgrade, restore and rollback drills pass; fresh single-container start works with minimal config; backend-switch drills pass in both directions (round trip preserves config, certificates, stats, queue and history; checksums verify; quiesce adds no duplicate sends except deliveries flagged `possible_duplicate`; rollback works; resume of an interrupted history copy works) |
| 6 | No open critical or high findings; 7-day soak; DoS suite within memory and CPU ceilings; runbooks reviewed |

## Cut order

If the schedule slips, cut in this order (cheapest to cut first):

1. ARC and Ed25519
2. TLS-RPT sending (keep collection)
3. DMARC aggregate-report generation
4. Guided dashboard switch flow (keep the `mta migrate-storage` CLI)
5. Webhook replay UI (keep automatic retries)
6. Benchmark baselines beyond Postfix and KumoMTA
7. Per-send attachment flag (keep the tenant setting)
8. DANE and the Unbound sidecar (keep MTA-STS)
9. Message view and resend (keep status only)
10. UTS#46 tables (rely on ICU only)
11. Dashboard polish (ship API and a minimal status page first)
12. BDAT/CHUNKING (last, and only with care; can be disabled by config without breaking clients)

The Postgres provider is no longer cuttable: it is the only path to more than one replica.

## Risks

1. **Schedule.** The estimate has a 2× spread; a first-time hand-written MTA hits interop surprises from real-world servers.
2. **Security bugs in hand-written parsers** (smuggling, STARTTLS injection, DoS) with no independent reviewer. Mitigated by the in-house plan and an external audit before production-critical use.
3. **Postgres size, WAL growth and restore time** are the main storage risks; monitor from the start.
4. **Deliverability:** IP reputation, port-25 blocking and warm-up are operational, not code.
5. **Unicode/IDN correctness:** ICU dependency, silent failure in invariant mode (startup self-test).
6. **DANE/DNSSEC trust:** the Unbound carve-out breaks the pure single-process story and adds an upgrade surface.
7. **MIME edge cases:** real-world messages violate the RFCs in endless ways; the long tail is hard to estimate.
8. **Key-person risk:** a few engineers own protocol code nobody else knows.
9. **Scope creep:** every deferred feature returns as a customer request.
10. **Two providers** double the test and maintenance load, and feature identity means every feature is tested on both.
11. **SQLite single-writer ceiling**, and corruption or loss if someone puts the file on a network volume.
12. **Stats flush window** (up to about 10 s of counters lost on process crash).
13. **SQLite default `synchronous=OFF` can corrupt the database on an OS crash or power loss** (SQLite docs), losing all queued mail including mail acknowledged with `250`. A process kill is safe. Owner-accepted for speed; mitigated by loud warnings (startup log, persistent dashboard banner, metric and health detail; no acknowledgement gate), prominent README/design wording, `Sqlite:SyncMode=Normal|Full`, startup integrity check with quarantine, optional backups, and `config.db` kept at `Full` (owner-decided). Also keep "fire-and-forget" from being misread as "may lose mail" under process-crash-safe operation.
14. **Disk-full queue on the SQLite backend** (reply `452`).
15. **No per-message traceability under `History:Mode=StatsOnly`** (an opt-in lightweight setting on either backend; `Full` is the default) makes support harder (mitigated by the ring and logs).
16. **Forged VERP tokens** if the HMAC key is mishandled.
17. **Unlimited retention (`0`)** can fill the disk or inflate Postgres/SQLite files if operators forget manual cleanup; mitigated by dashboard warnings.
18. **Supply chain:** npm (dashboard), Certes (dormant 2021–2026, single recent author; own-client fallback is 6–12 weeks).
19. **EF Core overhead on the hot path:** several KB per operation even when tuned; mitigated by batching.
20. **Backend-switch engine** is a data-moving feature: an incorrect export/import could lose or corrupt data, mishandle queued mail, or mis-rewrap DKIM keys. Mitigated by refusing a non-empty target, drain-first by default, checksums and counts, a read-only source kept until the owner finalizes, round-trip tests in both directions and a documented rollback.
21. **Cross-file non-atomicity on the SQLite backend** (several files, atomic per file only) requires idempotent, ordered effects; the same code paths must behave identically to PostgreSQL's single transactions.
22. **Private keys and the ACME account key live in the database** (encrypted by Data Protection). A leak of both a database copy and the key-protection certificate/KMS exposes them; backups and replicas carry the ciphertext. Mitigated by keeping the key-protection secret outside the database, least-privilege roles and the dashboard's read-only role having no access to secret tables.
23. **Quiesce can still duplicate deliveries** that were in flight after the end of message data when the 30-second timeout aborted them (they are requeued at-least-once and flagged `possible_duplicate`), and cannot de-duplicate SMTP clients that retried without an idempotency key. Mitigated by waiting for in-flight work, the flag and event, preserved ids and API idempotency keys.
24. **Certificate renewal across replicas** (lease lock correctness and a database outage during renewal) and the bootstrap order (database before TLS) need dedicated tests.
