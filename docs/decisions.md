# Decisions record

Consolidated record of decisions for EggMail (as of 2026-10-12). Rationale and detail are in [design.md](design.md). Figures and defaults marked "proposed" are design-author choices, not independent standards.

## Decided by default: pending owner confirmation

The owner answered the four open questions by accepting the proposed defaults. They are recorded as decided, **flagged for explicit owner confirmation**:

| # | Question | Default adopted |
|---|---|---|
| A | License | **Apache-2.0** (adoption plus patent grant). Alternatives considered: MIT (Postal, mox), AGPL-3.0 + commercial license (Stalwart; protects against closed hosted forks) |
| B | Webhook retention | **7 days** for finished outbox rows and the attempt log, configurable up to 30 |
| C | Lite "move to Full" signals | Writer queue depth **over 1,000 for 5 minutes**, or p99 commit latency **over about 100 ms** |
| D | `Lite:SyncMode=Normal` | Documented as an **explicit opt-in** ("I accept power-loss risk"); default stays `FULL` for `queue.db` |

**Still pending (not decided):** a real trademark search for the name "EggMail". The research found no exact collision on GitHub, npm, NuGet, crates.io, PyPI or Docker Hub, but similar names exist (npm `egg-mail`, an Egg.js plugin last published in 2022; a cancelled "EGISMAIL" trademark) and eggmail.com/.net/.org appear registered. That was not a trademark search.

## Product and goals

1. EggMail is an open-source, self-hosted outbound email server (SMTP ingress, HTTP API, delivery tracking, dashboard) from eggspot. Primary goal: the fastest SMTP server, claimed only after reproducible measurement ([benchmarks.md](benchmarks.md)).
2. .NET 10 LTS (supported to 2028-11-14). Docker deployable.
3. Two modes: Full (Postgres) and Lite (SQLite, single node, statistics only). Shared core; storage behind interfaces.

## Build boundary

4. Hand-written, BCL-only SMTP stack: SMTP server and client (including BDAT/CHUNKING, full SMTPUTF8, PIPELINING, SIZE, 8BITMIME, ENHANCEDSTATUSCODES, STARTTLS, AUTH PLAIN/LOGIN), MIME, DKIM sign and verify (RSA-2048 only), SPF, DMARC, DSN/ARF, DNS client, MTA-STS, TLS-RPT, DANE. ARC is optional and deferrable. Enforced by CI: those assemblies have no package references.
5. Libraries allowed elsewhere: Npgsql + EF Core, Microsoft.Data.Sqlite, Certes (ACME), OpenTelemetry with OTLP, Data Protection, dashboard frontend stack, tests (MimeKit and MailKit as oracles only).
6. DANE uses a local validating resolver (Unbound on loopback). This is the one carve-out from "no external binaries".
7. One image, chiseled with ICU (the `-extra` variant) plus a startup Unicode self-test.

## Storage

8. Full mode: Postgres only, via EF Core only. One database, one schema, three roles (owner, runtime, read-only). Minimum PG 16, default `postgres:17`. Managed HA is a deployment prerequisite; `451` during a database outage is accepted.
9. Tables: live queue unpartitioned and small; events and content day-partitioned; retention is partition drop (`DETACH … CONCURRENTLY`, then `DROP`), created ahead by an in-app job under a transaction-level advisory lock. Claim with native `FOR UPDATE SKIP LOCKED … RETURNING` through `SqlQuery<T>`. A pure-LINQ `ExecuteUpdate` claim is the test fallback.
10. Migrations: `Auto` by default (EF 9+ takes a database-wide lock), or `Never` plus `mta migrate-db` and a script. Two connection strings: schema owner and runtime.
11. No blob store. FS, S3 and R2 providers are dropped. R2 is removed. An `IMessageBodyStore` interface remains for a possible later provider.
12. Content: subject + text + html stored by default for 7 days (6–30). Raw message stays verbatim in `message_spool` until all recipients are final. Attachments are not stored unless enabled per tenant or per send (then raw is moved to `message_raw_retained`). Resend is available from retained raw; attachment-free messages can be re-composed. Metadata kept 30 days.
13. Lite mode: SQLite in three files (`queue.db`, `stats.db`, `config.db`), single node, one replica, multi-tenant, local volume only. Durable queue by default (`synchronous=FULL`), 48 h queue lifetime, 10 MiB max message, acknowledgement after commit. No per-message history. Statistics only: hourly rows 30 days and daily rollups 400 days, top-20/top-10 recipient domains, series cap. Recent-events ring of 1,000. Stateless signed VERP bounce correlation. Webhooks supported with a persisted outbox. No throughput cap.
14. Upgrade path: Lite → Full by drain-and-switch plus config export/import. Full → Lite unsupported.
15. Two EF providers: one `DbContext`, separate migrations assemblies, provider-specific hot-path stores, a shared `IStatsStore` using `ON CONFLICT` upserts.

## Webhooks

16. Standard Webhooks signing, retry schedule immediate/5 s/5 m/30 m/2 h/5 h/10 h/10 h, 15 s timeout, 410 disables, disable after 5 days of failure, SSRF guard (validate resolved IPs, no redirects, HTTPS default), 7-day outbox and attempt-log retention (see decision B above).

## Network and TLS

17. Ports (each switchable): 587 STARTTLS, 465 implicit TLS, 2525 STARTTLS on by default; 2587 and 2465 off; port 25 bounce role only; plain only on loopback or internal networks. Container ports are high (5587, 4465, 2525, 2526) and mapped outward. Dashboard on 8080 (HTTP, probes) and 8443 (HTTPS), optionally published as 443.
18. Outbound: direct MX on port 25; relay fallback chain on 587, 465 or 2525 is opt-in per domain, with every delivery recording which route was used.
19. TLS: one shared certificate store; own `ServerCertificateSelector`; TLS 1.2 minimum; certificate hot reload by polling; ACME with Certes, DNS-01 default (Cloudflare first); outbound opportunistic by default with per-domain policy, MTA-STS enforce, TLS version, cipher and peer certificate recorded per attempt.
20. Domain verification: DKIM TXT with RSA-2048 (CNAME delegation optional later), return-path CNAME, SPF include optional, DMARC informational. State machine: the consolidated record is truncated after "State machine"; the proposed machine from the earlier domain-verification research is summarized in [design.md §8](design.md#8-domain-verification) and needs confirmation.

## Secrets and security

21. API keys shown once and stored as SHA-256 digests; SMTP auth PLAIN/LOGIN only; DKIM keys and the Data Protection key ring wrapped with a certificate or KMS. Encryption at rest is a storage-layer responsibility (envelope encryption deferred behind an interface).
22. Security review is in-house (STRIDE threat model, ASVS L2/L3, fuzzing, smuggling and STARTTLS-injection suites, port pen-tests, DoS tests, container hardening, cross-review and a red-hat week). An external audit is recommended before first production-critical use.

## Deployment

23. Full: app + managed Postgres, via compose or Kubernetes; replicas above 1 are safe (no local blobs). Lite: one container, one volume, one replica. Health: `--healthcheck`, liveness separate from readiness.

## Performance and plan

24. Pipelines-based server, zero-byte reads for idle connections, group-commit writers; durable and non-durable results always reported together; Postfix, KumoMTA and Haraka as baselines on the same hardware.
25. Estimate: about 264 engineer-weeks central (196–385): about 20 months with 4 engineers, about 36 with 2 ([plan.md](plan.md)).
26. Cut order: as listed in [plan.md](plan.md#cut-order).
