# Decisions record

Consolidated record of decisions for EggMail (as of 2026-10-12, after owner decisions A–D). Rationale and detail are in [design.md](design.md). Figures and defaults marked "proposed" are design-author choices, not independent standards.

## Owner decisions (2026-10-12)

The four items previously "decided by default" are now **OWNER-DECIDED**, with the changes below. One sub-point remains a recommendation awaiting confirmation (marked).

| # | Topic | Decision |
|---|---|---|
| A | License | **MIT**, copyright holder "eggspot". Owner wants 100% open source where anyone can do anything. Replaces the earlier Apache-2.0 default. Consequence: MIT has no express patent grant (Apache-2.0 had one); this is accepted. The Unlicense/CC0 public-domain dedication is the only more-permissive alternative (see [open-questions.md](open-questions.md)) |
| B | Webhook retention | Outbox and attempt-log retention default **7 days**, configurable, and **unlimited is allowed with value `0`** ("keep forever"; no automatic cleanup, disk grows, manual or external cleanup needed). The earlier 30-day cap is removed. Convention and per-knob analysis in [design.md §5.1](design.md#51-retention-knobs-and-unlimited-retention) (see decision 28) |
| C | Lite vs Full switching | **Never automatic.** The "move to Full" signals (writer queue over 1,000 for 5 minutes, p99 commit over about 100 ms) are **advisory dashboard indicators only**. The dashboard offers an owner-triggered, guided switch (Lite → Full: preflight, drain, export/import config, confirm). Full → Lite is a config-only export to seed a new install, not an in-place switch (safest option; open question). See decision 14 |
| D | Lite SQLite sync default | **`PRAGMA synchronous=OFF`** (fastest) is the default for `queue.db` and `stats.db`, replacing `FULL`/`NORMAL`. `Lite:SyncMode = Off (default) \| Normal \| Full`. **Recommendation awaiting owner confirmation:** keep `config.db` at `FULL` (`Lite:ConfigSyncMode`). **Prominent consequence:** process kill or container restart is safe; an OS crash or power loss can **corrupt** the database per the SQLite docs, not merely lose recent commits. See decision 13 |

**Still pending (not decided):** a real trademark search for the name "EggMail". The research found no exact collision on GitHub, npm, NuGet, crates.io, PyPI or Docker Hub, but similar names exist (npm `egg-mail`, an Egg.js plugin last published in 2022; a cancelled "EGISMAIL" trademark) and eggmail.com/.net/.org appear registered. That was not a trademark search.

## Product and goals

1. EggMail is an open-source, self-hosted outbound email server (SMTP ingress, HTTP API, delivery tracking, dashboard) from eggspot. Primary goal: the fastest SMTP server, claimed only after reproducible measurement ([benchmarks.md](benchmarks.md)).
2. .NET 10 LTS (supported to 2028-11-14). Docker deployable.
3. Two modes: Full (Postgres) and Lite (SQLite, single node, statistics only). Shared core; storage behind interfaces. Performance is a permanent first-class goal in **both** modes: Lite is engineered for large, high-throughput workloads and is not treated as a toy (see decision 27).

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
13. Lite mode: SQLite in three files (`queue.db`, `stats.db`, `config.db`), single node, one replica, multi-tenant, local volume only. Default `synchronous=OFF` for `queue.db` and `stats.db` (**owner-decided**; `config.db` stays `FULL`, recommendation awaiting confirmation): **process-crash-safe, not power-loss-safe**. `250` means the data was handed to the OS, not fsynced; an OS crash or power loss can corrupt the database (per the SQLite docs) and lose all queued mail, including mail already acknowledged. Knobs: `Lite:SyncMode = Off | Normal | Full`, `Lite:ConfigSyncMode`, `Lite:QueuePersistence = Persistent | Memory` (renamed from `Lite:QueueDurability`; "durable queue" is retired for Lite). Startup integrity check, quarantine of a corrupt file, start empty with an alert, optional `VACUUM INTO` backups. 48 h queue lifetime, 10 MiB max message. No per-message history. Statistics only: hourly rows 30 days and daily rollups 400 days (both may be unlimited with `0`), top-20/top-10 recipient domains, series cap. Recent-events ring of 1,000. Stateless signed VERP bounce correlation. Webhooks supported with a persisted outbox. No throughput cap.
14. Mode switching is **manual only, never automatic** (owner-decided). Lite → Full: owner-triggered guided dashboard action (preflight, drain, config export/import, confirmation, restart under Full); queued messages are not migrated. Full → Lite: no in-place switch; config-only export to seed a new Lite install, with per-message history not carried over and explicit confirmation (open question whether to offer even this).
15. Two EF providers: one `DbContext`, separate migrations assemblies, provider-specific hot-path stores, a shared `IStatsStore` using `ON CONFLICT` upserts.

## Webhooks

16. Standard Webhooks signing, retry schedule immediate/5 s/5 m/30 m/2 h/5 h/10 h/10 h, 15 s timeout, 410 disables, disable after 5 days of failure, SSRF guard (validate resolved IPs, no redirects, HTTPS default), 7-day default outbox and attempt-log retention, configurable, `0` = unlimited (decision B).

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

24. Pipelines-based server, zero-byte reads for idle connections, group-commit writers; durable and non-durable results always reported together, with Lite and Full benchmarked separately (Lite's default `synchronous=OFF` is a non-durable configuration); Postfix, KumoMTA and Haraka as baselines on the same hardware.
25. Estimate: about 267 engineer-weeks central (about 198–390): about 20 months with 4 engineers, about 36 with 2 ([plan.md](plan.md)). The +2.5 over the earlier 264 is new author estimate for Lite corruption handling and the guided mode switch.
26. Cut order: as listed in [plan.md](plan.md#cut-order).
27. **Design principle:** performance optimization is a permanent first-class goal in both Full and Lite. Lite is engineered to perform well for large and high-throughput workloads, not treated as a toy. Benchmarks cover Lite and Full separately ([benchmarks.md](benchmarks.md)).
28. **Retention convention:** a retention value of `0` means "keep forever"; negative values are invalid. Allowed for webhook outbox/attempt log, `Retention:MetadataDays`, `Stats:HourlyRetentionDays` and `Stats:DailyRetentionDays` (with documented disk-growth cost and manual cleanup). **Not** allowed for `Content:RetentionDays`, which stays 6–30 (floor: must outlive the 5-day queue lifetime; ceiling: personal-data and storage bound). Suppressions have no expiry. Analysis in [design.md §5.1](design.md#51-retention-knobs-and-unlimited-retention).
