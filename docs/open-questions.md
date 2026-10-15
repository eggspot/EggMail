# Open questions

## Owner decisions applied (2026-10-12)

The four former "decided by default" items are **OWNER-DECIDED**, and a later owner correction (5) makes the storage backends feature-identical. See [decisions.md](decisions.md) (A–N).

| # | Topic | Decision |
|---|---|---|
| 1 | License | **MIT**, copyright eggspot (owner wants 100% open source where anyone can do anything) |
| 2 | Webhook retention | 7-day default, configurable, `0` = keep forever (unlimited allowed; manual or external cleanup needed) |
| 3 | Switching | Never automatic. Thresholds (queue over 1,000 for 5 min, p99 commit over about 100 ms) are advisory dashboard indicators only |
| 4 | SQLite sync default | `synchronous=OFF` for the SQLite data files (process-crash-safe, **not** power-loss-safe; corruption possible on OS crash or power loss). `Sqlite:SyncMode = Off (default) \| Normal \| Full` |
| 5 | Backends are feature-identical | SQLite vs PostgreSQL is only a storage choice; every feature behaves identically. `History:Mode = StatsOnly \| Full` is a separate setting on either backend. Switching is symmetric (Lite ↔ Full), via one portable bundle, a CLI and a guided dashboard action, with rollback. This resolves the earlier question about Full → Lite |
| 6 | `config.db` sync mode | **OWNER-DECIDED:** `config.db` stays at `synchronous=FULL` (`Sqlite:ConfigSyncMode` default `Full`); `queue.db` and `stats.db` stay `OFF` |
| 7 | Name and trademark | **OWNER-DECIDED:** keep the name EggMail; no formal trademark search and no mark registration planned. Optional, light recommendation: before wide promotion, do a free check of the USPTO, EUIPO and WIPO databases. MIT licenses the code, not the name |
| 8 | Secrets in the bundle | **OWNER-DECIDED:** Data Protection is the mechanism. Design (bundle key ring protected by a passphrase-protected throwaway certificate; target re-protects under its own ring) is DESIGN-DECIDED ([design.md §4.6](design.md#46-switching-backends-manual-and-symmetric)) |
| 9 | Quiesce and history migration | **OWNER-DECIDED:** both are in v1; `--drain` stays the safe option; history migration is streamed, resumable and skippable |
| 10 | Preset defaults | **OWNER-DECIDED:** identical defaults for every behavioural setting. The value `History:Mode=Full` (5-day queue, 25 MiB, 7-day content) is DESIGN-DECIDED |
| 11 | Certificates and ACME state | **OWNER-DECIDED:** live in the database (config store, both backends) and travel in the bundle |
| 12 | SQLite history layout | **DESIGN-DECIDED:** single `history.db`, batched deletes ([design.md §4.4](design.md#44-sqlite-backend-microsoftdatasqlite)) |
| 13 | API status for history not recorded | **DESIGN-DECIDED:** `410 Gone` / `history_not_recorded`; `body_expired` reused; `404` for unknown ids ([design.md §5.2](design.md#52-api-behavior-when-history-is-not-recorded-or-has-expired-design-decided)) |
| 14 | Orchestrator-managed configuration | **DESIGN-DECIDED:** the switch never rewrites env/ConfigMaps; verified target plus cutover patch, startup gate and source fence ([design.md §4.6](design.md#46-switching-backends-manual-and-symmetric)) |
| 15 | `Content:RetentionDays` range | **OWNER-DECIDED:** stays 6–30, no unlimited; `0` = unlimited is the convention for the other retention knobs |
| 16 | `synchronous=OFF` acknowledgement | **DESIGN-DECIDED:** no acknowledgement setting; loud warnings instead (startup log, persistent dashboard banner, metric and health detail, README). `Sqlite:SyncMode=Normal`/`Full` are the documented safer knobs |
| 17 | Default storage backend | **OWNER-DECIDED:** SQLite (single-container quick start); `History:Mode` stays `Full` on both backends (see question 1 below for the flagged tension) |
| 18 | Quiesce timeout | **DESIGN-DECIDED:** graceful shutdown: `Switch:QuiesceTimeoutSeconds` default 30, then requeue with the same message id and retry state and a `possible_duplicate` flag/event; no blocking `in_doubt` state |
| 19 | Release and packaging | Single image on `ghcr.io/eggspot/eggmail`, released from GitHub Actions on version tags: built and smoke-tested, see [release.md](release.md) |

Note on the license: the Unlicense / CC0 public-domain dedication is the only more-permissive alternative to MIT (weaker legal footing in some jurisdictions, and no patent grant either); say so if the owner wants it. MIT itself also has no express patent grant, unlike Apache-2.0.

## Blockers only the owner can clear

- ~~**GitHub Actions is disabled for `eggspot/EggMail` by the organization**~~ **Resolved (2026-10-13):** Actions is enabled; `ci` runs on pull requests and `main`, and the `release` workflow has published images. Pull requests are now merged on a green `ci` run.

## Questions awaiting the owner

1. **`History:Mode=Full` as the default on the default (SQLite) backend.** The owner made SQLite the default backend and kept `History:Mode=Full` as the default on both backends. The quick start therefore writes events and content into `history.db` by default (more writes, a larger file, more retention-delete work than `StatsOnly`), which may conflict with the lightness expected of the single-container quick start and with SQLite performance. This is **unmeasured**; it is flagged here and not changed. Options if it proves a problem: keep `Full`, or choose `StatsOnly` as the single default for both backends (lighter, no personal data stored by default, but no message search or resend out of the box).
2. **Effort.** The totals now include about +15 weeks over the earlier 264 as new rough author estimates (+2.5 corruption handling, +5.5 feature-identical backends and the symmetric switch, +6.5 for the answers that grew scope, +0.5 release automation); they should be re-estimated ([plan.md](plan.md)).
3. **Release details.** Docker Hub mirror (later), standalone `mta` binaries as release assets, the nightly tag name and the arm64 build approach ([release.md](release.md)).
4. **Delivery connection reuse.** The outbound connection pool keeps 2 idle connections per destination, while the destination throttle allows 5 to 20 concurrent connections. Under load most deliveries therefore open a new connection (and, with TLS, a new handshake) instead of reusing one; with the limit raised to the concurrency the benchmark delivers at 17 KB instead of 28 KB allocation per recipient and about 10 percent less CPU. `Delivery:MaxIdleConnectionsPerTarget` now sets it (default 2, unchanged). Raising the default (for example to the throttle's `MaxConnections`, capped) means more idle sockets to the same receiver for up to 30 seconds; it needs a decision and a trial against real receivers ([benchmarks.md](benchmarks.md#allocation-work-third-round-2026-10-15), decision 89).
5. **IMAP/POP3 mailbox serving (inbound mail, decision 95).** Inbound mail is read through the API, the dashboard and webhooks; there is no IMAP or POP3 server, so people cannot read it with a mail client. Building one means a per-user mailbox model (folders, flags, UIDs), password or app-password authentication on a new port and a much larger test surface. Decide whether it is wanted at all, and if so whether it comes before or after the route actions are proven in use.
6. **Relay SRS bounces to the original sender?** A bounce for a forwarded message comes back to its SRS address on port 25. EggMail accepts it from the null sender, counts it and drops it; it is not relayed to the original sender (backscatter to what is usually a forged sender, and a way to turn a forged SRS address into an open relay). The tenant learns of a failed forward from the forwarded copy, which is an ordinary outbound message of the tenant (`bounced` event and `message.bounced` webhook). Classic forwarders relay the bounce; say if you want that as an opt-in per route.
7. **Signed, expiring attachment URLs for inbound webhooks.** Attachments are fetched with an API key (`inbound:read` scope); a receiver that cannot hold a key would need pre-signed URLs, which make a leaked payload equal to leaked mail.
8. **Own database file for inbound mail.** Stored mail lives in `queue.db` (decision 95); a deployment that stores a lot would prefer a separate file. Decide after measuring real volumes.
9. **DMARC aggregate reports about received mail.** `Mta.Auth.Reports` can write them; sending them to the domains whose mail was received is not wired (it is mail to third parties on behalf of tenants, so it needs an opt-in and an abuse review).
10. **PROXY protocol v2 for inbound mail.** SPF, the DNSBL and the per-address limits need the real client address. Behind a TCP load balancer or source NAT the server sees the balancer's address instead; the design asks the operator to preserve the client address (host networking, `externalTrafficPolicy: Local`, a layer-4 balancer that keeps it) and the server warns when addresses look internal. Accepting the PROXY protocol with a list of trusted sources would support balancers that cannot; it is not built. Decide whether it is wanted.

## Owner action items

- **A cloud KMS for `Secrets:KeyProtection=Kms`.** Design section 9.1 lists `Certificate | Kms | None`. What is built: `Kms` with the `LocalKey` provider (AES-256-GCM, a 32-byte key from a file or the environment held outside the database) and the `IKeyWrapProvider` extension point. What is **not** built: AWS KMS, Azure Key Vault or Google Cloud KMS providers. Each needs a cloud SDK package (allowed outside the protocol assemblies) and, to be anything more than untested code, **an account to test against**, which only the owner can provide. Say which service(s) are wanted and provide a sandbox account; until then `Secrets:KmsProvider` with any other name stops the start with a message that points here. Decision: [decisions.md](decisions.md) 79.
- **Funding:** enable and get approved for **GitHub Sponsors for the eggspot organization**; choose a payout route (bank account in a supported region, or a fiscal host); add other platforms to `.github/FUNDING.yml` if wanted; review the policy draft. Until Sponsors is enabled, the README badge and the `FUNDING.yml` button point at a profile that does not exist yet. Steps in [funding.md](funding.md).
- **Security reporting:** enable *Private vulnerability reporting* for the repository (Settings, Code security); [SECURITY.md](../SECURITY.md) and `/.well-known/security.txt` point reporters at it. Decide who receives the reports.
- ~~**Actions**~~ done: Actions is allowed for the repository and both workflows have run.
- **Release:** the `ghcr.io/eggspot/eggmail` package is public (anonymous pull is checked on every release run). Still open: the first stable tag (`v0.1.0`) and the decisions listed in [release.md](release.md) (Docker Hub mirror, standalone binaries).

## Questions still open in the sources

- What are the real daily message volume and average message size? The Postgres content-storage sizing and split thresholds scale with them.
- Is raw Npgsql allowed for the body insert if profiling shows EF `byte[]` allocates too much? Default: EF only.
- Should subjects be stored in the 30-day metadata, given the privacy question? (`Content:StoreSubject` is configurable either way.)
- Is a 7-day default for content, with resend only inside that window, acceptable? (Adopted as the working default.)
- Who owns deliverability operations (IPs, warm-up, abuse desk)? They sit outside the engineering estimate.
- Is a time-boxed external security audit funded before first production-critical use?
- Which deployment targets must work first (single container only, or Kubernetes from day one), and which cloud will host it? That decides whether inbound port 25 and a multi-port LoadBalancer are possible.
- Is a Cloudflare DNS-01 integration enough for ACME in the first release? (Answered by decision 87: HTTP-01 on a built-in listener is the default without DNS credentials; Cloudflare stays the only DNS provider.)
- Should "require TLS" be a tenant-level setting, a per-domain setting, or both?
- Is DANE needed at launch, or can it wait with TLS-RPT?
- Domain verification state machine: the consolidated decisions record is truncated at that item; confirm the proposed machine ([design.md §8](design.md#8-domain-verification)).

## Items to settle with spikes

- SQLite commit rate on SSD under `synchronous=OFF`, `NORMAL` and `FULL` (Phase 0/1 benchmark spike), and the SQLite backend's behavior under group commit; whether group commit still pays off under `OFF`.
- Bundle export/import throughput on both backends (EF bulk insert in batches), and verification cost, for large stats and history volumes.
- Round-trip fidelity: SQLite → PostgreSQL → SQLite preserves config, stats and queue exactly (date/time and decimal handling differ between the providers).
- History migration throughput and resumability on realistic volumes (chunking, checksums, backfill after activation); all time estimates for it are unverified.
- Retention-delete cost on a single SQLite `history.db` under load, and the `WITHOUT ROWID (day, id)` key proposal; whether the bundled SQLite build's `ATTACH` limit would matter (only relevant if per-day files are adopted later).
- The bundle's Data Protection flow: certificate-protected standalone key ring, PKCS#12 export with PBES2 / AES-256 (`ExportPkcs12`), and RSA assumptions, across source and target with different `Secrets:KeyProtection`.
- Quiesce correctness: no duplicate sends except deliveries flagged `possible_duplicate`, requeue with preserved retry state at the 30-second timeout, fence behavior on restart, rollback before and after activation.
- Certificates in the database: renewal lease under contention and outage, hot reload by polling, bootstrap order, first-run self-signed flow.
- Startup integrity-check cost (`quick_check` vs `integrity_check`) on large `queue.db` files, and whether it should run only after an unclean shutdown.
- Fault injection: behavior of `Off`, `Normal` and `Full` under simulated OS crash and power loss.
- Whether the advisory thresholds (1,000 queue depth / 100 ms p99) are meaningful under `OFF`, where commit latency should be much lower.
- Whether `SqlQuery<T>` composes over `UPDATE … RETURNING` on Npgsql and on SQLite (call `ToListAsync` directly).
- Whether Data Protection's EF store works on SQLite.
- Which provider-specific model annotations behave in a shared model; EF's default WAL setting on SQLite.
- Independent-writer behavior of separate SQLite files (inferred from per-file WALs).

## Unverified items

Claims not confirmed against a primary source (also noted inline in the other docs):

- SQLite commits/s numbers (above); the 442/s vs 33k/s snippet
- The 120 B row size and 30% active-series assumptions behind the stats size model
- Stripe's and Postmark's webhook timeouts; SendGrid's 24 h webhook retry (snippet only); SendGrid's full SMTP port list
- Haraka's ingest behavior and fsync policy
- WAL volume at 1–1.5× data and text/HTML compression ratios; that a day partition's TOAST table is dropped with it
- Whether the EF provider can map `Stream` for `bytea`
- Mailgun and SendGrid retention/at-rest figures; Cloud SQL pricing and HA behavior
- OpenSSL TLS 1.3 ticket caching; fsync behavior on overlayfs/XFS/ext4; Native AOT feasibility
- The partition-count cost of unlimited `Retention:MetadataDays` (PostgreSQL partitioning docs, not re-fetched)
- All values marked "proposed" or "mine" in the source: 256 KiB stored body, 1,000-event ring, 20 KB average content size, 7-day retention default, per-endpoint concurrency 4, connection pool sizes, volume thresholds for splitting databases, and the 15–20 week Lite-first saving
- Release plan facts not confirmed: organization settings that may block public packages, GitHub Actions billing for public repositories, ([release.md](release.md); attestations on multi-platform images and ReadyToRun cross-architecture compilation are now verified by the release workflow and the throughput workflow)
