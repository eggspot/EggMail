# Open questions

## Owner decisions applied (2026-10-12)

The four former "decided by default" items are **OWNER-DECIDED**, and a later owner correction (5) makes the storage backends feature-identical. See [decisions.md](decisions.md) (A–G).

| # | Topic | Decision |
|---|---|---|
| 1 | License | **MIT**, copyright eggspot (owner wants 100% open source where anyone can do anything) |
| 2 | Webhook retention | 7-day default, configurable, `0` = keep forever (unlimited allowed; manual or external cleanup needed) |
| 3 | Switching | Never automatic. Thresholds (queue over 1,000 for 5 min, p99 commit over about 100 ms) are advisory dashboard indicators only |
| 4 | SQLite sync default | `synchronous=OFF` for the SQLite data files (process-crash-safe, **not** power-loss-safe; corruption possible on OS crash or power loss). `Sqlite:SyncMode = Off (default) \| Normal \| Full` |
| 5 | Backends are feature-identical | SQLite vs PostgreSQL is only a storage choice; every feature behaves identically. `History:Mode = StatsOnly \| Full` is a separate setting on either backend. Switching is symmetric (Lite ↔ Full), via one portable bundle, a CLI and a guided dashboard action, with rollback. This resolves the earlier question about Full → Lite |
| 6 | `config.db` sync mode | **OWNER-DECIDED:** `config.db` stays at `synchronous=FULL` (`Sqlite:ConfigSyncMode` default `Full`); `queue.db` and `stats.db` stay `OFF` |
| 7 | Name and trademark | **OWNER-DECIDED:** keep the name EggMail; no formal trademark search and no mark registration planned. Optional, light recommendation: before wide promotion, do a free check of the USPTO, EUIPO and WIPO databases. MIT licenses the code, not the name |

Note on the license: the Unlicense / CC0 public-domain dedication is the only more-permissive alternative to MIT (weaker legal footing in some jurisdictions, and no patent grant either); say so if the owner wants it. MIT itself also has no express patent grant, unlike Apache-2.0.

## Questions awaiting the owner

1. **DKIM key re-wrapping across different key protection.** Source and target may use different `Secrets:KeyProtection` (a certificate on one, a KMS on the other, different Data Protection key rings). The design exports keys encrypted under a bundle key and re-wraps them on import. Which bundle encryption do we want: an operator passphrase (PBKDF2 from the BCL), the target's certificate public key, or both? Must it work when the source KMS key cannot be exported (the tool only needs to unwrap, so it needs access to the source KMS during export)? The exact scheme is unspecified.
2. **Queued mail during a switch.** Drain-first (empty queue, nothing to move) is the default. Is `--quiesce` (export queued deliveries and spool bodies, import preserving ids and due times) in scope for v1? It risks duplicate delivery if the source is later resumed after the target has dispatched; the design guards this by keeping the source read-only and by making rollback after activation a reverse switch.
3. **Per-message history across backends.** Moving events, content and retained raw (only when `History:Mode=Full` on both sides) is designed as optional and streamed, but can be hundreds of GB. Is it in scope for v1, or is "config, stats, queue" enough with history left in the read-only source? (It is the first cut item after ARC/TLS-RPT/DMARC reports; +1.5 weeks.)
4. **Preset defaults vs identical settings.** Every setting exists on every backend, but defaults follow the backend (SQLite: `StatsOnly`, 48 h queue lifetime, 10 MiB max message; PostgreSQL: `Full`, 5 days, 25 MiB). Should the queue lifetime and max message size defaults be unified across backends? The switch tool already carries effective values across, so switching never changes behavior silently.
5. **SQLite with `History:Mode=Full`.** A fourth file, `history.db`, holds events, content and retained raw. Is that layout acceptable, and what sizing guidance should the docs give (retention is batched `DELETE`, no partition drop)?
6. **Error status for `history_not_recorded`.** Per-message lookups in `StatsOnly` return a clear error code; the HTTP status (proposed 404) is undecided.
7. **Activating a switch.** The tool can rewrite a bootstrap file on the data volume; under orchestrators that inject configuration (environment, Kubernetes manifests) it can only display the change to apply. Acceptable?
8. **Where certificates and ACME state live.** The design keeps them in a certificate store independent of the backend (volume or secret mount). If they are meant to live in the database, they must travel in the bundle as wrapped secrets.
9. **`Content:RetentionDays`.** It stays 6–30 with no unlimited value (floor: outlive the 5-day queue; ceiling: personal data and storage). Does the owner want a higher ceiling or an explicit override switch? Unlimited was allowed for webhook outbox/attempt log, `Retention:MetadataDays`, `Stats:HourlyRetentionDays` and `Stats:DailyRetentionDays` ([design.md §5.1](design.md#51-retention-knobs-and-unlimited-retention)); confirm that `0` as the "keep forever" value is fine.
10. **SQLite default warnings.** Is the prominent power-loss/corruption warning in the README acceptable as the main mitigation, or should the SQLite backend refuse `Off` unless an explicit acknowledgement setting is present? (Current design: `Off` is the silent default plus a dashboard banner.)
11. **Effort.** The totals now include roughly +8 weeks (+2.5 corruption handling and the earlier switch, +5.5 for feature-identical backends and the symmetric switch) as new rough author estimates; they should be re-estimated ([plan.md](plan.md)).

## Questions still open in the sources

- What are the real daily message volume and average message size? The Postgres content-storage sizing and split thresholds scale with them.
- Is raw Npgsql allowed for the body insert if profiling shows EF `byte[]` allocates too much? Default: EF only.
- Should subjects be stored in the 30-day metadata, given the privacy question? (`Content:StoreSubject` is configurable either way.)
- Is a 7-day default for content, with resend only inside that window, acceptable? (Adopted as the working default.)
- Who owns deliverability operations (IPs, warm-up, abuse desk)? They sit outside the engineering estimate.
- Is a time-boxed external security audit funded before first production-critical use?
- Which deployment targets must work first (single container only, or Kubernetes from day one), and which cloud will host it? That decides whether inbound port 25 and a multi-port LoadBalancer are possible.
- Is a Cloudflare DNS-01 integration enough for ACME in the first release?
- Should "require TLS" be a tenant-level setting, a per-domain setting, or both?
- Is DANE needed at launch, or can it wait with TLS-RPT?
- Domain verification state machine: the consolidated decisions record is truncated at that item; confirm the proposed machine ([design.md §8](design.md#8-domain-verification)).

## Items to settle with spikes

- SQLite commit rate on SSD under `synchronous=OFF`, `NORMAL` and `FULL` (Phase 0/1 benchmark spike), and the SQLite backend's behavior under group commit; whether group commit still pays off under `OFF`.
- Bundle export/import throughput on both backends (EF bulk insert in batches), and verification cost, for large stats and history volumes.
- Round-trip fidelity: SQLite → PostgreSQL → SQLite preserves config, stats and queue exactly (date/time and decimal handling differ between the providers).
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
- All values marked "proposed" or "mine" in the source: 256 KiB stored body, 48 h Lite-preset queue lifetime, 10 MiB Lite-preset max message, 1,000-event ring, 20 KB average content size, 7-day retention default, per-endpoint concurrency 4, connection pool sizes, volume thresholds for splitting databases, and the 15–20 week Lite-first saving
