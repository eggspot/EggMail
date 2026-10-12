# Open questions and pending items

## Owner decisions applied (2026-10-12)

The four former "decided by default" items are now **OWNER-DECIDED**. See [decisions.md](decisions.md) (A–D).

| # | Topic | Decision |
|---|---|---|
| 1 | License | **MIT**, copyright eggspot (owner wants 100% open source where anyone can do anything) |
| 2 | Webhook retention | 7-day default, configurable, `0` = keep forever (unlimited allowed; manual or external cleanup needed) |
| 3 | Lite vs Full | Never automatic. Thresholds (queue over 1,000 for 5 min, p99 commit over about 100 ms) are advisory dashboard indicators only. Switching is a guided, owner-triggered dashboard action |
| 4 | Lite SQLite sync default | `synchronous=OFF` for `queue.db` and `stats.db` (process-crash-safe, **not** power-loss-safe; corruption possible on OS crash or power loss). `Lite:SyncMode = Off (default) \| Normal \| Full` |

Note on the license: the Unlicense / CC0 public-domain dedication is the only more-permissive alternative to MIT (weaker legal footing in some jurisdictions, and no patent grant either); say so if the owner wants it. MIT itself also has no express patent grant, unlike Apache-2.0.

## Questions awaiting the owner

1. **`config.db` sync mode.** The design authors recommend keeping `config.db` at `FULL` (`Lite:ConfigSyncMode`), because it is rarely written and holds DKIM keys, API-key hashes and the Data Protection key ring. This deviates from the owner's "`OFF` for queue and stats" and needs explicit confirmation.
2. **Full → Lite.** Earlier decision: unsupported. Adopted for now as the safest option: no in-place switch; only a config-only export (explicit typed confirmation, per-message history does not carry over, Full data untouched) to seed a new Lite install. Should the dashboard offer even that export, or remain fully unsupported?
3. **`Content:RetentionDays`.** It stays 6–30 with no unlimited value (floor: outlive the 5-day queue; ceiling: personal data and storage). Does the owner want a higher ceiling or an explicit override switch? Unlimited was allowed for webhook outbox/attempt log, `Retention:MetadataDays`, `Stats:HourlyRetentionDays` and `Stats:DailyRetentionDays` ([design.md §5.1](design.md#51-retention-knobs-and-unlimited-retention)); confirm that `0` as the "keep forever" value is fine.
4. **Lite default warnings.** Is the prominent power-loss/corruption warning in the README acceptable as the main mitigation, or should Lite refuse `Off` unless an explicit acknowledgement setting is present? (Current design: `Off` is the silent default plus a dashboard banner.)
5. **Effort.** The +2.5 weeks (range +1.5 to +4.5) for Lite corruption handling and the guided mode switch are new rough author estimates; they should be re-estimated.

## Pending checks

- **Trademark search for "EggMail": not done.** The earlier research only found no exact name collision on GitHub, npm, NuGet, crates.io, PyPI or Docker Hub; similar names exist (npm `egg-mail`, an Egg.js plugin last published in 2022; a cancelled "EGISMAIL" trademark); eggmail.com/.net/.org appear registered. This is not a trademark search. The name remains provisional until a real one is done.

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

- SQLite commit rate on SSD under `synchronous=OFF`, `NORMAL` and `FULL` (Phase 0/1 benchmark spike), and Lite behavior under group commit; whether group commit still pays off under `OFF`.
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
- The 120 B row size and 30% active-series assumptions behind the Lite stats size model
- Stripe's and Postmark's webhook timeouts; SendGrid's 24 h webhook retry (snippet only); SendGrid's full SMTP port list
- Haraka's ingest behavior and fsync policy
- WAL volume at 1–1.5× data and text/HTML compression ratios; that a day partition's TOAST table is dropped with it
- Whether the EF provider can map `Stream` for `bytea`
- Mailgun and SendGrid retention/at-rest figures; Cloud SQL pricing and HA behavior
- OpenSSL TLS 1.3 ticket caching; fsync behavior on overlayfs/XFS/ext4; Native AOT feasibility
- The partition-count cost of unlimited `Retention:MetadataDays` (PostgreSQL partitioning docs, not re-fetched)
- All values marked "proposed" or "mine" in the source: 256 KiB stored body, 48 h Lite queue, 10 MiB Lite max message, 1,000-event ring, 20 KB average content size, 7-day retention default, per-endpoint concurrency 4, connection pool sizes, volume thresholds for splitting databases, and the 15–20 week Lite-first saving
