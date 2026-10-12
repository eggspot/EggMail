# Open questions and pending items

## Decided by default: awaiting owner confirmation

The owner answered all four questions with the proposed defaults. They are treated as decided, and kept here until the owner explicitly confirms.

| # | Question | Default adopted |
|---|---|---|
| 1 | License | Apache-2.0 (patent grant, adoption). Alternatives: MIT, or AGPL-3.0 + commercial license to guard against closed hosted forks |
| 2 | Webhook outbox and attempt-log retention | 7 days, configurable up to 30 |
| 3 | Lite "move to Full" signals | Writer queue depth over 1,000 for 5 minutes, or p99 commit latency over about 100 ms |
| 4 | `Lite:SyncMode=Normal` | Documented as an explicit opt-in; default remains `FULL` |

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

- SQLite commit rate on SSD with `synchronous=FULL` (Phase 0/1 benchmark spike), and Lite behavior under group commit.
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
- All values marked "proposed" or "mine" in the source: 256 KiB stored body, 48 h Lite queue, 10 MiB Lite max message, 1,000-event ring, 20 KB average content size, 7-day retention default, per-endpoint concurrency 4, connection pool sizes, volume thresholds for splitting databases, and the 15–20 week Lite-first saving
