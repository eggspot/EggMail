# EggMail

An open-source, self-hosted **outbound email server** from [eggspot](https://github.com/eggspot): SMTP ingress, an HTTP API, delivery tracking and a dashboard, built on .NET 10 with performance as the primary goal.

> **Status: design phase.** There is no code yet. This repository currently holds the design documents only. Nothing here is released, benchmarked or production-ready.

> **Name:** "EggMail" is a working name. A real trademark search has **not** been done yet (see [docs/open-questions.md](docs/open-questions.md)).

> **Lite mode default is fast, not power-loss-safe.** Lite defaults to SQLite `PRAGMA synchronous=OFF` for `queue.db` and `stats.db`. A process kill or container restart is safe. If the **operating system crashes or power fails**, the SQLite docs say the database **can be corrupted** (not just lose the latest commits), which can lose all queued mail, including mail already acknowledged with `250`. Use `Lite:SyncMode=Full` (or `Normal`) if you need power-loss safety, or use Full mode. See [docs/design.md §4.2](docs/design.md#42-lite-mode-sqlite-via-microsoftdatasqlite).

## What and why

- Accepts mail over SMTP (submission ports 587/465/2525) and over an HTTP API, queues it, and delivers it directly to recipient MX servers (or through an opt-in relay chain).
- Tracks every delivery (events, bounces, complaints), sends signed webhooks and shows it all in a dashboard.
- The goal is to be **the fastest SMTP server**. That claim will be made only after reproducible measurement, with durable and non-durable results always reported together and an independent run reproducing them. Performance is a permanent first-class goal in **both** modes: Lite is engineered for large, high-throughput workloads, not treated as a toy. See [docs/benchmarks.md](docs/benchmarks.md).
- The SMTP stack (server and client, MIME, DKIM, SPF, DMARC, DSN/ARF, DNS client, MTA-STS, TLS-RPT, DANE) is hand-written and uses only the .NET BCL and ASP.NET Core shared framework. CI will enforce that those assemblies have no package references.

## Modes

| | **Full** | **Lite** |
|---|---|---|
| Storage | PostgreSQL (EF Core + Npgsql) | SQLite (Microsoft.Data.Sqlite), three files |
| Deployment | App + managed Postgres (HA is a prerequisite), compose or Kubernetes | One container, one volume, one replica |
| Replicas | Several | One |
| Per-message record | Yes: events, content, search, resend | No: statistics only |
| Tenancy | Multi-tenant | Multi-tenant |
| Throughput cap | None built in | None built in (bounded by your hardware) |
| Queue lifetime | 5 days | 48 hours |
| Acknowledgement | `250`/`202` only after a durable (synced) commit | `250`/`202` after the data is handed to the OS. **Process-crash-safe, not power-loss-safe** by default (`Lite:SyncMode=Off`) |
| Switching | Manual only (see below) | Manual only (see below) |

**Modes never switch automatically.** The Lite dashboard shows advisory "consider Full" indicators; moving between modes is a guided, explicit, owner-triggered action (Lite → Full: drain, export/import config, confirm; Full → Lite: config-only export for a fresh install). Details in [docs/design.md](docs/design.md).

## Documentation

| Document | Contents |
|---|---|
| [docs/design.md](docs/design.md) | Architecture, components, interfaces, Full vs Lite storage, content retention, webhooks, TLS and ports, security, deployment |
| [docs/decisions.md](docs/decisions.md) | The decisions record (owner decisions and items 1–28) |
| [docs/plan.md](docs/plan.md) | Components with engineer-week estimates, phases, cut order, risks, calendar |
| [docs/benchmarks.md](docs/benchmarks.md) | How performance will be measured and compared, per mode |
| [docs/open-questions.md](docs/open-questions.md) | Pending checks, questions awaiting the owner, unverified items |

## Caveats

- All effort figures are estimates and all sizes are modeled, not measured.
- Items marked **unverified** in the docs were not confirmed against a primary source.
- Defaults marked "proposed" are the design authors' choices, not industry standards.

## License

[MIT](LICENSE), copyright eggspot. Owner-decided.
