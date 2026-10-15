# EggMail

An open-source, self-hosted **outbound email server** from [eggspot](https://github.com/eggspot): SMTP ingress, an HTTP API, delivery tracking and a dashboard, built on .NET 10 with performance as the primary goal.

> **Status: implemented, not yet production-ready.** The SMTP stack, delivery engine, both storage backends, the HTTP API, the dashboard and the backend switch are written and tested locally (see [docs/progress.md](docs/progress.md) for exactly what is verified and what is not). No stable release has been tagged (so there is no `latest` image and no GitHub Release yet), no publishable benchmark results exist, and no independent security audit has been done. GitHub Actions runs CI and the release workflow, which pushes the image by digest, smoke-tests that digest and only then tags it (`nightly`, `nightly-<sha>` for manual runs). Every build gets the image test (SMTP submission with AUTH, API, delivery to a sink) and the PostgreSQL compose test; tags and manual runs also test the SQLite compose file, the Unbound sidecar and the Kubernetes manifests; see [docs/release.md](docs/release.md).

> **Name:** the name EggMail is kept. No formal trademark search or registration is planned (owner decision); the MIT license covers the code, not the name. A free check of the USPTO, EUIPO and WIPO databases before wide promotion is recommended but optional (see [docs/decisions.md](docs/decisions.md)).

> **The SQLite backend's default is fast, not power-loss-safe.** The SQLite backend defaults to `PRAGMA synchronous=OFF` for its data files. A process kill or container restart is safe. If the **operating system crashes or power fails**, the SQLite docs say the database **can be corrupted** (not just lose the latest commits), which can lose all queued mail, including mail already acknowledged with `250`. EggMail does not ask you to acknowledge this; instead it warns loudly (a startup log warning, a persistent dashboard banner, and a metric and health detail). Use `Sqlite:SyncMode=Full` (or `Normal`) if you need power-loss safety, or use the PostgreSQL backend. See [docs/design.md §4.4](docs/design.md#44-sqlite-backend-microsoftdatasqlite).

## What and why

- Accepts mail over SMTP (submission ports 587/465/2525) and over an HTTP API, queues it, and delivers it directly to recipient MX servers (or through an opt-in relay chain).
- Tracks every delivery (events, bounces, complaints), sends signed webhooks and shows it all in a dashboard.
- The goal is to be **the fastest SMTP server**. That claim will be made only after reproducible measurement, with durable and non-durable results always reported together and an independent run reproducing them. Performance is a permanent first-class goal on **both** storage backends: the SQLite backend is engineered for large, high-throughput workloads, not treated as a toy. See [docs/benchmarks.md](docs/benchmarks.md).
- The SMTP stack (server and client, MIME, DKIM, SPF, DMARC, DSN/ARF, DNS client, MTA-STS, TLS-RPT, DANE) is hand-written and uses only the .NET BCL and ASP.NET Core shared framework. CI will enforce that those assemblies have no package references.

## Storage backends: one feature set, two ways to store it

**SQLite vs PostgreSQL is only a storage-backend choice.** Every feature (SMTP/API, DKIM/SPF/DMARC, domain verification, tenants, API keys, suppressions, webhooks, rate limits, warm-up, settings, dashboard pages, ACME/TLS) behaves identically on both. The backend decides only how data is stored persistently and long-term.

**SQLite is the default backend**, so a single container with one volume works out of the box; PostgreSQL is selected by configuration in the same image. How much **per-message history** is recorded is a separate setting, `History:Mode` (`StatsOnly` | `Full`), that works on either backend. **Any combination is allowed.**

"Lite" and "Full" are friendly names for the two backends' default deployment shapes: **Lite = SQLite, Full = PostgreSQL. They have exactly the same defaults for every behavioural setting.** Only the storage backend and its storage-specific defaults differ:

| | **Lite** (SQLite) | **Full** (PostgreSQL) |
|---|---|---|
| `Storage:Backend` | `Sqlite` (**the default**) | `Postgres` |
| `History:Mode` default | `Full` | `Full` |
| Queue lifetime / max message / recipients | 5 days / 25 MiB / 50 | 5 days / 25 MiB / 50 |
| Content retention, attachments, webhooks, stats | identical | identical |
| Acknowledgement | `250`/`202` after the data is handed to the OS (`Sqlite:SyncMode=Off`, a storage setting): **process-crash-safe, not power-loss-safe** | `250`/`202` only after a durable (synced) commit |

`History:Mode=Full` (events, search, content for 7 days, resend) is the default on both. For the lightweight, fire-and-forget behavior (statistics and a recent-events ring, no per-message record) set `History:Mode=StatsOnly` on either backend. See [docs/design.md §4.1](docs/design.md#41-backends-history-level-and-presets).

Backend **characteristics** (not missing features): SQLite is single node and one replica, has a single-writer throughput ceiling, uses a local volume only, and retains data with batched deletes instead of partition drops; PostgreSQL brings HA and multiple replicas and needs a managed Postgres. Details in [docs/design.md §4.2](docs/design.md#42-backend-characteristics-not-feature-differences).

**Switching is manual, symmetric and easy; it never happens automatically.** Dashboard indicators are advisory only. A guided dashboard action and a CLI (`mta migrate-storage --to postgres|sqlite`) move you in either direction with one portable, versioned bundle: preflight, drain or quiesce (no need to wait for an empty queue), export, import, verify, confirm, activate, with rollback. The bundle carries config, certificates and ACME state, stats, queued mail and, optionally, per-message history; secrets travel protected by Data Protection and are never written in clear. Only the storage changes; features and settings stay as they were. See [docs/design.md §4.6](docs/design.md#46-switching-backends-manual-and-symmetric).

## Quick start

One Docker image, one command, **no configuration**: it starts on SQLite with everything it needs and is usable at once. There is no stable release yet, so there is no `latest` or version tag: use `nightly` (the daily build of `main`; manual runs publish `nightly-<short sha>`) and pin a digest, or a version tag once releases exist.

```sh
docker run -d --name eggmail -p 587:5587 -p 465:4465 -p 2525:2525 -p 8443:8443 \
  -v eggmail-data:/data ghcr.io/eggspot/eggmail:nightly
docker logs eggmail    # the dashboard administrator password, printed ONCE, between two marker lines
```

Open `https://localhost:8443` (the certificate is self-signed until you set up a real one, and the dashboard says so), sign in as `admin` with the printed password and choose your own when the dashboard asks (the printed one is temporary, and it stays readable in the container log until you do). SMTP submission with AUTH works on 587 (STARTTLS), 465 (implicit TLS) and 2525. The first start creates the data directory and SQLite files, the key ring, the VERP key, the administrator and the certificate; a DKIM key is generated for every sending domain you add.

Then, in the dashboard: add your sending domain (it shows the DNS records to publish; the domain is usable once its DKIM record verifies), create an **SMTP credential** or an **API key** under Credentials, and point your application at port 587 (or `POST /api/v1/messages`).

**For a real server** add three or four variables (the complete list, with what each one maps to, is [The simple environment variables](docs/operations.md#the-simple-environment-variables); the long configuration keys keep working and win):

```sh
docker run -d --name eggmail-prod \
  -p 587:5587 -p 465:4465 -p 2525:2525 -p 8443:8443 -v eggmail-prod-data:/data \
  -e EGGMAIL_HOSTNAME=mail.example.com \
  -e EGGMAIL_ACME_EMAIL=admin@example.com \
  -e EGGMAIL_DOMAINS=example.com \
  ghcr.io/eggspot/eggmail:nightly
```

`EGGMAIL_HOSTNAME` is the name in SMTP greetings, the certificate and the dashboard; together with `EGGMAIL_ACME_EMAIL` it turns on a free, automatically renewed certificate. `EGGMAIL_DOMAINS` registers your sending domains at the start, `CLOUDFLARE_API_TOKEN` selects the DNS-01 challenge instead of port 80, `EGGMAIL_ADMIN_PASSWORD_FILE` lets you choose the administrator password instead of having one generated, `EGGMAIL_RELAY=host:port` adds a smarthost fallback. What you must still do outside the container (DNS records, reverse DNS, outbound port 25, firewall) is [listed in the operations guide](docs/operations.md#what-only-you-can-do-outside-the-container); port 25 is not a submission port ([ports](docs/operations.md#ports)).

**Lost the administrator password?** (Use your own container and volume names.) Create another administrator (SQLite: the server container must be stopped; PostgreSQL: it can run, add your `-e EGGMAIL_DATABASE=...`), then reset or delete the old account in the dashboard:

```sh
docker stop eggmail
docker run --rm -v eggmail-data:/data -e MTA_ADMIN_PASSWORD='a-new-password-1' ghcr.io/eggspot/eggmail:nightly admin create --user rescue
docker start eggmail
```

**With Docker Compose** (the tested file is [`deploy/compose/compose.yaml`](deploy/compose/compose.yaml)):

```yaml
services:
  eggmail:
    image: ghcr.io/eggspot/eggmail:nightly
    environment:
      EGGMAIL_HOSTNAME: mail.example.com
      EGGMAIL_ACME_EMAIL: admin@example.com
    ports: ["587:5587", "465:4465", "2525:2525", "8443:8443"]
    volumes: ["eggmail-data:/data"]
volumes:
  eggmail-data:
```

**With PostgreSQL**: the same, plus **one** variable, `EGGMAIL_DATABASE` (the tested file is [`deploy/compose/compose.postgres.yaml`](deploy/compose/compose.postgres.yaml)):

```yaml
services:
  eggmail:
    image: ghcr.io/eggspot/eggmail:nightly
    depends_on: { postgres: { condition: service_healthy } }
    environment:
      EGGMAIL_HOSTNAME: mail.example.com
      EGGMAIL_ACME_EMAIL: admin@example.com
      EGGMAIL_DATABASE: "Host=postgres;Database=eggmail;Username=eggmail;Password=change-me"   # the only difference
    ports: ["587:5587", "465:4465", "2525:2525", "8443:8443"]
    volumes: ["eggmail-data:/data"]
  postgres:
    image: postgres:17
    environment: { POSTGRES_USER: eggmail, POSTGRES_PASSWORD: change-me, POSTGRES_DB: eggmail }
    volumes: ["pgdata:/var/lib/postgresql/data"]
    healthcheck: { test: ["CMD-SHELL", "pg_isready -U eggmail -d eggmail"], interval: 5s, retries: 10 }
volumes:
  eggmail-data:
  pgdata:
```

Ready-made, tested deployment files live in [`deploy/`](deploy/):

| What | Where |
|---|---|
| Compose, SQLite (default) | [`deploy/compose/compose.yaml`](deploy/compose/compose.yaml) |
| Compose, PostgreSQL | [`deploy/compose/compose.postgres.yaml`](deploy/compose/compose.postgres.yaml) |
| Optional Unbound sidecar (DNSSEC validation, so DANE works) | [`deploy/compose/compose.unbound.yaml`](deploy/compose/compose.unbound.yaml) |
| Kubernetes (StatefulSet for SQLite, Deployment for PostgreSQL, NetworkPolicy, probes) | [`deploy/kubernetes/`](deploy/kubernetes/) |

The container healthcheck is `["CMD", "/app/mta", "--healthcheck"]`: the chiseled image has no shell and `mta` is not on `PATH`, so the absolute path is required. Details, ports and the release process: [docs/release.md](docs/release.md) and [docs/operations.md](docs/operations.md).

## Documentation

| Document | Contents |
|---|---|
| [SECURITY.md](SECURITY.md), [docs/security.md](docs/security.md) | How to report a vulnerability; the threat model, implemented controls and known gaps |
| [docs/operations.md](docs/operations.md) | Running it: configuration reference, DNS records, backups and restore, monitoring, upgrades |
| [docs/design.md](docs/design.md) | Architecture, components, interfaces, storage backends and history level, switching, content retention, webhooks, TLS and ports, security, deployment |
| [docs/decisions.md](docs/decisions.md) | The decisions record (owner and design decisions A–T and items 1–52) |
| [docs/plan.md](docs/plan.md) | Components with engineer-week estimates, phases, cut order, risks, calendar |
| [docs/benchmarks.md](docs/benchmarks.md) | How performance is measured and compared, per mode; the allocation regression gate; the Postfix/KumoMTA comparison setup; trend numbers from CI |
| [docs/release.md](docs/release.md) | Release and packaging: the single Docker image, `ghcr.io/eggspot/eggmail`, the GitHub Actions release workflow and its smoke tests, release assets, compose and Kubernetes files |
| [CHANGELOG.md](CHANGELOG.md) | What changed in each release (Keep a Changelog, Semantic Versioning); the source of the GitHub Release notes |
| [docs/funding.md](docs/funding.md) | Sponsorship and funding policy draft, platform options, the owner's setup steps |
| [docs/open-questions.md](docs/open-questions.md) | Questions awaiting the owner, items to settle with spikes, unverified items |

## Caveats

- All effort figures are estimates and all sizes are modeled, not measured.
- Items marked **unverified** in the docs were not confirmed against a primary source.
- Defaults marked "proposed" are the design authors' choices, not industry standards.

## Sponsor / Support the project

[![Sponsor eggspot](https://img.shields.io/badge/sponsor-eggspot-ea4aaa?logo=githubsponsors&logoColor=white)](https://github.com/sponsors/eggspot)

EggMail is free and MIT-licensed, and stays that way: sponsors get no features and no priority. If it is useful to you, sponsorship helps pay for maintenance, security work (including a future external audit), benchmark hardware and documentation. Details and policy: [docs/funding.md](docs/funding.md).

<!-- The sponsor link works once GitHub Sponsors is enabled for the eggspot organization (see docs/funding.md). -->

## License

[MIT](LICENSE), copyright eggspot. Owner-decided.
