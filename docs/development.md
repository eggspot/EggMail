# Development guide

## Prerequisites

- .NET 10 SDK (`global.json` pins the feature band; `dotnet --version` should print 10.0.x).
- Node 22 and npm 10 for the dashboard (`dashboard/`), only needed to work on the UI.
- Optional: a local PostgreSQL (16 or newer) for the Postgres backend tests. Docker is **not** used for development (project rule); the Docker image is built by GitHub Actions only.

## Build and test

```sh
dotnet build EggMail.slnx
dotnet test EggMail.slnx                 # all unit, protocol, loopback and storage tests
dotnet test tests/Mta.Smtp.Server.Tests  # one project
```

Postgres-backed tests read `EGGMAIL_TEST_POSTGRES` (a connection string to an existing server and a database the test user may create schemas in). Without it the tests start a throwaway cluster from the PostgreSQL binaries on `PATH` (`initdb`, `pg_ctl`), and are skipped when those are not installed.

## Project map

See [design.md §2.2](design.md#22-indicative-solution-layout). The assemblies `Mta.Core`, `Mta.Dns`, `Mta.Mime`, `Mta.Dkim`, `Mta.Auth`, `Mta.Dsn`, `Mta.Tls` and `Mta.Smtp.*` are **package-free** (decision 4): `tests/Mta.ArchitectureTests` fails the build if one of them gains a `PackageReference` or references a non-guarded project. Component notes live in `docs/components/`.

## Run it locally

```sh
dotnet run --project src/Mta.Host -c Release -- --Sqlite:DataDirectory=/tmp/eggmail-data
```

Defaults: SQLite backend in `Sqlite:DataDirectory` (default `/data`), SMTP on 5587 (STARTTLS submission), 4465 (implicit TLS), 2525, 2526 (bounce role), dashboard/API on 8080 (HTTP) and 8443 (HTTPS, self-signed on first run). Configuration comes from, highest precedence first: command line, environment variables (`Storage__Backend=Postgres`), a `bootstrap.json` in the data directory, built-in defaults ([design.md §4.6](design.md#46-switching-backends-manual-and-symmetric)).

## Load and sink tools

`src/Mta.Tools` builds `mta-tools` (see [benchmarks.md](benchmarks.md)). Benchmarks use BenchmarkDotNet: `dotnet run -c Release --project bench/Mta.Benchmarks -- --filter "*Dkim*"`.

## Conventions

- Branch per milestone (`feat/<slug>`), pull request into `main`, squash merge after the diff has been reviewed twice (correctness, then style/tests/leftovers). Commit messages end with the co-author trailer.
- Warnings are errors; nullable is on; file-scoped namespaces; no allocations on hot paths without a benchmark.
- Every user-visible behavior that a decision names is covered by a test; update [decisions.md](decisions.md), [design.md](design.md) and [progress.md](progress.md) in the same pull request when implementation forces a change, marking it DESIGN-DECIDED with the reason.

## Continuous integration

`.github/workflows/ci.yml` builds and tests on Linux with a Postgres service. GitHub Actions is currently disabled for the repository by the organization, so contributors must run `dotnet test EggMail.slnx` locally before merging ([open-questions.md](open-questions.md)).
