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

## ACME tests (Pebble)

`tests/Mta.Integration.Tests/Acme` runs the certificate issuance and renewal flow against [Pebble](https://github.com/letsencrypt/pebble), Let's Encrypt's ACME test server, and `pebble-challtestsrv` (the DNS server Pebble validates DNS-01 against and resolves the test names with; HTTP-01 is validated against the listener of the tests). They are **skipped** unless `EGGMAIL_TEST_ACME_DIRECTORY` is set. CI runs both as containers; locally, without Docker, use the release binaries from the Pebble releases page (pinned in CI to 2.10.1) and the test certificates in the Pebble source tree:

```sh
# 1. Switch the challenge servers off (DNS-01 is answered through its management API, HTTP-01 by the tests' own listener on :5002), and
#    answer IPv4 only so that Pebble connects to 127.0.0.1. Listens on :8053 (DNS) and :8055 (management).
pebble-challtestsrv -http01 "" -https01 "" -tlsalpn01 "" -doh "" -defaultIPv6 ""
# 2. Pebble, from a checkout/tarball of the same release (it reads test/config and test/certs relative to the working directory).
PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 PEBBLE_AUTHZREUSE=100 pebble -config test/config/pebble-config.json -dnsserver 127.0.0.1:8053
# 3. Optional, for the external account binding tests: a second Pebble that refuses accounts without it (same environment variables; the config
#    is .github/pebble/pebble-config-eab.json, with its own ports 14100 and 15100).
PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 PEBBLE_AUTHZREUSE=100 pebble -config <repo>/.github/pebble/pebble-config-eab.json -dnsserver 127.0.0.1:8053
# 4. The tests.
EGGMAIL_TEST_ACME_DIRECTORY=https://localhost:14000/dir \
EGGMAIL_TEST_ACME_EAB_DIRECTORY=https://localhost:14100/dir \
EGGMAIL_TEST_ACME_CA_FILE=<pebble checkout>/test/certs/pebble.minica.pem \
  dotnet test tests/Mta.Integration.Tests --filter "FullyQualifiedName~Acme"
```

The Go toolchain builds both binaries from the tag if there is no release for your platform: `git clone --branch v2.10.1 https://github.com/letsencrypt/pebble && cd pebble && GOBIN=$PWD/bin go install ./cmd/pebble ./cmd/pebble-challtestsrv`.

| Variable | Meaning |
|---|---|
| `EGGMAIL_TEST_ACME_DIRECTORY` | Pebble's directory URL. Required; unset skips the tests |
| `EGGMAIL_TEST_ACME_CA_FILE` | PEM of the CA behind Pebble's own HTTPS certificate (`test/certs/pebble.minica.pem`). Unset: system trust |
| `EGGMAIL_TEST_ACME_CHALLTESTSRV` | Management API of the challenge test server, default `http://localhost:8055` |
| `EGGMAIL_TEST_ACME_MANAGEMENT` | Pebble's management API (issuing roots), default `https://<directory host>:15000` |
| `EGGMAIL_TEST_ACME_HTTP_PORT` | The port Pebble's validation authority connects to for HTTP-01 (`httpPort` of its config), default 5002. The HTTP-01 tests bind it on the test host, so keep it free; those test classes run one after the other |
| `EGGMAIL_TEST_ACME_EAB_DIRECTORY` | Directory of the second Pebble that requires external account binding (its keys `kid-1` and `kid-2` are the ones of `pebble-config-eab.json`). Unset: the EAB tests are skipped |

Pebble knobs: `PEBBLE_VA_NOSLEEP=1` removes the random 1 to 5 s validation delay; `PEBBLE_WFE_NONCEREJECT=0` and `PEBBLE_AUTHZREUSE=100` make the CA deterministic (by default it rejects 5 % of nonces and reuses a valid authorization in half of the orders). **`PEBBLE_AUTHZREUSE=0` does not turn reuse off**: Pebble draws `rand.Intn(100) > percent`, so 0 still reuses in 1 % of the orders, which made the tests flake with "Cannot update challenge with status valid"; 100 reuses always, and two tests assert exactly that (the second order of a name publishes no TXT record). The tests also pass with `PEBBLE_WFE_NONCEREJECT=15` (the order is repeated on `badNonce`). Do not use `PEBBLE_VA_ALWAYS_VALID`: the tests rely on real validation. Pebble picks one of its certificate profiles (90 or 6 days) at random for each order; the tests derive the renewal schedule from the issued certificate. On macOS repeated runs can exhaust the ephemeral ports Pebble uses for its DNS queries ("can't assign requested address"); wait a minute between runs.

## Project map

See [design.md §2.2](design.md#22-indicative-solution-layout). The assemblies `Mta.Core`, `Mta.Dns`, `Mta.Mime`, `Mta.Dkim`, `Mta.Auth`, `Mta.Dsn`, `Mta.Tls` and `Mta.Smtp.*` are **package-free** (decision 4): `tests/Mta.ArchitectureTests` fails the build if one of them gains a `PackageReference` or references a non-guarded project. Component notes live in `docs/components/`.

## Run it locally

```sh
dotnet run --project src/Mta.Host -c Release -- --Sqlite:DataDirectory=/tmp/eggmail-data
```

Defaults: SQLite backend in `Sqlite:DataDirectory` (default `/data`), SMTP on 5587 (STARTTLS submission), 4465 (implicit TLS), 2525, 2526 (bounce role), dashboard/API on 8080 (HTTP) and 8443 (HTTPS, self-signed on first run). Configuration comes from, highest precedence first: command line, environment variables (`Storage__Backend=Postgres`), a `bootstrap.json` in the data directory, built-in defaults ([design.md §4.6](design.md#46-switching-backends-manual-and-symmetric)).

## Load and sink tools

`src/Mta.Tools` builds `mta-tools` (see [benchmarks.md](benchmarks.md)). Benchmarks use BenchmarkDotNet: `dotnet run -c Release --project bench/Mta.Benchmarks -- --filter "*Dkim*"`.

## Fuzzing

`dotnet test` includes `tests/Mta.Fuzz.Tests` (seeds, checked-in corpus, past findings and a fixed number of seeded mutations per parser, no timing assertions). The long, coverage-guided runs are `.github/workflows/fuzz.yml` (weekly, or run it by hand with the `seconds_per_target` and `targets` inputs). Details, the list of targets and how to add a regression input are in [security.md](security.md#fuzzing).

```sh
dotnet run --project fuzz/Mta.Fuzz.Harness -c Release -- list
dotnet run --project fuzz/Mta.Fuzz.Harness -c Release -- mutate dns-message 200000 7     # longer local run of the same mutator
dotnet run --project fuzz/Mta.Fuzz.Harness -c Release -- replay mime path/to/crash-file  # reproduce a finding
```

## Tests and time

Tests never assert elapsed time, throughput or process memory (they measure the load of the machine, not the code): waits are signals or polls with a deadline far above any plausible load, "no hang" is a generous limit that only turns a hang into a failure, and "bounded work" is asserted on results and on the allocated bytes of the running thread. Throughput belongs to `bench/`.

## Conventions

- Branch per milestone (`feat/<slug>`), pull request into `main`, squash merge after the diff has been reviewed twice (correctness, then style/tests/leftovers). Commit messages end with the co-author trailer.
- Warnings are errors; nullable is on; file-scoped namespaces; no allocations on hot paths without a benchmark.
- Every user-visible behavior that a decision names is covered by a test; update [decisions.md](decisions.md), [design.md](design.md) and [progress.md](progress.md) in the same pull request when implementation forces a change, marking it DESIGN-DECIDED with the reason.

## Dashboard end-to-end tests

`dashboard/e2e` drives Chromium against the real server with fake DNS, recipient SMTP and webhook receiver (`npm run e2e` in `dashboard/`, after `npx playwright install chromium`; needs the .NET SDK, `openssl`, and `psql` with `EGGMAIL_TEST_POSTGRES` or local PostgreSQL binaries for the storage switch specs). See [components/dashboard.md](components/dashboard.md#end-to-end-tests).

## Continuous integration

`.github/workflows/ci.yml` starts on every pull request (no path filter, so a required `build-test` check always reports); its first step runs `.github/scripts/changed-code.sh` and, when the change is documentation only (`docs/**`, any `*.md`, `.github/FUNDING.yml`; but `docs/operations.md` counts as code because tests compare it with the code), skips everything else and ends green after about a minute. A push to `main` keeps the path filter. Otherwise it builds and tests on Linux in one job with PostgreSQL 17 and Pebble (with its challenge test server) started by `docker run` before the tests, then checks the dashboard. Run `dotnet test EggMail.slnx` locally before pushing; without the environment variables above the PostgreSQL and ACME tests start a local cluster or are skipped. `release.yml` publishes the image and smoke-tests it ([release.md](release.md)); `bench-gate.yml` (weekly allocation gate) and `bench-throughput.yml` (manual) are described in [benchmarks.md](benchmarks.md). The deployment smoke tests in `deploy/smoke/` need Docker and are meant for Actions, but `deploy/smoke/smoke.py` runs against a locally started `mta serve` too (see its docstring).
