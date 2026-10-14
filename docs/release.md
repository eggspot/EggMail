# Release and packaging

**Status: built and exercised, not yet released.** The workflow `.github/workflows/release.yml` exists and runs: manual runs from branches publish `ghcr.io/eggspot/eggmail:nightly-<short sha>`, the package is public and the workflow pulls it anonymously on every run. **No stable tag exists yet**, so there is no `latest`, no version tag and no GitHub Release; the daily `nightly` build of `main` has been fixed but its first scheduled run is still to come. The deployment files (Compose, Kubernetes) and the smoke tests described below are in the repository and run against every published image. Facts below are marked **verified** (checked against GitHub or Docker documentation on 2026-10-12, or by a workflow run) or **unverified** (not confirmed). Decisions come from the owner or are design decisions; see [decisions.md](decisions.md).

## Decisions

| Topic | Decision |
|---|---|
| Image | **One Docker image** that runs out of the box: SQLite backend (the default), one volume at `/data`, the default ports of [design.md §7.1](design.md#71-listeners). The PostgreSQL backend is selected by configuration (`Storage:Backend=Postgres`) in the **same image** |
| Base | Chiseled .NET 10 `-extra` base (ICU included), as in decision 7; non-root, no shell |
| Platforms | `linux/amd64` and `linux/arm64` (multi-arch manifest) |
| Registry | GitHub Container Registry: `ghcr.io/eggspot/eggmail` |
| Trigger | GitHub Actions on version tags (`vMAJOR.MINOR.PATCH`); a rolling nightly build from `main`; manual runs (published as `nightly-<sha>` only) |
| Auth | `GITHUB_TOKEN` with `packages: write`; **no personal access token** |
| Supply chain | SBOM (one SPDX file per platform) and provenance attestations; GitHub Release with curated notes from `CHANGELOG.md`, per-platform digests, SBOMs and checksums |
| Docker Hub mirror | Optional, a **later** decision |

## Image tags

| Tag | Moves? | Meaning |
|---|---|---|
| `v1.4.2` | never | Exact release, from git tag `v1.4.2` |
| `1.4` | with each `1.4.x` patch release | Latest patch of a minor line |
| `latest` | with each stable release | Latest stable release |
| `nightly` | daily, from `main` | Latest `main` (the "main/nightly" tag; the name `nightly` is a proposal) |
| `nightly-<short sha>` | never | A manual run of the workflow from any branch or commit (what exists today) |

Pre-releases (`v1.5.0-rc.1`) publish only their exact tag; they do not move `1.5` or `latest`. Version numbers follow semantic versioning and the tag points at the commit that bumps the version.

## GHCR facts

- **Free for public images (verified).** GitHub's billing documentation says "GitHub Packages usage is free for public packages" and "Container image storage and bandwidth for the Container registry is currently free", with at least one month's notice before any change. Private packages have quotas and are billed beyond them.
- **New packages are private by default (verified).** GitHub's documentation says "When you first publish a package, the default visibility is private." Linking a package to a repository affects permissions, not visibility. The documentation does not say that publishing from a workflow in a **public repository** makes the package public, so a **one-time manual step** was planned (done: the package is public and the release workflow pulls the digest it just pushed with an empty Docker configuration on every run): after the first successful publish, open the package's settings, go to the "Danger Zone", choose "Change visibility", select **Public** and type the package name to confirm. **This cannot be undone** ("Once you make a package public, you cannot make it private again"). Until then anonymous pulls fail.
- **Anonymous pull works for public packages (verified):** "You can also access public container images anonymously." Check it after the visibility change with `docker logout ghcr.io` followed by `docker pull`.
- **Linking the package to the repository (verified):** add the label `org.opencontainers.image.source=https://github.com/eggspot/EggMail` in the Dockerfile; publishing from a workflow with `GITHUB_TOKEN` also links the repository. Set the label in the Dockerfile as well, so manual and local builds carry it.
- **First publish must come from the workflow (verified caveat):** GitHub warns that `GITHUB_TOKEN` cannot push if a package was previously pushed to the same namespace without being connected to the repository. Do not seed the package by hand with a personal token.
- **Publishing with `GITHUB_TOKEN` (verified in part):** the documentation lists `GITHUB_TOKEN` for publishing packages associated with the workflow repository; the attestation documentation lists `packages: write` (together with `id-token: write`, `attestations: write`, `contents: read`) for container images.
- **Image name (partly verified):** the format is `ghcr.io/NAMESPACE/IMAGE_NAME`. `eggspot/eggmail` is already lowercase; a lowercase requirement was not stated on the page checked (**unverified**), so keep it lowercase.
- **Unverified:** the organization-level settings that can restrict package visibility or creation (an organization owner may have to allow public packages); GitHub Actions minutes for public repositories (see below).

## Supply chain

- **SBOM and provenance with Docker (verified):** `docker/build-push-action` takes `sbom: true`; provenance is set with `provenance: mode=max` (public repositories already default to `mode=max`). Caveats from Docker's documentation: provenance contains build argument values, so **never pass secrets as build args** (use secret mounts); attestations require pushing directly to a registry (not `load: true` or the `docker` exporter). **Verified by a run:** with `linux/amd64,linux/arm64` the index carries an SPDX SBOM and a provenance attestation per platform, and `.github/scripts/release-assets.sh` extracts one SBOM file per platform from it.
- **GitHub artifact attestation (verified):** an `attest` action step after the build (documented as `actions/attest@v4`), with `subject-name: ghcr.io/eggspot/eggmail` (fully qualified, **no tag**), `subject-digest` from the build step's `digest` output, `push-to-registry: true`, and workflow permissions `id-token: write`, `attestations: write`, `contents: read`, `packages: write`. **Verified by a run:** on a multi-platform image pushed to a public repository the action also wants `artifact-metadata: write` (it creates a "storage record"; the run log said `Failed to create storage record ... Please check that the "artifact-metadata:write" permission has been included`), which the workflow now grants.
- **GitHub Release** on each tag (a tag with a `-` is marked pre-release): release notes from the curated `CHANGELOG.md` section of the version, the image digests of the index and of each platform, one SBOM file per platform, and a `checksums.txt` (SHA-256) covering the attached files. The SBOMs and checksums are uploaded by the same workflow as the release, so they are conveniences (they detect a corrupted download), **not** an independent integrity proof; that is the registry digest plus the build-provenance attestation, whose verification command (with `--source-ref` and `--signer-workflow`) is in every release note. Attesting the SBOMs themselves (`actions/attest` SBOM predicate) is possible and not done yet. Standalone `mta` CLI binaries are not planned as release assets (open question). Creating the Release itself has not run yet (it needs a tag); everything it attaches is produced, checked and kept as a workflow artifact on every manual run.

## The release workflow (as built)

`.github/workflows/release.yml`. One job on `ubuntu-latest` (billing rules: one job, the cheapest runner, tight per-step timeouts, cheapest checks first, no larger runners, no matrix). Triggers: push of a tag `vMAJOR.MINOR.PATCH[-pre]`; a daily schedule for `nightly` that does nothing when that commit already has a nightly (a cache marker); `workflow_dispatch`, which publishes **only** `nightly-<short sha>` (never a version tag, never `latest`, no GitHub Release). Permissions are job-level: `contents: write` (the Release), `packages: write`, `id-token: write`, `attestations: write` and `artifact-metadata: write`. The last one is needed by `actions/attest`, which stores a "storage record" for the image; without it the action logs `Failed to create storage record ... Please check that the "artifact-metadata:write" permission has been included` and the attestation still succeeds but is not linked to the package.

| Step | What it does | Fails the run when |
|---|---|---|
| Refuse a dispatch on a tag; tag on main | a `workflow_dispatch` on a tag ref is refused (only pushing the tag releases it); the tag commit must be on `main` (`gh api compare/main...<sha>` says `identical` or `behind`) | either is false |
| Validate (tags only) | the tag is `vMAJOR.MINOR.PATCH[-pre]`, equals `<Version>` in `Directory.Build.props`, and `CHANGELOG.md` has a non-empty `## [X.Y.Z]` section (a pre-release may fall back to `[Unreleased]` with a warning) | any is false |
| `ci` green for this commit? | asks the API whether the `ci` workflow succeeded for the same SHA (needs `actions: read` at job level); if so the build and tests are not repeated | never (it only chooses) |
| Build and test | `dotnet build` and `dotnet test` of the solution, only when CI has not already passed | a build or test failure |
| Version tag must not exist | `docker buildx imagetools inspect <image>:vX.Y.Z` must fail: published version tags never move | the tag exists |
| Build and push **by digest** | `docker/build-push-action` with `push-by-digest=true`: `linux/amd64,linux/arm64`, SBOM and `provenance: mode=max`, `READYTORUN` build argument (below), layer cache in the Actions cache. **No tag is applied yet.** The .NET stage runs on the build platform and publishes for each target runtime, so there is no QEMU emulation | |
| Attest | `actions/attest` on the image digest, pushed to the registry | |
| Image smoke test | `deploy/smoke/image.sh` on the digest (below) | any check |
| Release assets | `.github/scripts/release-assets.sh`: per-platform digests, one SPDX SBOM file per platform, `checksums.txt`; kept as a workflow artifact for 3 days on manual runs | an expected manifest or SBOM is missing |
| PostgreSQL compose smoke test | `deploy/smoke/compose.sh postgres` | any check |
| SQLite compose, Unbound, Kubernetes smoke tests | `deploy/smoke/compose.sh sqlite`, `compose.sh unbound`, `kubernetes.sh`; **tags and manual runs only**, not the daily nightly (about two extra minutes) | any check |
| Give the tested digest its tags | `docker buildx imagetools create -t ... <image>@<digest>` for the tags computed by `docker/metadata-action` (`vX.Y.Z`, `X.Y`, `latest` for a stable tag push; `nightly` for the schedule; `nightly-<sha>` for a manual run), then each tag is resolved again and must equal the digest | a tag does not resolve to the digest |
| Nightly marker | remembers the commit that has a nightly | |
| GitHub Release (tag **push** only) | notes from the `CHANGELOG.md` section (`.github/scripts/release-notes.sh`) plus pull and verify instructions and the digest list; attaches `image-digests.txt`, `sbom-linux-amd64.spdx.json`, `sbom-linux-arm64.spdx.json` and `checksums.txt`; a tag with `-` in it is a GitHub pre-release | |

All third-party actions are pinned by commit SHA (the version is in a comment); a bump is a deliberate pull request. **Trade-off, accepted:** the whole release is one job, so the build and test step (when `ci` has not already passed on the commit) runs with the job's write permissions (`packages`, `contents`, `id-token`, `attestations`). Splitting it into a read-only test job and a write job would add a second job's set-up and per-minute rounding to every release. The mitigation is in the triggers: tags on `main`, the schedule, and manual runs by people with write access, never pull requests, plus the SHA pins.

Because the image is pushed by digest and tagged only after the tests, a failing smoke test leaves **no tag** pointing at the failed image: the untagged digest stays in the registry (and can be garbage-collected) and the previous `nightly` keeps pointing at the last good build. A stable tag whose run failed has no image tags at all; fix forward with a new patch version, never re-tag.

### Smoke tests (`deploy/smoke/`)

All scripts run by hand too, **on Linux with Docker** (they find the host address for the DNS stub with `ip route`; set `SMOKE_HOST_IP` elsewhere; `kind`, `kubectl` and `kustomize` are also needed for the Kubernetes one) and use a fresh random password per run. They are safe next to a real deployment of the same files as far as removal goes: `image.sh` uses unique container and volume names and ephemeral loopback ports, `compose.sh` runs every command with `-p eggmail-smoke-<pid>` so `down -v` can only remove its own project, `kubernetes.sh` creates and deletes its own uniquely named kind cluster. The Compose files publish fixed ports (587, 465, 2525, 8443, loopback 8080), so `compose.sh` cannot run where those are taken.

| Script | Proves |
|---|---|
| `image.sh <ref> <version>` | anonymous pull works (empty Docker config); `--version` prints the build's version; `--healthcheck` without a server exits 1 cleanly; `mta admin create` works on a fresh volume (the `/data` ownership); the container becomes **healthy by Docker's own `HEALTHCHECK`** (the log shows how long it took); `docker exec /app/mta --healthcheck` succeeds; the `synchronous=OFF` startup warning is logged; then `smoke.py` below. When `READYTORUN=true` is in the environment (the workflow sets it) it also copies `mta.dll`, `Mta.Core.dll` and `Mta.Smtp.Server.dll` out of the image and checks for the ReadyToRun native header, so the image really is what the decision says. It also prints whether `mta` resolves on `PATH` (it does not, see the healthcheck note under "Deployment files") |
| `smoke.py` | the end-to-end flow against a running instance, using only public interfaces: capabilities report the expected backend; the bootstrap administrator signs in; a tenant and a domain are created and the domain **verifies** (the script is the DNS server: it answers the DKIM TXT record, and an MX for the recipient domain that points at its own SMTP sink, on the ports given to the instance with `Dns:Servers`, `Delivery:RemotePort` and `Delivery:AllowPrivateMxAddresses`); an SMTP credential is created through the API; a message is submitted over **STARTTLS with AUTH** and accepted with 250; it appears in `GET /messages` as queued, deferred or delivered; it is **delivered to the sink, DKIM-signed**; admin status shows the backend. Standard library only (Python 3.9+); it also ran against `mta serve` on a laptop |
| `compose.sh postgres` | `compose.postgres.yaml` as shipped: `docker compose up --wait` (PostgreSQL 17 and EggMail healthy through the compose healthchecks), `/app/mta --healthcheck` by `exec`, then the full `smoke.py` with **`backend: postgres`** in the capabilities and the bootstrap administrator from the file secret |
| `compose.sh sqlite` | `compose.yaml` as shipped (read-only root filesystem, no capabilities, tmpfs `/tmp`) starts, becomes healthy, the bootstrap administrator signs in |
| `compose.sh unbound` | `compose.yaml` plus `compose.unbound.yaml`: the running EggMail container carries `Dns__TrustAuthenticatedData=true` and the fixed resolver address; Unbound becomes healthy (its health check asks a local-zone name, not a third-party domain); a DNSSEC-signed name (`cloudflare.com`) answers with the AD flag and a name with a broken signature (`sigfail.verteiltesysteme.net`) answers SERVFAIL |
| `kubernetes.sh` | on a throw-away kind cluster: the SQLite StatefulSet becomes Ready through its probes with a bound PVC, the administrator signs in and a tenant is created **through the API**, the pod is deleted and the replacement comes back on the same volume with that tenant still there (a recreated bootstrap administrator alone would not prove persistence); the PostgreSQL Deployment plus the Unbound component against a throw-away `postgres:17` pod becomes Ready, reports `postgres`, and the sidecar answers with the AD flag. NetworkPolicy objects are applied but enforcement is not tested (kind's default network plugin may not enforce them) |

What these do **not** prove: delivery to a real MX on the Internet, DANE against a real DANE-enabled host, ACME, a real load balancer or inbound port 25, behaviour on other Kubernetes distributions, or that the dashboard works in a browser.

### Release assets and the changelog

- `CHANGELOG.md` follows Keep a Changelog and Semantic Versioning. Changes accumulate under `## [Unreleased]`; the release pull request moves them to `## [X.Y.Z] - YYYY-MM-DD` and bumps `<Version>` in `Directory.Build.props` (the validation step checks both). The section becomes the first part of the Release notes, followed by the pull command, the digests and the `gh attestation verify` command.
- `image-digests.txt`: `index <ref>@<digest>` and one `linux/<arch> <ref>@<digest>` line per platform manifest (what `docker pull --platform` resolves to); pin one of these in production.
- `sbom-linux-amd64.spdx.json`, `sbom-linux-arm64.spdx.json`: the SPDX documents BuildKit attached per platform, extracted with `docker buildx imagetools inspect --format '{{ json .SBOM }}'`; the script fails if one is missing or lists fewer than ten packages.
- `checksums.txt`: SHA-256 of the files above (`sha256sum -c checksums.txt`). The image itself is covered by the registry digest and the attestation, not by a checksum.
- No standalone `mta` binaries are attached (open item).

### ReadyToRun (DESIGN-DECIDED)

**Decision: the release image is built with `PublishReadyToRun=true`** (Dockerfile build argument `READYTORUN`, default `true`, passed by `release.yml`). [design.md §10](design.md#10-deployment) already said "ReadyToRun; no trimming (EF is not trim-safe)"; the Dockerfile had the switch but defaulted it to off and the workflow never passed it. The question was whether the tradeoff is worth switching it on, so it was measured instead of assumed.

**Measured** on GitHub-hosted `ubuntu-latest` runners (4 logical cores as seen by the process; noisy, not publishable) by the `bench-throughput` workflow, three runs on different runner instances: `linux-x64`, framework-dependent publish of `Mta.Host`, `mta serve` from spawn until `GET /healthz` answers, median of 7 starts each, a fresh data directory for the first start and the same directory again for the restart.

| | JIT (`PublishReadyToRun=false`) | ReadyToRun | Change |
|---|---:|---:|---:|
| Application publish directory | 18.4 MiB | 42.1 MiB | +23.7 MiB (about 2.3x) |
| Image size as pulled (`docker image inspect`, uncompressed, linux/amd64) | 181 MB | 206 MB | +25 MB |
| First start (empty data directory) | 2.11 s, 1.83 s, 1.31 s | 1.44 s, 1.30 s, 0.92 s | -32 %, -29 %, -30 % |
| Restart | 1.79 s, 1.57 s, 1.10 s | 1.24 s, 1.12 s, 0.79 s | -31 %, -29 %, -28 % |
| `linux-arm64` ReadyToRun built on the amd64 runner (cross-compilation) | | works: 48 MiB publish directory, and the multi-platform image build with it succeeded | |
| Steady-state ingest, SQLite `Sqlite:SyncMode=Off`, 3 x 30,000 messages, same harness published with and without ReadyToRun | 5,027 and 7,184 msg/s (two runs) | 4,966 and 7,488 msg/s | -1 % and +4 %, inside the run-to-run noise (the same JIT configuration measured 4,114, 5,027 and 7,184 msg/s on three runners) |

On a MacBook (osx-arm64, laptop under load) the same start-up comparison gave 1.08 s versus 1.00 s for the first start, 0.93 s versus 0.78 s for a restart, and 18.7 versus 47.2 MiB: a smaller gain, in the same direction.

**Why yes:** about 30 % off every cold start and restart (a Kubernetes rollout, a crash restart, a `docker compose up`) and off the JIT warm-up of the first requests, consistent across all three runs, in exchange for about 25 MB of uncompressed image content and a longer image build (the arm64 cross-compilation runs inside the existing build stage, on the build platform, without emulation). Steady-state throughput is unchanged within the noise, as expected: ReadyToRun code is replaced by tier-1 code for hot methods. The rule applied before measuring: adopt if the start-up gain is at least 25 % and the size increase is under 30 MiB. **Unverified:** the size of the compressed image layers (a pull transfers compressed layers) and the effect on the latency of the very first messages after a start.

Changing the decision is a one-line edit (`READYTORUN` in `release.yml`); `docker build --build-arg READYTORUN=false` builds the JIT image.

## Deployment files

The files are in `deploy/` and are the ones the smoke tests run; [operations.md](operations.md) lists them with the pitfalls. Ports are the container ports of decision 17: `5587` (587 STARTTLS), `4465` (465 implicit TLS), `2525`, `2526` (the port-25 bounce role) and `8443` (dashboard and API over HTTPS); `8080` (HTTP probes and first setup) is published on the loopback interface of the Docker host only, or not at all in Kubernetes. The first start generates a self-signed certificate ([design.md §7.3](design.md#73-tls)).

**The healthcheck must use the absolute path.** The Dockerfile has `HEALTHCHECK ... CMD ["/app/mta", "--healthcheck"]`, and so do the Compose files. The earlier snippet in this document, `["CMD", "mta", "--healthcheck"]`, was wrong for this image: the chiseled base has no shell, `/app` (where the application and its `mta` apphost live) is not on `PATH`, and the exec form therefore fails with "executable file not found in $PATH", so the container would be reported unhealthy forever. `deploy/smoke/image.sh` prints the image's `PATH` and whether `mta` resolves on every release run.

### Single container (SQLite, the default)

```sh
docker volume create eggmail-data
docker run --rm -v eggmail-data:/data -e MTA_ADMIN_PASSWORD='a-long-password' ghcr.io/eggspot/eggmail:nightly admin create --user admin
docker run -d --name eggmail -p 587:5587 -p 465:4465 -p 2525:2525 -p 8443:8443 \
  -v eggmail-data:/data ghcr.io/eggspot/eggmail:nightly
# Receiving bounces needs inbound port 25 to the bounce listener:  add  -p 25:2526
```

### Docker Compose

```sh
cd deploy/compose
cp .env.example .env                     # EGGMAIL_HOSTNAME, EGGMAIL_IMAGE, EGGMAIL_DB_PASSWORD
mkdir -p secrets && printf '%s' 'a-long-admin-password' > secrets/admin_password.txt && chmod 644 secrets/admin_password.txt
docker compose up -d                                        # SQLite
docker compose -f compose.postgres.yaml up -d              # or PostgreSQL 17 + EggMail
docker compose -f compose.yaml -f compose.unbound.yaml up -d   # add the Unbound sidecar so DANE works (also works with compose.postgres.yaml)
```

`compose.yaml` and `compose.postgres.yaml` have no default image on purpose (there is no `:latest` before the first stable release): `EGGMAIL_IMAGE` must be set (the `.env.example` has `:nightly`; pin a version tag or a digest in production), and `EGGMAIL_DB_PASSWORD` is empty in `.env.example` so that Compose refuses to start until you choose one. The PostgreSQL service is pinned to a minor release (`postgres:17.11`) and runs with `no-new-privileges`. The admin password file must be readable by uid 1654 (mode 644), so keep its `secrets/` directory private (mode 700) and out of version control. Both run with a read-only root filesystem, all capabilities dropped, `no-new-privileges`, a tmpfs `/tmp` and a 60 s stop grace period. Reminder: the SQLite default (`Sqlite:SyncMode=Off`) is process-crash-safe, **not power-loss-safe**, and EggMail logs a startup warning and shows a dashboard banner about it. For power-loss safety set `Sqlite__SyncMode=Normal` or `Full`, or use PostgreSQL. The PostgreSQL example uses one database user for both roles to stay short. The design calls for a schema-owner role and a least-privilege runtime role ([design.md §4.3](design.md#43-postgresql-backend-ef-core--npgsql-only)), managed PostgreSQL with HA for production, and secrets through the `*_FILE` convention instead of plain environment variables. When the connection strings come from environment variables, the application is "orchestrator-managed" and a backend switch produces a cutover patch instead of rewriting them ([design.md §4.6](design.md#46-switching-backends-manual-and-symmetric)).

### DANE and the Unbound sidecar

DANE needs the AD bit of DNS answers, which EggMail only believes with `Dns:TrustAuthenticatedData=true`, which is only safe with a local validating resolver. `compose.unbound.yaml` adds `klutchell/unbound` (pinned by tag **and** digest, DNSSEC validation with the root trust anchor) on a fixed address of a fixed subnet; it publishes no port, and answers private ranges only, so containers on that compose network can use it and nothing else can and sets `Dns__Servers__0`, `Dns__RequestDnssec` and `Dns__TrustAuthenticatedData` for EggMail; `deploy/kubernetes/components/unbound` does the same with a sidecar container on `127.0.0.1:53` plus the egress rule it needs. Without it DANE never applies (see [components/tls.md](components/tls.md)).

### Kubernetes

```sh
kubectl create namespace eggmail
kubectl -n eggmail create secret generic eggmail-admin --from-literal=admin-password='a-long-admin-password'
kubectl apply -n eggmail -k deploy/kubernetes/sqlite      # StatefulSet, one replica, ReadWriteOnce claim
# or, with a managed PostgreSQL (and a secret eggmail-postgres with owner-connection-string and runtime-connection-string):
kubectl apply -n eggmail -k deploy/kubernetes/postgres    # Deployment, replicas > 1 is safe
```

`base` holds the ConfigMap (`Hostname`, bootstrap administrator), the Services (headless, ClusterIP for the dashboard and API, a `LoadBalancer` for 587/465/2525 with `externalTrafficPolicy: Local` so per-client limits see client addresses), the service account without a token, and the NetworkPolicy of [design.md §7.1](design.md#71-listeners): ingress only on the listener ports (8080 from the namespace only), egress to cluster DNS and, to the public Internet only, TCP 25, 465, 587, 2525 and 443. The StatefulSet and the Deployment run non-root (uid 1654) with a read-only root filesystem, no capabilities, the default seccomp profile, a startup probe and liveness on `/healthz`, readiness on `/readyz`, and 90 s of termination grace. Edit `images:` in the overlay (or copy the overlay) to pin the image and the ConfigMap literal `Hostname`. The manifests use `imagePullPolicy: Always` because the overlay points at the moving tag `nightly`; change it to `IfNotPresent` once the image is pinned to a version tag or digest. The Unbound component listens on all addresses of the pod (it answers private ranges only); the base NetworkPolicy allows ingress only on the application ports, so with a CNI that enforces NetworkPolicy no other pod can use it, without enforcement it is reachable inside the cluster. Its readiness probe asks a local-zone name, never a third-party domain. Inbound port 25 for bounces needs a load balancer that offers it (the Service has the port commented out).

## Cutting a release

1. A pull request moves the `Unreleased` entries of `CHANGELOG.md` to `## [X.Y.Z] - date` and sets `<Version>` in `Directory.Build.props` to `X.Y.Z`; `ci` must be green; merge it.
2. Tag the merge commit `vX.Y.Z` (pre-releases `vX.Y.Z-rc.1`) and push the tag. The workflow validates, builds, pushes `vX.Y.Z`, `X.Y` and `latest` (stable only), attests, smoke-tests and creates the GitHub Release.
3. First release only: check `docker logout ghcr.io && docker pull ghcr.io/eggspot/eggmail:vX.Y.Z` (the smoke test already pulls the digest anonymously on every run).
4. A broken release is fixed forward with a new patch version; tags and the images they point to are never moved.

## Effort

See [plan.md](plan.md): the baseline "Packaging 4 weeks" covers the single chiseled image, compose and Kubernetes manifests, and runtime packaging concerns. It does not enumerate this release automation (tag-driven multi-arch build, attestations, GHCR publishing, the GitHub Release, nightly), so a separate **+0.5 week (0.5–1)** is added there.

## Open items

- Whether to mirror to Docker Hub (later), and under which name.
- Whether to attach standalone `mta` CLI binaries to Releases (no decision; the image contains the CLI).
- Whether `main` also gets its own tag besides `nightly`.
- Kubernetes: NetworkPolicy enforcement, other distributions, a managed load balancer with inbound port 25; Helm chart (not planned; the kustomize overlays are the supported form).
- Organization settings that may block public packages: not an issue so far (the package is public and anonymous pulls work).
- Billed minutes: the manual run [38459533507](https://github.com/eggspot/EggMail/actions/runs/38459533507) (ci already green for the commit, so no test run; build cache warm) took 6 minutes in one job: 3 min 16 s for the two-platform ReadyToRun image build and push, 12 s image smoke test, 14 s PostgreSQL compose test, 14 s SQLite compose and Unbound tests, 78 s kind test, the rest set-up. A cold cache and a run that has to build and test the solution itself take longer. Public repositories on standard runners are not billed, which was not checked; record the figures of the first tagged release here.
