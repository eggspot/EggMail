# Release and packaging plan

**Status: a plan.** There is no code yet, so **no workflow file exists** and `ghcr.io/eggspot/eggmail` has not been published. Facts below are marked **verified** (checked against GitHub or Docker documentation on 2026-10-12) or **unverified** (not confirmed). Decisions come from the owner or are design decisions; see [decisions.md](decisions.md).

## Decisions

| Topic | Decision |
|---|---|
| Image | **One Docker image** that runs out of the box: SQLite backend (the default), one volume at `/data`, the default ports of [design.md §7.1](design.md#71-listeners). The PostgreSQL backend is selected by configuration (`Storage:Backend=Postgres`) in the **same image** |
| Base | Chiseled .NET 10 `-extra` base (ICU included), as in decision 7; non-root, no shell |
| Platforms | `linux/amd64` and `linux/arm64` (multi-arch manifest) |
| Registry | GitHub Container Registry: `ghcr.io/eggspot/eggmail` |
| Trigger | GitHub Actions on version tags (`vMAJOR.MINOR.PATCH`); a rolling nightly build from `main` |
| Auth | `GITHUB_TOKEN` with `packages: write`; **no personal access token** |
| Supply chain | SBOM and provenance attestations; GitHub Release with changelog and checksums |
| Docker Hub mirror | Optional, a **later** decision |

## Image tags

| Tag | Moves? | Meaning |
|---|---|---|
| `v1.4.2` | never | Exact release, from git tag `v1.4.2` |
| `1.4` | with each `1.4.x` patch release | Latest patch of a minor line |
| `latest` | with each stable release | Latest stable release |
| `nightly` | daily, from `main` | Latest `main` (the "main/nightly" tag; the name `nightly` is a proposal) |

Pre-releases (`v1.5.0-rc.1`) publish only their exact tag; they do not move `1.5` or `latest`. Version numbers follow semantic versioning and the tag points at the commit that bumps the version.

## GHCR facts

- **Free for public images (verified).** GitHub's billing documentation says "GitHub Packages usage is free for public packages" and "Container image storage and bandwidth for the Container registry is currently free", with at least one month's notice before any change. Private packages have quotas and are billed beyond them.
- **New packages are private by default (verified).** GitHub's documentation says "When you first publish a package, the default visibility is private." Linking a package to a repository affects permissions, not visibility. The documentation does not say that publishing from a workflow in a **public repository** makes the package public, so **plan for a one-time manual step**: after the first successful publish, open the package's settings, go to the "Danger Zone", choose "Change visibility", select **Public** and type the package name to confirm. **This cannot be undone** ("Once you make a package public, you cannot make it private again"). Until then anonymous pulls fail.
- **Anonymous pull works for public packages (verified):** "You can also access public container images anonymously." Check it after the visibility change with `docker logout ghcr.io` followed by `docker pull`.
- **Linking the package to the repository (verified):** add the label `org.opencontainers.image.source=https://github.com/eggspot/EggMail` in the Dockerfile; publishing from a workflow with `GITHUB_TOKEN` also links the repository. Set the label in the Dockerfile as well, so manual and local builds carry it.
- **First publish must come from the workflow (verified caveat):** GitHub warns that `GITHUB_TOKEN` cannot push if a package was previously pushed to the same namespace without being connected to the repository. Do not seed the package by hand with a personal token.
- **Publishing with `GITHUB_TOKEN` (verified in part):** the documentation lists `GITHUB_TOKEN` for publishing packages associated with the workflow repository; the attestation documentation lists `packages: write` (together with `id-token: write`, `attestations: write`, `contents: read`) for container images.
- **Image name (partly verified):** the format is `ghcr.io/NAMESPACE/IMAGE_NAME`. `eggspot/eggmail` is already lowercase; a lowercase requirement was not stated on the page checked (**unverified**), so keep it lowercase.
- **Unverified:** the organization-level settings that can restrict package visibility or creation (an organization owner may have to allow public packages); GitHub Actions minutes for public repositories (see below).

## Supply chain

- **SBOM and provenance with Docker (verified):** `docker/build-push-action` takes `sbom: true`; provenance is set with `provenance: mode=max` (public repositories already default to `mode=max`). Caveats from Docker's documentation: provenance contains build argument values, so **never pass secrets as build args** (use secret mounts); attestations require pushing directly to a registry (not `load: true` or the `docker` exporter). Whether and how they work with multi-platform builds is not stated on the page checked (**unverified**; they are expected to attach per platform to the index).
- **GitHub artifact attestation (verified):** an `attest` action step after the build (documented as `actions/attest@v4`), with `subject-name: ghcr.io/eggspot/eggmail` (fully qualified, **no tag**), `subject-digest` from the build step's `digest` output, `push-to-registry: true`, and workflow permissions `id-token: write`, `attestations: write`, `contents: read`, `packages: write`. The documentation page checked mentions no plan or repository-visibility restriction (**unverified** whether any applies).
- **GitHub Release** on each stable tag: release notes (GitHub's generated notes plus a curated `CHANGELOG.md` section), the image digests of the index and of each platform, the exported SBOM files, and a `checksums.txt` (SHA-256) covering every attached asset. Standalone `mta` CLI binaries are not planned as release assets (open question).

## Planned workflow: required steps

No file is created now. Single job, on `ubuntu-latest`, to keep billed minutes low (one job, the cheapest runner, tight timeouts, no needless triggers):

1. **Triggers:** push of tags `v*.*.*`; a daily `schedule` for `nightly` that runs only if `main` has new commits since the last nightly and ignores docs-only changes; `workflow_dispatch`.
2. **Permissions** (job level, least privilege): `contents: write` (create the Release), `packages: write`, `id-token: write`, `attestations: write`.
3. **Concurrency:** one group per workflow and ref, **`cancel-in-progress: false`** (never cancel a release mid-flight).
4. `timeout-minutes` set to a realistic ceiling; `fetch-depth: 1`.
5. **Validate the tag** is a well-formed semantic version and matches the version in the source.
6. **Cheapest checks first:** restore, build, lint and unit tests; stop before publishing on any failure. The package-free-stack CI check ([design.md §2.1](design.md#21-build-boundary)) runs here.
7. **Set up buildx** (and QEMU only if the arm64 build needs emulation); log in to `ghcr.io` with `docker/login-action` using `github.actor` and `secrets.GITHUB_TOKEN`.
8. **Compute tags and labels** (`docker/metadata-action`): the tag set above and the OCI labels, including `org.opencontainers.image.source`.
9. **Build and push** `linux/amd64,linux/arm64` with `sbom: true`, `provenance: mode=max`, layer cache in the GitHub Actions cache (`cache-from`/`cache-to` of type `gha`). To avoid slow QEMU emulation, the .NET build stage should run on the build platform and publish for each target runtime identifier (cross-publishing); ReadyToRun cross-architecture compilation is **unverified**, with emulation or a native Arm runner as the fallback.
10. **Attest** the pushed image digest (`attest` step above).
11. **Smoke test** the pushed image: `docker run` it, check `--healthcheck`, run `self-test` (the image must ship ICU), and check the startup warning for `synchronous=OFF` is present; repeat for the Postgres compose example in CI only on releases.
12. **Create the GitHub Release** (stable tags only): notes, SBOMs, `checksums.txt`.
13. **Post-publish check** (first release only, manual): set the package public, then `docker logout ghcr.io` and pull anonymously.

Billed minutes: public repositories using standard GitHub-hosted runners are generally free, but that was not checked here (**unverified**); measure billed minutes per release once the workflow exists and state them in the pull request.

## Quick start

These snippets describe the planned image. The image does not exist yet. Ports are the container ports of decision 17: `5587` (587 STARTTLS), `4465` (465 implicit TLS), `2525`, `2526` (the port-25 bounce role) and `8443` (dashboard/API over HTTPS); `8080` (HTTP probes) is not published. The first start generates a self-signed certificate ([design.md §7.3](design.md#73-tls)). Config key names and the `mta --healthcheck` command are proposals.

### Single container (SQLite, the default)

```sh
docker run -d --name eggmail \
  -p 587:5587 -p 465:4465 -p 2525:2525 -p 8443:8443 \
  -v eggmail-data:/data \
  ghcr.io/eggspot/eggmail:latest
# Receiving bounces needs inbound port 25 to the bounce listener:
#   add  -p 25:2526
```

```yaml
# compose.yaml
services:
  eggmail:
    image: ghcr.io/eggspot/eggmail:1.4      # pin a minor line in production, not :latest
    restart: unless-stopped
    ports:
      - "587:5587"
      - "465:4465"
      - "2525:2525"
      - "8443:8443"
      # - "25:2526"                          # bounce listener, if used
    volumes:
      - eggmail-data:/data                   # SQLite files; a local volume only, one replica
    read_only: true
    cap_drop: [ALL]
    tmpfs: [/tmp]
    healthcheck:
      test: ["CMD", "mta", "--healthcheck"]  # chiseled image: exec form, no shell
      interval: 30s
volumes:
  eggmail-data:
```

Reminder: the SQLite default (`Sqlite:SyncMode=Off`) is process-crash-safe, **not power-loss-safe**, and EggMail logs a startup warning and shows a dashboard banner about it. For power-loss safety set `Sqlite:SyncMode=Full` (or `Normal`), or use PostgreSQL.

### With PostgreSQL (same image)

```yaml
# compose.postgres.yaml
services:
  postgres:
    image: postgres:17
    restart: unless-stopped
    environment:
      POSTGRES_USER: eggmail
      POSTGRES_PASSWORD: ${EGGMAIL_DB_PASSWORD:?set a password}
      POSTGRES_DB: eggmail
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U eggmail -d eggmail"]
      interval: 5s
      retries: 10
  eggmail:
    image: ghcr.io/eggspot/eggmail:1.4
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      Storage__Backend: Postgres
      Storage__Postgres__OwnerConnectionString: "Host=postgres;Database=eggmail;Username=eggmail;Password=${EGGMAIL_DB_PASSWORD}"
      Storage__Postgres__RuntimeConnectionString: "Host=postgres;Database=eggmail;Username=eggmail;Password=${EGGMAIL_DB_PASSWORD}"
      Mail__Database__Migrate: Auto
    ports:
      - "587:5587"
      - "465:4465"
      - "2525:2525"
      - "8443:8443"
    volumes:
      - eggmail-data:/data                   # bootstrap file, quarantine area
    read_only: true
    cap_drop: [ALL]
    tmpfs: [/tmp]
volumes:
  pgdata:
  eggmail-data:
```

This example uses one database user for both roles to stay short. The design calls for a schema-owner role and a least-privilege runtime role ([design.md §4.3](design.md#43-postgresql-backend-ef-core--npgsql-only)), managed Postgres with HA for production, and secrets through the `*_FILE` convention instead of plain environment variables. When the connection strings come from environment variables, the application is "orchestrator-managed" and a backend switch produces a cutover patch instead of rewriting them ([design.md §4.6](design.md#46-switching-backends-manual-and-symmetric)).

## Effort

See [plan.md](plan.md): the baseline "Packaging 4 weeks" covers the single chiseled image, compose and Kubernetes manifests, and runtime packaging concerns. It does not enumerate this release automation (tag-driven multi-arch build, attestations, GHCR publishing, the GitHub Release, nightly), so a separate **+0.5 week (0.5–1)** is added there.

## Open items

- Whether to mirror to Docker Hub (later), and under which name.
- Whether to attach standalone `mta` CLI binaries to Releases (no decision; the image contains the CLI).
- The nightly tag name (`nightly` proposed), and whether `main` also gets its own tag.
- Arm64 build approach (cross-publish, native Arm runner or emulation), to be measured.
- Organization settings that may block public packages (unverified).
