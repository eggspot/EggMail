# EggMail — Claude Code instructions

Self-hosted outbound email server (SMTP ingress, HTTP API, delivery tracking, dashboard) on .NET 10. MIT OR Apache-2.0.
Status: implemented, not production-ready. `docs/progress.md` says what is verified; keep it honest.

## Build, test, run (no Docker locally — images are built by GitHub Actions only)
- `dotnet test EggMail.slnx` (compiles too; one project: `dotnet test tests/<Project>`)
- Postgres tests: set `EGGMAIL_TEST_POSTGRES`, or have `initdb`/`pg_ctl` on PATH; otherwise skipped.
- ACME/Pebble tests: see docs/development.md; skipped unless `EGGMAIL_TEST_ACME_DIRECTORY` is set.
- Run: `dotnet run --project src/Mta.Host -c Release -- --Sqlite:DataDirectory=/tmp/eggmail-data`
- Dashboard (`dashboard/`, Preact + Vite, npm): `npm run dev:mock`, `npm test`, `npm run lint`, `npm run e2e`.

## Rules
- Package-free assemblies (decision 4): Mta.Core, Dns, Mime, Dkim, Auth, Dsn, Tls, Smtp.* use BCL/ASP.NET
  shared framework only. `tests/Mta.ArchitectureTests` enforces it — never add a PackageReference there.
- SQLite and PostgreSQL are a storage choice only: every feature must behave identically on both,
  with tests on both backends.
- Performance is a first-class goal; benchmark hot-path changes (`bench/Mta.Benchmarks`). No claims
  without reproducible numbers (docs/benchmarks.md).
- Design decisions are numbered in docs/decisions.md; cite/add one for any non-obvious choice.
- Every behaviour-changing PR adds a line under `Unreleased` in CHANGELOG.md. Version lives in
  Directory.Build.props (first release 0.1.0); release flow in docs/release.md.
- Dashboard has light and dark themes (system preference or a user-forced `data-theme`): keep the three color
  token blocks in `dashboard/src/styles/app.css` in sync (`dashboard/tests/contrast.test.mjs` checks them). No inline
  styles; keep CSP clean (`npm run check-csp`).
- Security-relevant changes: update docs/security-test-map.md with a regression test.
- Go-live tracking: docs/go-live-checklist.md + docs/progress.md (not a separate readiness file).
