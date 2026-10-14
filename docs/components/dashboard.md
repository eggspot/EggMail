# Dashboard (`dashboard/`)

A Preact + Vite + TypeScript single-page app that talks to the HTTP API of [api.md](../api.md) on the same origin. It is an admin surface and is built to the supply-chain rules of [design.md §9.3](../design.md#93-dashboard-supply-chain). Nothing in `dashboard/` depends on .NET code: the host serves the static build, and a dependency-free mock API (`dashboard/mock`) stands in for the host during development and tests.

## Direct dependencies (9, exact versions pinned, `package-lock.json` committed)

| Package | Version | Kind | Why |
|---|---|---|---|
| `preact` | 10.29.8 | runtime | UI |
| `preact-iso` | 2.12.2 | runtime | tiny router, `lazy` route chunks |
| `vite` | 8.3.2 | dev | build and dev server |
| `@preact/preset-vite` | 2.10.6 | dev | JSX transform |
| `typescript` | 6.0.3 | dev | `tsc --noEmit` type check |
| `vitest` | 5.0.3 | dev | tests |
| `@testing-library/preact` | 3.2.4 | dev | component tests |
| `jsdom` | 30.1.1 | dev | DOM for tests |
| `@playwright/test` | 1.63.0 | dev | real-browser end-to-end tests (Chromium only; the browser is downloaded by `npx playwright install`, never by an install script) |

No UI kit, no chart library (the charts are small hand-written SVG components), no state library (hooks and context), no icon or font packages (system fonts, no external requests). `dashboard/.npmrc` sets `ignore-scripts=true` and `save-exact=true`. All versions were published at least 7 days before they were pinned (design §9.3, "minimum release age"; Playwright 1.64 was 6 days old, so 1.63.0 is used). Preact 11 was released shortly before this work and is deliberately not used yet; TypeScript 7 likewise.

## Layout

```
dashboard/
  index.html, vite.config.mjs, tsconfig.json, package.json, package-lock.json, .npmrc
  src/
    main.tsx, app.tsx            entry, providers, lazy routes, offline / login gating
    api/                         client.ts (fetch, CSRF, tenant header, problem+json), endpoints.ts (typed calls),
                                 types.ts (wire types), errorMessages.ts (code -> friendly text)
    state/                       app.tsx (session, capabilities, tenants), theme.ts
    lib/                         hooks.ts (useApi, useAction, useCooldown, usePolling), format.ts, switchFlow.ts, ...
    components/                  ui.tsx (chips, dialogs, one-time secrets, tabs, fields), Layout, WarningBanner,
                                 HistoryGate, ErrorBoundary, charts/, switch/, ...
    pages/                       one lazy chunk per route (admin/ for the admin pages)
    styles/app.css               one stylesheet: custom properties, light/dark, responsive
  mock/                          dependency-free mock API (see below)
  scripts/                       lint.mjs, check-csp.mjs, size.mjs
  tests/                         Vitest unit, component and mock-contract tests
  e2e/                           Playwright end-to-end tests against the real server (see "End-to-end tests")
  playwright.config.mjs          Chromium only, one worker
```

## Running it

```sh
cd dashboard
npm ci --ignore-scripts

npm run dev:mock      # mock API on :8787 + Vite dev server on http://localhost:5173 (proxies /api)
npm run start:mock    # build, then serve dist/ from the mock on http://127.0.0.1:8787 with the strict CSP

npm run build         # production build into dashboard/dist
npm run test          # Vitest
npm run typecheck     # tsc --noEmit
npm run lint          # tsc --noEmit + scripts/lint.mjs (security and CSP rules)
npm run check-csp     # fails if dist/ has inline script/style, style= attributes, eval, external URLs
npm run size          # raw and gzip sizes of dist/
npm run e2e           # build, then the Playwright end-to-end tests against the real server (needs the .NET SDK, see below)
```

Sign in to the mock as `admin` / `eggmail` (role `admin`, acts on a tenant chosen in the header) or `tenant` / `eggmail` (role `tenant`, tenant "Acme Corp").

### Mock server switches

`node mock/server.mjs` (or `npm run start:mock`, or `npm run dev:mock` which passes the environment through):

| Variable | Values | Effect |
|---|---|---|
| `MOCK_HISTORY` | `full` (default), `statsonly` | `capabilities.history.mode`; in `statsonly` every per-message endpoint answers `410 history_not_recorded` |
| `MOCK_BACKEND` | `sqlite` (default), `postgres` | `capabilities.backend` (informational only in the UI) |
| `MOCK_WARNINGS` | comma list, default `sqlite_sync_off` on sqlite | `capabilities.warnings` (others: `certificate_expiring`, `self_signed_certificate`) |
| `MOCK_NOT_READY` | `1` | every API call answers `503 not_ready` |
| `MOCK_LATENCY_MS` | number | artificial latency |
| `MOCK_ORCHESTRATED` | `1` | the storage switch reports an orchestrator-managed deployment (cutover patch) |
| `PORT`, `HOST`, `MOCK_DIST`, `VITE_URL` | | listen address, dist folder, proxy non-API requests to a Vite server |

The same switches can be flipped live with `POST /__mock/config` (`{ "history": "statsonly", "warnings": [], "notReady": true }`) and the fixtures reset with `POST /__mock/reset`. The mock implements the endpoints of [api.md](../api.md) with realistic in-memory fixtures and the error cases (`401`, `403` for a missing CSRF token or the wrong role, `404`, `409`, `410` with both codes, `429` with `Retry-After`, `400 validation_failed` with `errors[]`, `503 not_ready`). It is test tooling, not a reference implementation: where the contract is open the shapes in "API contract gaps" below are what it returns.

## How the host serves it

The host serves the contents of `dashboard/dist` as static files under `/` and answers any `GET` that is not an API or operational path and has no file extension with `index.html` (SPA fallback). Paths the host must keep for itself: `/api/`, `/healthz`, `/readyz`, `/metrics`. Assets are content-hashed under `/assets/` and can be cached for a year (`immutable`); `index.html` must be served `no-cache`. All asset URLs are absolute from `/` (Vite `base`).

The build is compatible with this strict CSP (`npm run check-csp` enforces the build side). The mock sends the first policy below; the real host sends the second (it also allows `data:` images and sets no `frame-src`, so frames fall back to `default-src 'self'`):

```
mock: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
host: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'
```

plus `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` and `Cross-Origin-Opener-Policy: same-origin`. The host answers `/assets/*` with `Cache-Control: public, max-age=31536000, immutable` and everything else it serves (the shell `index.html`, the SPA fallback, the favicon) with `no-cache` (the assets used to have no cache header; found by the end-to-end tests). A missing path under `/api/` is an API `404 problem+json`, never the HTML shell.

Docker Node stage (design §9.3):

```sh
cd dashboard && npm ci --ignore-scripts && npm run build   # copy only dashboard/dist into the final image
```

Run `npm audit signatures` and an OSV scan in CI next to it (design §9.3).

## Security properties

- The session is an HttpOnly, SameSite=Strict cookie that script cannot read. The CSRF token from `GET /api/v1/me` lives in a module variable (never in web storage) and is sent as `X-CSRF-Token` on every `POST`, `PUT`, `PATCH` and `DELETE`. A `401` from any call returns the user to the sign-in form. Failed sign-ins surface `429` and `Retry-After`.
- One-time secrets (API key, SMTP password, webhook signing secret) are held only in the state of the creating component, shown with a copy button and a warning, and dropped when the user confirms they saved them.
- Stored message HTML is rendered only in `<iframe sandbox="" srcdoc=...>` (no sandbox flags at all: no scripts, no forms, no popups, unique origin) whose document starts with a CSP `<meta>` (`default-src 'none'; img-src data:`). The frame has no styling of its own: a `srcdoc` document also inherits the host page's `style-src 'self'`, so inline styles are blocked whatever the meta says (a `<style>` block of the dashboard's own was a CSP violation until the end-to-end tests found it). The plain-text view is the default. HTML is never inserted into the app DOM. `scripts/lint.mjs` rejects `innerHTML`, `dangerouslySetInnerHTML`, `eval`, inline styles, `fetch` outside `src/api/client.ts`, external URLs and any `<iframe>` without `sandbox` or with `allow-*` flags.
- No runtime network access except same-origin `/api/v1/*` (and `/readyz`); no CDN, font or analytics requests; no inline script or style, so the CSP above holds.
- Web storage holds only non-secret conveniences: theme choice (`localStorage`), the acting tenant of an admin and the collapsed state of a warning (`sessionStorage`).

## Behavior that must not depend on the backend

Features are identical regardless of storage backend (decision E). The UI adapts only to `capabilities.history.mode`: with `statsonly` the Messages and message-detail pages show an explanatory empty state without calling the API, and a `410 history_not_recorded` or `410 body_expired` from the server is handled with the same explanations (capabilities can be stale). `capabilities.backend` is shown informationally in the header and used by the storage switch wizard only to name the opposite direction. `capabilities.warnings` render as a persistent banner on every page including the sign-in page; `sqlite_sync_off` is a loud alert that can be collapsed for the session but never dismissed permanently.

## Accessibility and theming

Semantic landmarks and headings, a skip link, focus moved to the page content after navigation, labelled form controls with `aria-describedby` and `aria-invalid`, modal dialogs with a focus trap and focus restore, tab widgets with arrow-key support, status chips that always carry their meaning in text, charts with an accessible name and a data table. Light and dark themes are CSS custom properties (`prefers-color-scheme`, plus a manual System / Light / Dark toggle through `data-theme`); `tests/contrast.test.mjs` computes WCAG contrast for every text pair in all three token blocks. Layouts work down to phone width (navigation collapses behind a Menu button, tables scroll inside `.table-wrap`).

## Bundle size

`npm run build` then `npm run size` (gzip level 9): the initial load (entry JS + CSS) is **21.8 KiB gzip**. All routes are separate lazy chunks of 0.2 to 7 KiB gzip each. The whole `dist/` is 71.4 KiB gzip (189 KiB raw, no fonts or images apart from a 0.2 KiB favicon).

Verification at the time of writing: `npm run lint` (tsc plus custom rules over 51 source files), `npm run typecheck`, `npm test` (31 files, 424 tests, including contrast checks for both themes, the CSP checker, the mock API contract, and a smoke test that renders every route against the real mock server for both roles and both history modes), `npm run build` and `npm run check-csp` pass, and the end-to-end tests (below) pass against the real server.

## Pages and features, audited against the plan

[plan.md](../plan.md) and [design.md](../design.md) name the dashboard by its parts: overview and statistics, message search with timeline and resend, domains with DNS records, webhooks, suppressions, keys and SMTP credentials, settings, tenants, certificates, the persistent warnings, the sandboxed message view, the advisory pressure indicators and the guided storage switch. [api.md](../api.md) is the full list of what the server offers. Every endpoint of api.md that a person would use has a page; the audit (2026-10) found these API features without one, or shown wrongly, and fixed them:

| Where | Change |
|---|---|
| Domain | the DKIM keys of the domain (signing, waiting for DNS, retired) and cancelling a pending key rotation (`DELETE /domains/{id}/dkim/rotate`); the key card describes the key that signs, not the pending one |
| Webhooks | finishing a secret rotation (`DELETE /webhooks/{id}/previous-secret`, shown while `secretRotationPending`); the `webhook.endpoint.disabled` event type; the attempt log refreshes for 20 s after a test event or a replay (deliveries are asynchronous); replaying a delivery that waits for its retry explains why the server refuses |
| Certificates | the ACME renewal state (`GET /admin/certificates/acme`: status, last and next attempt, failures, last error) |
| Server status | the maintenance report (`GET /admin/maintenance`) |
| Settings | "takes effect the next time the server starts" for stored values that `requiresRestart` |
| Message | content that was never recorded (`Content:Mode=None`: `not_recorded`, `410 content_not_recorded`), truncated stored content, the real recipient count (the list carries only the first five addresses) |
| Header | the tenant picker follows tenants created, renamed or suspended on the Tenants page (it was loaded once at sign-in); the first tenant of a fresh install becomes the acting tenant |
| Statistics | daily ranges (longer than 30 days): the server rolls hourly rows up into daily rows only for finished days, so the page adds today and yesterday from the hourly rows (a new install showed "no traffic" for 30 and 400 days) |
| Webhook attempts, recent events | the "Event" and "Sending domain" columns appear only when the server fills them (it does not: api.md) |
| Sign-in | a wrong password says so (it said the session had expired); the user of a suspended tenant is told why |
| Storage switch | the `verifying` state (the page was blank), the activation result (cutover patch or bootstrap note) on the finalize step, where the server produces it, whether the deployment supplies the storage pointer before activation, the reason when finalize is refused |

The storage switch wizard is built (`pages/admin/StorageSwitch.tsx`, `components/switch/`): direction, drain or quiesce and what to include, preflight, typed confirmation and export passphrase, progress, verification report, confirm, activate, finalize, and rollback until activation. **There is no bundle download**: the bundle is a directory on the server volume (`Switch:BundleDirectory`) written and read by the server only ([switch.md](switch.md)), and design §4.6 has none. The API only switches between backends (`to` must differ from the running backend), so the wizard offers the opposite one; moving SQLite files to another volume is a copy of the stopped server's data directory.

**Users and Account.** `pages/admin/Users.tsx` (administrators only, nav "Users", `/admin/users`) lists the dashboard users (role, tenant, enabled or disabled, created) and offers create (user name, role, tenant for a tenant user, an optional password: left empty the server generates one, shown once in the one-time-secret box), role and tenant change, reset password (optional password, a generated one is shown once), enable and disable (confirmation) and delete (confirmation). Errors from the server stay on the page: a taken name under the field, and the last-administrator refusal ("This is the only enabled administrator...") inside the open dialog. Your own row has no reset button (the server refuses it too). `pages/Account.tsx` (every signed-in user, nav "Account", `/account`) shows who you are and has the change-password form (current, new, new again; short, equal-to-current and mismatching passwords are caught on the page, a wrong current password is shown under its field by the server's answer, and a lockout shows the `429` message with the wait). After a change the other sessions of the user are signed out and this one continues. Contract: `GET/POST /admin/users`, `PATCH/DELETE /admin/users/{id}`, `POST /admin/users/{id}/reset-password`, `POST /me/password` ([api.md](../api.md#dashboard-users-role-admin-addition)); the mock server (`mock/routes/users.mjs`) implements the same rules, including session invalidation and last-admin protection.

Deliberately not in the dashboard: changing the storage pointer by hand (deployment configuration), Bearer API keys as a sign-in (cookie sessions only).

## End-to-end tests

`dashboard/e2e/` drives Chromium (`@playwright/test` 1.63.0, chromium only, one worker) against the **real server**. A fixture publishes `src/Mta.Host` (`dotnet publish -c Release`), puts the production `dashboard/dist` into its `wwwroot` (what the Docker image contains), creates the administrator with `mta admin create`, and starts `mta serve` on a temporary SQLite data directory with loopback ports. Three fakes stand where the internet would be, and the server is pointed at them by configuration (`Dns:Servers`, `Delivery:RemotePort`, `Delivery:AllowPrivateMxAddresses`, `Webhooks:AllowHttp`): a DNS server (a domain's records are published exactly as the dashboard shows them, wrongly, or not at all; the recipients' MX points at the sink), an SMTP sink for the recipients' mail server (a recipient named `reject...` is refused with 550) and a webhook receiver. Nothing is mocked in the server or the browser.

```sh
cd dashboard
npm ci --ignore-scripts
npx playwright install chromium          # once; add --with-deps on a fresh Linux machine
npm run e2e                              # npm run build, then npx playwright test
npx playwright test webhooks             # one spec file
```

Needs the .NET 10 SDK, Node 22, `openssl` (the certificate upload test makes a certificate) and, for the storage switch specs, `psql` plus either `EGGMAIL_TEST_POSTGRES` (a connection string to a server whose role may create databases; CI provides one) or the PostgreSQL binaries (`initdb`, `postgres`; `EGGMAIL_TEST_PG_BIN`) for a throwaway cluster, found the way the .NET tests find theirs. Without PostgreSQL the switch specs are skipped with the reason; in CI a missing PostgreSQL fails the job. `EGGMAIL_E2E_APP_DIR` reuses an already published host.

| Spec | Drives |
|---|---|
| `auth` | wrong and right sign-in, cookie flags, CSRF (missing, wrong, valid token), sign-out ends the session on the server, an ended session returns to the form, API keys never reach `/admin` |
| `tenants-domains` | create, rename, suspend and activate a tenant (its keys stop at once), add a domain, the DNS records view and copy buttons, the verification states (nothing published: missing; wrong value: invalid with found and expected; correct: verified, SPF and DMARC only advice), the 30 s verify limit, DKIM rotation and cancelling it, deleting a domain |
| `send-and-messages` | create an API key in the dashboard and use its one-time secret, revoke it, SMTP credentials, send through the API, the message becomes delivered (the sink receives a DKIM-signed copy), detail with events and sandboxed HTML, resend, a refused recipient ends as bounced with the reply in the events, search filters, many recipients, the send page with an attachment, an unverified domain is refused |
| `settings-suppressions` | tenant and global settings (validation, locked values, persistence), suppressions (add, filter, remove, paging, a suppressed recipient is not delivered) |
| `webhooks` | the SSRF guard until an administrator allows loopback, create and test with a signature verified in the test, a failing receiver and replay, edit, disable and delete, secret rotation with both signatures until the previous one is removed, a delivered message produces a signed event |
| `overview-admin` | counters, recent events and the per-domain table after real traffic, server status and maintenance, certificate upload (PEM, wrong key, duplicate, ACME not configured), navigation |
| `storage-switch` | the wizard from SQLite to PostgreSQL: refusals, typed phrase, verification report, source fenced while pending, rollback, and a full switch through the bootstrap file with a restart on PostgreSQL, the data that came along, and finalize; a deployment that pins the storage pointer gets a cutover patch without secrets |
| `users` | an administrator creates a user in the dashboard (generated password shown once, validation, taken name) and the user signs in with it and sees no administration; disabling ends the session at once and blocks sign-in until enabled; reset password; role change signs the user out and moves between tenant user and administrator; the last enabled administrator cannot be disabled or deleted (the message is on the page) while another one can; tenant users and API keys are refused by the API and cookie mutations need the CSRF token; the Account page changes a password (field errors, other session ended, old password dead). The brute-force lockout of `POST /me/password` is not driven here: it keys on the client address, and failing ten times from loopback would lock every other spec of the shared server out (the host tests cover it) |
| `tenant-user` | a tenant account (made with `mta admin create --role tenant` between two server starts) sees no administration, cannot change the webhook allowlist, cannot see or touch another tenant, is told when its tenant is suspended |
| `csp-pages` | headers of the shell, assets and API, every page of the administrator, the message frame with a hostile message, the sign-in page |

Every test also fails on any console error, page error or `securitypolicyviolation` event (an automatic fixture; "Failed to load resource" lines for the 4xx answers a test provokes are not counted, and a test can list messages it expects, for example the browser reporting a blocked remote image). Tests create their own uniquely named data on one shared server, except the storage switch and tenant account specs, which start servers of their own (a switch fences the server it runs on). Not covered: other browsers, a screen reader, Docker, a PostgreSQL source, the domain states `temporary_failure` and `failed` (they need days of simulated time; component tests and the server's `DomainVerificationTests` cover them).

What the first run found and fixed: `mta admin create --role admin` lost its role (the command parser removed every argument equal to the command name); the bootstrap file was looked for in `/data` when the data directory was given on the command line (a switch then ended in a 500); the cutover patch was never shown; the state `verifying` produced a blank page; assets had no cache header; the message frame violated the CSP with its own `<style>`; the tenant picker was never refreshed; the daily statistics lacked the days not yet rolled up; and two table columns the server never fills.

## API contract gaps and additions

[api.md](../api.md) left several shapes open. The dashboard and the mock assume the following. **The API implementation ([api.md](../api.md), [components/api.md](api.md)) adopted all of them and documents them in api.md**; the differences are: a storage switch step in the wrong state answers `409 conflict` (the mock used `409 validation_failed`; the dashboard does not depend on the code), and there are extra response members and error codes (`conflict`, `tenant_disabled`, `content_not_recorded`, `unsupported_media_type`) that the dashboard shows by their `detail` because it has no friendly text for them. `ApiContractTests` in `tests/Mta.Host.Tests/Api` checks the real API against `dashboard/src/api/types.ts`. The end-to-end tests run the dashboard against the real API in a browser; where they found the assumptions below wrong, this list says so.

1. **CSRF token:** read from the `csrfToken` member of `GET /me` (the `X-CSRF-Token` response header is not read). The mock sends both.
2. **Sign-out:** `DELETE /api/v1/session` (not in the contract).
3. **Tenant settings:** `GET /api/v1/settings` returns `{ items: [{ key, value, type, options?, description?, locked? }] }`; `PUT /api/v1/settings` takes `{ values: { key: value } }` and returns the same shape. The contract has no tenant settings endpoint.
4. **Global settings** (`/admin/settings`): the same `{ items }` / `{ values }` shapes, with `locked: true` for values set by deployment configuration.
5. **Admin acting on a tenant:** tenant-scoped endpoints need `X-Tenant-Id` for admins. The mock answers `400 validation_failed` without it. The dashboard loads `GET /admin/tenants` after an admin signs in and sends the header.
6. **Validation status code:** `validation_failed` is assumed to be `400` with `errors: [{ field, message }]`; field names are the request member names (`url`, `name`, ...). The client does not depend on the numeric status.
7. **Lists** may be a bare array or `{ items, next_cursor }`; the client accepts both. Messages and suppressions are cursor-paged (`next_cursor`).
8. **Statistics:** `GET /stats` returns `{ granularity, rows: [...] }` (a bare array is accepted); each row has `period` (ISO start), `sendingDomain`, `recipientDomain` and the counters `accepted, delivered, deferred, hardBounce, softBounce, expired, complained, rejected, suppressed`. `GET /stats/recent-events` returns `[{ at, type, recipientDomain, sendingDomain }]`.
9. **Object shapes** not spelled out in api.md: webhook `{ id, url, event_types, enabled, disabledReason, createdAt, secret? }` with event types such as `message.delivered`; webhook attempt `{ id, outboxId, at, status, durationMs, errorClass, snippet }` (the mock also sends `eventType`; the real API does not, and the dashboard shows the column only when present); API key `{ id, name, prefix, scopes, createdAt, lastUsedAt, key? }`; SMTP credential `{ id, username, createdAt, password? }` (create body `{ username }`); tenant `{ id, name, status, createdAt }` with status `active|suspended`. Webhook members are snake_case (`event_types`) as in the contract while most others are camelCase; the client follows the contract literally.
10. **Message detail** carries the text and html parts in `content` (the dashboard falls back to `GET /messages/{id}/content` when they are missing and treats its `410 body_expired` as an expected state).
11. **Admin status:** `{ version, backend, historyMode, uptimeSeconds, queue: { depth, deferred, oldestDueAt }, storage: { healthy, detail, warnings }, certificates: [{ subject, notAfter, source }], pressure: { writerQueueDepth, writerQueueOverThresholdSeconds, commitP99Ms, advisory }, switch: { state } }`. `pressure` is advisory only.
12. **Certificates:** list items `{ id, subject, issuer, san, notBefore, notAfter, source: acme|upload|self_signed, active }`; upload body `{ certificatePem, privateKeyPem }` or `{ pfxBase64, pfxPassword }`; ACME request body `{ domains: [...] }`.
13. **Storage switch:** `preflight` returns `{ ok, checks: [{ name, ok, message, severity }], counts, estimate, notCarried: [...], orchestratorManaged }`. `start` takes the preflight body plus `exportPassphrase` (at least 12 characters, design 4.6) and `confirmation` (the typed phrase `switch to <postgres|sqlite>`). `GET /admin/storage/switch` returns `{ switchId, state, direction, mode, include, progress: { phase, percent, rowsDone, rowsTotal }, verifyReport, cutoverPatch: { kind, text }, orchestratorManaged, error }` with `state` one of `none, draining, quiescing, fenced, exporting, importing, verifying, verified, confirmed, active, finalized, rolled_back, failed` (the real server also reports `verifying`; an unknown state is treated as work in progress). The server creates `cutoverPatch` when `activate` is called (`kind: "patch"` for an orchestrator-managed deployment, `"bootstrap"` with a note when the bootstrap file was rewritten), so the dashboard shows it on the finalize step; `orchestratorManaged` is known from the start. `confirm`, `activate`, `rollback` and `finalize` return the new status; calling them in the wrong state should answer `409`.
14. **CSRF and role failures** are assumed to be `403 forbidden` (no dedicated code is listed in api.md).

## Known gaps

- **Message HTML is shown without remote images and without styling.** The frame's policy and the host page's policy (a `srcdoc` document inherits it) block remote content and inline styles, and the browser logs each blocked item to the console. There is no "load remote images" option; the text view is the default.
- Charts are static SVG without hover tooltips; the data table next to them is the accessible alternative.
- Lists such as tenants and domains are not paged; suppression search filters the loaded entries only.
- After a switch has been activated and the server restarted on the target, `finalize` from the dashboard needs the old store described as `SwitchSource:*` ([switch.md](switch.md)); otherwise the page shows the reason and the CLI command (`mta migrate-storage finalize`).
- The webhook attempt log and the recent-events ring do not record the event type or the sending domain (api.md), so those columns are absent.
- Verified in Chromium only; no screen-reader pass, no Firefox or Safari run.
- English only; no i18n. Bearer API keys are not used by the dashboard (cookie session only).
