# Dashboard (`dashboard/`)

A Preact + Vite + TypeScript single-page app that talks to the HTTP API of [api.md](../api.md) on the same origin. It is an admin surface and is built to the supply-chain rules of [design.md §9.3](../design.md#93-dashboard-supply-chain). Nothing in `dashboard/` depends on .NET code: the host serves the static build, and a dependency-free mock API (`dashboard/mock`) stands in for the host during development and tests.

## Direct dependencies (8, exact versions pinned, `package-lock.json` committed)

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

No UI kit, no chart library (the charts are small hand-written SVG components), no state library (hooks and context), no icon or font packages (system fonts, no external requests). `dashboard/.npmrc` sets `ignore-scripts=true` and `save-exact=true`. All versions were published at least 7 days before they were pinned (design §9.3, "minimum release age"). Preact 11 was released shortly before this work and is deliberately not used yet; TypeScript 7 likewise.

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

The build is compatible with this strict CSP (the mock sends exactly this; `npm run check-csp` enforces the build side):

```
default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self';
frame-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
```

plus `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`.

Docker Node stage (design §9.3):

```sh
cd dashboard && npm ci --ignore-scripts && npm run build   # copy only dashboard/dist into the final image
```

Run `npm audit signatures` and an OSV scan in CI next to it (design §9.3).

## Security properties

- The session is an HttpOnly, SameSite=Strict cookie that script cannot read. The CSRF token from `GET /api/v1/me` lives in a module variable (never in web storage) and is sent as `X-CSRF-Token` on every `POST`, `PUT`, `PATCH` and `DELETE`. A `401` from any call returns the user to the sign-in form. Failed sign-ins surface `429` and `Retry-After`.
- One-time secrets (API key, SMTP password, webhook signing secret) are held only in the state of the creating component, shown with a copy button and a warning, and dropped when the user confirms they saved them.
- Stored message HTML is rendered only in `<iframe sandbox="" srcdoc=...>` (no sandbox flags at all: no scripts, no forms, no popups, unique origin) whose document starts with a CSP `<meta>` (`default-src 'none'; img-src data:`; inline styles only). The plain-text view is the default. HTML is never inserted into the app DOM. `scripts/lint.mjs` rejects `innerHTML`, `dangerouslySetInnerHTML`, `eval`, inline styles, `fetch` outside `src/api/client.ts`, external URLs and any `<iframe>` without `sandbox` or with `allow-*` flags.
- No runtime network access except same-origin `/api/v1/*` (and `/readyz`); no CDN, font or analytics requests; no inline script or style, so the CSP above holds.
- Web storage holds only non-secret conveniences: theme choice (`localStorage`), the acting tenant of an admin and the collapsed state of a warning (`sessionStorage`).

## Behavior that must not depend on the backend

Features are identical regardless of storage backend (decision E). The UI adapts only to `capabilities.history.mode`: with `statsonly` the Messages and message-detail pages show an explanatory empty state without calling the API, and a `410 history_not_recorded` or `410 body_expired` from the server is handled with the same explanations (capabilities can be stale). `capabilities.backend` is shown informationally in the header and used by the storage switch wizard only to name the opposite direction. `capabilities.warnings` render as a persistent banner on every page including the sign-in page; `sqlite_sync_off` is a loud alert that can be collapsed for the session but never dismissed permanently.

## Accessibility and theming

Semantic landmarks and headings, a skip link, focus moved to the page content after navigation, labelled form controls with `aria-describedby` and `aria-invalid`, modal dialogs with a focus trap and focus restore, tab widgets with arrow-key support, status chips that always carry their meaning in text, charts with an accessible name and a data table. Light and dark themes are CSS custom properties (`prefers-color-scheme`, plus a manual System / Light / Dark toggle through `data-theme`); `tests/contrast.test.mjs` computes WCAG contrast for every text pair in all three token blocks. Layouts work down to phone width (navigation collapses behind a Menu button, tables scroll inside `.table-wrap`).

## Bundle size

`npm run build` then `npm run size` (gzip level 9): the initial load (entry JS + CSS) is **21.2 KiB gzip** (entry JS 18.2 KiB, CSS 3.7 KiB). All routes are separate lazy chunks of 1 to 7 KiB gzip each, except the storage switch wizard (6.5 KiB gzip). The whole `dist/` is 64.8 KiB gzip (154 KiB JS raw, 14 KiB CSS raw, no fonts or images apart from a 0.2 KiB favicon).

Verification at the time of writing: `npm run lint` (tsc plus custom rules over 49 source files), `npm run typecheck`, `npm test` (26 files, 371 tests, including contrast checks for both themes, the CSP checker, the mock API contract, and a smoke test that renders every route against the real mock server for both roles and both history modes), `npm run build` and `npm run check-csp` all pass.

## API contract gaps and additions

[api.md](../api.md) left several shapes open. The dashboard and the mock assume the following. **The API implementation ([api.md](../api.md), [components/api.md](api.md)) adopted all of them and documents them in api.md**; the differences are: a storage switch step in the wrong state answers `409 conflict` (the mock used `409 validation_failed`; the dashboard does not depend on the code), and there are extra response members and error codes (`conflict`, `tenant_disabled`, `content_not_recorded`, `unsupported_media_type`) that the dashboard shows by their `detail` because it has no friendly text for them. `ApiContractTests` in `tests/Mta.Host.Tests/Api` checks the real API against `dashboard/src/api/types.ts`. The dashboard has not been run against the real API in a browser.

1. **CSRF token:** read from the `csrfToken` member of `GET /me` (the `X-CSRF-Token` response header is not read). The mock sends both.
2. **Sign-out:** `DELETE /api/v1/session` (not in the contract).
3. **Tenant settings:** `GET /api/v1/settings` returns `{ items: [{ key, value, type, options?, description?, locked? }] }`; `PUT /api/v1/settings` takes `{ values: { key: value } }` and returns the same shape. The contract has no tenant settings endpoint.
4. **Global settings** (`/admin/settings`): the same `{ items }` / `{ values }` shapes, with `locked: true` for values set by deployment configuration.
5. **Admin acting on a tenant:** tenant-scoped endpoints need `X-Tenant-Id` for admins. The mock answers `400 validation_failed` without it. The dashboard loads `GET /admin/tenants` after an admin signs in and sends the header.
6. **Validation status code:** `validation_failed` is assumed to be `400` with `errors: [{ field, message }]`; field names are the request member names (`url`, `name`, ...). The client does not depend on the numeric status.
7. **Lists** may be a bare array or `{ items, next_cursor }`; the client accepts both. Messages and suppressions are cursor-paged (`next_cursor`).
8. **Statistics:** `GET /stats` returns `{ granularity, rows: [...] }` (a bare array is accepted); each row has `period` (ISO start), `sendingDomain`, `recipientDomain` and the counters `accepted, delivered, deferred, hardBounce, softBounce, expired, complained, rejected, suppressed`. `GET /stats/recent-events` returns `[{ at, type, recipientDomain, sendingDomain }]`.
9. **Object shapes** not spelled out in api.md: webhook `{ id, url, event_types, enabled, disabledReason, createdAt, secret? }` with event types such as `message.delivered`; webhook attempt `{ id, outboxId, eventType, at, status, durationMs, errorClass, snippet }`; API key `{ id, name, prefix, scopes, createdAt, lastUsedAt, key? }`; SMTP credential `{ id, username, createdAt, password? }` (create body `{ username }`); tenant `{ id, name, status, createdAt }` with status `active|suspended`. Webhook members are snake_case (`event_types`) as in the contract while most others are camelCase; the client follows the contract literally.
10. **Message detail** carries the text and html parts in `content` (the dashboard falls back to `GET /messages/{id}/content` when they are missing and treats its `410 body_expired` as an expected state).
11. **Admin status:** `{ version, backend, historyMode, uptimeSeconds, queue: { depth, deferred, oldestDueAt }, storage: { healthy, detail, warnings }, certificates: [{ subject, notAfter, source }], pressure: { writerQueueDepth, writerQueueOverThresholdSeconds, commitP99Ms, advisory }, switch: { state } }`. `pressure` is advisory only.
12. **Certificates:** list items `{ id, subject, issuer, san, notBefore, notAfter, source: acme|upload|self_signed, active }`; upload body `{ certificatePem, privateKeyPem }` or `{ pfxBase64, pfxPassword }`; ACME request body `{ domains: [...] }`.
13. **Storage switch:** `preflight` returns `{ ok, checks: [{ name, ok, message, severity }], counts, estimate, notCarried: [...], orchestratorManaged }`. `start` takes the preflight body plus `exportPassphrase` (at least 12 characters, design 4.6) and `confirmation` (the typed phrase `switch to <postgres|sqlite>`). `GET /admin/storage/switch` returns `{ switchId, state, direction, mode, include, progress: { phase, percent, rowsDone, rowsTotal }, verifyReport, cutoverPatch: { kind, text }, orchestratorManaged, error }` with `state` one of `none, draining, quiescing, fenced, exporting, importing, verified, confirmed, active, finalized, rolled_back, failed`. `confirm`, `activate`, `rollback` and `finalize` return the new status; calling them in the wrong state should answer `409`.
14. **CSRF and role failures** are assumed to be `403 forbidden` (no dedicated code is listed in api.md).

## Known gaps

- **No real browser run.** Everything was verified with jsdom component tests and the mock API; no screenshot, real-browser or screen-reader pass has been done. Layout and the sandboxed iframe under the strict CSP should be checked once in Chrome, Firefox and Safari.
- **Message HTML is shown without remote images and with limited styling.** The iframe CSP blocks remote content, and a `srcdoc` document inherits the host page's CSP, so inline styles in messages may be dropped under `style-src 'self'`. There is no "load remote images" option; the text view is the default.
- Charts are static SVG without hover tooltips; the data table next to them is the accessible alternative.
- Lists such as tenants and domains are not paged; suppression search filters the loaded entries only.
- The storage wizard has only been run against the mock engine; real timing, restarts mid-switch and the cutover patch format are unverified.
- `npm audit signatures` and an OSV scan are not wired up (GitHub Actions is disabled for the repository, see open-questions.md); the lockfile is committed and `npm ci --ignore-scripts` is the supported install.
- English only; no i18n. Bearer API keys are not used by the dashboard (cookie session only).
