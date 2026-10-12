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

BUNDLE_SIZE_PLACEHOLDER

## API contract gaps and additions

API_GAPS_PLACEHOLDER

## Known gaps

KNOWN_GAPS_PLACEHOLDER
