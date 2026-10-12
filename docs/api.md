# HTTP API (v1)

The contract between the host and the dashboard (and API clients). Base path `/api/v1`. JSON in and out, UTF-8, timestamps are ISO 8601 UTC (`2026-10-12T08:00:00.000Z`), ids are lower-case 32-hex-digit UUIDv7 strings (no hyphens). The same endpoints behave identically on both storage backends (decision E); anything that depends on `History:Mode` says so and uses the error rules of [design.md §5.2](design.md#52-api-behavior-when-history-is-not-recorded-or-has-expired-design-decided).

## Authentication

- **API clients:** `Authorization: Bearer <api key>`. Keys are shown once at creation, stored as SHA-256 digests, scoped to one tenant and to a list of scopes (`send`, `read`, `domains`, `webhooks`, `suppressions`, `keys`).
- **Dashboard:** `POST /api/v1/session` with `{ "user": "...", "password": "..." }` sets an HttpOnly, SameSite=Strict, Secure cookie and returns `{ user, role, tenantId }`. Mutating requests with a cookie must carry the `X-CSRF-Token` header returned by `GET /api/v1/me`. Roles: `admin` (all tenants; selects a tenant with the `X-Tenant-Id` header) and `tenant` (one tenant).
- Failed logins are rate limited and share lockouts with SMTP AUTH.

## Errors

RFC 9457 problem details (`application/problem+json`): `{ "type", "title", "status", "detail", "code", "request_id", ... }`. Stable `code` values include `unauthorized`, `forbidden`, `not_found`, `validation_failed` (with `errors: [{field, message}]`), `rate_limited` (with `Retry-After`), `domain_not_verified`, `recipient_suppressed`, `payload_too_large`, `idempotency_conflict`, `history_not_recorded` (410), `body_expired` (410), `message_not_found` (404), `attachments_not_stored` (409), `not_ready` (503).

## Capabilities

`GET /api/v1/capabilities` (no auth needed for the dashboard shell to adapt) returns:

```json
{ "version": "0.1.0", "backend": "sqlite", "history": { "mode": "full" }, "content": { "retentionDays": 7, "storeAttachments": false },
  "limits": { "maxMessageBytes": 26214400, "maxRecipients": 50 }, "warnings": [ { "code": "sqlite_sync_off", "message": "..." } ] }
```

The dashboard hides per-message pages only when `history.mode` is `statsonly`, never based on `backend`. `warnings` drives the persistent banner (decision P); `sqlite_sync_off` is shown on every page while it is present.

## Sending

`POST /api/v1/messages` (scope `send`), optional `Idempotency-Key` header (same key and tenant returns the original result, `409 idempotency_conflict` if the body differs):

```json
{ "from": "Name <sender@example.com>", "to": ["a@x.test"], "cc": [], "bcc": [], "reply_to": "r@example.com",
  "subject": "Hello", "text": "plain", "html": "<p>html</p>",
  "headers": { "X-Campaign": "autumn" },
  "attachments": [ { "filename": "a.pdf", "content_type": "application/pdf", "content": "<base64>", "content_id": null } ],
  "store_attachments": false, "tags": ["welcome"] }
```

Response `202`: `{ "id": "<message id>", "status": "queued", "recipients": 1 }`. Validation: the From domain must belong to the tenant and be `verified` (or `temporary_failure`), at most 50 recipients, total size within `maxMessageBytes`, no CR/LF/NUL in headers. Suppressed recipients are accepted into the response but recorded as `suppressed`. `POST /api/v1/messages/raw` accepts `{ "from", "to": [...], "raw": "<base64 RFC 5322 message>" }` for pre-built (for example already DKIM-signed) mail.

## Messages (`read` scope; per-message history, `History:Mode=full`)

- `GET /messages?recipient=&sender=&subject=&status=&from=&to=&limit=&cursor=` → `{ items: [MessageSummary], next_cursor }`.
- `GET /messages/{id}` → `{ id, tenantId, receivedAt, subject, from, recipients: [..], status, size, content: { state: "available"|"body_expired", text?, html?, attachments: [..] }, rawRetained }`.
- `GET /messages/{id}/events` → `[ { id, type, at, recipient, smtpCode, enhancedCode, message, mxHost, route, tls } ]` (types: `queued`, `delivered`, `deferred`, `bounced`, `expired`, `suppressed`, `cancelled`, `complained`, `aborted_by_switch`, `possible_duplicate`).
- `GET /messages/{id}/content` → text/html parts; `410 body_expired` once past `Content:RetentionDays`.
- `POST /messages/{id}/resend` → `202` with the new message id; from retained raw, or re-composed (labelled `recomposed: true`) for attachment-free messages; `409 attachments_not_stored`; `410 body_expired`.
- Under `History:Mode=statsonly` all of the above return `410 history_not_recorded`.

## Domains (`domains` scope)

- `GET /domains`, `POST /domains` `{ "name": "mail.example.com" }` (creates a DKIM key and returns the records), `GET /domains/{id}`, `DELETE /domains/{id}`.
- Domain object: `{ id, name, status: "pending"|"verifying"|"verified"|"temporary_failure"|"failed", sendingPaused, lastCheckedAt, nextCheckAt, lastError, records: [ { type, host, value, ttl, purpose: "dkim"|"return_path"|"spf"|"dmarc", status: "ok"|"missing"|"invalid"|"pending", found?, expected } ], dkim: { selector, publicKey, active, createdAt } }`.
- `POST /domains/{id}/verify` (rate limited to once per 30 s per domain) → the domain object after an immediate check. `POST /domains/{id}/dkim/rotate` publishes selector N+1, keeps N for at least 7 days.

## Suppressions (`suppressions` scope)

`GET /suppressions?cursor=&limit=`, `POST /suppressions` `{ "address": "...", "reason": "manual" }`, `DELETE /suppressions/{address}`.

## Webhooks (`webhooks` scope)

- `GET/POST /webhooks`, `GET/PATCH/DELETE /webhooks/{id}`. Create: `{ "url": "https://...", "event_types": ["message.delivered", ...] }` → includes the signing secret once (`whsec_...`). HTTPS only unless the host allows http; internal addresses need the tenant allowlist (SSRF guard).
- `POST /webhooks/{id}/rotate-secret` signs with old and new until the old one is removed. `POST /webhooks/{id}/test` sends a `webhook.test` event.
- `GET /webhooks/{id}/attempts?limit=` → the attempt log (status, duration, error class, response snippet ≤ 1 KB).
- `POST /webhook-events/{outboxId}/replay` re-queues a finished or failed delivery.

## Credentials (`keys` scope)

`GET/POST/DELETE /api-keys` (create returns the key once) and `GET/POST/DELETE /smtp-credentials` (SMTP AUTH users for this tenant).

## Statistics (`read` scope)

`GET /stats?from=&to=&granularity=hour|day&domain=` → rows with `accepted, delivered, deferred, hardBounce, softBounce, expired, complained, rejected, suppressed` per period, sending domain and recipient domain bucket; `GET /stats/recent-events?limit=` → the content-free ring. Available on every backend and in both history modes.

## Admin (role `admin`)

- `GET/POST/PATCH /admin/tenants`, `GET /admin/status` (queue depth, oldest due, storage health incl. warnings, certificate expiry, backend, version, mode-switch state), `GET/PUT /admin/settings` (global settings; values locked by deployment configuration are marked `locked: true`), `GET /admin/certificates`, `POST /admin/certificates` (upload PEM/PFX), `POST /admin/certificates/acme` (request a certificate), `POST /admin/maintenance/run`.
- Backend switch (decision 14, design §4.6), never automatic: `POST /admin/storage/switch/preflight` `{ "to": "postgres"|"sqlite", "target": {...}, "include": ["queue","history"], "mode": "drain"|"quiesce" }`, `POST /admin/storage/switch/start`, `GET /admin/storage/switch` (state, progress, report), `POST .../confirm`, `POST .../activate`, `POST .../rollback`, `POST .../finalize`. The same engine backs `mta migrate-storage`.

## Operational endpoints (no `/api/v1` prefix)

`GET /healthz` (liveness, always cheap), `GET /readyz` (readiness; fails when the storage backend is down; response includes `warnings`), `GET /metrics` (Prometheus text exposition of the `Mta.*` meters, admin-network only).

## Compatibility

Additive changes only within `v1`. Unknown JSON members in requests are rejected with `validation_failed`; unknown members in responses must be ignored by clients.
