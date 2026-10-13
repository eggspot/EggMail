# HTTP API (`Mta.Host/Api`)

ASP.NET Core Minimal APIs implementing [api.md](../api.md). It lives in `Mta.Host` (a Web SDK project) as an extension, not as a composition root: the host that owns `Program.cs` (not built yet) calls two methods.

```csharp
builder.Services.AddEggMailApi(loadedConfig);        // or AddEggMailApi(new ApiOptions { ... })
var app = builder.Build();
app.MapEggMailApi();                                  // /api/v1/** plus /healthz, /readyz, /metrics
```

## Wiring into `mta serve`

`Hosting/ApiHosting.cs` connects the API to the runtime built by `EggMailRuntime`: it registers the runtime's `SubmissionService`, `ISecretProtector`, `AuthThrottle` (the instance the SMTP ingest uses), `IDnsResolver` and `AcmeRenewalService`, calls `AddEggMailApi(loadedConfig)`, maps the routes (`/healthz` moved here from `DashboardHosting`), gives the webhook dispatcher the tenants' SSRF allowlists (`SettingsService.GetWebhookAllowlistSnapshot`) and creates the first administrator from `Dashboard:BootstrapAdminUser` and the password file `Dashboard:BootstrapAdminPasswordFile` when no admin exists. `Cli.ServeAsync` has three calls into it.

## What the host must provide

Registered by the host (the API registers none of them): `IStorage`, `StorageOptions`, `ISecretProtector` (Data Protection in production), `SubmissionService`, `IDnsResolver` (for domain verification). Optional: `IClock`, `AuthThrottle` (**share the instance with the SMTP ingest** so the failed-login lockout is shared), `IStorageSwitchService` (the engine; without it the endpoints answer 503 `not_ready`), `AcmeRenewalService` (without it `POST /admin/certificates/acme` answers 503), `PrometheusTextExporter` (for `/metrics`), `IStoragePressureSource`. `AddEggMailApi` registers the API services, the `DomainVerificationService` hosted service, two health contributors (storage warnings, certificate warnings), `HealthService` and defaults for the optional services above. `ApiOptions` (`AddEggMailApi(LoadedConfig)` derives limits, the bounce domain, the locked configuration keys, webhook options and `MetricsEnabled` from the deployment configuration) holds every limit with its default.

Deployment notes: behind a reverse proxy configure the forwarded-headers middleware, otherwise the session cookie decision, the login throttle and the `/metrics` allowlist see the proxy's address (`/metrics` refuses any request that still carries `X-Forwarded-For`). The dashboard origin and the API are the same origin, so there is no CORS.

## Layout

| File | Contents |
|---|---|
| `ApiOptions.cs` | limits and switches (`MaxSendBodyBytes` 40 MiB, `MaxBodyBytes` 1 MiB, `MaxInFlightSendBytes`, session lifetimes, per-tenant caps, `LockedKeys`, metrics networks) |
| `ApiErrors.cs`, `ApiJson.cs`, `ApiInfrastructure.cs` | `ApiException` + RFC 9457 writer, strict JSON reading (unknown members rejected, streamed size limit, request digest), `ApiEndpointFilter` (request id, `no-store`, `nosniff`, exception to problem), query parsing, result helpers |
| `ApiAuth.cs` | `ApiAuthenticator` (API keys, sessions, CSRF, roles, tenant resolution), `SessionService` (sign-in/out, cookie), `ApiScopes` |
| `SessionApi`, `CapabilitiesApi`, `SendingApi`, `MessagesApi`, `DomainsApi`, `SuppressionsApi`, `WebhooksApi`, `CredentialsApi`, `StatsApi` (+ tenant settings), `AdminApi` | one class per endpoint group, each with `Map(RouteGroupBuilder)` |
| `DomainVerificationService.cs` | background scheduler and the shared `CheckAsync` (also behind "Verify now"), DKIM key creation and rotation helpers |
| `SettingsService.cs` | the settings catalog (tenant and global), validation, locks, the webhook allowlist |
| `StorageSwitch.cs` | `IStorageSwitchService` and its models, `UnavailableStorageSwitchService` |
| `AdminServices.cs` | `MaintenanceRunner`, `AcmeCertificateRequester`, `IStoragePressureSource`, `ApiRuntimeInfo` |
| `DashboardAccounts.cs` | create users / first admin / change password (for the CLI and bootstrap) |
| `EggMailApiExtensions.cs` | `AddEggMailApi`, `MapEggMailApi` |

## Design decisions

**Handlers throw, a filter answers.** Endpoint code throws `ApiException(status, code, detail, errors?, extensions?, headers?)`; one endpoint filter on the `/api/v1` group turns it into problem+json. Anything else becomes a generic 500 (logged with the request id, never echoed). Request bodies are read by the API itself (not by minimal-API binding) so the limit is enforced while streaming, the body can be hashed for idempotency, unknown members (`JsonUnmappedMemberHandling.Disallow`) and bad base64 become `validation_failed` with the member path as `field`, and base64 attachments are decoded straight into `byte[]` by the JSON reader (no intermediate string).

**Authentication.** A bearer key is looked up by the SHA-256 digest of the token (`IConfigStore.FindApiKeyAsync`), compared again in constant time, rejected when revoked or when its tenant is suspended; `LastUsedAt` is written at most once a minute per key. A session cookie is a 256-bit random secret whose digest is the primary key of `dashboard_session`; it is checked for absolute expiry and idleness, the user and (for tenant users) the tenant must still be enabled, and for mutations the `X-CSRF-Token` is compared in constant time with the token stored in the session. If an `Authorization` header is present it is the only credential considered (no fallback to the cookie). Sign-in verifies PBKDF2 (a dummy hash for unknown users), counts failures in the `AuthThrottle` under the keys SMTP AUTH uses (`<ip>` and `user:<name>`), upgrades old hashes, replaces the session of the presented cookie and purges expired sessions at most every ten minutes. `Secure` is set on the cookie except for plain HTTP from loopback (`CookieSecureMode.Auto`).

**Tenant isolation.** `RequireTenantAsync` resolves the effective tenant once per request (the caller's own; for an admin the `X-Tenant-Id`), and every storage call that follows takes that tenant id: history queries, suppressions, API keys, SMTP credentials, statistics and settings are tenant-keyed in storage; domains and webhook endpoints are fetched by id and checked (`TenantId == caller`) before use, answering `404` otherwise. The tests (`tests/Mta.Host.Tests/Api`) cover every group with two tenants.

**Sending** composes JSON with `MessageBuilder` (header injection is rejected, denied headers cannot be set) or takes a raw message, then calls `SubmissionService` like the SMTP ingest does: sender policy, header repair, content extraction, durable intake, idempotency. The idempotency fingerprint (SHA-256 of the endpoint and the exact request bytes) is stored with the key by storage; a duplicate whose stored fingerprint differs is 409. A byte budget (`SendBudget`) limits the memory of send bodies in flight.

**Domain verification** (`DomainVerificationService`). Every 15 s (configurable) it takes the domains due (`GetDomainsDueForCheckAsync`), at most four in parallel, and runs `CheckAsync`, which is also what "Verify now" calls (guarded by `VerificationSchedule.CanVerifyNow` and a per-domain in-flight set): plan the records (`DomainRecordPlanner`) from the published DKIM keys, look them up (`DomainChecker`), apply the result to the fresh domain row with `VerificationSchedule.Apply` (statuses, failure counts, the 72-hour grace, `SendingPaused`, next check), persist, remember the per-record results in memory, and switch signing to a rotated-in key whose record was found. Only the signing key's DKIM record and the return-path CNAME (when a bounce domain is configured) are required; a pending next key, a retired key within its 7-day grace, SPF and DMARC are advice. Unexpected checker exceptions count as a DNS failure so a bug cannot degrade a domain. `SenderPolicy` (existing) enforces the resulting status at submission time: `Pending`/`Verifying`/`Failed` and `SendingPaused` refuse, `TemporaryFailure` sends.

**Rotation.** `rotate` adds an inactive key; the delivery engine signs with the newest `Active` and not retired key, so signing is unchanged until `SetActiveDkimKeyAsync` runs (which retires the previous key with `RetiredAt = now`). Published keys are the active one, pending ones and retired ones for 7 days. Selector names are `egg<YYYYMM>` (`DkimKeyTools.SuggestSelector`) with `-n` suffixes, never reused.

**Webhook secrets** are stored as one protected string of one or two space-separated `whsec_` secrets, newest first, which is what the dispatcher signs with. SSRF: `WebhookUrlValidator` at registration (allowlist from `SettingsService.GetWebhookAllowlistAsync`, which the host should also give to `WebhookDispatcher.AllowlistProvider`), the dispatcher's resolver guard at delivery.

**Settings.** The catalog in `SettingsService` is the single list of what can be changed through the API. Tenant `Content:StoreAttachments` is the tenant record's flag; other values are `SettingRecord`s (tenant-scoped or global) with a JSON scalar. Locked means deployment-only, fixed by a configuration key the deployment sets (`ApiOptions.LockedKeys`), administrator-only (tenant view), or (attachments) disabled by the operator.

**Uploads.** A PEM upload must contain a key that belongs to the first certificate; the key is exported as PKCS#8, protected with `SecretPurposes.TlsPrivateKey` and stored like the ACME ones, so `DatabaseCertificateProvider` serves it at its next poll. ACME requests run in the background through `AcmeRenewalService.RequestAsync`; certificates requested for other names than the configured set are stored as `acme:<first name>` and renewed by `CheckOnceAsync` with the configured one.

## Limits (defaults)

JSON body 1 MiB (sending endpoints 40 MiB), message 25 MiB, 50 recipients, 50 attachments, 50 custom headers, 10 tags; 200 domains, 100 API keys, 100 SMTP credentials, 50 webhooks per tenant; list pages 200 (suppressions 500); statistics 50,000 rows, 35 days (hourly) / 800 days (daily); sessions 12 h absolute / 2 h idle; capabilities and readiness cached 5 s; send bodies in flight 512 MiB.

## Tests

`tests/Mta.Host.Tests/Api` runs the real endpoints in process (TestHost) over `InMemoryStorage` and, for a smoke subset per group, SQLite in a temp directory, with a controllable clock and DNS. Groups: authentication and sessions (cookie flags, CSRF, throttle shared with SMTP AUTH, expiry, roles, `X-Tenant-Id`), errors and limits, capabilities and operational endpoints, sending and idempotency, messages and resend, `StatsOnly` (410s), domains (state machine, rate limit, rotation), suppressions, webhooks (SSRF refusals, secrets, test/attempts/replay), credentials, statistics, settings, admin (tenants, status, settings, certificates, ACME with a fake authority, maintenance, switch with a fake engine), accounts, and `ApiContractTests`, which checks real responses against the TypeScript types in `dashboard/src/api/types.ts` (a small reader of the `.ts` file, no Node needed) and that every request member the dashboard sends is accepted.

## Known gaps

- The automated tests run in process (TestHost). `mta serve` was smoke-tested on Kestrel by hand (curl); a reverse proxy, TLS in front of the API and a browser were not exercised, and the dashboard's own Vitest suite runs against its mock, not against this API.
- Per-record DNS results are remembered in memory only (see api.md).
- Domain verification and DKIM rotation are serialized per domain inside one process only. With several replicas two of them can check the same domain at once (a failure may be counted twice, so a verified domain can reach `temporary_failure` after one real failure) and two rotations can race; a lease (as the ACME renewal uses) would fix it.
- Statistics queries load the rows of the range (bounded by the range limits and the storage series cap) before the row cap and the `domain` filter apply.
- Behind a reverse proxy set `ASPNETCORE_FORWARDEDHEADERS_ENABLED=true` (the built-in switch of the ASP.NET Core host) so client addresses are seen; there is no EggMail setting for it.
- A domain name can be registered by one tenant only, first come first served, with no proof of ownership beyond the DNS records the owner must publish; there is no admin transfer.
- Global settings are stored but the runtime does not apply them at startup yet (it reads deployment configuration only); `mta admin create` is not written (`DashboardAccounts` is what it will call).
- `tags` are validated but not stored. `recipient_suppressed` is reserved.
- No audit log of administrative actions, no per-tenant request rate limit (only the failed-login throttle, the verify limit and the send byte budget), no API for creating dashboard users (use `DashboardAccounts`).
- The switch endpoints are a validated pass-through: nothing behind them exists yet.
