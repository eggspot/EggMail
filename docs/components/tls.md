# Mta.Tls: outbound TLS policy

`src/Mta.Tls` decides, per recipient domain and MX host, how an outbound SMTP connection must use TLS, validates the peer certificate accordingly, and collects the data for TLS-RPT reports. It implements MTA-STS (RFC 8461), TLS-RPT (RFC 8460) and DANE for SMTP (RFC 7672, 7671, 6698), plus the per-domain configured level (like Postfix `smtp_tls_security_level`) that ties them together.

It is part of the hand-written, BCL-only stack ([design.md §2.1](../design.md#21-build-boundary)): no package references (enforced by `tests/Mta.ArchitectureTests`). It references `Mta.Core` (`IClock`, `Ids`) and `Mta.Dns` (`IDnsResolver`, `TxtRecord`, `TlsaRecord`, `DnsResponse.AuthenticatedData`) and uses only BCL types: `HttpClient`, `System.Security.Cryptography.X509Certificates`, `System.Formats.Asn1`, `System.Text.Json`, `System.IO.Compression`.

The certificates EggMail serves itself (ACME, the certificate store, hot reload) are a separate component: [acme.md](acme.md).

The library never opens SMTP connections and never sends mail. The delivery layer calls it before connecting (policy), during the TLS handshake (certificate validation), and after each attempt (recording, reporting).

## Namespaces and main types

| Namespace | Types |
|---|---|
| `Mta.Tls` | `TlsSecurityLevel`, `OutboundTlsConfiguration`, `OutboundTlsOptions`, `OutboundTlsPolicyResolver`, `DomainTlsContext`, `TlsPolicyDecision`, `TlsPolicyKind`, `TlsValidationMode`, `TlsPolicyReason`, `RemoteCertificateValidator`, `RemoteCertificateValidatorOptions`, `CertificateValidationOutcome`, `TlsSessionRecord`, `TlsPeerCertificateInfo`, `TlsResultType`, `TlsPolicyType` |
| `Mta.Tls.MtaSts` | `MtaStsTxtParser`, `MtaStsPolicyParser`, `MtaStsPolicy`, `MtaStsMode`, `MtaStsMxMatcher`, `MtaStsEvaluation`, `IMtaStsPolicyFetcher`, `MtaStsPolicyFetcher`, `MtaStsFetchOptions`, `MtaStsFetchResult`, `IMtaStsCache`, `InMemoryMtaStsCache`, `MtaStsCacheEntry`, `MtaStsPolicyStore`, `MtaStsStoreOptions`, `MtaStsLookupResult` |
| `Mta.Tls.Dane` | `DaneTlsaLookup`, `DaneLookupResult`, `DaneStatus`, `DaneVerifier`, `DaneVerificationResult`, `TlsaRecordClassifier` |
| `Mta.Tls.TlsRpt` | `TlsRptRecordParser`, `TlsRptRecordLookup`, `TlsRptCollector`, `TlsRptReportBuilder`, `TlsRptReport`, `TlsRptHttpsSender` |

## Typical use by the delivery layer

```csharp
// Once at startup (shared, thread-safe):
var sts      = new MtaStsPolicyStore(dns, new MtaStsPolicyFetcher(), cache /* IMtaStsCache */, clock);
var resolver = new OutboundTlsPolicyResolver(sts, new DaneTlsaLookup(dns));
var rpt      = new TlsRptCollector(clock);

// Per recipient domain:
DomainTlsContext domain = await resolver.ResolveDomainAsync("example.com", configuredForDomain);

// Per MX host the delivery will try (mxAuthenticated = the MX answer had the AD bit):
TlsPolicyDecision d = await resolver.ResolveForMxAsync(domain, "mx1.example.com", mxAuthenticated);
if (d.IsBlocked) { /* skip this MX, defer if no other MX; record d.BlockedFailure */ }

// Connect, EHLO, then STARTTLS only if d.AttemptTls and the server offers it:
var validator = new RemoteCertificateValidator(d);
await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
{
    TargetHost = d.MxHost,
    EnabledSslProtocols = d.AllowedProtocols,
    RemoteCertificateValidationCallback = validator.Callback,
});
TlsSessionRecord record = validator.CreateSessionRecord(ssl);   // persist per attempt (decision 19)

// Record the outcome for TLS-RPT (only for domains that publish a TLS-RPT record):
rpt.RecordSuccess(d.RecipientDomain, d.TlsRptPolicy, d.MxHost);
rpt.RecordFailure(d.RecipientDomain, d.TlsRptPolicy, d.MxHost, TlsResultType.CertificateExpired);
```

If STARTTLS is not offered or the handshake fails: `d.AllowsPlaintextFallback` says whether the message may be sent in clear. When it is false, `d.FailureMustDefer` is true: defer (4xx, retry later), never bounce and never send in plaintext.

## 1. Outbound TLS policy decision

### Configured level

`OutboundTlsConfiguration.Level` (per domain; default `May`). In the server the per-domain levels are the TLS policies an administrator manages through the API and the dashboard (`/api/v1/admin/tls-policies`, [../api.md](../api.md#relay-routes-and-tls-policies-role-admin-addition); `TlsPolicyTable` maps a recipient domain to the most specific pattern); `EnableMtaSts`, `EnableDane` and `RequireDane` are not per-domain settings there and stay at their defaults:

| Level | Meaning |
|---|---|
| `None` | Never use TLS. MTA-STS and DANE are not even looked up. An explicit operator override. |
| `May` (default) | Opportunistic: STARTTLS when offered, any certificate accepted, fall back to plaintext on failure. The platform `SslPolicyErrors` are recorded. |
| `Encrypt` | TLS required, certificate not validated. |
| `Verify` | TLS required, PKIX chain and a SAN matching the MX host name required. |

`EnableMtaSts` and `EnableDane` (default true) switch the sources off per domain; `RequireDane` (default false) blocks MX hosts without a usable TLSA policy with `dane-required` (like Postfix `dane-only`).

### Precedence (`OutboundTlsPolicyResolver.Decide`, a pure function)

1. Level `None` -> `Disabled`; nothing else is consulted.
2. **DANE usable** (secure TLSA with at least one usable record) -> `Dane`: TLS required, `Validation = Dane`, enforced, defer on failure. MTA-STS is ignored for this MX, even `enforce` with a non-matching MX list.
3. **DANE secure but unusable, or the TLSA lookup failed** (SERVFAIL, transport error) -> the MX is **blocked** (`IsBlocked`, defer). A permissive MTA-STS policy never overrides a failing DANE result.
4. `RequireDane` and no DANE policy -> blocked with `dane-required`.
5. **MTA-STS `enforce`**: MX must match the policy (else blocked, `validation-failure`); TLS required; PKIX validation of the MX name enforced; defer on failure.
6. **MTA-STS `testing`**: validate and report, deliver regardless (`EnforceValidation = false`). The configured level is a floor: `Encrypt` still requires TLS, `Verify` still enforces validation.
7. MTA-STS `none` (or no policy): the configured level alone decides.

TLS 1.2 is the minimum whenever TLS is required (`AllowedProtocols = Tls12 | Tls13`); for opportunistic delivery `OutboundTlsOptions.OpportunisticProtocols` applies (same default).

`TlsPolicyDecision.Reasons` carries pre-connection facts for TLS-RPT (STS fetch/parse/WebPKI errors even when a cached policy is still used, DANE problems, an MX outside a testing-mode policy). `TlsRptPolicy` yields the descriptor (`sts`, `tlsa`, `no-policy-found`) for the collector.

### Certificate validation (`RemoteCertificateValidator`)

One instance per connection attempt; `Callback` plugs into `SslClientAuthenticationOptions.RemoteCertificateValidationCallback`. It never throws.

* **No validation (`May`, `Encrypt`)**: accepts everything, records `SslPolicyErrors`; `Verified` is true only if the platform found no errors.
* **PKIX**: builds its own `X509Chain` (revocation not checked, server-auth EKU, time from the injected clock) from the presented certificates, using the system store or `RemoteCertificateValidatorOptions.CustomTrustAnchors`; the name check is done against `ExpectedHostname` (the MX host) on SAN dNSName entries only (no common-name fallback; wildcard = one whole left-most label under a suffix of at least two labels). The platform's own name-mismatch flag is ignored because `TargetHost` may legitimately differ. Failures map to `certificate-not-trusted`, `certificate-expired`, `certificate-host-mismatch`. With `EnforceValidation = false` (testing mode) the failure is recorded in the outcome and tolerated.
* **DANE**: `DaneVerifier` over the decision's TLSA records. A failure always aborts.

`CreateSessionRecord(SslStream, Exception?)` returns the `TlsSessionRecord` that delivery persists per attempt: TLS version, cipher suite, peer certificate (subject, issuer, validity, SHA-256, SAN DNS names), `SslPolicyErrors`, `Verified`, the policy applied, the failure classification and notes.

## 2. MTA-STS (RFC 8461)

* **TXT** `_mta-sts.<domain>`: `MtaStsTxtParser` (`v=STSv1; id=<1-32 alphanumerics>`). Records not starting with `v=STSv1` are ignored; if the number of candidates is not exactly one, or the candidate is invalid, there is no usable record.
* **Policy parser** `MtaStsPolicyParser`: `version: STSv1`, `mode: enforce|testing|none`, `mx:` (exact or `*.` wildcard; names normalised to lower-case A-labels), `max_age` (digits, clamped to 31,557,600 s). CRLF and LF accepted, case-insensitive keys, blank lines, a leading BOM and unknown keys tolerated. Invalid: missing or duplicate version/mode/max_age, unknown mode, bad `mx`, `mx` missing for `enforce`/`testing`, a line without a colon, more than 100 `mx` lines, over 64 KiB, invalid UTF-8.
* **Matching** (`MtaStsMxMatcher`, `MtaStsEvaluation.IsMxAllowed`): `*.example.com` matches exactly one extra label (`mail.example.com`, not `example.com`, not `a.b.example.com`); case-insensitive; trailing dot ignored. `Evaluate` returns the per-mode requirements (enforce: TLS and a valid certificate for the MX name; testing: validate but do not enforce).
* **Fetch** `MtaStsPolicyFetcher` (`IMtaStsPolicyFetcher`): `GET https://mta-sts.<domain>/.well-known/mta-sts.txt`. Only HTTP 200; **redirects are never followed** (3xx, or a response for another URI, is a failure); content type must be `text/plain` (UTF-8 or ASCII charset); body at most 64 KiB (checked on `Content-Length` and while streaming); total timeout 15 s (configurable); strict platform TLS validation (failures classify as `sts-webpki-invalid`); no proxy, cookies or decompression; TLS 1.2+. The default handler additionally refuses to connect to loopback, private, link-local and other non-public addresses after DNS resolution (SSRF guard; `AllowNonPublicAddresses` for local testing). Parse errors classify as `sts-policy-invalid`, everything else as `sts-policy-fetch-error`. A custom `HttpMessageHandler` can be injected (tests, egress control); it must not follow redirects.
* **Store** `MtaStsPolicyStore` over `IMtaStsCache` (in-memory default `InMemoryMtaStsCache`, bounded to 50,000 entries, so the host can persist later):
  * TXT id unchanged and entry fresh -> cached policy, no fetch. TXT id changed -> refetch.
  * Unchanged id but entry older than `RevalidateAfter` (24 h) -> refetch to extend the lifetime; a failed refetch keeps the cached policy.
  * Fetch failure with a cached policy -> the cached policy keeps applying (and the failure is reported in `MtaStsLookupResult.Failure`).
  * **No downgrade**: TXT missing, malformed, duplicated, SERVFAIL or timing out -> the cached policy applies until `max_age` expires. A policy is withdrawn by publishing `mode: none` with a new id.
  * `max_age: 0` is not cached. Failed fetches back off for 5 minutes per domain. Concurrent lookups for one domain share one fetch.

## 3. DANE (RFC 7672, 7671, 6698)

* **Lookup** `DaneTlsaLookup.LookupAsync(mxHost, port = 25, mxRrsetAuthenticated, ct)` queries `_25._tcp.<mx-host>` TLSA. Results (`DaneStatus`):
  * `NotApplicable`: no TLSA records, **or records without the AD bit** (insecure: treated as absent), or the MX RRset itself was not authenticated.
  * `Usable`: secure and at least one usable record.
  * `Unusable`: secure, but no usable record (only usages 0/1, unknown parameters, wrong lengths). An authenticated failure, never a downgrade (`tlsa-invalid`).
  * `LookupFailed`: SERVFAIL (`dnssec-invalid`), other rcodes or transport errors. The MX cannot be used safely.
  * If the MX name is an AD-authenticated alias, TLSA is tried at the CNAME target first and at the original name second; the DANE-TA name check accepts both.
  * AD is only trustworthy from a trusted local validating resolver (decision 6, Unbound on loopback).
* **Verification** `DaneVerifier.Verify(records, leaf, chainCertificates, mxHostname, options)`:
  * Usages 2 (DANE-TA) and 3 (DANE-EE) only; usages 0 and 1 are ignored for SMTP with a note. Selectors 0 (certificate) and 1 (SPKI); matching types 0 (exact), 1 (SHA-256), 2 (SHA-512).
  * **DANE-EE**: the leaf must match. No name check and no validity check (RFC 7672 §3.1.1).
  * **DANE-TA**: the chain must be anchored at a certificate that matches the record (presented in the chain; a hash of a certificate the server did not send cannot anchor), or at a certificate or public key carried in full in the record (selector 0 or 1 with matching type 0), each link signature-verified, issuers must be CAs (basic constraints / key usage), certificates below the anchor must be valid in time, and the leaf SAN must match the MX name (or the CNAME-derived reference names).
  * Signature support is RSA PKCS#1 v1.5 and ECDSA with SHA-256/384/512; SHA-1, RSA-PSS and EdDSA signatures do not verify. At most 16 presented certificates and 64 signature checks per record are considered (hostile chain bound).
  * The result has `Success`, a `TlsResultType` failure (`tlsa-invalid`, `validation-failure`, `certificate-host-mismatch`, `certificate-expired`), the matched record and notes explaining every ignored or unmatched record.
  * Servers must send the DANE-TA certificate for hash-type records (RFC 7671). Note that .NET servers (`SslStreamCertificateContext`) omit the self-signed root; publish the intermediate as trust anchor or the full root certificate (selector 0, matching 0).

## 4. TLS-RPT (RFC 8460)

* **Record** `_smtp._tls.<domain>`: `TlsRptRecordParser` / `TlsRptRecordLookup` parse `v=TLSRPTv1; rua=mailto:...,https://...` into endpoints (`Mailto` with the address, `Https` with the URI). Other schemes are skipped; HTTPS endpoints with credentials, IP literals or single-label hosts are rejected; at most 8 endpoints; multiple TLS-RPT TXT records mean no usable record. **Sending to `mailto:` endpoints is the delivery layer's job** (the library only exposes the parsed addresses and the attachment bytes/name).
* **Collector** `TlsRptCollector` (thread-safe, one lock): aggregates per policy domain, UTC day, policy (type plus policy string) and failure line (result type, sending IP, MX host, HELO, receiving IP, text, code). Counts are exact; distinct lines are bounded (500 per policy, 16 policies per domain-day, 100,000 domain-days, 256 characters per text field); overflow is counted (`DroppedFailureDetailCount`, `DroppedSessionCount`). `DrainCompletedDays()` yields (and removes) all days before today; `Snapshot()` copies without clearing. For persistence (below) `DrainAll()` yields and removes everything including today (a delta since the last call), `Absorb(data)` adds an aggregate back (counts add exactly, the bounds above still apply) and the static `Merge(pieces)` merges the persisted pieces of one domain and day into one report's data.
* **Report** `TlsRptReportBuilder.Build(data)` produces the RFC 8460 JSON (`organization-name`, `date-range` from 00:00:00Z to 23:59:59Z, `contact-info`, `report-id`, `policies[]` with `policy-type`, `policy-string`, `policy-domain`, `mx-host`, `summary`, `failure-details[]`), the gzip payload and the file name `<submitter-domain>!<policy-domain>!<begin-epoch>!<end-epoch>!<report-id>.json.gz` (RFC 8460 §5.1 calls the first component the sender, i.e. the reporting organisation's domain; `!` and path separators are stripped from the parts). `Decompress` has a size cap.
* **HTTPS delivery** `TlsRptHttpsSender.SendAsync(endpoint, report)`: POST with `Content-Type: application/tlsrpt+gzip`, 2xx is success, redirects are not followed, strict TLS, the same non-public-address guard as the policy fetcher, 30 s timeout, 10 MiB cap. It never throws on remote failures.

* **Persistence (host layer, `Mta.Host/Reports`).** The collector stays an in-memory buffer so recording a session costs no I/O. `TlsReportJournal` moves what it collected into the config store every minute and at shutdown (`tls_rpt_bucket`, one append-only row per flush, policy domain and UTC day, so replicas and restarts never overwrite each other; [storage.md](storage.md)); when the write fails the counts go back into the collector. `TlsReportSender` (hourly) reads the buckets of completed days, merges the pieces of each domain and day with `TlsRptCollector.Merge` and sends one report per domain and day; a delivered report (or a domain that no longer publishes a TLS-RPT record) deletes its rows, a failed one replaces them by their merged counters with the attempt count raised (up to `MaxAttempts` = 6, hourly, then the report is dropped; counters of a day more than `MaxReportAgeDays` = 7 old are dropped without a report), so **a restart loses neither the counters nor a pending report**. A run holds the `tls-rpt-sender` lease (ten minutes, renewed before every report; a run that loses it stops), so with replicas on one database each report is sent once; a day counts as completed ten minutes after midnight UTC (`CompletionGrace`), so a replica's last flush of the day does not cause a second report; one run reads at most 20,000 pieces and leaves the last, possibly cut, domain and day to the next run; a crash between sending and deleting sends the report again (at-least-once). A crash loses at most the counts since the last flush (a minute). The rows move with the config part in a backend switch (the source flushes when it quiesces). Proven with three runtimes over one PostgreSQL that all hold counters and run the sender at the same moment: one report per domain and day, carrying everyone's counts (`MultiReplicaTlsReportTests`); the corner that stays at-least-once is a flush that fails for longer than the ten-minute completion grace, which would split the day into two reports.

## Limits and hostile-input handling

| Input | Limit |
|---|---|
| MTA-STS policy body | 64 KiB, 100 `mx` lines, `max_age` clamped to 31,557,600 s |
| MTA-STS fetch | 200 only, no redirects, `text/plain`, 15 s, TLS 1.2+, public addresses only |
| MTA-STS cache | 50,000 entries (evict expired, then oldest fetch); failure memory 10,000 domains |
| TXT records | 1 KiB (MTA-STS), 4 KiB (TLS-RPT) |
| DANE chain | 16 presented certificates, depth 8, 64 signature checks per record |
| TLS-RPT collector | see above |
| TLS-RPT report | 10 MiB sent, 16 MiB decompressed |

Every parser returns `false` instead of throwing; deterministic fuzz tests cover the parsers and the collector.

## Known gaps

* No persistent `IMtaStsCache` (the host provides one; the in-memory cache is lost on restart, which only costs a refetch).
* No revocation checking for PKIX (deliberate for MX delivery) and no OCSP stapling check.
* Signature algorithms in DANE-TA chains are limited as described above.
* **The AD bit is wired end to end.** DANE needs to know whether the MX answer was DNSSEC-authenticated (`mxRrsetAuthenticated`): `Mta.Dns.MxResolver` sets `MxResolution.MxAuthenticated` from the AD bit of the MX answer, the delivery engine (`DeliveryProcessor`) passes it to `ResolveForMxAsync`, and `DaneTlsaLookup` reads the AD bit of the TLSA answer itself. The bit only ever exists when `Dns:TrustAuthenticatedData` is true (the DNS client reports AD only then, and sets the AD query bit), and that setting is only safe with a local validating resolver. **With the default (`false`) every answer is "insecure", DANE never applies and delivery falls back to MTA-STS and opportunistic TLS.** The deployment artifacts ship the resolver: the Unbound sidecar in `deploy/compose/compose.unbound.yaml` and `deploy/kubernetes/components/unbound` set `Dns__Servers__0`, `Dns__RequestDnssec` and `Dns__TrustAuthenticatedData` together, and the release workflow checks that the sidecar answers with the AD flag for a signed name and with SERVFAIL for a broken signature. What is not verified: DANE against a real DANE-enabled MX on the Internet.
* `mailto:` report delivery, report scheduling and the retry of failed HTTPS posts belong to the delivery/host layers (implemented in `Mta.Host/Reports`, persisted as described above).
* Opportunistic sessions with no TLS-RPT-relevant policy are aggregated like any other; the caller decides whether to record domains without a TLS-RPT record.
* No tests against real internet policies (the tests use fakes, generated certificates and loopback TLS only); plan.md's "tested against real policies" gate is still open.
