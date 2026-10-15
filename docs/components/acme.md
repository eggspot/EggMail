# ACME and the certificate store (`Mta.Host/Tls`)

How EggMail gets and serves its own TLS certificates (SMTP STARTTLS/implicit TLS and the dashboard/API HTTPS listener). Outbound TLS policy (MTA-STS, DANE, TLS-RPT) is a different component: [tls.md](tls.md). Decisions: K and 19 in [decisions.md](../decisions.md); design: [design.md §7.3](../design.md).

## Parts

| Type | Job |
|---|---|
| `AcmeRenewalService` | Decides when a certificate is due, takes the renewal lease, runs one order through an `IAcmeOrderRunner`, stores the result, records failures with back-off. `CheckOnceAsync` (scheduled, hourly in `RunAsync`), `RequestAsync` (the dashboard's "request a certificate": ignores the schedule and the back-off). |
| `CertesOrderRunner` (`IAcmeOrderRunner`) | One order with Certes 4.1: account, new order, **DNS-01** challenges, validation, finalize, download. The constructor takes an optional `HttpMessageHandler` (tests trust a private CA with it; deployments behind an egress proxy can use it). |
| `IDnsChallengeProvider` | Creates and deletes `_acme-challenge.<name>` TXT records. Must hold several values at one name (wildcard plus base name). `CloudflareDnsChallengeProvider` is the only production implementation. |
| `DatabaseCertificateProvider` | Holds the certificates of the store in memory, polls the store version (`Tls:PollInterval`) and swaps the set in atomically; first-run self-signed certificate; optional file override. Serves SMTP (`IServerCertificateProvider`) and HTTPS. |
| `HttpsCertificateSelection.UseCertificateStore` | Configures the Kestrel HTTPS listener from the provider (see below). |
| `CertificateMaterial` | Record to `X509Certificate2` (private key through Data Protection) and the self-signed bootstrap certificate. |

## Challenge types: DNS-01 only

The design supports **DNS-01 only** ([decisions.md](../decisions.md) 19, design §7.3: "DNS-01 by default, Cloudflare first, pluggable DNS-provider interface"). HTTP-01 and TLS-ALPN-01 are not implemented and not designed; there is therefore nothing to test for them. DNS-01 needs no inbound port 80 or 443, supports wildcards, and works for a host that is only reachable on port 25. External account binding (EAB, needed by some CAs such as ZeroSSL or Google Trust Services, not by Let's Encrypt) is also not part of the design: there are no configuration keys for it.

## Flow of one order

1. Lease `acme-renew:<certificate name>` (20 minutes; works on both backends). Another replica holding it makes this replica skip the order.
2. Renewal row set to `ordering`.
3. Account: the stored account for `Acme:DirectoryUrl` is used (its key is unprotected with purpose `AcmeAccountKey`). Without one, the runner registers a new account and the service **stores it immediately** (before the order can fail), Data Protection protected.
4. New order. An authorization the CA hands back already valid (RFC 8555 lets servers reuse valid authorizations of an account; Let's Encrypt and Pebble do) is skipped: no TXT record, no challenge request (posting to a valid challenge is refused). For each pending authorization one DNS-01 TXT record (a wildcard authorization is for the base name, so `*.example.com` and `example.com` put two values at `_acme-challenge.example.com`), `Acme:PropagationDelay`, validation requests, polling of the authorizations (200 ms growing to 3 s, about two minutes at most; the CA's explanation of an invalid authorization is part of the error), finalize with a fresh ES256 key, download of the chain. TXT records are removed in every case.
5. The certificate row is **replaced** (same name, same id, new version) so the poller of every replica sees one change and no old certificate stays active next to the new one. The chain is stored as sent by the CA (leaf plus intermediates), the private key as PKCS#8 protected with Data Protection.
6. Renewal row `issued`, failures 0.

Renewal is due when the CA's advice says so (ARI, next section), when a third of the lifetime is left (`Acme:RenewAtRemainingFraction`) if there is no advice, or when the configured names changed. A failed attempt of any kind (the CA refusing, unreachable or too slow; the DNS provider failing; an unreadable chain) is recorded in the renewal row (`failed`, failure count, last error, next attempt) and backed off 10, 20, 40 minutes, … up to 6 hours; it is never thrown, so the renewal loop survives. The old certificate keeps being served.

When the CA rejects the anti-replay nonce (`badNonce`; they expire and are per front end), the order is repeated up to four times in total, keeping an account that an earlier attempt registered.

## Renewal timing: ACME Renewal Information (ARI, RFC 9773)

Design §7.3 says "renew using ARI". `Acme:UseRenewalInfo` (default true) turns it on; `CertesOrderRunner.GetRenewalInfoAsync` asks the CA, `AcmeRenewalSchedule` (pure rules) decides, `AcmeRenewalService` persists.

* **Asking.** When the CA's directory has `renewalInfo`, the service GETs `<renewalInfo>/<certID>` where certID is `base64url(Authority Key Identifier)` `.` `base64url(serial)` of the certificate in use (Certes builds it; a stub-CA test pins the format). No account is needed. A directory without `renewalInfo` is looked at again after a day (the lifetime rule applies). Answers are limited to 1 MiB, the explanation URL must be an https URL of at most 2 KB, errors are kept to 1 KB.
* **Window.** The answer is a suggested window; times in any UTC offset are read as instants. The service picks **one random time inside it** the first time it sees that window and keeps it while the CA repeats (about) the same window, that is both ends within five minutes (a CA that computes the window from the current time would otherwise drift to the end of it at every poll). A different window picks again. A window or pick that has passed (what a CA answers for a revoked certificate or after an incident) means renew at the next check.
* **Due.** The chosen time is due when it falls before the next check (`now + Acme:CheckInterval`, RFC 9773 section 4.2 step 5). **Minimum age** (DESIGN-DECIDED): ARI alone never renews a certificate younger than the larger of one day and a twentieth of its lifetime (4.5 days for 90 days), so a CA that keeps answering "renew now" cannot cause an order at every check and hit the duplicate-certificate rate limit. The price is that a revoked certificate is replaced up to 4.5 days late, which the CA's own revocation already makes the client's problem.
* **Polling.** `Retry-After` is honoured within one minute and one day (no header: 6 hours); a stored wait further away than a day (clock stepped back, damaged value) is ignored. The CA is therefore asked about once per `Retry-After`, at least daily, and never faster than the hourly renewal check. Certes exposes `Retry-After` of successful answers only, so the one of a 429 or 503 is not honoured; the error back-off applies instead.
* **Failure** (RFC 9773 section 4.3.3). After a server error (5xx) or a network failure the CA is asked again after 5 minutes, doubling per consecutive failure up to 6 hours; after any other error (a 404 for an unknown certificate, an unparsable answer, a window that ends before it starts) after 6 hours. Meanwhile the lifetime rule decides, or the earlier window of the same certificate if there is one. The count of failures is part of the stored advice. The CA being unable to answer never blocks a renewal.
* **Safety limit** (DESIGN-DECIDED): whatever the advice says, a certificate with a sixth of its lifetime or less left is renewed (never later than `Acme:RenewAtRemainingFraction` would, if that is smaller), so a wrong or stale window cannot let it expire. The names-changed rule applies first and needs no advice.
* **`replaces`.** An order that renews a certificate sharing a name with it carries the certificate id in `replaces` (RFC 9773 section 5) when the CA advertises ARI, so it can treat the order as a renewal (rate limits) and mark the old certificate replaced. If the CA refuses the link itself (`alreadyReplaced`, `malformed`, `conflict`, `unauthorized` for a certificate of another account, 404) or fails on its side (5xx, `serverInternal`: Pebble 2.10 answers 500 for a certificate whose issuing order it has not indexed yet, a few microseconds after it issued it, and a real CA may hiccup) the order is repeated without the link, with a Debug log line; the plain order loses only the renewal treatment of the link. Other errors (rate limits, bad nonce handling) are not retried that way: asking again at once makes them worse and the plain order would meet the same.
* **State.** Stored as JSON in the existing `acme_renewal.ari_json` column of the certificate's row (window, chosen time, last/next check, explanation URL, error, failure count, directory-has-no-renewal-info flag; keyed by the certificate's thumbprint, so advice for an older certificate is ignored). No schema change; it moves with the switch bundle with the rest of the row. It is written with `IConfigStore.SetAcmeRenewalAdviceAsync`, which updates that column only, so a replica that was waiting for the CA cannot overwrite the status or back-off another replica wrote meanwhile (all backends; conformance test). A database error while saving is logged and the advice in hand is still used. The renewal row is read again under the lease before an order, so a back-off set during the question is honoured. A failed order keeps the advice; a new certificate clears it.

## Serving

* SMTP: `SmtpServer` asks the provider per handshake (`GetContext(sni)`), which returns the cached `SslStreamCertificateContext` with the intermediates, so a renewed certificate is used by the next connection and strict peers receive the full chain.
* HTTPS: `Cli.ServeAsync` calls `listen.UseCertificateStore(runtime.Certificates)`. Kestrel's `ServerCertificateSelector` returns a bare leaf and the intermediates are then not sent (found by the Pebble tests: the dashboard served a chain a strict client could not verify); the helper uses the handshake callback instead and returns the same context, TLS 1.2 minimum.
* Reload: the poller notices a new store version within `Tls:PollInterval`; a certificate that cannot be loaded or is expired is skipped with a log line and the previous set stays.

## Tests

`tests/Mta.Integration.Tests/Acme` runs the real flow (`AcmeRenewalService` + `CertesOrderRunner` + the real Data Protection secret protector over a SQLite or PostgreSQL config store) against **Pebble**, Let's Encrypt's ACME test server, with `pebble-challtestsrv` as the DNS server Pebble validates DNS-01 against. The challenges are really validated (the tests publish the TXT record through the challenge server's management API and Pebble queries it); nothing is stubbed with `PEBBLE_VA_ALWAYS_VALID`.

| Test | Covers |
|---|---|
| Issues a certificate and stores it encrypted | New order, challenge, finalize, one active ACME row for the requested name, chain (leaf + intermediate) verifies against Pebble's root, private key only as ciphertext and usable, TXT record created and deleted, renewal row `issued`, no second order while fresh |
| Wildcard and base name | Two authorizations, one TXT name, two values; both names in the certificate |
| Account key | Account row exists, key protected, reused by a "restarted" service (no second registration, same row) and a changed name set replaces the certificate row |
| Renewal (lifetime rule, ARI off) | Not renewed at 60 % of the lifetime, renewed at 70 %: same row id, new thumbprint, store version up, same account |
| ARI against Pebble (`AcmeRenewalInfoPebbleTests`) | Pebble accepts the certificate id; its window is stored; not due at 40 % of the lifetime, due at 70 %; the renewal order carries `replaces` and succeeds; advice is cleared by the new certificate. A window set through Pebble's management API 5 to 6 days ahead is followed instead of the lifetime rule (not due when the lifetime rule of a 6 day certificate would renew, due when the window opens); a window in the past does not renew a certificate minutes old and does renew an old enough one at the next check; unparsable advice falls back to the lifetime rule; a second order replacing an already replaced certificate falls back to a plain order |
| ARI rules (`Mta.Host.Tests/AcmeRenewalInfoTests.cs`, no CA) | Random position in the window, its stability (same window within five minutes), Retry-After bounds and an absurd stored wait, invalid and failed answers, the exponential error back-off and the six hour wait, bounded CA text and https-only explanation URL, due before the next check, due earlier and later than the lifetime rule, the minimum age, the safety limit and its relation to `RenewAtRemainingFraction`, window in the past, advice JSON, `Acme:UseRenewalInfo` binding |
| ARI service (same file; scripted CA, SQLite, fake clock) | Earlier and later than the lifetime rule, a CA that keeps saying "now" causes one order in days of hourly checks, Retry-After honoured and changed windows followed, no ARI and failing ARI with their cadences, off switch, failed order keeps the advice and the back-off beats ARI, other names skip the question and name the replaced certificate only if they share a name, database error while saving the advice, an advice save that must not overwrite another replica's back-off, a back-off set during the question |
| ARI on the wire (same file; stub CA through the real runner) | Window times with UTC offsets, the certificate id format, any Retry-After value (huge, negative, a date, text) ends between a minute and a day, directory without `renewalInfo`, 404 and 503 answers classified, a 2 MiB answer refused, and which refusals of `replaces` lead to a plain order (alreadyReplaced, malformed, conflict, unauthorized) and which do not (rateLimited, serverInternal) |
| Failed validation | No TXT record: failure recorded with the CA's explanation, back-off 10 min, no order inside the window, account kept after the failed order, recovery after the window clears the state; back-off grows 10/20/40 min |
| Rejected identifier | A name on Pebble's blocklist is a recorded failure before any challenge |
| Two replicas | While one order is in flight the second replica sees the lease, makes no request and publishes nothing; a dashboard request bypasses the back-off |
| Hot swap (runtime) | The runtime serves the self-signed certificate; with the host's loops running the poller swaps in the ACME certificate on the SMTP STARTTLS listener and the HTTPS listener (chain verified against Pebble's root, name matches); a renewal replaces it again without restart; a failed renewal leaves the served certificate unchanged |
| Unreachable and slow CA (no Pebble needed, always run) | Refused connection and HTTP timeout are recorded failures with back-off and do not end the renewal loop |

Run them locally with the two Pebble binaries (no Docker needed): see [development.md](../development.md#acme-tests-pebble). They are reported as **skipped** when `EGGMAIL_TEST_ACME_DIRECTORY` is not set. CI starts both as containers (`ghcr.io/letsencrypt/pebble:2.10.1`, `ghcr.io/letsencrypt/pebble-challtestsrv:2.10.1`) in the single `build-test` job.

## Bugs the Pebble tests found (fixed)

* The dashboard HTTPS listener sent only the leaf certificate (above).
* A failed first order stranded the ACME account: the key was stored only after a successful order, so every retry registered another account at the CA (rate-limited at real CAs). The account is now stored the moment the CA creates it.
* An HTTP timeout surfaced as a cancellation, was not caught by the renewal service and ended the renewal loop silently until restart. Every failure of an attempt is now recorded with back-off.
* `badNonce` from the CA failed the whole attempt (Certes retries it only for some requests); the order is now repeated.
* Transport errors reached the renewal record as "One or more errors occurred"; they now say what happened.
* An already valid authorization was challenged anyway and the CA refused ("Cannot update challenge with status valid, only status pending"); it showed up as CI flakes because Pebble reuses authorizations at random even with `PEBBLE_AUTHZREUSE=0`. The runner now checks the authorization and challenge status first, and CI pins reuse to always (`=100`) so both paths are deterministic.
* Authorization polling checked every 3 s; it now starts at 200 ms and grows to 3 s, so a quick CA no longer costs a multiple of 3 s per order.

## Known gaps

* **Not verified against a production CA.** Pebble follows RFC 8555 but is not Let's Encrypt: rate limits, CAA checks, the real DNS propagation of Cloudflare and the real profiles are not exercised. See [operations.md](../operations.md#tls-certificates-and-acme) for the staging run.
* Only DNS-01 and only Cloudflare as provider; no HTTP-01, TLS-ALPN-01 or EAB.
* ARI is verified against Pebble's draft-03 implementation and a stub CA only (the certificate id format is the same as in RFC 9773); Let's Encrypt's production answers are untested. Certes does not expose `Retry-After` of error answers, so 429 and 503 use the error back-off. The directory is fetched again for every ARI question and every order (a few small requests a day). Revoking a certificate ourselves is not implemented.
* No certificate profile selection (Let's Encrypt `classic`/`tlsserver`/`shortlived`).
* The ACME account email is only used at registration; changing `Acme:Email` does not update an existing account.
