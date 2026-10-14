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

Renewal is due when a third of the lifetime is left (`Acme:RenewAtRemainingFraction`) or when the configured names changed. A failed attempt of any kind (the CA refusing, unreachable or too slow; the DNS provider failing; an unreadable chain) is recorded in the renewal row (`failed`, failure count, last error, next attempt) and backed off 10, 20, 40 minutes, … up to 6 hours; it is never thrown, so the renewal loop survives. The old certificate keeps being served.

When the CA rejects the anti-replay nonce (`badNonce`; they expire and are per front end), the order is repeated up to four times in total, keeping an account that an earlier attempt registered.

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
| Renewal | Not renewed at 60 % of the lifetime, renewed at 70 %: same row id, new thumbprint, store version up, same account |
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
* ACME Renewal Information (ARI) is not used although the design mentions it (the `acme_renewal` row has a field for it that is never filled); renewal is purely lifetime-based. Revocation is not implemented.
* No certificate profile selection (Let's Encrypt `classic`/`tlsserver`/`shortlived`).
* The ACME account email is only used at registration; changing `Acme:Email` does not update an existing account.
