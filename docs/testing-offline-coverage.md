# Offline coverage of what cannot be verified against the real Internet

Some things can only be proven against systems nobody on the project controls: real mail servers, real DNS and DNSSEC, real certificate authorities, a week of wall-clock time. This document lists what the automated tests *do* establish about them offline, and, for each area, what they **do not** prove. It is not a substitute for the checks in [progress.md](progress.md) ("Not verified"); it makes the boundary explicit.

All tests here run in `dotnet test`, use ephemeral loopback ports only (no fixed ports), assert no wall-clock time (decision 73: waits are polls with minutes-long hang guards, retry timing is read off a fake clock), and need no Docker, no network and no root.

## 1. Remote mail servers: `tests/Mta.RemoteMta.Tests`

Run: `dotnet test tests/Mta.RemoteMta.Tests -c Release` (about 30 s, 190 tests).

### What it is

A lab (`Harness/MtaLab.cs`) runs the **real** delivery engine (scheduler, processor, SMTP client, connection pool, retry schedule, destination throttle, TLS policy resolver with MTA-STS and DANE, TLS-RPT collector, DSN service, webhook outbox) over in-memory storage. Only the outside world is replaced:

| Replaced | By |
|---|---|
| Remote MTAs | `FakeMta`: a hand-written SMTP server on a loopback port, driven by an `MtaPersonality` (banner, extensions, per-command hooks) and `Step` (reply, multi-line reply, raw garbage, silence, FIN, RST, gated reply). It does not use the project's SMTP server, so a server bug cannot hide a client bug. |
| DNS | `FakeDns`: MX, A/AAAA, CNAME, TXT (`_mta-sts`, `_smtp._tls`), TLSA, null MX, **the AD bit per name**, SERVFAIL, unreachable resolver, query log. |
| MTA-STS policy host | `FakeMtaStsWebServer`: a real TLS web server on loopback (policy, 404, redirect, wrong content type, oversize, hang, wrong/expired/untrusted certificate), reached by the real `MtaStsPolicyFetcher` through a handler that does full chain and name validation against a private root. |
| Certificates | `TestPki`: a private CA; valid, expired, wrong-name and unknown-CA leaves. The engine trusts the private CA through `DeliveryServices.CertificateValidation`. |
| Time | `FakeClock`: moves only when the test says so; five days of retries take milliseconds. |

The personalities (`Gmail`, `Outlook`, `Postfix`, `Exim`) use the banner, extension list and reply formats those systems are publicly documented to use (Google's SMTP error reference, Microsoft's NDR reference, Postfix's default restriction texts, Exim's default configuration without enhanced status codes). They are **not captured traffic**.

### Scenarios (each test is named for the behaviour)

Greylisting (450 at RCPT and after the data, with and without enhanced codes, server retry hints); 421 rate limits and connection throttling, the 10 / 10 / 30 / 60 / 120 / 240 / 480 minute throttle ladder, AIMD cut of the destination's rate, per-destination concurrency ceiling, a peer that refuses connections beyond its limit; 5xx policy, reputation, authentication and content refusals in 16 provider shapes at banner, MAIL, RCPT, DATA and end of data (bounce yes, suppression only when the address is the problem, DSN content); 552 by SIZE, at MAIL and after the data, full mailbox; STARTTLS offered / required / stripped / refused (454) / broken in four ways, downgrade after first contact under `may`, `encrypt`, `verify`, MTA-STS and DANE; certificates valid, expired, wrong name, unknown CA under each level; MTA-STS enforce and testing, policy fetch failures (nine kinds), cached and stale policies, id changes, mx patterns, TLS-RPT records and the built report JSON; DANE-EE match, mismatch, rollover, no AD bit, unsigned MX, unusable usages, SERVFAIL, required DANE, alias MX, precedence over MTA-STS; 8BITMIME and SMTPUTF8 absent, HELO-only peers; hung and slow peers (banner, tarpit, DATA, verdict after the data lost as silence, FIN and RST) and the `possible_duplicate` flag through to webhooks; MX failover, preference order, equal-preference spread, null MX, implicit MX, NXDOMAIN, SERVFAIL, CNAME to MX, IPv6 and IPv4 fallback in both directions (skipped with the reason where there is no IPv6 loopback); connection reuse (RSET before and NOOP after, idle expiry on the fake clock, peer-closed idle connections, per-connection caps), pipelining on and off, BDAT on and off; very long and many-lined replies, garbage, bare LF line ends, unsolicited extra replies; partial recipient success, 452 too many recipients, 421 in the middle of the envelope; the full five-day retry timeline to expiry with the bounce and the webhook stream.

### Bugs this suite found (fixed, each with a regression test)

1. A `421` during the envelope was replaced by a generic "connection lost" (the server closes right after it), so a rate-limit reply was retried after one minute instead of the throttle schedule. The 421 is now the verdict.
2. A broken STARTTLS upgrade (peer closes after `220`, plain text, reset, injected data) deferred the message for good under opportunistic TLS. RFC 7435 opportunistic TLS retries on a new connection without STARTTLS; the failure is still reported to TLS-RPT.
3. Sessions authenticated by DANE or by a configured private CA were recorded as `verified: false` (the platform alone was consulted); the policy's own verdict is recorded.
4. MTA-STS **testing** mode counted failing sessions (bad certificate, MX not listed) as successes in TLS-RPT, which defeats the mode's purpose (RFC 8460).
5. A non-SMTP line where the verdict after the data should be did not set `possible_duplicate`.

### What it does NOT prove

- **Real provider behaviour.** Nothing here says Gmail or Outlook accept mail from a given IP, domain or content, what their current reply texts are, how they weigh reputation, or what their real rate limits are. The reply shapes are reproductions of documentation.
- **Real-network conditions.** Loopback has no packet loss, latency, MTU, middleboxes, NAT, firewalls that drop (a connect that times out rather than being refused is not simulated), port 25 egress blocking, or reverse DNS (rDNS/FCrDNS) checks.
- **IP reputation, blocklists, greylisting durations of real servers** (real greylisters have their own minimum delays).
- **Real DNS and DNSSEC.** `FakeDns` says what the AD bit is. Whether a real validating resolver sets it, how it fails, TTL behaviour, truncation/TCP fallback and resolver outages are not exercised (the DNS client has its own tests against a scripted server).
- **Real certificates and trust stores.** Chains are from a private CA; real intermediate chains, OS trust stores, revocation (not checked by design), OCSP and CT are not involved.
- **TLS stack variety.** Only the .NET TLS stack on both ends. Servers with legacy protocol/cipher limits are not reproduced beyond "the handshake breaks".
- **Scale and soak.** About a hundred messages at a time at most.

## 2. Authentication: `tests/Mta.Authentication.Tests`

Run: `dotnet test tests/Mta.Authentication.Tests -c Release` (about 5 s, 223 tests). The three older suites stay as they are: `Mta.Dkim.Tests` (MimeKit differential, canonicalization, fuzzing), `Mta.Auth.Tests` (SPF case table in the style of the openspf suite, DMARC, ARC with a MimeKit cross-check, Authentication-Results).

- **`DkimCrossCheckTests`**: 15 message shapes (folded and tabbed headers, trailing and leading blank lines, empty and CRLF-only bodies, no final newline, empty header values, repeated headers, long lines, 8-bit text, two `From`) x 4 canonicalization pairs. Each signature made by `Mta.Dkim` is judged by four code paths: `Mta.Dkim`'s verifier; MimeKit (BouncyCastle); `IndependentDkim`, a from-scratch reading of RFC 6376 using only strings and the BCL, which also **signs again and must reproduce `b=` byte for byte** (PKCS#1 v1.5 is deterministic); and the `openssl dgst -verify` command line (skipped with a reason where `openssl` is absent). Tampering (nine kinds) must be rejected by all readings in all canonicalizations. `l=` handling, canonicalization-insensitive edits, and added `From` headers (oversigning) are cross-checked the same way.
- **`Rfc6376VectorTests`**: the appendix A body hash, and the published SHA-256 constants of empty bodies under simple and relaxed canonicalization. **The signature of RFC 6376 appendix A.2 cannot be used as a vector**: the RFC's typesetting changed the text (the body printed with two spaces hashes to the printed `bh=` with one) and no variant of the folding white space verifies against the printed key; the RFC has no private key to sign it again. The test says so.
- **`Rfc7208AppendixATests`**: the DNS of RFC 7208 appendix A as printed and every verdict the appendix states (A.1 simple examples, A.2 include/redirect, A.3 DNSBL-style macros, A.4 multiple requirements; the `-ptr` of A.4 needs an explicit target, see the comment in the test).
- **`Rfc7489ExampleTests`**: the worked alignment examples of section 3.1 and the organizational-domain examples of 3.2.
- **`AuthenticationResultsFixtureTests`**: 17 fixture files in `Fixtures/ar/*.case` (connection, DNS zone, message signed with a published test key and edited like an intermediary would, expected `Authentication-Results`). Reading one file shows a whole receive-side scenario: forwarding, list footers, provider bounce domains, subdomain policy, strict alignment, public-suffix signatures, expired signatures, missing keys, SPF `temperror`, null sender.

RFC 8617 (ARC) publishes an example message but no keys, so it cannot be verified byte for byte; ARC is covered by `Mta.Auth.Tests/Arc` (round trips, tampering, MimeKit cross-check).

### What it does NOT prove

- That a receiver such as Gmail **accepts** EggMail's DKIM/SPF/DMARC (it also weighs reputation and content), or how it renders the result. Only the correctness of the signature and the header text against the RFCs and three independent implementations is shown.
- Real DNS publication: record syntax at a real registrar, TXT string splitting by DNS providers, caching and propagation.
- Ed25519 (RFC 8463): not implemented.

## 3. How these tests relate to the other offline areas

The ACME/Cloudflare, security-audit and accelerated-soak areas of the same request are separate changes. Nothing in this document is an independent audit, a 7-day soak or a real-internet delivery test; those stay open in [progress.md](progress.md) until done.
