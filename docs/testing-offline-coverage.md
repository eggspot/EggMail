# What the offline tests prove, and what they do not

Some parts of EggMail talk to systems the test suite cannot reach from a build machine: a production certificate authority, Cloudflare, the public DNS, remote mail servers. For those the tests use test doubles and local servers. This page says, per area, what that proves and, as important, what it does **not**, so nobody reads a green build as more than it is. Each section is written by the change that added the tests for the area; [progress.md](progress.md) says what is verified overall.

## ACME and Cloudflare

Where the code is: [components/acme.md](components/acme.md). The tests: `tests/Mta.Host.Tests/Acme/*` (always run, no network), `tests/Mta.Integration.Tests/Acme/*` (against Pebble, run when `EGGMAIL_TEST_ACME_DIRECTORY` is set; CI sets it).

### How the pieces are tested

| Piece | Tested against | Nature of the double |
|---|---|---|
| ACME client (`CertesOrderRunner`, Certes 4.1) and renewal service | **Pebble** (CI), and a **mock CA** (`MockAcmeServer`, every build) | Pebble is Let's Encrypt's own test server: a real RFC 8555 implementation over real HTTP and TLS. The mock is written by us: an in-process `HttpMessageHandler` that speaks the RFC 8555 wire format, verifies signatures, nonces and external account binding, parses the CSR and issues real certificates from a throw-away CA, and can be scripted to misbehave |
| Cloudflare DNS-01 provider | **A fake Cloudflare** (`FakeCloudflare`, every build) | Written by us from Cloudflare's API documentation and observed behaviour: an in-process `HttpMessageHandler` with the v4 envelope, tokens, zones, paged lists and TXT records |
| Certificate store, hot swap, lease and replicas | Real storage (in-memory in the offline tests, SQLite and PostgreSQL in the integration tests) and the real services, with a fake clock | None for the logic under test |

### Proven

* **The client behaves correctly on every failure we could script**: rate limits (with and without `Retry-After`), a `badNonce` storm, `serverInternal`, answers that are not JSON or are cut off, a captive-portal page instead of the CA, timeouts and refused connections, an order that is `invalid` before or after finalize, challenges that fail (with the CA's explanation), time out or never finish, authorizations that expire, an order that stays `processing`, a refused or bad-nonce'd download, a certificate chain in the wrong order, without its intermediate, for other names, for another key, cut off, garbage, empty or already expired, an account that is deactivated or that the CA forgot, external account binding missing or wrong, a directory without `renewalInfo`, ARI answers that are errors, with `Retry-After` or garbage. For each, the test pins the outcome: what is stored (nothing, when the answer is not the answer to the order), what the renewal row and the banner say, what is waited and for how long, and that the TXT records and HTTP tokens are removed.
* **The wire format is right where the mock checks it**: the account key's JWS signatures verify at the mock, every nonce is used once, the key authorization is computed from the account key and the token (the mock validates the TXT value and the HTTP answer for real), the CSR carries exactly the ordered names, the external account binding HMAC verifies. (Pebble proves the same against a second, independent implementation.)
* **Time rules, exactly**: with a fake clock, a certificate is due at the instant a third of its lifetime is left and not a tick earlier; ARI renews one check interval before the chosen time; the minimum age and the one-sixth safety limit hold at their boundaries; the back-off is 10, 20, 40, 80, 160, 320, then 360 minutes, nothing is asked a second early, and a CA's `Retry-After` lengthens it (at most a day).
* **Replicas**: two replicas racing cause one order; a dead replica's lease is taken over exactly when it expires; a replica whose lease was taken over drops its certificate and leaves the other's result alone; a store failing after the CA issued leaves nothing half stored and the next attempt orders again; a restarted process continues with the stored account and the recorded back-off.
* **The served certificate set changes in one step**: readers racing a writer only ever see a complete certificate with its key; a damaged replacement does not take the working certificate out of service.
* **Cloudflare**: zone selection (sub-zones, pending zones, scoped tokens), exact request URLs, escaping and headers, several TXT values at one name, idempotent create and delete, every error envelope we know (400, 403 for a bad token or missing scope, 404, 429 with and without `Retry-After`, 5xx), HTML and damaged answers, retries and the exact waits, the token never in a message or a log line (also when Cloudflare or the HTTP stack repeats it), and that the **propagation delay** is what makes an order succeed when records become visible late.

### NOT proven

* **Production CA behaviour.** Pebble and the mock follow the RFC; Let's Encrypt (and ZeroSSL, Google, Buypass) have their own error wording, `Retry-After` values, rate-limit rules (certificates per registered domain, duplicate certificates, failed validations, new accounts, new orders), CAA checking, multi-perspective validation, authorization reuse rules, profiles, and quirks that are not in the RFC. The *classification* of an error by its ACME type is tested; whether a particular CA uses that type for a particular situation is not.
* **Real rate limits.** The tests prove the client stops, records, waits at least the `Retry-After` and asks again later. They do not prove that the waits chosen (10 minutes doubling to 6 hours, a day at most for `Retry-After`) keep an installation inside a real CA's limits, or that a certificate is issued in time if the limit lasts days.
* **Real Cloudflare behaviour.** The fake is our reading of the API. In particular not verified against the real service: the exact error codes (the adoption of an existing record relies on 81057/81058), the message texts, whether `content` is returned quoted, the page-size caps, the rules of token permissions and zone scopes (and which status a missing scope gets: 400, 401 or 403), `Retry-After` on 429 (Cloudflare often sends none), rate-limit windows, record-per-zone limits, eventual consistency between the API and the edge nameservers, proxied records, CNAME flattening and DNSSEC interplay, and the API's behaviour for internationalized zone names beyond the `xn--` form.
* **Propagation timing.** `Acme:PropagationDelay` (30 s default) is a guess. The tests prove the delay is waited and that it is what lets a late-visible record validate, with a lag the test chose. Real Cloudflare publishes within seconds to a minute; the CA's resolvers (and several vantage points) may take longer or hold negative answers in cache; nothing here measures that.
* **The network.** The doubles are in-process transports: URLs, headers, bodies and parsing are exercised, TCP, TLS (the CA's and Cloudflare's certificates), HTTP/2, proxies, IPv6-first behaviour, connection reuse, real timeouts and slow-loris behaviour are not. A "timeout" in these tests is a thrown exception, not elapsed time.
* **Anything the mock and the clients both misread.** The mock was written from the same RFC by the same team as the client; a shared misreading passes. Pebble is the independent check, and it is itself not a production CA.
* **Certes' behaviour outside the paths we use**, and its future versions; the mock is only as complete as the requests Certes 4.1 makes.
* **Single-use external account binding keys.** ZeroSSL and Google issue EAB keys that work for one registration only; the mock accepts a key any number of times, so "register again after the CA forgot the account" is proven for the client's logic, not for a CA that would refuse the reused key.
* **Nonce freshness on retries beyond what the mock can see.** The mock consumes every nonce once and checks it before any scripted failure, so a client that reuses a nonce fails; whether a real CA's front ends accept a nonce from a sibling front end is not known.
* **`Retry-After` as an HTTP date.** Certes turns a date into seconds against the real clock (a date far ahead becomes `int.MaxValue` seconds, which the service bounds to a day); the tests pin that behaviour, they do not prove what a CA sends.
* **The lease fence against a real database under contention.** The fence (renewing with the fencing token before any write, success path and failure path) is proven with the in-memory store's lease rules; the SQL stores share those rules and have their own conformance tests, but a take-over racing the renew inside the database is not exercised here.
* **A deadline over a whole order**: there is none (see components/acme.md, Known gaps).
* **A real renewal over weeks**: the clock rules are exercised with a fake clock in minutes; no test lets a real certificate age.
* **HTTP-01 against the internet** (port 80 reachable from the CA, IPv6 first, a load balancer in front): only the listener and the local Pebble connection are tested ([components/acme.md](components/acme.md), "Known gaps").

### What a green build therefore means

The client and the provider do the right thing for every answer the test doubles can give, and the answers they give were chosen to be those of the RFC and of the documented API. Before relying on it, run the staging checklist in [operations.md](operations.md#tls-certificates-and-acme) once against Let's Encrypt staging and a real Cloudflare zone: that run is the only thing that proves the two real services.

All tests in the two sections below (remote mail servers and authentication) use ephemeral loopback ports only, need no Docker, no network and no root, and assert no elapsed time or throughput (decision 73): retry timing is read off a fake clock and waits are polls with hang guards. The hung-peer scenarios (`SlowAndHungPeerTests`, the MTA-STS fetch time-out) do use real protocol time-outs of one second for the single stage under test, because a time-out is the behaviour being tested; they assert outcomes, not durations.

## Remote mail servers: `tests/Mta.RemoteMta.Tests`

Run: `dotnet test tests/Mta.RemoteMta.Tests -c Release` (about 30 s, 194 tests).

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

## Authentication (DKIM, SPF, DMARC, Authentication-Results): `tests/Mta.Authentication.Tests`

Run: `dotnet test tests/Mta.Authentication.Tests -c Release` (about 10 s, 223 tests). The test RSA key in `Fixtures/keys/` is public on purpose (it protects nothing; a secret scanner that flags it should be told to allow that path), so that the signatures, and with them the expected `header.b=` values, are reproducible. The three older suites stay as they are: `Mta.Dkim.Tests` (MimeKit differential, canonicalization, fuzzing), `Mta.Auth.Tests` (SPF case table in the style of the openspf suite, DMARC, ARC with a MimeKit cross-check, Authentication-Results).

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

## What is still open

Nothing in this document is an independent audit, a 7-day soak or a real-internet delivery test; those stay open in [progress.md](progress.md) until done.
