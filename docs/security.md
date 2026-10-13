# Security model

Status of the security work, written to be checked against the code and the tests. **No independent audit has been done.** Items marked *gap* are not implemented or not verified.

## Trust boundaries and what protects them

| Boundary | Threats (STRIDE) | Controls implemented | Evidence |
|---|---|---|---|
| **SMTP in (submission and bounce listeners)** | Spoofing, tampering, DoS, elevation (open relay) | Only CRLF ends a line and `.` terminator is recognised by a state machine, so smuggling variants are refused (`DataScanner`); bare CR/LF refused; commands sent behind `STARTTLS` are discarded (injection guard); `BDAT` chunks are inert; AUTH PLAIN/LOGIN only after TLS; per-IP and global connection caps, in-flight byte budget, line/size/recipient/error limits, timeouts; no path from an unauthenticated session to the delivery queue (the bounce listener accepts only signed bounce addresses and never queues mail for delivery); sender domain must belong to the tenant and be verified (`SenderPolicy`) | `Mta.Smtp.Protocol.Tests` (smuggling vectors, chunk independence), `Mta.Smtp.Server.Tests` (STARTTLS injection, limits, garbage fuzz), `Mta.Host.Tests` (`IngestTests`: auth, unowned sender domain, relay attempts on the bounce listener, forged bounce token) |
| **SMTP out (delivery)** | Tampering (downgrade), information disclosure | STARTTLS stripping/injection guard in the client; MTA-STS and DANE policy resolution per MX, enforced validation; per-domain TLS level overrides; `possible_duplicate` marking; DKIM signing at delivery; envelope sender is a signed VERP token | `Mta.Smtp.Client.Tests`, `Mta.Tls.Tests`, `Mta.Delivery.Tests` |
| **DNS** | Spoofing, DoS | Random IDs and source-port randomisation by the OS, answer must match the question, optional 0x20, bounded CNAME chains, response size and record limits, DNSSEC/AD bit only trusted when configured; MX hosts that resolve to special-use addresses are excluded by default (`Delivery:AllowPrivateMxAddresses=false`) | `Mta.Dns.Tests` |
| **Hostile message content (MIME, DKIM, SPF, ARC parsers)** | DoS, crashes | Explicit limits on header bytes/count, nesting depth, parts, decoded size, parameters, addresses; parsers never throw on input and set anomaly flags; allocation budgets; seeded mutation fuzzing and exhaustive prefix/deletion sweeps; differential tests against MimeKit | `Mta.Mime.Tests`, `Mta.Dkim.Tests`, `Mta.Auth.Tests` |
| **HTTP out (webhooks, MTA-STS fetch, TLS-RPT)** | SSRF | Resolved addresses are validated and connections are made to the validated address; private, loopback, link-local and metadata ranges denied unless allow-listed per tenant; no redirects; HTTPS by default; response size/time limits | `Mta.Webhooks.Tests`, `Mta.Tls.Tests` |
| **Credentials** | Spoofing, brute force | Passwords: PBKDF2-SHA256, 600,000 iterations, per-password salt, constant work for unknown users; API keys: 256-bit random, only a SHA-256 digest is stored, constant-time comparison; failed-login throttling shared between SMTP AUTH and the API | `Mta.Host.Tests` (`SecurityTests`, `IngestTests`) |
| **Secrets at rest** | Information disclosure | DKIM private keys, webhook secrets, TLS private keys, ACME account key and relay passwords are protected with ASP.NET Core Data Protection (one purpose string per kind); the key ring lives in the config store and is encrypted with a certificate (`Secrets:KeyProtection=Certificate`); `None` is allowed for development and logs a warning; backend switch bundles never contain clear-text secrets (separate bundle key ring, passphrase-protected PKCS#12) | `Mta.Host.Tests` (`SecretsTests`), `Mta.Storage.Portability.Tests` |
| **Storage** | Tampering, data loss | Integrity check at start and quarantine of a corrupt SQLite file, ordered and idempotent cross-file writes, crash-recovery tests including SIGKILL in every sync mode; per-tenant scoping on every query *(HTTP layer: see the API PR)* | `Mta.Storage.Sqlite.Tests`, conformance suites |
| **Dashboard and HTTP API** | XSS, CSRF, session theft | Strict CSP (`script-src 'self'`, no inline script or style, no `eval`), `nosniff`, `no-referrer`, frame denial, HSTS over HTTPS; HttpOnly + SameSite=Strict cookies and a CSRF header for cookie-authenticated writes; dashboard has about 8 direct dependencies, exact versions, lockfile, `ignore-scripts` | `dashboard` tests (CSP checker, lint rules), API tests *(in the API PR)* |
| **Release and supply chain** | Tampering | Package-free guard for the protocol assemblies; central package management with exact versions; image build and publish only from GitHub Actions with attestations *(workflow written, never run: Actions is disabled for the organization)* | `Mta.ArchitectureTests`, `docs/release.md` |

## Parser review checklist (used for every new parser)

1. Every length, count and nesting depth has an explicit limit and a test at the limit and above it.
2. Hostile input never throws out of the parser, never allocates proportionally to a claimed (not actual) size, and never loops without consuming input.
3. Text that comes from the network is sanitised before it reaches a log, a header, a DSN or a webhook payload (control characters, CR/LF).
4. Round trip and differential tests against a reference implementation exist where one is available.
5. Seeded mutation tests run in the normal test suite; crashers found by external fuzzers are added as regression tests.

## Operational guidance

- Run the container as the non-root user it is built with, read-only root file system, drop all capabilities, publish only the ports you enable (`docs/design.md` section 7).
- Use `Secrets:KeyProtection=Certificate` (a certificate that is not stored in the database) or `Kms` (a wrapping key from a mounted secret; see [operations.md](operations.md)). Keep the database backups and the key-protection certificate separate.
- Put the dashboard/API behind TLS (the built-in HTTPS listener serves the certificate from the database or from a file override).
- Review webhook allow-lists: internal addresses are denied unless explicitly allowed per tenant.

## Known gaps

- **No external audit.** Recommended before production-critical use ([plan.md](plan.md)).
- No coverage-guided fuzzing (SharpFuzz) runs in CI yet; fuzzing is seeded mutation inside the unit tests.
- Container hardening, Trivy/Grype scans, `testssl.sh` and Internet.nl checks, and the SMTP attack suites from the design (smtpsmug, EAST, slowloris tooling) have not been run against a deployed instance.
- ACME has not been verified against a real certificate authority.
- Rate limits and circuit-breaker state are per process.
