# Implementation progress

Running status of the implementation, updated in every pull request. **Production readiness is not claimed until every feature in [plan.md](plan.md) is implemented and its quality gate passes.** This file says exactly what is done, what is verified and how, and what is not.

## Milestones

| # | Milestone | Status | PR |
|---|---|---|---|
| M0 | Foundations: solution, shared contracts, package-free guard, CI | done (merged) | #1, #2 |
| M1a | SMTP protocol library and server (STARTTLS, implicit TLS, AUTH, BDAT, pipelining, smuggling defenses) | in review | feat/smtp-protocol |
| M1c | Outbound SMTP client (STARTTLS policy, AUTH, pipelining, DATA/BDAT, pool) | in review | feat/smtp-client |
| M1d | Webhooks library (Standard Webhooks signing, SSRF guard, dispatcher, event factory) | in review | feat/webhooks |
| M1e | Load generator and sink (`mta-tools`) | in review | feat/tools |
| M1b | Mime, DNS, DKIM, SPF/DMARC, MTA-STS/DANE/TLS-RPT libraries | in progress (parallel work) | feat/mime, feat/dns, feat/dkim, feat/auth-spf-dmarc, feat/tls-policy |

## Verified so far

- Smtp.Protocol: 90 tests (command parser incl. fuzz, DATA scanner incl. smuggling vectors and chunk-independence, reply parser, dot-stuffer round trips, SASL, session state).
- Smtp.Server: 32 loopback tests (full transactions, pipelining, BDAT, smuggling attempts refused, STARTTLS and its injection guard, implicit TLS, AUTH PLAIN/LOGIN, limits, timeouts, quiesce, concurrency, garbage-input fuzz) and MailKit interop over STARTTLS and implicit TLS including a 3 MiB attachment.
- `dotnet build EggMail.slnx` and `dotnet test EggMail.slnx` pass locally (Core address/id tests, architecture guard tests).
- The package-free guard checks `.csproj` files and `obj/project.assets.json` of the guarded assemblies.

- Smtp.Client: 21 loopback tests against the real server and scripted peers (STARTTLS stripping and injection, drop after end-of-data, timeouts, pool reuse, relay AUTH over implicit TLS, local size/UTF8/bare-LF failures).

## Not verified / known gaps

- **GitHub Actions is disabled for the repository by the organization**, so the CI workflow and the release workflow cannot run. Pull requests are merged after a full local `dotnet test` and two self-review passes; the workflows are written but unproven on GitHub. Owner action: allow Actions for `eggspot/EggMail` ([open-questions.md](open-questions.md)).
- Everything beyond the skeleton is not implemented yet. See the milestone table.
- Docker image build and GHCR publish can only run in GitHub Actions (no Docker is used locally).
- No real-internet MX delivery has been tested; no independent security audit has been done.
