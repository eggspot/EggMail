# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not in a public issue or pull request.

Use GitHub's private vulnerability reporting for this repository: <https://github.com/eggspot/EggMail/security/advisories/new>.

Include what you found, how to reproduce it (a failing test or a short script is ideal), the affected version or commit, and what you think the impact is. Do not include real customer data.

What to expect (targets of this project, not a contract): an acknowledgement within 3 working days, an assessment within 10 working days, and a fix or mitigation plan communicated to you. We credit reporters who want credit. Severity is rated with CVSS 4.0; the fix targets are critical 7 days, high 30 days, medium 90 days, counted from confirmation.

## Scope

In scope: the EggMail server and its container image (SMTP server and client, MIME/DKIM/SPF/DMARC/ARC/DNS/TLS-policy code, the HTTP API and dashboard, storage and the backend switch, secrets handling, the release pipeline). Out of scope: findings that need an already-compromised host, denial of service by volume alone on an unprotected deployment, and issues in third-party services you point EggMail at.

Particularly interesting classes: SMTP smuggling or command injection, STARTTLS downgrade or injection, header injection through the API, authentication or tenant-isolation bypass, SSRF through webhooks / MTA-STS / TLS-RPT, unsafe handling of hostile MIME or DNS input (crashes, unbounded memory or CPU), and secrets exposure.

## Supported versions

Until a 1.0.0 release exists, only the latest release (and `main`) receives fixes.

## For operators

The threat model, the controls that are implemented and tested, and the known gaps are in [docs/security.md](docs/security.md). An independent security audit has **not** been done yet and is recommended before production-critical use.
