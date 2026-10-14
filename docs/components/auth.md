# Mta.Auth: SPF, DMARC, Authentication-Results and aggregate reports

`src/Mta.Auth` is part of the hand-written, BCL-only stack ([decisions.md](../decisions.md) item 4): **no package references** (enforced by `tests/Mta.ArchitectureTests`). It does no network I/O itself; all DNS access goes through `Mta.Dns.IDnsResolver`, so every piece is testable with `StaticDnsResolver`. ARC is a separate, later component and is not part of this one (the Authentication-Results builder only carries an `arc=` clause as a string).

DNS data and message headers are hostile input. Every parser and evaluator in this component returns a result instead of throwing, bounds its work, and treats DNS timeouts and server failures as `TempError` (SPF, DMARC) as the RFCs require. Only caller cancellation propagates as `OperationCanceledException`.

## Namespaces and main types

| Namespace | Types |
|---|---|
| `Mta.Auth.Spf` | `ISpfEvaluator`, `SpfEvaluator`, `SpfOptions`, `SpfCheckRequest`, `SpfCheckResult`, `SpfSessionResult`, `SpfResult`, `SpfRecord`, `SpfMacroString`, `SpfMacroContext` |
| `Mta.Auth.Dmarc` | `IDmarcEvaluator`, `DmarcEvaluator`, `DmarcOptions`, `DmarcInput`, `SpfAuthResult`, `DkimAuthResult`, `DmarcEvaluation`, `DmarcRecord`, `DmarcReportUri`, `DmarcReportAuthorizer` |
| `Mta.Auth.Domains` | `PublicSuffixList` (embedded Public Suffix List, `GetOrganizationalDomain`) |
| `Mta.Auth.AuthenticationResults` | `AuthenticationResultsBuilder`, `AuthenticationResultsHeader`, `AuthenticationResultsParser`, `AuthenticationResultsPolicy` |
| `Mta.Auth.Reports` | `DmarcAggregateCollector`, `DmarcAggregateReport` (model), `DmarcAggregateReportWriter`, `DmarcAggregateReportReader` |

`DkimAuthResult(string Domain, bool Passed, string? Selector)` and `SpfAuthResult(SpfResult Result, string? Domain)` are deliberately small input types so DMARC does not depend on `Mta.Dkim` or `Mta.Mime` APIs.

## SPF (RFC 7208)

```csharp
var spf = new SpfEvaluator(resolver, new SpfOptions { ReceivingHostName = "mx.example.org" });

// One identity:
SpfCheckResult r = await spf.CheckHostAsync(new SpfCheckRequest(clientIp, "example.com", "user@example.com", helo));

// A whole SMTP transaction (HELO and MAIL FROM; null reverse-path uses postmaster@helo):
SpfSessionResult s = await spf.CheckSessionAsync(clientIp, helo, mailFrom);
SpfCheckResult forDmarc = s.Effective;   // MAIL FROM, or HELO when the reverse-path was null
```

`SpfCheckResult` carries `Result` (`None`, `Neutral`, `Pass`, `Fail`, `SoftFail`, `TempError`, `PermError`), the checked `Domain`, the `MatchedMechanism` text (for example `ip4:192.0.2.0/24`), the `Explanation` (for `Fail`), a `Reason` for None/TempError/PermError, and the DNS and void lookup counts used.

What is implemented:

- Record selection: exactly one `v=spf1` TXT record; several is `PermError`; none is `None`. CNAME chains come back from the resolver.
- Parser (strict ABNF): all mechanisms (`all`, `include`, `a`, `mx`, `ptr`, `ip4`, `ip6`, `exists`), qualifiers, `redirect=`, `exp=`, unknown modifiers (ignored, but their macro syntax is validated). Any syntax error anywhere in a record is a `PermError` before evaluation, as RFC 7208 section 4.6 requires. CIDR lengths reject leading zeros and out-of-range values; dual-CIDR (`a:host/24//64`) works for `a` and `mx`.
- Macros: letters `s l o d i p v h c r t`, digit counts, `r` reversal, all delimiters, `%%`, `%_`, `%-`, upper-case URL escaping, IPv6 nibble form for `%{i}`. `%{p}` uses the same validated-name procedure as `ptr`, computed lazily and once per check. `c`, `r` and `t` are only legal in explanations.
- `include` result mapping (Pass matches; Fail/SoftFail/Neutral do not; TempError and PermError propagate; None becomes PermError), `redirect` (ignored when `all` is present; target without a record is PermError), `exp=` explanation fetch and RFC default explanation (configurable, can be disabled).
- IPv4-mapped IPv6 clients (`::ffff:a.b.c.d`) are evaluated as IPv4.
- Domain validation: a check starts with `None` for a malformed domain, IP literal or all-numeric top label. Expanded domain-specs are truncated from the left to 253 characters; labels over 63 characters or illegal characters never match (include/redirect: `PermError`).

### Limits (all enforced, all configurable in `SpfOptions`)

| Limit | Default | On exceeding |
|---|---|---|
| DNS-querying terms (include, a, mx, ptr, exists, redirect), shared across include and redirect | 10 | `PermError` |
| Void lookups (NXDOMAIN or empty answer) | 2 | `PermError` |
| MX records examined by one `mx` mechanism | 10 | `PermError` |
| PTR names examined by `ptr` and `%{p}` | 10 | the rest are ignored |
| SPF record length | 4096 characters | `PermError` |
| One macro expansion (before the 253 truncation) | 4096 characters | `PermError` |
| Explanation text | 512 characters | explanation dropped (default text used) |
| Include/redirect nesting | 10 | `PermError` |
| Whole check | 20 s | `TempError` |

Notes on judgement calls: `exp=` lookups and the `ptr` forward lookups are not counted as terms or void lookups; an `mx` target that is the null MX (`.`) is skipped; DNS failures while validating `ptr` names skip that name rather than failing the check (RFC 7208 section 5.5); every other DNS failure is `TempError`.

## DMARC (RFC 7489)

```csharp
var dmarc = new DmarcEvaluator(resolver, new DmarcOptions { Random = Random.Shared });
DmarcEvaluation e = await dmarc.EvaluateAsync(new DmarcInput(
    fromDomain,
    new SpfAuthResult(spf.Result, spf.Domain),
    [new DkimAuthResult("example.com", passed: true, selector: "s1")]));
// e.Result: Pass | Fail | None | TempError | PermError; e.Disposition: None | Quarantine | Reject
```

- Policy discovery: TXT at `_dmarc.<from>`, then `_dmarc.<organizational domain>` when the first name has no DMARC candidate record. Several candidate records, or a record that fails validation, mean no policy and end discovery (no fallback). A DNS error is `TempError`.
- Parser: tolerant of whitespace, case and unknown tags; first occurrence of a duplicate tag wins; invalid optional tags (`adkim`, `aspf`, `pct`, `fo`, `ri`, `rf`) fall back to their defaults; a missing or invalid `p` (or invalid `sp`) rejects the record unless a valid `rua` exists, in which case it is accepted as `p=none` (`IsMonitoringFallback`). `p` does not have to be the second tag. Report addresses: `mailto:` with `!size` limits (`k m g t`), other URI schemes kept but not deliverable, lists bounded to 32 entries.
- Alignment: strict (exact) and relaxed (same organizational domain) for SPF (pass only, domain = MAIL FROM, or HELO for a null reverse-path) and DKIM (any passing signature).
- Policy selection: `sp` applies only when the record came from the organizational-domain fallback and the From domain is a subdomain; otherwise `p`. `pct` sampling takes `DmarcOptions.Random`: a failing message outside the sample gets the next weaker policy (reject becomes quarantine, quarantine becomes none) and `SampledOut` is set.
- `DmarcReportAuthorizer` implements the external destination check (`<policy-domain>._report._dmarc.<destination-domain>`, honouring a `rua=` restriction in the authorization record); same-organization destinations need no DNS.
- `DmarcEvaluator.Evaluate(input, lookup)` evaluates without DNS so callers can cache `LookupPolicyAsync` results.

## Public suffix list and NOTICE

`src/Mta.Auth/Domains/public_suffix_list.dat` is the Mozilla Public Suffix List, **embedded unmodified** (header, ICANN section and private section as published) and loaded lazily by `PublicSuffixList.Default`. The ICANN and private sections are both used, so `alice.github.io` is its own organization. Algorithm: exception rules prevail, then the longest matching normal or wildcard rule, then the implicit `*` rule; names are compared in A-label form.

NOTICE:

> This product embeds the Public Suffix List (https://publicsuffix.org/list/public_suffix_list.dat), which is made available under the Mozilla Public License, v. 2.0. A copy of the MPL is at https://mozilla.org/MPL/2.0/. The embedded file is unmodified and keeps its original header.
>
> List version: `2026-10-07_07-28-19_UTC`, commit `3929462652695bad04f0a27afb600974014a3c8b`, downloaded 2026-10-12.

To update, download the file again, replace the `.dat` unmodified, update the version above, and run the tests (`PublicSuffixListTests` check the header, both sections and known cases). `PublicSuffixList.Version` returns the stamp from the file.

## Authentication-Results (RFC 8601)

`AuthenticationResultsBuilder` writes `authserv-id; method=result (comment) ptype.property=value; ...`:

```csharp
var ar = new AuthenticationResultsBuilder("mx.example.org")
    .AddSpf(spfResult, SpfIdentityKind.MailFrom, "bounce@example.com")
    .AddDkim("dkim=pass header.d=example.com header.s=s1")   // preformatted fragment from the DKIM verifier
    .AddDmarc(dmarcEvaluation)                                // dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com
    .AddArc("arc=none");                                      // placeholder until ARC exists
string header = ar.BuildHeader();                             // folded at 78 columns, CRLF terminated
```

Values are emitted as a token, a `[local@]domain` pvalue, or a quoted string with `\` escaping. Control characters (CR, LF, tab) are replaced by spaces so a hostile `header.d` can never inject a header line; non-ASCII becomes `?` unless `allowUtf8` is set. Fragments are parsed and re-emitted (`TryAddFragment` for fragments built from message content).

`AuthenticationResultsHeader.TryParse` is a bounded, tolerant parser (nested comments, quoted strings, folding, `none`, method versions). `AuthenticationResultsPolicy.ShouldRemoveOnIngress` implements RFC 8601 section 5: remove incoming headers whose authserv-id is one of the MTA's own, or that cannot be parsed; `SelectTrusted` keeps only configured authserv-ids for downstream consumers.

## DMARC aggregate reports (RFC 7489 appendix C)

- `DmarcAggregateCollector` is thread safe. It counts evaluations keyed by policy domain, UTC day, source IP, disposition, alignment results, override reasons, identifiers and authentication results. Memory is bounded (`MaxRecordsPerReport` = 10 000 rows per report, `MaxPendingReports` = 100 000 policy-domain/day buckets); dropped messages are counted and noted in the report's `<error>` element. Messages whose policy has no `mailto:` report address are skipped by default. `DrainCompleted()` returns finished days as `DmarcPendingReport` (report plus the `rua` destinations).
- `DmarcAggregateReportWriter` writes schema-ordered XML with `XmlWriter` (illegal XML characters in hostile values become `?`), gzips it, names it `receiver!policy-domain!begin!end!unique.xml.gz`, and `CreateFiles(report, maxMessageBytes)` splits a report to fit a `rua` size limit (budget: three quarters of the limit minus 4 KiB, because the attachment is base64 encoded). The caller still has to check external destinations with `DmarcReportAuthorizer`, pick the size limit (`DmarcReportUri.MaxSizeBytes`) and send the mail.
- `DmarcAggregateReportReader` reads received reports (XML or gzip) with DTDs refused, a 64 MiB decompression cap and a nesting depth cap of 32 (`MaxElementDepth`; `XmlReader` time grows with the square of the depth, found by the fuzzer).

## Tests and benchmarks

`tests/Mta.Auth.Tests` has data-driven SPF cases in the style of the openspf.org suite (`Spf/SpfCases.cs`), RFC 7208 macro examples, DMARC alignment matrices, aggregate XML validated against the RFC 7489 appendix C schema, builder/parser round trips, and seeded fuzz tests for every parser. `bench/Mta.Benchmarks/Auth` holds `[MemoryDiagnoser]` benchmarks for SPF checks and DMARC evaluation against `StaticDnsResolver`.

## Known gaps

- ARC: see the ARC section below for its own gaps (RSA only, no Ed25519).
- No ZIP support in the aggregate report reader (gzip and plain XML only); no forensic (`ruf`) report generation.
- The collector is in memory; persistence across restarts and scheduling/sending of reports is the caller's job.
- SPF results are not cached here; the resolver is expected to cache.
- The SPF `ptr` mechanism is implemented but discouraged; its forward lookups do not count as void lookups.

## ARC (RFC 8617)

Namespace `Mta.Auth.Arc`, BCL only. Canonicalization and the tag-value parser are local to `Mta.Auth` (the `Mta.Dkim` helpers are internal); only the public `DkimKeyRecord`, `DkimKeyTools` and `DkimCanonicalization` are reused. Nothing changed in `Mta.Dkim`.

### API

```csharp
// Inbound: validate the chain of the message as received.
var validator = new ArcValidator(dnsResolver);                     // ArcValidatorOptions: limits, ComputeOldestPass
ArcChainResult chain = await validator.ValidateAsync(rawMessage);  // Status None|Pass|Fail, Failure, FailedInstance, OldestPassingInstance, SealDomains

// Authentication-Results of this hop, including the arc= result.
var ar = new AuthenticationResultsBuilder("mx.example.org")
    .AddSpf(...).AddDkim(...).AddArc(ArcAuthenticationResults.Format(chain, remoteIp));

// Outbound/forward: add the next ARC set.
using var sealer = new ArcSealer(new ArcSealerOptions { Domain = "example.org", Selector = "arc1" }, rsaPrivateKey);
ArcSealResult sealed = sealer.Seal(rawMessage, ar, chain);         // or Seal(bytes, string authenticationResults, chain)
// sealed.HeaderBytes: ARC-Seal, ARC-Message-Signature, ARC-Authentication-Results, CRLF terminated: prepend to the message.
```

`ArcSealHeader`, `ArcMessageSignatureHeader` and `ArcAuthenticationResultsHeader` expose `TryParse` (never throws). `ArcAuthenticationResults.Format` gives `arc=pass header.oldest-pass=N smtp.remote-ip=...` or `arc=fail reason="..."`.

### What is verified

1. Structure: every instance 1..N has exactly one ARC-Seal, ARC-Message-Signature and ARC-Authentication-Results; no duplicates, no gaps; instance numbers are plain decimal 1..50 (no sign or leading zeros).
2. `cv`: instance 1 must be `none`, later instances `pass`; any `cv=fail` makes the chain fail (`ChainFailedUpstream`).
3. ARC-Message-Signature of the newest set over the message (header selection bottom-up as in DKIM, body hash, the signature header itself without `b=`; simple or relaxed per `c=`).
4. ARC-Seal of every set, newest first: relaxed canonicalization of AAR, AMS, AS of sets 1..i in order, with the seal being checked having an empty `b=` and no trailing CRLF.
5. Optionally (`ComputeOldestPass`, default on) the lowest instance whose AMS still verifies, reported as `header.oldest-pass`.
6. Keys: TXT at `selector._domainkey.domain`, via the shared DKIM key record parser; revoked keys, non-RSA keys, keys outside 1024..4096 bits fail. Distinct lookups per message are capped (`MaxKeyLookups`, default 25).

Parsing is strict: duplicate tags, empty tags, and non-ASCII are errors; `h=` in a seal, `l=` in an AMS, and ARC-Seal/ARC-Message-Signature in an AMS `h=` are rejected; unknown tags are ignored. Folding and whitespace around tags are tolerated. Limits: 50 sets, 16 KiB per ARC header, 1024 header fields.

### Sealer behaviour

- First hop: `i=1`, `cv=none`. Passing chain: `i=N+1`, `cv=pass`. The chain result must match the ARC headers actually in the message, otherwise `ArgumentException`.
- Failed chain: a set with `cv=fail` whose seal covers only the new set; if the newest seal already says `cv=fail`, or the instance numbers cannot be read, or 50 sets exist, nothing is sealed and `NotSealedReason` says why. A transient DNS failure also counts as `Fail`: callers may prefer to defer the message instead of sealing `cv=fail` (`ArcChainResult.IsTransient`).
- AMS: `rsa-sha256`, relaxed/relaxed, headers from `ArcSealerOptions.SignedHeaders` (default: the DKIM set plus DKIM-Signature), only instances that exist unless `OversignHeaders` is on (default off, because later hops are expected to alter the message). Seal the message exactly as it will leave this hop.

### Verification status

Verified differentially against MimeKit 4.18.1 in both directions (`ArcMimeKitInteropTests`): MimeKit-sealed 1 and 5 hop chains validate with `ArcValidator`, our 1, 2 and 5 hop chains validate with MimeKit's `ArcVerifier`, a mixed MimeKit/our/MimeKit chain validates in both, and the same tamperings fail in both. Also covered: parser tables, tamper tests (body, headers, earlier AAR/AMS, removed/duplicated/reordered/renumbered sets, cv changes, wrong/revoked/missing/malformed keys, DNS failure, 51 instances, limits), seeded mutation fuzzing, and a sealing allocation check.

### Known gaps

- **Not verified against an independent implementation:** the signature scope of a `cv=fail` seal (only the new set) follows our reading of RFC 8617 section 5.1.1; MimeKit cannot validate such a chain, so only the "chain fails" side is cross-checked. The `header.oldest-pass` meaning (lowest instance whose AMS verifies) is our reading of RFC 8617 section 5.2; `arc.chain`/other AR properties are not emitted.
- `rsa-sha256` only: Ed25519 and rsa-sha1 chains fail with `UnsupportedAlgorithm` (a legitimate Ed25519 chain is reported as `fail`, not as unverifiable).
- `x=` expiry on AMS and `t=` are not enforced.
- Canonicalization is a copy of the DKIM one (the `Mta.Dkim` helpers are internal), so a canonicalization fix must be applied in both places; the MimeKit tests cover this code for ARC.
- ARC trust (which sealers to believe) is policy outside this component; a `pass` only means the chain is cryptographically intact.
