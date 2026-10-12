# Delivery policy (`Mta.Policy`)

Pure, deterministic policy logic the scheduler and the SMTP/API intake consult. No I/O, no packages (it references only `Mta.Core` and `Mta.Storage` contracts). Time comes from `IClock`, jitter from `IRandomSource`; everything stateful is thread-safe with per-key locks or lock-free counters. The scheduler itself (claiming deliveries, running attempts, persisting results) is a separate component.

**Every default below is a proposal by the design author, not a standard.** Each is a property on an options class so operators can change it. Where a figure comes from the design documents it is cross-referenced; where it comes from practice elsewhere (for example the 72 h grace) it is labelled as such. Nothing here has been tuned against real traffic.

| Area | Type | Design reference |
|---|---|---|
| Retry schedule | `RetrySchedule`, `RetryAfterHint` | decisions 18, 24 |
| Reply classification | `ReplyClassifier`, `DeliveryClass` | decision R (possible duplicate is handled by the delivery layer, not here) |
| Per-destination throttling | `DestinationThrottle` | design 3, 7.2 |
| Circuit breakers | `RouteHealth` | design 7.2 |
| Relay fallback | `RoutePlanner` | decision 18, design 7.2 |
| Sending limits and warm-up | `SendingLimits`, `WarmupSchedule`, `ISendingCounterStore` | design 2.4 (rate limits and warm-up are identical on both backends) |
| Sender and tenancy | `SenderPolicy` | design 8 |
| Domain verification cadence | `VerificationSchedule` | design 8 |

## How the scheduler is expected to use it

1. **Before an attempt:** `SendingLimits.TryReserve(tenant, sendingDomain)`. `Deferred(until)` means hold the delivery until then (do not drop); `Rejected` is a configuration problem (limit of zero). `DestinationThrottle.TryAcquire(key)` returns a lease or a `RetryAfter`. `RoutePlanner.Plan(domain, previousRoute, previousResult)` returns the ordered routes; `TryBegin(step)` right before connecting claims the half-open probe.
2. **During the attempt:** `lease.TryTakeMessage` for further messages on the same connection; record `step.Name` as `DeliveryAttempt.Route`.
3. **After a reply:** `ReplyClassifier.Classify(reply, stage)` gives the `DeliveryClass`. `DeliveryClass.ShouldSuppressRecipient()` is true only for `PermanentRecipient` (set `DeliveryAttempt.Suppress`). `DestinationThrottle.SignalFor` maps the class to a `ThrottleSignal` for `lease.Report`. `RoutePlanner.Decide` says whether to try the next route, defer, or fail. `RoutePlanner.ReportAttempt` / `ReportMxHost` feed the breakers.
4. **Deferral:** `RetrySchedule.NextAttemptAt(attemptsMade, now, expiresAt, reply, stage)` returns the retry time or "expire now". `attemptsMade` is `ClaimedDelivery.Attempt + 1`.

## Retry schedule (`RetrySchedule`)

| Setting | Proposed default |
|---|---|
| Delay ladder | 2 m, 5 m, 15 m, 30 m, 1 h, 2 h, 4 h, then every 4 h until `ExpiresAt` |
| Jitter | plus or minus 10 % of every delay |
| Connection problem (no reply, 421, 4.4.x), first retry only | 1 m instead of 2 m |
| Greylisting (class `TransientGreylist`) | delay clamped to 5 to 15 min |
| Throttling (class `TransientThrottle`) | 2 x the scheduled delay, at least 10 min, at most 8 h |
| Server hint ("try again in 20 minutes", "Retry-After: 120") | raises the delay to the hint, bounded to 30 s to 4 h; never shortens the schedule; applied after jitter |
| Final attempt | if the next retry would pass `ExpiresAt`, one last attempt 1 min before it provided at least 2 min remain; otherwise expire now |

The result is never at or after `ExpiresAt`; at or after expiry the answer is "expire now". `GetBaseDelay` exposes the jitter-free ladder (non-decreasing; tested). `MaxDelay` caps computed delays; a server hint can exceed it only up to `MaxHint`.

## Reply classification (`ReplyClassifier`)

Input: `RemoteReply(code, enhancedCode, text)` and an `SmtpStage` (`Connect`, `Handshake`, `MailFrom`, `RcptTo`, `Data`, `EndOfData`). Output: `DeliveryClass` plus a constant reason string naming the rule that matched. The classifier is stateless and allocation-free (roughly 0.4 ns to 270 ns per reply in a short local run of `bench/Mta.Benchmarks/Policy`, not a published result; run it with `dotnet run -c Release --project bench/Mta.Benchmarks -- --filter "*Policy*"`).

Evidence order: the first digit of the reply code decides temporary versus permanent (an enhanced code of a contradicting class is ignored); then specific RFC 3463 codes; then keyword heuristics on the text for generic codes, 5.7.x and replies without an enhanced code; then generic enhanced subjects; then the reply code and the stage. The rules are an ordered, table-driven list in `ReplyClassifier.cs`; the first match wins.

| Class | Meaning | Typical triggers | Suppress recipient |
|---|---|---|---|
| `Delivered` | 2xx (and 354 at DATA) | | no |
| `Transient` | retry normally | other 4xx, 4.1 to 4.6, 421, 4.4.x | no |
| `TransientThrottle` | retry slower, reduce concurrency | 4.7.x, 4.4.5, "rate limit", "too many connections", "temporarily deferred", Gmail 4.2.1 "receiving mail at a rate" | no |
| `TransientGreylist` | retry in 5 to 15 min | "greylisted" (any 4xx) | no |
| `PermanentRecipient` | hard bounce, recipient is bad | 5.1.1/2/3/4/6/10, 5.2.1, 5.2.4, 5.4.1 at RCPT, "user unknown", "no such user", 556/521, 550/551/553 at RCPT with no other signal | **yes** |
| `PermanentSender` | hard bounce, sender or its authentication | 5.1.7/8, 5.7.20 to 24, 5.7.26/27, 5.7.509, "SPF/DKIM/DMARC", "sender verify failed", any 5xx at MAIL FROM with no other signal | no |
| `PermanentPolicy` | hard bounce, we or our IP are refused | 5.7.x default, blocklist words (Spamhaus, "blocked", "reputation"), "relay denied", 5.7.25, 5.7.30, 5.4.5 sending quota | no |
| `PermanentContent` | hard bounce, content rejected | 5.6.x, "spam", "unsolicited", "virus", "suspicious", prohibited attachment, any 5xx at DATA/end of data with no other signal | no |
| `SoftBounceMailboxFull` | full mailbox, soft bounce count | 4.2.2/5.2.2, "over quota", "mailbox full", 552 at RCPT | no (retry or bounce per `ShouldRetry(retryMailboxFull)`) |
| `PermanentConfigurationProblem` | our or the route's configuration | 5.3.x (message too large 5.3.4), 5.5.x, 5.2.3, authentication failures (5.7.8, 535), 5xx during EHLO/AUTH | no |

Only `PermanentRecipient` suppresses, because a wrong suppression silently stops mail to a valid address while a missed one only costs one more bounce later. The keyword lists are tuned for the English texts of Gmail, Microsoft, Yahoo, Postfix and Exim as the design author remembers them, so the 109 test samples (`ReplyClassifierTests`) are **representative, not verbatim captures**. Providers change wording; unrecognized texts fall back to the stage rules.

## Per-destination throttling (`DestinationThrottle`)

Keyed by `ThrottleKey(destination, route?)` (domain or MX host, optionally narrowed to a relay or sending IP; case-insensitive). Per key: a cap on concurrent connections, a cap on messages per connection, and a token bucket (messages per minute).

| Setting | Proposed default |
|---|---|
| Ceilings (`Defaults`) | 20 connections, 600 messages/min, 100 messages per connection; per-destination `Overrides` supported |
| Starting point | 5 connections, 120 messages/min (capped by the ceiling) |
| Burst allowance | 10 s of the current rate |
| Decrease (AIMD) | multiply by 0.5 on a `Throttled` signal (throttle class or 421), or on 3 `ConnectionFailure` signals within 30 s; floors 1 connection and 6 messages/min |
| Increase | after 20 consecutive successes: +1 connection and +10 % of the rate ceiling, up to the ceilings |
| Cooldown | 60 s after a decrease with no further decrease or increase (a burst halves once) |
| Eviction | keys idle for 15 min are forgotten (learned limits reset); a soft cap of 100,000 keys evicts every idle key |

`TryAcquire` takes a connection slot and the first message's token and returns a `ThrottleLease` (or `RetryAfter` with the reason `ConcurrencyLimit` or `RateLimit`). The lease is a class, so copies cannot double-release or lose the per-connection message count; dispose is idempotent. A lease is about 40 bytes of allocation per acquire. Each key has its own short lock; parallel tests confirm the concurrency limit and the token bucket are never exceeded.

## Circuit breakers (`RouteHealth`)

Per route (`direct`, relay names) and per MX host. Closed, then Open after 5 consecutive connect failures or timeouts (failures older than 10 min do not accumulate), then for a 5 minute cooldown (doubling after each failed probe, up to 1 h) all traffic is refused; afterwards exactly one probe is admitted (half-open); a success closes it. A probe that never reports back frees its slot after 2 minutes. `GetSnapshots()` feeds the dashboard. Healthy idle entries are evicted after 1 h. `IsAvailable` is a non-claiming check used when planning; `TryAdmit` claims the probe.

## Relay fallback chain (`RoutePlanner`)

Rules from design 7.2, implemented as `Plan` (ordering) and `Decide` (what to do after an attempt):

- Default plan: direct MX (`direct`) only. A relay joins a plan only if the recipient domain is listed in its `RelayRouteRecord.Domains` (exact name, `*.suffix`, or `*`); disabled routes and routes without domains are never used. Relays follow direct, ordered by `Priority` ascending (lower number first), then by name.
- Connect timeout or refusal: `TryNextRoute`; after the last route, `DeferAllRoutesFailed`.
- 4xx, TLS policy failure, dropped connection: `DeferRetrySameRoute`; the next `Plan(domain, previousRoute, previousResult)` puts that route first (unless its circuit is open).
- 5xx: `FailPermanently`. A permanent rejection is never retried on another route (a relay changes the sending IP, SPF, bounce path and alignment).
- Open circuits are left out of the plan and listed in `RoutePlan.Skipped`; if nothing is usable `RoutePlan.RetryNotBefore` is the earliest cooldown end.
- `RoutePlan.Steps[i].Name` is the string to store as `DeliveryAttempt.Route`.
- `DirectMxAvailable` lets an operator declare port 25 unusable (relay-only plans for opted-in domains).

Report a connect failure on the `direct` route only after every MX host failed to connect; use `ReportMxHost` for individual hosts.

## Sending limits and warm-up (`SendingLimits`)

Global, per-tenant and per-sending-domain caps per UTC hour and per UTC day, all unlimited until configured. Each check atomically reserves in all affected counters (global, tenant, domain; hour and day) or none, so concurrent senders never exceed a cap. Results: `Allowed`, `Deferred(until the next hour or UTC midnight)`, `Rejected(reason)` (a zero limit, or a batch larger than a hard cap). Counters sit behind `ISendingCounterStore`; `InMemorySendingCounterStore` is lock-free and prunes windows older than the previous hour or day. Under contention it can refuse a request that would have fitted (a concurrent reservation briefly inflates the counter); it never allows more than the limit. `Release` returns a reservation (pass `SendingDecision.At`).

Proposed warm-up ramp (`WarmupSchedule.Default`, per sending domain, UTC days since it started): 50, 100, 200, 400, 800, 1,500, 3,000, 5,000, 10,000, 20,000, 40,000 messages per day, then no warm-up cap. It is a design-author proposal. Warm-up is combined with the domain's explicit limits by taking the stricter. Warm-up state (start day, schedule) lives in memory in this component; persisting it is the caller's job (see known gaps).

## Sender and tenancy policy (`SenderPolicy`)

`Evaluate(tenant, envelopeFrom, headerFromDomain, tenantDomains)`:

| Condition | Result |
|---|---|
| Tenant disabled | reject `tenant_disabled` |
| Null reverse-path | reject `null_sender_not_allowed` (option to allow) |
| Domain not registered to the tenant | reject `sender_domain_not_registered` |
| `Pending` or `Verifying` | reject `sender_domain_not_verified` |
| `Failed` | reject `sender_domain_verification_failed` |
| `SendingPaused` | reject `sending_paused` |
| `Verified` | allow |
| `TemporaryFailure` | allow, `ShowTemporaryFailureBanner = true` |

Every refusal carries SMTP 550 with enhanced code 5.7.1, human text, and a stable API error code. Both the header From domain and (by default) the envelope sender domain must pass. Subdomains of a tenant's registered domain are allowed and attributed to the parent; an explicit record for the subdomain overrides the parent (so an unverified subdomain stays blocked); lookalike suffixes (`notexample.com`) never match. `CheckRecipientCount` returns a temporary `452 4.5.3` (clients split the message; proposed limit 100). `SelectReturnPath` picks the tenant's verified return-path host or the shared bounce domain, and `BuildVerpInputs` collects the inputs for the VERP address (ids, host, recipient); encoding and signing live elsewhere.

## Domain verification (`VerificationSchedule`)

A pure function implementing design 8: `Evaluate(state, checkResult, now)` and `Apply(domainRecord, result, now, error)`.

| Setting | Proposed default |
|---|---|
| Unverified cadence | every 90 s for the first 15 min after creation (design: 1 to 2 min), every 15 min for the next 24 h, then hourly |
| Verified | daily; after a first failed check, re-check in 15 min |
| `Verified` to `TemporaryFailure` | 2 consecutive failed checks |
| `TemporaryFailure` | hourly; back to `Verified` on success; to `Failed` and `SendingPaused = true` once the 72 h grace (counted from entering temporary failure) has passed at a failed check |
| `Failed` | daily; recovers to `Verified` (and lifts the pause it set) when the records return |
| DNS temporary failure | never changes the status or counters; re-check in 5 min |
| "Verify now" | at least 30 s after the last check (`CanVerifyNow`) |

A manual pause on a healthy domain is not lifted by a successful check; only the pause set on entering `Failed` is.

## Extension points

- `IRandomSource`: deterministic jitter (`SeededRandomSource` provided).
- `ISendingCounterStore`: persistent or shared counters. The contract is atomic all-or-nothing `TryReserve`, `Release`, `GetCount`, `Prune`.
- Options classes on every component; per-destination overrides on the throttle; `RoutePlanner.UpdateRoutes` for hot reload of relay definitions.
- `ReplyClassifier` rules are a private ordered table; adding operator-defined rules (for example per provider) is a possible later extension.
- `design.md` lists an `IRoutingPolicy` interface; this component deliberately exposes concrete types and leaves the composing interface to the scheduler.

## Known gaps

- Warm-up start dates, per-tenant and per-domain overrides and counters are in memory; persistence (settings store and a persistent `ISendingCounterStore`) is not implemented. A restart resets counters, which can allow a short overshoot of a daily cap.
- State is per process: with several replicas on the PostgreSQL backend each replica throttles and counts on its own.
- Nothing has been measured against real mail servers; rules and defaults are proposals.
- Classification of non-English or unusual texts falls back to stage rules.
