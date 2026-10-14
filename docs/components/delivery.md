# Delivery engine (`Mta.Delivery`) and ingest (`Mta.Host/Ingest`, `Mta.Host/Submission`)

## Outbound

`DeliveryEngine` leases due deliveries (`IDeliveryStore.ClaimAsync`), groups them by (message, recipient domain) and runs each group through `DeliveryProcessor` concurrently (`MaxConcurrentGroups`). A group is one SMTP transaction (at most `MaxRecipientsPerTransaction` recipients).

Per group, in order:

1. Expired deliveries are recorded as `Expired`; suppressed recipients as `Suppressed` (nothing is sent).
2. The raw message is read from the spool; a missing message is a permanent failure.
3. `SendingLimits.TryReserve`, then `DestinationThrottle.TryAcquire`. A refusal holds the deliveries (`Deferred` with `CountAttempt=false`: no attempt is counted, no event, no webhook).
4. DKIM: `IDkimSignerProvider` (config store: the domain or its nearest registered parent, newest active key; cached) supplies the signer. No key means the message goes out unsigned. The signature is made later, per server, over the bytes that are actually transmitted (step 6).
5. Envelope sender: a signed VERP bounce address when a bounce domain is configured (not for bounces themselves), else the original sender. A bounce domain written as a U-label is accepted and goes on the wire as its A-label.
6. Routes from `RoutePlanner`: direct MX, then opted-in relays. For direct delivery MX hosts are tried in order (circuit breaker per host); each host gets a TLS decision from `OutboundTlsPolicyResolver` (MTA-STS, DANE, per-domain level overrides from `TlsPolicyTable`). A blocked or failed TLS negotiation moves on to the next MX host; a connect failure moves on to the next address; once a server answers, the answer decides. What is sent is decided per connection, after the EHLO, by `OutboundTransaction.Plan` (see "8-bit and internationalized mail").
7. Per recipient the reply is classified (`ReplyClassifier`): 2xx at end of data delivers, permanent classes fail (only `PermanentRecipient` suppresses), the rest are deferred with `RetrySchedule` or expire when the next retry would pass the delivery's lifetime.
8. Results are recorded with `RecordAttemptAsync` (storage writes the event, statistics and webhook outbox rows in the same commit). For permanent failures and expiries of SMTP-submitted mail a bounce message (RFC 3464) is queued **before** recording, because recording the last recipient frees the stored message.

A connection lost after the end of data was sent is deferred with the `possible_duplicate` flag. A delivery whose lease ran out while its holder was still sending is claimed again by another replica (or the same engine), which sets the row's flag; when the first holder reports, the attempt planner also reads the row's flag, so the report carries `possible_duplicate` too (decision 80). `QuiesceAsync` stops claiming, waits up to the timeout, cancels what is left (recorded as `AbortedBySwitch`, requeued unchanged, flagged possible duplicate only when the end of the message data had begun to be written, see `SmtpClientConnection.EndOfDataStarted`) and releases the leases (decision R).

### Metrics and traces

`DeliveryMetrics` (`Mta.Delivery`): attempts by outcome, group duration, holds, claims and their duration, the duration of storing results, bounces generated, and the queue gauges. The gauges (`mta_delivery_queue_depth` by state, the age of the oldest due delivery, spooled bytes) read the last `QueueSample` of `QueueGauges`, a background loop that calls `GetQueueStatsAsync` every `Observability:QueueSampleSeconds`; a scrape never queries the queue. A failed sample keeps the previous numbers and is counted. The metric table is in [../operations.md](../operations.md#monitoring).

`DeliveryTracing` adds the delivery side of the message trace (`MessageTrace`, source `Mta.Message`): `mta.queue.wait` (emitted at the first claim, starting at the acceptance time) and one `mta.delivery.attempt` span per group with a `recipient.result` event per recipient. The trace id is the message id and the parent span id is derived from it, so no trace context is stored in the queue (DESIGN-DECIDED, decision 69). With no listener each entry point costs one check.

## 8-bit and internationalized mail

`OutboundTransaction` (internal to `Mta.Delivery`) holds one transaction's stored message, envelope and DKIM signer, and turns the answer of each server's EHLO into the bytes and MAIL FROM parameters actually used. Each variant is built at most once per transaction (a second MX host reuses it). Standards: RFC 6152 (8BITMIME), RFC 6531/6532/6533 (SMTPUTF8, UTF-8 headers, internationalized DSN), RFC 2045 section 6.4, RFC 3463 status codes.

| Message | Server | Result |
|---|---|---|
| 8-bit body | offers `8BITMIME` | `BODY=8BITMIME`, bytes unchanged (signed as they are) |
| 8-bit body | no `8BITMIME` | body converted to 7-bit by `EightBitDowngrader` (`Mta.Mime`), no `BODY` parameter, **then** signed; if no safe conversion exists: permanent `554 5.6.1` naming the reason |
| 7-bit body | any | no `BODY` parameter |
| valid UTF-8 in the header section (also when every address is ASCII), or the persisted flag `ClaimedDelivery.HeadersUtf8` | offers `SMTPUTF8` | `SMTPUTF8` declared |
| same | no `SMTPUTF8` | nothing is sent: permanent `554 5.6.9` (headers are not downgraded: RFC 6857 is experimental) |
| sender with a non-ASCII local part | no `SMTPUTF8` | permanent `553 5.6.7` for the whole transaction (after the other hosts of the domain were asked) (a bounce domain makes the sender an ASCII VERP address, which avoids it) |
| recipient with a non-ASCII local part | no `SMTPUTF8` | the others in the group are sent without `SMTPUTF8`; that recipient is offered to the other hosts and fails with `553 5.6.7` only if all refuse |

* "Needs SMTPUTF8" is decided by `EmailAddress.RequiresSmtpUtf8` (non-ASCII local part), not `IsInternational`: a domain is held as an A-label, so `user@bücher.example` is plain ASCII on the wire.
* The persisted flag (`AcceptedMessage.HeadersUtf8`, column `delivery_queue.headers_utf8`, schema version 5 / PostgreSQL `V005`) is decided at intake from the message bytes (`MessageInspector.HasValidUtf8Headers`), not from the submitter's MAIL FROM parameter; delivery also re-checks the stored bytes, so rows queued before the upgrade are handled. UTF-8 that is not valid (8-bit headers in a legacy charset) is not announced as SMTPUTF8 and is sent as is.
* 5.6.x replies are classified `PermanentContent`: the message bounces, the recipient is **not** suppressed. The bounce (DSN) carries the text.
* **A refusal is final only when every candidate host was asked and refused.** A server that lacks an extension does not end the delivery while another MX host of the domain has not been asked: the refusal is remembered and the next host is tried. If a host failed in another way (unreachable, TLS, banner), or was not asked at all in this attempt (circuit breaker open, `MaxMxHostsPerAttempt` reached, no address), the result is a temporary `4.4.1` and the delivery is retried until it expires.
* **Recipients are not failed on the first MX.** When a host takes the group except for recipients whose address it cannot take (no SMTPUTF8), those recipients are offered to the remaining hosts in a transaction of their own (`AttemptResult.Followup`); the others are recorded as delivered or failed by the first host. They fail with `5.6.7` only if every host that answers refuses. (One level only: a second partial refusal on a later host is final for those recipients.)
* **No rerouting through a relay.** A capability refusal is a permanent reply and `RoutePlanner` never reroutes a permanent reply: the relay chain is opt-in per domain for networks that block port 25 (decision 18), not a way around a destination's limits. A relay that supports the extension is reached when the relay is the only route, not as a fallback after a refusal.
* Conversion rules are in [mime.md](mime.md#8bitmime-downgrade); the DKIM-signed bytes are exactly the converted bytes (the conversion changes the body and the `Content-Transfer-Encoding` fields, which a signature made before it would not survive).
* Bounce messages for internationalized recipients use RFC 6533: `message/global-delivery-status` with `Final-Recipient: utf-8; ...` (see `DsnBuilder`), `message/global-headers` or `message/global` for the returned original when its headers hold UTF-8, and the DSN is queued with the SMTPUTF8 flag when its own header section holds UTF-8 (an internationalized sender). Such a report is itself 8-bit and goes through the same conversion for servers without `8BITMIME`.

## TLS-RPT sending address

`sending-mta-ip` in TLS-RPT failure details is `Delivery:PublicSendingIp` when configured; otherwise the local address of the TCP connection, but only when it is a public address (private, loopback and link-local addresses are left out of reports that go to other organizations). The local address comes from `SmtpClientConnection.LocalIpAddress`, also carried by `SmtpClientException.LocalIpAddress` for failures during setup). When a policy blocks an MX host before any connection exists, it is the address the operating system would use to reach it (a UDP "connect" probe that sends nothing). Successful sessions are only counted, as RFC 8460 asks.

## Inbound

`IngestHandler` is the `ISmtpServerHandler`. Submission listeners authenticate a tenant's SMTP credential (PBKDF2 hash, shared lockout through `AuthThrottle`, constant work for unknown users) and pass each message to `SubmissionService`, the one path into the queue for SMTP and the HTTP API: size and recipient limits, `SenderPolicy` (From header domain and envelope sender must belong to the tenant and be verified), `Bcc` removal, Message-ID and Date repair, content extraction for history when `History:Mode=Full`, durable intake. The bounce listener accepts only recipients that are valid signed bounce addresses (or postmaster/abuse), always answers 250 for them and hands the message to `BounceProcessor`: permanent DSN failures that the reply classifier attributes to the recipient suppress it, abuse complaints suppress as complaints, and both are published as webhooks. With `History:Mode=Full` the report is also **attached to the message it is about**: the VERP token (verified, so trusted) names the tenant, the `Message-ID` in the returned headers (stored in `message_index.message_id_header` when the message was accepted, normalized without angle brackets and in lower case) finds the tenant's message (the newest, if a client reused an id), and a `bounced` or `complained` event is appended to its history with the recipient, the enhanced status and the diagnostic; the message status follows (`delivered` becomes `bounced`, or `partial` with several recipients; a complaint makes a delivered message `complained`). The webhook payload then carries `message_id`. With `StatsOnly` nothing per message is stored (the lookup finds nothing), and the suppression and the webhook happen exactly as before. A report whose token names another tenant can only ever look among that tenant's messages. Nothing on the bounce listener can queue mail for delivery.

### Parse once

`SubmissionService` parses the submitted message a single time. The sender check (From domain), the header repair (is there a Message-ID, a Date, a Bcc) and the history extraction (`MessageContentExtractor.Extract(MimeMessage)`) all use that parse. Only headers are added or removed, so subject, bodies and attachments are those of the stored message. The Bcc rule is dropped only when the parsed header list is complete (not cut by `MaxHeaderCount` or `MaxHeaderBytes`) and has no Bcc; otherwise the editor removes it as before, so a Bcc behind the header limits cannot reach the stored copy. Allocation figures: [../benchmarks.md](../benchmarks.md#allocation-work-second-round-2026-10-13).

## Known gaps

- **Behaviour change.** A message with UTF-8 header fields used to be sent as is to every server; it now bounces with `5.6.9` (nothing is sent) when the server lacks SMTPUTF8, as RFC 6531 requires. Header downgrading (RFC 6857, experimental) is not implemented, so such mail cannot reach those servers. The `8BITMIME` conversion does not touch 8-bit header fields of nested parts or embedded messages either (it refuses, see mime.md).
- `BINARYMIME`/`CHUNKING` are not used for binary bodies: a `binary`-encoded part is base64-encoded when the server lacks `8BITMIME` and sent as 8-bit otherwise.
- The capability fallback to the next MX host is tested with two loopback servers (IPv4 and IPv6 loopback on the same port); those tests are reported as skipped, with the reason, on a machine without a usable IPv6 loopback address.
- Throttle state and circuit breakers are per process (see `components/policy.md`). The sending counters are persisted and shared through the config store (see `components/policy.md`); TLS-RPT counters and pending reports are persisted too (see `components/tls.md`).

See [../progress.md](../progress.md).
