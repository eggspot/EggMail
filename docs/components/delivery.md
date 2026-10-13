# Delivery engine (`Mta.Delivery`) and ingest (`Mta.Host/Ingest`, `Mta.Host/Submission`)

## Outbound

`DeliveryEngine` leases due deliveries (`IDeliveryStore.ClaimAsync`), groups them by (message, recipient domain) and runs each group through `DeliveryProcessor` concurrently (`MaxConcurrentGroups`). A group is one SMTP transaction (at most `MaxRecipientsPerTransaction` recipients).

Per group, in order:

1. Expired deliveries are recorded as `Expired`; suppressed recipients as `Suppressed` (nothing is sent).
2. The raw message is read from the spool; a missing message is a permanent failure.
3. `SendingLimits.TryReserve`, then `DestinationThrottle.TryAcquire`. A refusal holds the deliveries (`Deferred` with `CountAttempt=false`: no attempt is counted, no event, no webhook).
4. DKIM: `IDkimSignerProvider` (config store: the domain or its nearest registered parent, newest active key; cached) signs the message at delivery. No key means the message goes out unsigned.
5. Envelope sender: a signed VERP bounce address when a bounce domain is configured (not for bounces themselves), else the original sender.
6. Routes from `RoutePlanner`: direct MX, then opted-in relays. For direct delivery MX hosts are tried in order (circuit breaker per host); each host gets a TLS decision from `OutboundTlsPolicyResolver` (MTA-STS, DANE, per-domain level overrides from `TlsPolicyTable`). A blocked or failed TLS negotiation moves on to the next MX host; a connect failure moves on to the next address; once a server answers, the answer decides.
7. Per recipient the reply is classified (`ReplyClassifier`): 2xx at end of data delivers, permanent classes fail (only `PermanentRecipient` suppresses), the rest are deferred with `RetrySchedule` or expire when the next retry would pass the delivery's lifetime.
8. Results are recorded with `RecordAttemptAsync` (storage writes the event, statistics and webhook outbox rows in the same commit). For permanent failures and expiries of SMTP-submitted mail a bounce message (RFC 3464) is queued **before** recording, because recording the last recipient frees the stored message.

A connection lost after the end of data was sent is deferred with the `possible_duplicate` flag. `QuiesceAsync` stops claiming, waits up to the timeout, cancels what is left (recorded as `AbortedBySwitch`, requeued unchanged, flagged possible duplicate only when the end of the message data had begun to be written, see `SmtpClientConnection.EndOfDataStarted`) and releases the leases (decision R).

## Inbound

`IngestHandler` is the `ISmtpServerHandler`. Submission listeners authenticate a tenant's SMTP credential (PBKDF2 hash, shared lockout through `AuthThrottle`, constant work for unknown users) and pass each message to `SubmissionService`, the one path into the queue for SMTP and the HTTP API: size and recipient limits, `SenderPolicy` (From header domain and envelope sender must belong to the tenant and be verified), `Bcc` removal, Message-ID and Date repair, content extraction for history when `History:Mode=Full`, durable intake. The bounce listener accepts only recipients that are valid signed bounce addresses (or postmaster/abuse), always answers 250 for them and hands the message to `BounceProcessor`: permanent DSN failures that the reply classifier attributes to the recipient suppress it, abuse complaints suppress as complaints, and both are published as webhooks. With `History:Mode=Full` the report is also **attached to the message it is about**: the VERP token (verified, so trusted) names the tenant, the `Message-ID` in the returned headers (stored in `message_index.message_id_header` when the message was accepted, normalized without angle brackets and in lower case) finds the tenant's message (the newest, if a client reused an id), and a `bounced` or `complained` event is appended to its history with the recipient, the enhanced status and the diagnostic; the message status follows (`delivered` becomes `bounced`, or `partial` with several recipients; a complaint makes a delivered message `complained`). The webhook payload then carries `message_id`. With `StatsOnly` nothing per message is stored (the lookup finds nothing), and the suppression and the webhook happen exactly as before. A report whose token names another tenant can only ever look among that tenant's messages. Nothing on the bounce listener can queue mail for delivery.

### Parse once

`SubmissionService` parses the submitted message a single time. The sender check (From domain), the header repair (is there a Message-ID, a Date, a Bcc) and the history extraction (`MessageContentExtractor.Extract(MimeMessage)`) all use that parse. Only headers are added or removed, so subject, bodies and attachments are those of the stored message. The Bcc rule is dropped only when the parsed header list is complete (not cut by `MaxHeaderCount` or `MaxHeaderBytes`) and has no Bcc; otherwise the editor removes it as before, so a Bcc behind the header limits cannot reach the stored copy. Allocation figures: [../benchmarks.md](../benchmarks.md#allocation-work-second-round-2026-10-13).

## Known gaps

- 8-bit message bodies are sent as they are even when the receiving server does not advertise `8BITMIME` (no downgrade to quoted-printable). `SMTPUTF8` is honoured: a server without it gets a permanent failure for internationalized addresses.
- Throttle state and circuit breakers are per process (see `components/policy.md`). The sending counters are persisted and shared through the config store (see `components/policy.md`); TLS-RPT counters and pending reports are persisted too (see `components/tls.md`).

See [../progress.md](../progress.md).
