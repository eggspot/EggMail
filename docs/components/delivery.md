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

A connection lost after the end of data was sent is deferred with the `possible_duplicate` flag. `QuiesceAsync` stops claiming, waits up to the timeout, cancels what is left (recorded as `AbortedBySwitch`, requeued unchanged, flagged possible duplicate when a connection had been made) and releases the leases (decision R).

## Inbound

`IngestHandler` is the `ISmtpServerHandler`. Submission listeners authenticate a tenant's SMTP credential (PBKDF2 hash, shared lockout through `AuthThrottle`, constant work for unknown users) and pass each message to `SubmissionService`, the one path into the queue for SMTP and the HTTP API: size and recipient limits, `SenderPolicy` (From header domain and envelope sender must belong to the tenant and be verified), `Bcc` removal, Message-ID and Date repair, content extraction for history when `History:Mode=Full`, durable intake. The bounce listener accepts only recipients that are valid signed bounce addresses (or postmaster/abuse), always answers 250 for them and hands the message to `BounceProcessor`: permanent DSN failures that the reply classifier attributes to the recipient suppress it, abuse complaints suppress as complaints, and both are published as webhooks. Nothing on the bounce listener can queue mail for delivery.

## Known gaps

See [../progress.md](../progress.md): per-process throttle state, no TLS-RPT counting yet, async bounces are not linked to history events.
