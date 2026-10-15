# SMTP protocol and server (`Mta.Smtp.Protocol`, `Mta.Smtp.Server`)

Hand-written and package-free (decision 4). `Mta.Smtp.Protocol` is pure (no I/O): command and reply parsing, the DATA scanner that removes dot-stuffing, the client-side `DotStuffer`, SASL helpers and the session state machine. `Mta.Smtp.Server` adds sockets, TLS, limits and the session loop over `System.IO.Pipelines`.

## Security properties (tested)

- Only CRLF ends a line. A bare LF or bare CR in a command line or in message data closes the connection with `500` (SMTP smuggling defense). The DATA scanner never treats `\n.\r\n`, `\r.\r\n` or `\r\n.\n` as a terminator.
- STARTTLS: any byte buffered behind the `STARTTLS` command aborts the upgrade (RFC 3207 §4.2 / CVE-2011-0411 family). After the handshake the session starts over and the client must EHLO again.
- AUTH is offered only on encrypted sessions (or an explicitly allowed plain listener). Failed attempts cost a delay and count toward the per-session error limit.
- Limits: line length, recipients, message size (`552`), errors per session (`421`), messages per session, per-read and total DATA time, global and per-IP connection caps (keyed globally across ports), a global in-flight bytes budget for messages being received (`452`).
- BDAT chunk payloads are inert: commands inside a chunk are never interpreted. They are not binary: the server does not advertise BINARYMIME, so a BDAT body gets the same line-ending rule as DATA (`LineEndingValidator`, state kept across chunks, so a CR at the end of one chunk and its LF at the start of the next are one line ending): a bare LF, a bare CR (also a CR at the very end) or a NUL is answered `500 5.5.2` and the connection is closed, nothing is queued. Before, only DATA was checked; the outbound client refuses such a message, so a BDAT message with a bare LF was acknowledged with `250` and bounced later.

## Performance design

- Idle connections hold no read buffer (zero-byte reads, as Kestrel does); pipes are pooled; replies to pipelined commands are batched into one flush.
- Message bodies are accumulated in pooled segments (`MessageBuffer`) and handed to the handler as a `ReadOnlySequence<byte>`; no contiguous allocation for large messages.
- Constant replies are pre-rendered.
- Allocation (2 KB message, plain text, no storage: about 0.1 KB per message, measured with `bench/Mta.Bench.Pipeline -- --sink-only true`; round 3, [../benchmarks.md](../benchmarks.md#allocation-work-third-round-2026-10-15)): a suspended `async` method is a state machine on the heap unless the runtime's small pool of boxes has one (it keeps about one per thread and core, so with tens of connections most miss), so the session avoids suspended frames: the command loop reads from the pipe itself, `DispatchAsync` is not asynchronous (a command returns the task of its handler) and the DATA transaction, the handler call and the reply are written out inside the loop's own state machine, which exists once per session. The session keeps one `SmtpMessage`, one `MailFromInfo`, one `MessageBuffer` (with its first segment object) and one `Received` buffer for all its messages, and an `EmailAddressCache` for the addresses it parses (the sender of every message, a recipient that returns; domains are shared by `EmailAddress` itself). Consequently **`SmtpMessage` (its `Body`, `ReceivedHeader` and `Recipients`) and `MailFromInfo` are valid only during the handler call** and are emptied after it; a handler that keeps anything must copy it. A message that fits one buffer segment reaches the handler as a single-segment sequence (the handler may use `Body.First` without copying); MAIL/RCPT paths are decoded in stack memory; the discard writer exists only for oversized messages.
- Client (`Mta.Smtp.Client`): one linked timeout source per connection is re-armed for every reply read and data block (it is replaced when the caller's token changes or it has fired), MAIL and RCPT lines are written into stack memory, `SmtpReplyParser` reads a line in place when it sits in one segment and shares the usual enhanced status strings. The pool still sends NOOP before and RSET after reusing a connection (two round trips per message); skipping either is a protocol-behaviour decision that has not been taken.

## Extension points

`ISmtpServerHandler` is the policy and storage seam (relay policy, AUTH, durable enqueue). The handler returns the reply; `250` must only be returned after the message is accepted according to the configured sync mode (design §4.4).

## Known gaps

- DSN extension parameters are parsed on RCPT but not advertised.
- `REQUIRETLS`, `BINARYMIME` and `LIMITS` are not implemented.

## Outbound client (`Mta.Smtp.Client`)

`SmtpClientConnection` connects to one address, reads the banner, issues EHLO, negotiates STARTTLS according to a caller-supplied `SmtpTlsPolicy` (the delivery layer derives it from the MTA-STS / DANE / per-domain decision), optionally authenticates (relay routes; credentials are never sent without TLS), and sends transactions with PIPELINING, DATA or BDAT.

- Network failures throw `SmtpConnectionException` with `EndOfDataSent`, which the delivery layer maps to "possible duplicate" when the connection dies after the terminating dot (decision R). SMTP-level refusals are returned in `SmtpSendResult`.
- The client never emits a bare CR/LF (the `DotStuffer` refuses them); such messages fail locally with `LocalFailure.MalformedMessage` and the connection is dropped.
- Local checks before touching the wire: SIZE limit, SMTPUTF8 and 8BITMIME support (the delivery processor decides beforehand what to send per server, so these are a safety net there: see [delivery.md](delivery.md#8-bit-and-internationalized-mail)). `SmtpClientConnection.LocalIpAddress` (and `SmtpClientException.LocalIpAddress` for failed setups) is the local address of the TCP connection, used for TLS-RPT.
- STARTTLS stripping is surfaced (`TlsSession.StartTlsAdvertised == false`, `TlsException(NotAdvertised)` when TLS is required) and plaintext injected behind the server's `220` aborts the upgrade.
- `SmtpConnectionPool` keeps idle connections per target (idle timeout, per-target and total caps, transaction cap).
