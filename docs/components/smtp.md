# SMTP protocol and server (`Mta.Smtp.Protocol`, `Mta.Smtp.Server`)

Hand-written and package-free (decision 4). `Mta.Smtp.Protocol` is pure (no I/O): command and reply parsing, the DATA scanner that removes dot-stuffing, the client-side `DotStuffer`, SASL helpers and the session state machine. `Mta.Smtp.Server` adds sockets, TLS, limits and the session loop over `System.IO.Pipelines`.

## Security properties (tested)

- Only CRLF ends a line. A bare LF or bare CR in a command line or in message data closes the connection with `500` (SMTP smuggling defense). The DATA scanner never treats `\n.\r\n`, `\r.\r\n` or `\r\n.\n` as a terminator.
- STARTTLS: any byte buffered behind the `STARTTLS` command aborts the upgrade (RFC 3207 §4.2 / CVE-2011-0411 family). After the handshake the session starts over and the client must EHLO again.
- AUTH is offered only on encrypted sessions (or an explicitly allowed plain listener). Failed attempts cost a delay and count toward the per-session error limit.
- Limits: line length, recipients, message size (`552`), errors per session (`421`), messages per session, per-read and total DATA time, global and per-IP connection caps (keyed globally across ports), a global in-flight bytes budget for messages being received (`452`).
- BDAT chunk payloads are binary and inert: commands inside a chunk are never interpreted.

## Performance design

- Idle connections hold no read buffer (zero-byte reads, as Kestrel does); pipes are pooled; replies to pipelined commands are batched into one flush.
- Message bodies are accumulated in pooled segments (`MessageBuffer`) and handed to the handler as a `ReadOnlySequence<byte>`; no contiguous allocation for large messages.
- Constant replies are pre-rendered.

## Extension points

`ISmtpServerHandler` is the policy and storage seam (relay policy, AUTH, durable enqueue). The handler returns the reply; `250` must only be returned after the message is accepted according to the configured sync mode (design §4.4).

## Known gaps

- DSN extension parameters are parsed on RCPT but not advertised.
- `REQUIRETLS`, `BINARYMIME` and `LIMITS` are not implemented.

## Outbound client (`Mta.Smtp.Client`)

`SmtpClientConnection` connects to one address, reads the banner, issues EHLO, negotiates STARTTLS according to a caller-supplied `SmtpTlsPolicy` (the delivery layer derives it from the MTA-STS / DANE / per-domain decision), optionally authenticates (relay routes; credentials are never sent without TLS), and sends transactions with PIPELINING, DATA or BDAT.

- Network failures throw `SmtpConnectionException` with `EndOfDataSent`, which the delivery layer maps to "possible duplicate" when the connection dies after the terminating dot (decision R). SMTP-level refusals are returned in `SmtpSendResult`.
- The client never emits a bare CR/LF (the `DotStuffer` refuses them); such messages fail locally with `LocalFailure.MalformedMessage` and the connection is dropped.
- Local checks before touching the wire: SIZE limit, SMTPUTF8 and 8BITMIME support.
- STARTTLS stripping is surfaced (`TlsSession.StartTlsAdvertised == false`, `TlsException(NotAdvertised)` when TLS is required) and plaintext injected behind the server's `220` aborts the upgrade.
- `SmtpConnectionPool` keeps idle connections per target (idle timeout, per-target and total caps, transaction cap).
