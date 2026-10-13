# Mta.Mime

MIME and RFC 5322 parsing, building and header editing. Part of the hand-written, BCL-only stack (decision 4): the project has **no package references** and only references `Mta.Core`. No I/O; every parser works on `ReadOnlyMemory<byte>` / `ReadOnlySpan<byte>` and writes to `IBufferWriter<byte>`, so it can be fuzzed and benchmarked directly.

All input is hostile. Every parser is bounded by `MimeLimits`, runs in time linear in the input (times the nesting depth for multipart scanning) and **does not throw for content problems**; it sets `MimeAnomaly` flags and truncates instead. The only documented exceptions are `HeaderInjectionException`, `MessageBuildException` (builder/editor, invalid model or output), `ArgumentException` family for programmer errors, and `FormatException` from `Mailbox.Parse`.

## Public API

| Area | Types |
|---|---|
| Limits and anomalies | `MimeLimits`, `MimeAnomaly` (flags), `HeaderInjectionException`, `MessageBuildException` |
| Headers | `HeaderList.Parse`, `HeaderList.FindBodyOffset`, `MimeHeader` (raw bytes, unfolded value, decoded value), `HeaderId`, `HeaderNames` |
| Structured fields | `ContentType`, `ContentDisposition`, `ParameterList` / `MimeParameter` (RFC 2231 resolved), `ContentTransferEncoding` + `ContentTransferEncodings.Parse`, `MimeVersion` |
| Encoded words | `Rfc2047.Decode` / `Encode` / `EncodeWords` / `TryDecodeWord`, `MimeCharsets` (`RegisterCodePages`, `TryGetEncoding`, `Decode`) |
| Addresses | `AddressList.Parse`, `Mailbox` (display name + `Mta.Core.EmailAddress`, `Domain`, `ToHeaderValue`), `MailboxGroup`, `AddressItem` |
| Dates | `MimeDate.Format` / `TryFormat` / `TryParse` |
| Tree | `MimeMessage.Parse` -> `MimePart` (headers, content type, lazy `Body`, `Children`, `DecodeBodyTo`, `GetDecodedBytes`, `GetDecodedLength`, `GetText`) |
| Transfer coding | `Base64Decoder`, `QuotedPrintableDecoder` (streaming, lenient), `BodyDecoder`, `TransferEncoder` (base64, quoted-printable, choice) |
| 8BITMIME downgrade | `EightBitDowngrader.Downgrade` -> `EightBitDowngradeResult` (`NotNeeded`, `Downgraded`, `Impossible` + reason) |
| History extraction | `MessageContentExtractor.Extract(bytes)` or `Extract(MimeMessage)` (on an already parsed message, with the limits it was parsed with) -> `ExtractedContent`, `AttachmentInfo` |
| Sender check | `AddressList.GetCommonDomain(header, limits, out domain)` and `AddressList.GetCommonDomain(out domain)` -> `CommonDomainResult` (`NoValidMailbox`, `Single`, `MultipleDomains`); a single plain address is answered from the header bytes, anything else by the full parser (same result, tested differentially) |
| Building | `MessageBuilder`, `MessageBuilderOptions`, `BuilderAttachment`, `HeaderPolicy`, `BuiltMessage`, `HeaderFolder`, `HeaderValidator` |
| Editing raw bytes | `MessageHeaderEditor` (prepend, append, remove, replace, raw fields, `PrependRawWithoutCopy` to reference a field instead of copying it), `LineEndings.ToCrlf`, `MessageInspector` (`Inspect`, `HasUtf8Headers`, `HasEightBitBody`, `ContainsBareLf`, `ContainsBareCr`) |
| Receive checks | `MessageValidator.Validate` -> `MessageValidationResult` (`MessageIssue`, `MessageIssueCode`, `IssueSeverity`) |

### How other components use it

* **SMTP server**: `HeaderList.FindBodyOffset` for a cheap split, `MessageInspector.Inspect` (bare CR/LF, NUL, 8-bit, line lengths) to decide reject/normalize and 8BITMIME/SMTPUTF8 handling, `MessageValidator.Validate` for policy, `MessageHeaderEditor` to prepend `Return-Path`/`Received` without touching the body.
* **DKIM**: `MimeHeader.Raw` (exact bytes, no final CRLF), `GetUnfoldedValueBytes()`, order preserved; duplicates are all present for bottom-up selection. `MessageHeaderEditor.PrependRaw` inserts the pre-folded `DKIM-Signature`.
* **DMARC**: `AddressList.Parse(headers[From])` -> `Mailbox.Domain` (lower-case A-label), `MultipleFromWithoutSender` and `InvalidFrom` issues.
* **Delivery**: `MessageInspector.HasValidUtf8Headers` / `HasEightBitBody` decide SMTPUTF8 and BODY=8BITMIME per transaction; `EightBitDowngrader` produces the 7-bit form for servers without 8BITMIME (the result is then DKIM-signed).
* **HTTP API / history**: `MessageBuilder` (compose), `MessageContentExtractor` (subject, text, html, attachment index, truncation flags).

## 8BITMIME downgrade

`EightBitDowngrader.Downgrade(message, writer)` produces the 7-bit form of a message with an 8-bit body for a server that does not offer 8BITMIME (RFC 6152). It parses the MIME tree, re-encodes only the leaves that need it and copies every other byte unchanged (headers, boundaries, 7-bit parts), so the result differs from the input exactly where it has to.

* **Leaf entities** with 8-bit bytes (labelled `8bit`, `binary`, or `7bit` while holding 8-bit bytes): `text/*` becomes quoted-printable when mostly ASCII and base64 otherwise (`TransferEncoder.ChooseForText`), anything else and `binary` become base64. The `Content-Transfer-Encoding` field is replaced (added if missing, duplicates dropped). At the message root, `MIME-Version: 1.0` is added when missing and, for a message with no `Content-Type` and a valid UTF-8 body, `Content-Type: text/plain; charset=utf-8`.
* A `-` that a quoted-printable soft line break would put at the start of a line is written `=2D`: an encoder must not create a line that looks like a MIME delimiter (`--boundary`) out of text that was mid-line in the original (boundary forgery).
* An embedded `message/rfc822` is a message of its own: when its headers lack `MIME-Version` it gets one (and, with no `Content-Type` and a valid UTF-8 body, `text/plain; charset=utf-8`), like the top-level message.
* **Composite entities** are never encoded as a whole (RFC 2045 section 6.4): `multipart/*` and embedded `message/rfc822` keep their structure and are processed recursively; an `8bit`/`binary` label on them becomes `7bit`.
* `message/global` and `message/global-*` (RFC 6532 section 3.7, RFC 6533: internationalized messages and delivery status reports) are encoded as a whole, as those RFCs allow. `MimePart` decodes such a part when it is quoted-printable or base64.
* **Refused (`Impossible`, with a reason fit for a bounce message):** 8-bit bytes in the header fields of a nested part or of an embedded message (header downgrading, RFC 6857, is experimental and not implemented), in a preamble, epilogue or delimiter line; a part declaring quoted-printable, base64 or an unknown encoding that nevertheless holds 8-bit bytes; `message/*` types other than `rfc822` and `global*`; structure the parser had to keep opaque (no boundary, duplicate boundary, `MaxDepth`/`MaxParts` exceeded) while holding 8-bit bytes; header blocks beyond `MaxHeaderCount`/`MaxHeaderBytes`. A truncated multipart (no closing delimiter) is converted normally.
* The headers of the message itself may hold UTF-8 (SMTPUTF8) and are left alone; only the transfer-encoding fields change.
* Tests: structure and decoded content are compared with MimeKit (fixed corpus and random trees), plus the refusal cases.

## Limits (`MimeLimits`, all configurable; defaults)

| Limit | Default | When exceeded |
|---|---|---|
| `MaxHeaderBytes` | 256 KiB | rest of the header block still scanned (to find the body) but not recorded; `HeaderBlockTooLarge` |
| `MaxHeaderCount` | 1000 | later headers not recorded; `TooManyHeaders` |
| `MaxLineLength` | 998 | `HeaderLineTooLong` / `BodyLineTooLong` (report only) |
| `MaxHeaderValueBytes` | 64 KiB | value text truncated when read as a string |
| `MaxDepth` | 20 (max 64) | deeper multipart / message/rfc822 stays an opaque leaf; `MaxDepthExceeded` |
| `MaxParts` | 1000 | remaining parts dropped; `TooManyParts` |
| `MaxDecodedBytes` | 64 MiB | decode stops; `DecodedSizeLimit` |
| `MaxParameters` | 64 | `TooManyParameters` |
| `MaxAddresses` | 1000 | `TooManyAddresses` |
| `MaxBoundaryLength` | 200 | treated as a missing boundary |

Worst-case materialized memory of a parse is bounded by the limits: a header record is 32 bytes, so at most `MaxParts` x `MaxHeaderCount` x 32 B = about 32 MB for the defaults, regardless of input size.

`MessageContentExtractor.Extract(raw, maxBodyBytes = 256 KiB)` limits each stored body to that many UTF-8 bytes (cut on a character boundary) and sets `TextTruncated` / `HtmlTruncated`; subjects are capped at 2048 chars. Decoded text has NUL removed (PostgreSQL text cannot hold it), subject and file names have control characters replaced.

## Security properties (each has tests)

* A bare CR is never a line break (no CR header smuggling); bare LF/CR, NUL, missing colon, 8-bit headers, over-long lines are reported.
* Header injection: any CR, LF, NUL or other control character in a header name or value written by the builder or editor is rejected with `HeaderInjectionException`. Decoded RFC 2047 text may contain CR/LF faithfully; the builder refuses to write it back, and the extractor replaces runs of control characters with one space.
* Multipart scanning finds delimiter lines with a constant-size needle (`LF "--"`) and only compares the boundary at line starts: linear even against boundary look-alike floods. Nested boundaries re-scan their region once per level (bounded by `MaxDepth`). A nested multipart that reuses an ancestor's boundary is kept opaque (`DuplicateBoundary`).
* Decoders never expand: base64 yields at most 3 bytes per 4 characters, quoted-printable at most 1 per input byte; output is also capped by `MaxDecodedBytes` / the caller's maximum.
* Charsets: names are validated (length, characters), UTF-7 is refused, unknown names fall back to ASCII/UTF-8/windows-1252 (with `UnknownCharset`), resolution is cached (bounded) and never throws.
* RFC 2231 continuation numbers are capped, gaps stop the value, the extended form wins over a plain fallback.
* Parsers are iterative or recursion-limited (depth <= 64); no unbounded loops (every loop consumes input).

## Behaviour notes

* Header values are decoded as strict UTF-8 (RFC 6532) and fall back to windows-1252 for other 8-bit bytes.
* `MimeHeader.Value` unfolds and trims; `GetDecodedValue` additionally decodes RFC 2047 words (unstructured fields).
* Whitespace between two adjacent encoded words is dropped (RFC 2047 6.2); adjacent words of the same charset are decoded together, so a character split across words survives.
* Quoted-printable decoding removes whitespace before a hard line break (RFC 2045 6.7 rule 3); an unpadded final base64 quantum is decoded.
* The builder: text -> `text/plain`, html -> `text/html`, both -> `multipart/alternative`, inline resources with HTML -> `multipart/related`, attachments -> `multipart/mixed`. Text parts are 7bit (short ASCII lines), 8bit only when `Allow8BitBody`, otherwise quoted-printable or base64 (control characters or a mostly non-ASCII body force base64). Output is CRLF only, boundaries are random per message. Non-ASCII header text is RFC 2047 encoded (UTF-8; Q or B, whichever is shorter, at most 75 characters per word) unless `AllowUtf8Headers`. File names use RFC 2231 with continuations when non-ASCII or long. Directory parts of attachment names are removed. Bcc is never written unless `IncludeBccHeader`.
* `HeaderPolicy` defaults deny the headers the builder owns and trace/authentication headers (`From`, `To`, `Subject`, `Date`, `Message-ID`, `Content-*`, `Return-Path`, `Received`, `DKIM-Signature`, `Authentication-Results`, `ARC-*`, `Resent-*`, `X-Mta-*` ...). An allow list narrows further; entries ending in `*` are prefixes.
* `MessageBuilder` and `MessageHeaderEditor` instances are not thread-safe; all parsers and static helpers are.

## Documented differences from MimeKit (differential tests)

1. Quoted-printable trailing whitespace before a hard line break is dropped (MimeKit keeps it).
2. An unpadded final base64 quantum is decoded (MimeKit drops it).
3. Stray `;` and `Name addr@host` (no angle brackets) in address lists are tolerated and flagged `InvalidAddress`; invalid entries are kept as `Mailbox.IsValid == false`.
4. 8-bit text with a missing/`us-ascii`/unknown charset is decoded as UTF-8 when valid, else windows-1252.
5. A multipart without a usable boundary, or whose boundary is reused by a descendant, is an opaque leaf with an anomaly flag.

## Known gaps

* Input must be contiguous memory (no `ReadOnlySequence<byte>` overloads yet; the SMTP layer buffers DATA in memory per design.md section 3).
* No charset detection from HTML `<meta>`, no HTML sanitizing, no `format=flowed`, no uuencode/yEnc, no S/MIME, PGP or TNEF handling.
* RFC 2047 encoding supports stateless charsets only (UTF-8 by default; ISO-2022 and UTF-16/32 are refused).
* Obsolete address routes are dropped; comments are only used as a display-name fallback.
* The header editor does not re-fold or normalize existing headers (by design: original bytes stay byte-exact); use `LineEndings.ToCrlf` first when needed.
* `MimeHeader.Value` truncates silently at `MaxHeaderValueBytes` (the struct API has no place for the flag; use `HeaderList.Anomalies` and `HeaderLineTooLong`).
* Parser-review checklist and SharpFuzz harnesses (design.md section 9) are not part of this component yet; the seeded mutation fuzzer in `tests/Mta.Mime.Tests` is the interim safety net.

## Performance (BenchmarkDotNet, short job, Apple silicon, indicative)

`bench/Mta.Benchmarks/Mime/MimeBenchmarks.cs`: header split ~80 ns, 0 B; header parse of an 8-header message ~200 ns, 728 B; MIME tree of a 200 KB attachment message ~8.5 us, 8.5 KB; extraction with a 200 KB base64 attachment ~144 us (dominated by counting the decoded size).
