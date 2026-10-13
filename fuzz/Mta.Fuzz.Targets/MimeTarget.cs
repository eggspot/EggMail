using System.Text;
using Mta.Mime;

namespace Mta.Fuzz;

/// <summary>Every public MIME parser over one input, with the invariants that must hold for any input (limits, bounds, the editor never touches the body).</summary>
internal static class MimeTarget
{
    private static readonly string[] AddressHeaders = ["From", "To", "Cc", "Bcc", "Reply-To", "Sender"];

    public static FuzzTarget Create() => new("mime", "MIME parsers: header list, addresses, dates, RFC 2047, MIME tree, content extractor, validator, header editor, line endings", Run, Seeds())
    {
        Tokens = Tokens(),
        MutationIterations = 12000,
        MaxInputLength = 128 * 1024,
    };

    private static void Run(ReadOnlySpan<byte> input)
    {
        byte[] data = input.ToArray();
        var limits = MimeLimits.Default;
        var memory = new ReadOnlyMemory<byte>(data);

        // ---- header list
        var headers = HeaderList.Parse(memory, limits);
        Guard.Check(headers.Count <= limits.MaxHeaderCount, "more headers than MaxHeaderCount");
        Guard.Check(headers.BodyOffset >= 0 && headers.BodyOffset <= data.Length, "body offset out of range");
        int previousEnd = 0;
        foreach (var h in headers)
        {
            Guard.Check(h.Offset >= previousEnd, "headers overlap or are out of order");
            previousEnd = h.Offset + h.LengthWithLineEnding;
            Guard.Check(previousEnd <= data.Length, "header extends past the input");
            _ = h.Name;
            _ = h.GetValue(4096);
            _ = h.GetDecodedValue(4096);
            _ = h.GetUnfoldedValueLength();
            _ = h.NameEquals("from");
        }

        foreach (string name in AddressHeaders)
        {
            if (headers.TryGetFirst(name, out var h))
            {
                var list = AddressList.Parse(h, limits);
                Guard.Check(list.MailboxCount <= 2 * limits.MaxAddresses, "more mailboxes than MaxAddresses allows");
                foreach (var m in list.Mailboxes)
                {
                    if (m.IsValid)
                    {
                        _ = m.Domain;
                        _ = m.ToString();
                    }
                }
            }
        }

        if (headers.TryGetFirst(HeaderId.Date, out var date))
        {
            MimeDate.TryParse(date.GetValue(256), out _);
        }

        // ---- MIME tree
        var message = MimeMessage.Parse(memory, limits);
        Guard.Check(message.PartCount <= limits.MaxParts, "more parts than MaxParts");
        int parts = 0;
        foreach (var part in message.EnumerateParts())
        {
            parts++;
            Guard.Check(part.Depth <= limits.MaxDepth + 1, "nesting deeper than MaxDepth");
            Guard.Check(part.Raw.Length <= data.Length, "part larger than the message");
            _ = part.ContentType.ToHeaderValue();
            _ = part.Disposition;
            _ = part.FileName;
            _ = part.ContentId;
            _ = part.IsAttachment;
            string text = part.GetText(2000, out _);
            Guard.Check(text.Length <= 2002, "GetText exceeded its limit");
            Guard.Check(part.GetDecodedBytes(5000).Length <= 5000, "GetDecodedBytes exceeded its limit");
            Guard.Check(part.GetDecodedLength() <= limits.MaxDecodedBytes, "decoded length above MaxDecodedBytes");
        }

        Guard.Check(message.PartCount == parts, "PartCount disagrees with the enumeration");

        // ---- extraction
        var content = MessageContentExtractor.Extract(memory, 256 * 1024, limits);
        Guard.Check(content.Attachments.Count <= limits.MaxParts, "more attachments than parts");
        Guard.Check(content.Subject is null || content.Subject.Length <= MessageContentExtractor.MaxSubjectChars, "subject longer than the maximum");
        foreach (string? s in new[] { content.Subject, content.TextBody, content.HtmlBody })
        {
            if (s is not null)
            {
                Guard.Check(!s.Contains('\0', StringComparison.Ordinal), "NUL in extracted text");
                Guard.Check(Encoding.UTF8.GetByteCount(s) <= 256 * 1024, "extracted text above the byte limit");
            }
        }

        if (content.Subject is not null)
        {
            Guard.Check(!content.Subject.Any(char.IsControl), "control character in the subject");
        }

        foreach (var a in content.Attachments)
        {
            Guard.Check(a.FileName is null || !a.FileName.Any(char.IsControl), "control character in a file name");
            Guard.Check(a.Size >= 0, "negative attachment size");
        }

        // ---- validator
        _ = MessageValidator.Validate(memory, limits).Issues;

        // ---- editor: the body is never touched
        var edited = new MessageHeaderEditor(memory)
            .Remove("Bcc")
            .Remove("Return-Path")
            .PrependReceived("from fuzz by test")
            .PrependReturnPath("a@example.com")
            .Append("X-Trace", "1")
            .ToArray();
        var editedHeaders = HeaderList.Parse(edited, limits);
        Guard.Check(editedHeaders.Body.Length == (headers.HasSeparator ? headers.Body.Length : 0), "the header editor changed the body length");
        if (headers.HasSeparator)
        {
            Guard.Check(editedHeaders.Body.Span.SequenceEqual(headers.Body.Span), "the header editor changed the body");
        }

        // ---- line endings
        var normalized = LineEndings.ToCrlf(data);
        Guard.Check(!MessageInspector.ContainsBareLf(normalized) && !MessageInspector.ContainsBareCr(normalized), "bare CR or LF after normalization");
        Guard.Check(normalized.Length <= data.Length * 2, "normalization more than doubled the size");
        _ = MessageInspector.Inspect(data);

        // ---- RFC 2047 on its own (the same bytes as a header value)
        string value = Encoding.Latin1.GetString(data, 0, Math.Min(data.Length, 70_000));
        _ = Rfc2047.Decode(value, out _);
    }

    private static IReadOnlyList<byte[]> Seeds() =>
    [
        Msg("From: Alice <alice@example.com>\r\nTo: Bob <bob@example.net>, \"Carol, C.\" <carol@example.org>\r\nSubject: Hello\r\nDate: Mon, 12 Oct 2026 12:00:00 +0000\r\nMessage-ID: <1@example.com>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello,\r\n\r\nBody.\r\n"),
        Msg("From: a@example.com\r\nTo: b@example.net\r\nSubject: =?UTF-8?B?w6TDtsO8?= =?utf-8?Q?caf=C3=A9_menu?=\r\nContent-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n--b1\r\nContent-Type: text/plain\r\n\r\nplain\r\n--b1\r\nContent-Type: multipart/alternative; boundary=b2\r\n\r\n--b2\r\nContent-Type: text/html; charset=iso-8859-1\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n<p>caf=E9</p>=\r\n\r\n--b2--\r\n--b1\r\nContent-Type: application/pdf; name=\"a.pdf\"\r\nContent-Disposition: attachment; filename*=UTF-8''%E2%82%AC.pdf\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK\r\n--b1--\r\n"),
        Msg("From: g: a@b.example, c@d.example;\r\nTo: <@route:a@b>, (comment (nested)) x@y\r\nCc: \"unterminated\r\nSubject: folded\r\n  value\r\n\twith tab\r\n\r\nbody"),
        Msg("Content-Type: multipart/mixed; boundary=x\n\n--x\nContent-Type: message/rfc822\n\nFrom: n@example.com\n\nnested\n--x--\n"),
        Msg("Received: from a by b\r\nReceived: from c by d\r\nBcc: hidden@example.com\r\nReturn-Path: <old@example.com>\r\nFrom: x@example.com\r\n\r\n"),
        Msg("\r\n\r\n\r\nFrom: after-blank@example.com\r\n"),
        Msg("X: \r\r\n\n\rY: z\r\n\r\n"),
        Msg("Date: Sun, 6 Nov 1994 08:49:37 GMT\r\nContent-Type: text/plain; charset=\"x-unknown\"; format=flowed\r\nContent-Transfer-Encoding: x-uuencode\r\n\r\nbegin 644 a\r\n"),
    ];

    private static IReadOnlyList<byte[]> Tokens() =>
    [
        Msg("\r\n"), Msg("\r\n\r\n"), Msg("\n"), Msg("\r\n "), Msg("\r\n\t"), Msg("--b1\r\n"), Msg("--b1--"), Msg("boundary="), Msg("multipart/mixed"), Msg("multipart/alternative"),
        Msg("message/rfc822"), Msg("Content-Type:"), Msg("Content-Transfer-Encoding: base64\r\n"), Msg("quoted-printable"), Msg("=?utf-8?B?"), Msg("=?iso-2022-jp?Q?"), Msg("?="),
        Msg("filename*0*="), Msg("charset="), Msg("<"), Msg(">"), Msg("\""), Msg("("), Msg(")"), Msg("@"), Msg(":"), Msg(";"), Msg(","), Msg("\\"), Msg("=\r\n"), Msg("=C3=A9"),
    ];

    private static byte[] Msg(string s) => Encoding.Latin1.GetBytes(s);
}
