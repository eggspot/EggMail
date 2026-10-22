using System.Buffers;
using System.Text;
using Mta.Core;
using Mta.Mime;

namespace Mta.Fuzz;

/// <summary>
/// The 8-bit to 7-bit downgrade for receivers without 8BITMIME. The message is whatever a customer submitted, so the input is any byte
/// string. Besides "no exception": nothing is written when no downgrade is needed, a downgraded body is 7-bit, and the downgrade keeps the
/// structure (same tree of parts) and the content (every leaf decodes to the same bytes as before, text up to its line breaks).
/// </summary>
internal static class EightBitDowngradeTarget
{
    private const int DecodedCompareLimit = 1 << 20;

    public static FuzzTarget Create() => new("eightbit-downgrade", "8BITMIME downgrade (re-encoding of 8-bit leaves to quoted-printable or base64)", Run, Seeds())
    {
        Tokens = Tokens(),
        MutationIterations = 60000,
        MaxInputLength = 128 * 1024,
    };

    private static void Run(ReadOnlySpan<byte> input)
    {
        byte[] data = input.ToArray();
        var output = new ArrayBufferWriter<byte>();
        var result = EightBitDowngrader.Downgrade(data, output);
        Guard.Check(Enum.IsDefined(result.Status), "undefined downgrade status");
        switch (result.Status)
        {
            case EightBitDowngradeStatus.NotNeeded:
                Guard.Check(output.WrittenCount == 0, "nothing may be written when no downgrade is needed");
                return;
            case EightBitDowngradeStatus.Impossible:
                Guard.Check(!string.IsNullOrEmpty(result.Reason), "an impossible downgrade needs a reason");
                Guard.Check(!result.Reason.Any(char.IsControl), "control character in the reason (it goes into a bounce)");
                return;
        }

        Guard.Check(result.Reason is null, "a successful downgrade has no reason");
        byte[] downgraded = output.WrittenSpan.ToArray();
        int bodyOffset = HeaderList.FindBodyOffset(downgraded);
        Guard.Check(Ascii.IsValid(downgraded.AsSpan(bodyOffset)), "8-bit byte in the body after the downgrade");

        Compare(MimeMessage.Parse(data).Root, MimeMessage.Parse(downgraded).Root, "the message");
    }

    /// <summary>Walks both trees together. A message/global entity is encoded as a whole, so below it only its decoded bytes are compared.</summary>
    private static void Compare(MimePart before, MimePart after, string path)
    {
        bool whole = before.ContentType.MediaType == "message" && before.ContentType.MediaSubtype.StartsWith("global", StringComparison.Ordinal) && after.Children.Count == 0;
        if (before.Children.Count > 0 && !whole)
        {
            Guard.Check(before.Children.Count == after.Children.Count, $"the downgrade changed the number of children of {path} from {before.Children.Count} to {after.Children.Count}");
            for (int i = 0; i < before.Children.Count; i++)
            {
                Compare(before.Children[i], after.Children[i], $"{path}/{i}");
            }

            return;
        }

        byte[] expected = whole ? before.Body.ToArray() : before.GetDecodedBytes(DecodedCompareLimit);
        byte[] actual = after.GetDecodedBytes(DecodedCompareLimit);
        if (whole || before.ContentType.IsText)
        {
            // Line breaks in text are CRLF in canonical form (RFC 2045 section 6.7): quoted-printable writes a bare CR or LF as a line
            // break. SMTP and the API never let a bare one through to the queue, so only the line-break-normalized text must survive.
            expected = LineEndings.ToCrlf(expected);
            actual = LineEndings.ToCrlf(actual);
        }

        int at = expected.AsSpan().CommonPrefixLength(actual);
        Guard.Check(
            at == expected.Length && at == actual.Length,
            $"the downgrade changed the decoded content of {path} ({before.ContentType.MimeType}) at byte {at}: [{Show(expected, at)}] became [{Show(actual, at)}]");
    }

    private static string Show(byte[] data, int at) =>
        Convert.ToHexString(data.AsSpan(Math.Max(0, at - 8), Math.Min(data.Length, at + 8) - Math.Max(0, at - 8)));

    private static IReadOnlyList<byte[]> Seeds() =>
    [
        Latin1("From: a@example.com\r\nTo: b@example.net\r\nSubject: café\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: 8bit\r\n\r\nCafé crème, mostly ASCII text.\r\n"),
        Utf8("From: a@example.com\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n日本語の本文です。\r\n"),
        Latin1("From: a@example.com\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b1\"\r\n\r\npreamble\r\n--b1\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nnaïve\r\n--b1\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n\u0000ÿ\u0080\r\n--b1\r\nContent-Type: text/plain\r\n\r\nseven bit\r\n--b1--\r\nepilogue\r\n"),
        Latin1("From: a@example.com\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: message/rfc822\r\n\r\nFrom: n@example.com\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: 8bit\r\n\r\nnested é\r\n--x--\r\n"),
        Latin1("From: a@example.com\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nalready =E9 but é\r\n"),
        Latin1("From: a@example.com\r\nContent-Type: message/global\r\n\r\nFrom: é@example.com\r\n\r\nbody é\r\n"),
        Latin1("From: a@example.com\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\r\n" + new string('a', 75) + "é\r\n--b1\r\n.\r\nFrom the start\r\n" + new string('b', 200) + "é \r\n"),
        Latin1("From: a@example.com\r\nContent-Type: multipart/alternative; boundary=b1\r\n\r\n--b1\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" + new string('x', 74) + "--b1é\r\n--b1--\r\n"),
    ];

    private static IReadOnlyList<byte[]> Tokens() =>
    [
        Latin1("\r\n"), Latin1("\n"), Latin1("\r"), Latin1("é"), Latin1("ÿ"), Latin1("\u0000"), Latin1(" \r\n"), Latin1("\t\r\n"), Latin1("=\r\n"), Latin1("--b1\r\n"), Latin1("--b1--"),
        Latin1("Content-Transfer-Encoding: 8bit\r\n"), Latin1("Content-Transfer-Encoding: binary\r\n"), Latin1("Content-Transfer-Encoding: base64\r\n"), Latin1("Content-Type: message/rfc822\r\n"),
        Latin1("Content-Type: multipart/mixed; boundary=b1\r\n"), Latin1("Content-Type: text/plain\r\n"), Latin1("\r\n\r\n"), Latin1("."), Latin1("From "), Utf8("€"),
    ];

    private static byte[] Latin1(string s) => Encoding.Latin1.GetBytes(s);

    private static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);
}

/// <summary>
/// The message builder behind <c>POST /send</c>: every field of the request (names, subject, bodies, custom headers, attachment names
/// and types, message ids) reaches it. The input is split into fields at 0xFF bytes. Refusals must be the documented exceptions; a built
/// message must be well formed (CRLF only, no line over 998 octets, 7-bit unless allowed) and contain exactly the header fields the model
/// asked for, so that no field value can add a header of its own.
/// </summary>
internal static class MessageBuilderTarget
{
    private const byte Separator = 0xFF;
    private static readonly FixedClock Clock = new(new DateTimeOffset(2026, 10, 13, 12, 0, 0, TimeSpan.Zero));

    private static readonly HashSet<string> BuilderHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Date", "From", "Sender", "Reply-To", "To", "Cc", "Bcc", "Subject", "Message-ID", "In-Reply-To", "References", "MIME-Version",
        "Content-Type", "Content-Transfer-Encoding", "Content-Disposition", "Content-ID",
    };

    public static FuzzTarget Create() => new("message-builder", "Message builder used by the send API (header encoding and folding, bodies, attachments)", Run, Seeds())
    {
        Tokens = Tokens(),
        MutationIterations = 40000,
        MaxInputLength = 64 * 1024,
    };

    private static void Run(ReadOnlySpan<byte> input)
    {
        var fields = Split(input);
        string Field(int i) => i < fields.Count ? Encoding.UTF8.GetString(fields[i]) : string.Empty;
        byte flags = fields.Count > 0 && fields[0].Length > 0 ? fields[0][0] : (byte)0;
        bool utf8Headers = (flags & 1) != 0;
        bool eightBitBody = (flags & 2) != 0;

        var builder = new MessageBuilder(new MessageBuilderOptions { MessageIdDomain = "mail.example.com", Clock = Clock, AllowUtf8Headers = utf8Headers, Allow8BitBody = eightBitBody })
        {
            IncludeBccHeader = (flags & 4) != 0,
        };

        try
        {
            if (!Mailbox.TryParse(Field(1), out var from))
            {
                from = new Mailbox(Field(2), EmailAddress.Parse("sender@example.com"));
            }

            builder.From = from;
            if (Mailbox.TryParse(Field(3), out var to))
            {
                builder.To.Add(to);
            }

            builder.Subject = NullIfEmpty(Field(4));
            builder.TextBody = NullIfEmpty(Field(5));
            builder.HtmlBody = NullIfEmpty(Field(6));
            builder.MessageId = NullIfEmpty(Field(7));
            builder.InReplyTo = NullIfEmpty(Field(8));
            if (Field(9).Length > 0)
            {
                builder.References.Add(Field(9));
            }

            if (Field(10).Length > 0)
            {
                builder.AddHeader(Field(10), Field(11));
            }

            if (Field(12).Length > 0)
            {
                byte[] content = fields.Count > 14 ? fields[14] : [];
                builder.Attachments.Add(new BuilderAttachment(Field(12), Field(13).Length > 0 ? Field(13) : "application/octet-stream", content)
                {
                    IsInline = (flags & 8) != 0,
                    ContentId = NullIfEmpty(Field(15)),
                });
            }
        }
        catch (Exception ex) when (ex is ArgumentException or MessageBuildException or FormatException)
        {
            return;   // the documented refusals of the model setters, AddHeader and BuilderAttachment
        }

        byte[] message;
        try
        {
            (message, var info) = builder.Build();
            Guard.Check(info.Length == message.Length, "BuiltMessage.Length differs from the bytes written");
        }
        catch (Exception ex) when (ex is HeaderInjectionException or MessageBuildException)
        {
            return;
        }

        CheckWellFormed(message, utf8Headers, eightBitBody);
        CheckHeaders(message, builder);
    }

    private static void CheckWellFormed(byte[] message, bool utf8Headers, bool eightBitBody)
    {
        Guard.Check(message.Length >= 2 && message[^2] == '\r' && message[^1] == '\n', "the message does not end with CRLF");
        int lineStart = 0;
        for (int i = 0; i < message.Length; i++)
        {
            byte b = message[i];
            Guard.Check(b != 0, $"NUL at offset {i}");
            if (b == '\r')
            {
                Guard.Check(i + 1 < message.Length && message[i + 1] == '\n', $"bare CR at offset {i}");
            }
            else if (b == '\n')
            {
                Guard.Check(i > 0 && message[i - 1] == '\r', $"bare LF at offset {i}");
                Guard.Check(i - 1 - lineStart <= 998, $"line of {i - 1 - lineStart} octets at offset {lineStart} (RFC 5322 allows 998)");
                lineStart = i + 1;
            }
        }

        int bodyOffset = HeaderList.FindBodyOffset(message);
        Guard.Check(utf8Headers || Ascii.IsValid(message.AsSpan(0, bodyOffset)), "8-bit header without AllowUtf8Headers");
        Guard.Check(eightBitBody || Ascii.IsValid(message.AsSpan(bodyOffset)), "8-bit body without Allow8BitBody");
    }

    private static void CheckHeaders(byte[] message, MessageBuilder builder)
    {
        var headers = HeaderList.Parse(message);
        Guard.Check(!headers.HasMalformedHeaders, "the builder wrote a header line without a colon");
        string? custom = builder.CustomHeaders.Count > 0 ? builder.CustomHeaders[0].Name : null;
        foreach (var h in headers)
        {
            Guard.Check(
                BuilderHeaders.Contains(h.Name) || string.Equals(h.Name, custom, StringComparison.OrdinalIgnoreCase),
                $"a header the model did not ask for: {h.Name}");
        }

        Guard.Check(headers.CountOf(HeaderId.From) == 1, "exactly one From");
        Guard.Check(headers.CountOf(HeaderId.MessageId) == 1, "exactly one Message-ID");
        Guard.Check(headers.CountOf(HeaderId.Subject) == (builder.Subject is null ? 0 : 1), "Subject count differs from the model");
        if (custom is not null && !BuilderHeaders.Contains(custom))
        {
            Guard.Check(headers.CountOf(custom) == 1, "the custom header is not there exactly once");
        }

        // The subject reads back as it was given (folding and encoded words may only change runs of white space).
        if (builder.Subject is not null && headers.TryGetFirst(HeaderId.Subject, out var subject))
        {
            string decoded = Collapse(subject.GetDecodedValue(1 << 20));
            Guard.Check(decoded == Collapse(builder.Subject), $"the subject does not read back: [{builder.Subject}] became [{decoded}]");
        }

        // The From mailbox reads back: the same address, and the display name up to runs of white space. Only within what the parser reads
        // of a header value (MimeLimits.MaxHeaderValueBytes): the builder itself sets no limit on a display name.
        Guard.Check(headers.TryGetFirst(HeaderId.From, out var fromHeader), "no From");
        if (fromHeader.GetUnfoldedValueLength() > MimeLimits.Default.MaxHeaderValueBytes)
        {
            return;
        }

        var fromList = AddressList.Parse(fromHeader);
        Guard.Check(fromList.Count == 1 && fromList[0] is Mailbox { IsValid: true }, $"From does not parse as one mailbox: {fromHeader.GetValue(2000)}");
        var from = (Mailbox)fromList[0];
        Guard.Check(string.Equals(from.AddrSpec, builder.From!.AddrSpec, StringComparison.Ordinal), $"the From address does not read back: {builder.From.AddrSpec} became {from.AddrSpec}");
        Guard.Check(
            Collapse(from.DisplayName ?? string.Empty) == Collapse(builder.From.DisplayName ?? string.Empty),
            $"the From display name does not read back: [{builder.From.DisplayName}] became [{from.DisplayName}]");
    }

    private static string Collapse(string s) => string.Join(' ', s.Split((char[])[' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries));

    private static string? NullIfEmpty(string s) => s.Length == 0 ? null : s;

    private static List<byte[]> Split(ReadOnlySpan<byte> input)
    {
        var fields = new List<byte[]>();
        while (true)
        {
            int next = input.IndexOf(Separator);
            if (next < 0)
            {
                fields.Add(input.ToArray());
                return fields;
            }

            fields.Add(input[..next].ToArray());
            input = input[(next + 1)..];
        }
    }

    private static byte[] Join(params string[] fields)
    {
        var output = new List<byte>();
        for (int i = 0; i < fields.Length; i++)
        {
            if (i > 0)
            {
                output.Add(Separator);
            }

            output.AddRange(Encoding.UTF8.GetBytes(fields[i]));
        }

        return output.ToArray();
    }

    // Field order: flags, From (parsed), From display name, To, Subject, text, HTML, Message-ID, In-Reply-To, References, custom
    // header name, custom header value, attachment file name, attachment type, attachment content, Content-ID.
    private static IReadOnlyList<byte[]> Seeds() =>
    [
        Join("\0", "Alice <alice@example.com>", "", "Bob <bob@example.net>", "Hello", "Hi Bob,\r\nplain text.", "", "", "", "", "X-Campaign", "spring"),
        Join("\0", "", "Jürgen \"Quote\" Müller", "b@example.net", "Grüße aus Köln – " + new string('x', 120), "Text", "<p>HTML</p>", "<id@example.com>", "parent@example.com", "<a@b> <c@d>"),
        Join("\u0003", "田中 <田中@例え.jp>", "", "", "件名のテスト", "本文", "", "", "", "", "", "", "résumé.pdf", "application/pdf", "%PDF-1.4"),
        Join("\b", "a@example.com", "", "b@example.net", "inline", "", "<img src=\"cid:logo\">", "", "", "", "List-Unsubscribe", "<https://example.com/u?a=b>", "logo.png", "image/png", "\u0089PNG", "logo"),
        Join("\0", "a@example.com", "", "b@example.net", "=?utf-8?q?looks_encoded?= but is not", new string('y', 2000), "", "", "", "", "X-Long", new string('z', 1500)),
        Join("\0", "a@example.com", "", "b@example.net", "inject\r\nBcc: victim@example.org", "body", "", "", "", "", "X-Evil", "a\r\nBcc: x@example.org"),
        Join("\0", "a@example.com", "", "b@example.net", "", "", "", "no-brackets", "", "", "Content-Type", "text/html", "../../etc/passwd", "text/plain; name=\"x\"\r\nX: y", "data"),
    ];

    private static IReadOnlyList<byte[]> Tokens() =>
        new[] { "ÿ", "\r\n", "\n", "\r", "\0", "\t", " ", "=?", "?=", "=?utf-8?B?", "\"", "\\", "<", ">", "@", ",", ";", ":", "(", ")", "é", "€", "😀", "Bcc: ", "X-" }
            .Select(s => s == "ÿ" ? [Separator] : Encoding.UTF8.GetBytes(s)).ToList();
}
