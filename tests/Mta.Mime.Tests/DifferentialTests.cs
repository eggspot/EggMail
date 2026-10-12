using System.Text;
using Mk = MimeKit;

namespace Mta.Mime.Tests;

/// <summary>
/// Differential tests against MimeKit 4.x as an oracle: the same corpus is parsed by both and the results must agree,
/// except for the differences documented in docs/components/mime.md (listed in <see cref="KnownDifferences"/>).
/// </summary>
public class DifferentialTests
{
    static DifferentialTests() => MimeCharsets.RegisterCodePages();

    private static Mk.MimeMessage MkLoad(byte[] raw)
    {
        using var ms = new MemoryStream(raw);
        return Mk.MimeMessage.Load(Mk.ParserOptions.Default, ms);
    }

    // ------------------------------------------------------------------ messages

    public static IEnumerable<object[]> Messages() => Corpus.Select(kv => new object[] { kv.Key });

    private static readonly Dictionary<string, string> Corpus = new()
    {
        ["simple"] = T.SimpleMessage,
        ["qp-utf8-and-encoded-subject"] =
            "From: =?utf-8?Q?J=C3=BCrgen_M=C3=BCller?= <jm@example.com>\nTo: \"Doe, John\" <john@example.com>, jane@example.org (Jane)\nSubject: =?utf-8?B?SGVsbG8gV8O2cmxk?=\nDate: Tue, 06 Oct 2026 10:00:00 +0000\nMessage-ID: <1@example.com>\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: quoted-printable\n\nGr=C3=BC=C3=9Fe aus M=C3=BCnchen =\nund mehr text\nzweite zeile=\n",
        ["alternative"] =
            "From: a@example.com\nTo: b@example.net\nSubject: alt\nMIME-Version: 1.0\nContent-Type: multipart/alternative; boundary=\"=_alt\"\n\nThis is a multi-part message.\n--=_alt\nContent-Type: text/plain; charset=us-ascii\n\nplain text\n--=_alt\nContent-Type: text/html; charset=utf-8\nContent-Transfer-Encoding: base64\n\nPHA+aHRtbCBib2R5PC9wPg==\n--=_alt--\n",
        ["mixed-with-attachment"] =
            "From: a@example.com\nTo: b@example.net\nSubject: att\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=outer\n\n--outer\nContent-Type: multipart/alternative; boundary=inner\n\n--inner\nContent-Type: text/plain\n\nplain\n--inner\nContent-Type: text/html\n\n<b>html</b>\n--inner--\n--outer\nContent-Type: application/pdf; name=\"report.pdf\"\nContent-Disposition: attachment; filename=\"report.pdf\"\nContent-Transfer-Encoding: base64\n\nJVBERi0xLjQKJcOkw7zDtsOfCjIgMCBvYmoKPDwvTGVuZ3RoIDMgMCBSPj4Kc3RyZWFt\nZW5kc3RyZWFtCg==\n--outer--\n",
        ["related-inline-image"] =
            "From: a@example.com\nSubject: rel\nMIME-Version: 1.0\nContent-Type: multipart/related; boundary=rel; type=\"text/html\"\n\n--rel\nContent-Type: text/html\n\n<img src=\"cid:x\">\n--rel\nContent-Type: image/gif\nContent-ID: <x>\nContent-Disposition: inline; filename=x.gif\nContent-Transfer-Encoding: base64\n\nR0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7\n--rel--\n",
        ["rfc2231-filename-continuations"] =
            "From: a@example.com\nSubject: 2231\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: application/octet-stream\nContent-Disposition: attachment;\n filename*0*=utf-8''long%20na;\n filename*1*=me%20%E2%82%AC.bin\nContent-Transfer-Encoding: base64\n\nAAEC\n--b--\n",
        ["iso-8859-1-qp"] =
            "From: a@example.com\nSubject: =?iso-8859-1?Q?caf=E9?=\nMIME-Version: 1.0\nContent-Type: text/plain; charset=iso-8859-1\nContent-Transfer-Encoding: quoted-printable\n\ncaf=E9 cr=E8me\n",
        ["embedded-rfc822"] =
            "From: a@example.com\nSubject: fwd\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain\n\nsee attached\n--b\nContent-Type: message/rfc822\n\nFrom: inner@example.org\nSubject: inner\nContent-Type: multipart/alternative; boundary=ib\n\n--ib\nContent-Type: text/plain\n\ninner plain\n--ib\nContent-Type: text/html\n\n<i>inner</i>\n--ib--\n--b--\n",
        ["folded-headers-and-comments"] =
            "From: Alice (the sender)\n <alice@example.com>\nTo: bob@example.net,\n carol@example.org\nSubject: a very long subject line that is folded\n over several lines\n\tand tabs\nContent-Type: text/plain;\n charset=\"utf-8\";\n format=flowed\n\nbody\n",
        ["no-headers-but-body"] = "\nbody only\n",
        ["epilogue-and-preamble"] =
            "From: a@example.com\nContent-Type: multipart/mixed; boundary=\"b b\"\n\npreamble text\n--b b\nContent-Type: text/plain\n\none\n--b b\n\ntwo (default type)\n--b b--\nepilogue text\n",
        ["digest"] =
            "From: a@example.com\nContent-Type: multipart/digest; boundary=d\n\n--d\n\nFrom: x@example.com\nSubject: one\n\nbody one\n--d--\n",
        ["base64-with-crlf-lines-and-padding"] =
            "From: a@example.com\nContent-Type: application/octet-stream\nContent-Transfer-Encoding: base64\n\nSGVsbG8sIHdvcmxkIQ==\n",
        ["8bit-utf8-body"] =
            "From: a@example.com\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\nCafé 世界\n",
        ["qp-soft-breaks"] =
            "From: a@example.com\nContent-Type: text/plain\nContent-Transfer-Encoding: quoted-printable\n\nline one\nsoft =\nbreak and =3D sign\n",
        ["text-calendar-attachment"] =
            "From: a@example.com\nContent-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain\n\nhi\n--b\nContent-Type: text/calendar; method=REQUEST\nContent-Disposition: attachment; filename=invite.ics\n\nBEGIN:VCALENDAR\nEND:VCALENDAR\n--b--\n",
    };

    [Theory]
    [MemberData(nameof(Messages))]
    public void Structure_headers_and_decoded_bodies_agree_with_MimeKit(string name)
    {
        byte[] raw = T.Crlf(Corpus[name]);
        var ours = MimeMessage.Parse(raw);
        var theirs = MkLoad(raw);

        Assert.Equal(MkTree(theirs.Body), OurTree(ours.Root));
        ComparePart(ours.Root, theirs.Body, name);
        CompareMessageHeaders(ours, theirs, name);
    }

    private static string OurTree(MimePart p)
    {
        string type = p.ContentType.MimeType;
        return p.Children.Count == 0 ? type : type + "(" + string.Join(",", p.Children.Select(OurTree)) + ")";
    }

    private static string MkTree(Mk.MimeEntity? e)
    {
        if (e is null)
        {
            return "<null>";
        }

        string type = e.ContentType.MimeType;
        switch (e)
        {
            case Mk.Multipart mp:
                return mp.Count == 0 ? type : type + "(" + string.Join(",", mp.Select(MkTree)) + ")";
            case Mk.MessagePart mpart:
                return mpart.Message is null ? type : type + "(" + MkTree(mpart.Message.Body) + ")";
            default:
                return type;
        }
    }

    private static void ComparePart(MimePart ours, Mk.MimeEntity? theirs, string context)
    {
        Assert.NotNull(theirs);
        Assert.Equal(theirs.ContentType.MimeType, ours.ContentType.MimeType);

        // parameters
        foreach (var p in ours.ContentType.Parameters)
        {
            Assert.True(theirs.ContentType.Parameters.TryGetValue(p.Name, out string? v), $"{context}: MimeKit lacks parameter {p.Name}");
            Assert.Equal(v, p.Value);
        }

        Assert.Equal(theirs.ContentType.Parameters.Count, ours.ContentType.Parameters.Count);

        // Content-Disposition
        Assert.Equal(theirs.ContentDisposition?.Disposition?.ToLowerInvariant(), ours.Disposition?.Disposition);
        Assert.Equal(theirs.ContentDisposition?.FileName, ours.Disposition?.FileName);
        Assert.Equal(theirs.ContentId, ours.ContentId);

        switch (theirs)
        {
            case Mk.Multipart mp:
                Assert.Equal(mp.Count, ours.Children.Count);
                Assert.Equal(mp.Boundary, ours.ContentType.Boundary);
                for (int i = 0; i < mp.Count; i++)
                {
                    ComparePart(ours.Children[i], mp[i], context + "/" + i);
                }

                Assert.Equal(Normalize(mp.Preamble), Normalize(T.Str(ours.Preamble)));
                break;
            case Mk.MessagePart mpart:
                if (mpart.Message?.Body is not null)
                {
                    Assert.Single(ours.Children);
                    ComparePart(ours.Children[0], mpart.Message.Body, context + "/msg");
                }

                break;
            case Mk.MimePart leaf:
                {
                    using var ms = new MemoryStream();
                    leaf.Content?.DecodeTo(ms);
                    byte[] expected = ms.ToArray();
                    byte[] actual = ours.GetDecodedBytes();
                    Assert.True(expected.AsSpan().SequenceEqual(actual), $"{context}: decoded body differs\nMimeKit: {Encoding.UTF8.GetString(expected)}\nours:    {Encoding.UTF8.GetString(actual)}");
                    break;
                }
        }
    }

    private static string Normalize(string? s) => (s ?? string.Empty).Replace("\r\n", "\n", StringComparison.Ordinal).Trim();

    private static void CompareMessageHeaders(MimeMessage ours, Mk.MimeMessage theirs, string context)
    {
        // Content-* headers belong to the body entity in MimeKit; compare the remaining message-level headers.
        var ourHeaders = ours.Headers.Where(h => !h.NameEquals("Content-Type") && !h.NameEquals("Content-Transfer-Encoding") && !h.NameEquals("Content-Disposition") && !h.NameEquals("Content-ID") && !h.NameEquals("Content-Description")).ToList();
        var theirHeaders = theirs.Headers.Where(h => !h.Field.StartsWith("Content-", StringComparison.OrdinalIgnoreCase)).ToList();
        Assert.Equal(theirHeaders.Count, ourHeaders.Count);
        for (int i = 0; i < ourHeaders.Count; i++)
        {
            Assert.Equal(theirHeaders[i].Field, ourHeaders[i].Name);
            string expectedRaw = Encoding.UTF8.GetString(theirHeaders[i].RawValue).TrimEnd('\r', '\n');
            string actualRaw = Encoding.UTF8.GetString(ourHeaders[i].RawValue.Span);
            Assert.Equal(expectedRaw, actualRaw);
        }

        // decoded subject, date and addresses
        if (ours.Headers.TryGetFirst(HeaderId.Subject, out var subject))
        {
            Assert.Equal(theirs.Subject, subject.DecodedValue);
        }

        if (ours.Headers.TryGetFirst(HeaderId.Date, out var date))
        {
            Assert.True(MimeDate.TryParse(date.Value, out var ourDate), context);
            Assert.Equal(theirs.Date, ourDate);
            Assert.Equal(theirs.Date.Offset, ourDate.Offset);
        }

        foreach (var (id, list) in new[] { (HeaderId.From, theirs.From), (HeaderId.To, theirs.To), (HeaderId.Cc, theirs.Cc), (HeaderId.ReplyTo, theirs.ReplyTo) })
        {
            if (ours.Headers.TryGetFirst(id, out var h))
            {
                CompareAddresses(list.Mailboxes.ToList(), AddressList.Parse(h).Mailboxes.ToList(), context);
            }
        }
    }

    private static void CompareAddresses(List<Mk.MailboxAddress> theirs, List<Mailbox> ours, string context)
    {
        Assert.Equal(theirs.Count, ours.Count);
        for (int i = 0; i < ours.Count; i++)
        {
            Assert.True(ours[i].IsValid, context);
            Assert.Equal(theirs[i].Address, ours[i].Address.ToString());
            Assert.Equal(string.IsNullOrEmpty(theirs[i].Name) ? null : theirs[i].Name, ours[i].DisplayName);
        }
    }

    // ------------------------------------------------------------------ addresses

    public static IEnumerable<object[]> AddressInputs() =>
        new[]
        {
            "alice@example.com",
            "Alice <alice@example.com>",
            "\"Alice Smith\" <alice@example.com>",
            "\"Smith, Alice\" <alice@example.com>, bob@example.net",
            "alice@example.com (Alice)",
            "Alice Smith <alice@example.com>, Bob <bob@example.net>, carol@example.org",
            "=?utf-8?Q?Alice_M=C3=BCller?= <alice@example.com>",
            "=?iso-8859-1?Q?Andr=E9?= <andre@example.com>",
            "\"=?utf-8?B?QWxpY2U=?=\" <alice@example.com>",
            "<alice@example.com>",
            "Alice <alice@example.com>, ",
            "\"Quoted \\\"inner\\\" Name\" <q@example.com>",
            "First Last <first.last+tag@sub.example.co.uk>",
            "user@[192.0.2.1]",
            "\"local part\"@example.com",
            "Team: a@example.com, b@example.com;",
            "Alice <alice@example.com> (comment)",
            "(leading comment) Alice <alice@example.com>",
            "Route <@relay.example:alice@example.com>",
            "Alice\n <alice@example.com>,\n Bob <bob@example.net>",
        }.Select(s => new object[] { s });

    [Theory]
    [MemberData(nameof(AddressInputs))]
    public void Addresses_agree_with_MimeKit(string input)
    {
        input = input.Replace("\n", "\r\n", StringComparison.Ordinal);
        Assert.True(Mk.InternetAddressList.TryParse(input, out var theirs), input);
        var ours = AddressList.Parse(input);

        Assert.Equal(theirs.Count, ours.Count);
        for (int i = 0; i < ours.Count; i++)
        {
            switch (theirs[i])
            {
                case Mk.MailboxAddress mb:
                    var m = Assert.IsType<Mailbox>(ours[i]);
                    Assert.Equal(mb.Address, m.Address.ToString());
                    Assert.Equal(string.IsNullOrEmpty(mb.Name) ? null : mb.Name, m.DisplayName);
                    break;
                case Mk.GroupAddress g:
                    var og = Assert.IsType<MailboxGroup>(ours[i]);
                    Assert.Equal(g.Name, og.Name);
                    Assert.Equal(g.Members.Mailboxes.Select(x => x.Address), og.Members.Select(x => x.Address.ToString()));
                    break;
            }
        }
    }

    // ------------------------------------------------------------------ encoded words

    public static IEnumerable<object[]> EncodedWordInputs() =>
        new[]
        {
            "=?utf-8?B?SGVsbG8=?=",
            "=?UTF-8?Q?Hello_World?=",
            "=?iso-8859-1?Q?caf=E9?=",
            "=?windows-1252?Q?=80uro?=",
            "=?utf-8?Q?a?= =?utf-8?Q?b?=",
            "=?utf-8?Q?a?=  \t =?utf-8?Q?b?=",
            "plain =?utf-8?Q?encoded?= plain",
            "=?utf-8?B?4g==?= =?utf-8?B?gqw=?=",
            "=?utf-8*en?Q?language?=",
            "no encoded words at all",
            "=?shift_jis?B?k/qWe4zq?=",
            "=?gb2312?B?1tDOxA==?=",
            "=?koi8-r?B?8NLJx9XQ?=",
            "text =?utf-8?Q?one?=\r\n =?utf-8?Q?two?= end",
            "=?utf-8?Q?under_score_and_=3D?=",
            "=?utf-8?q?lower?= =?UTF-8?Q?UPPER?=",
        }.Select(s => new object[] { s });

    [Theory]
    [MemberData(nameof(EncodedWordInputs))]
    public void Encoded_words_agree_with_MimeKit(string input)
    {
        string expected = Mk.Utils.Rfc2047.DecodeText(Encoding.ASCII.GetBytes(input));
        Assert.Equal(expected, Rfc2047.Decode(input));
    }

    [Fact]
    public void Our_encoder_output_decodes_identically_in_MimeKit()
    {
        foreach (string s in new[] { "Café", "世界 世界", "mixed ascii and résumé words", "€" + new string('x', 100), string.Concat(Enumerable.Repeat("üöä ", 60)), "emoji \U0001F600" })
        {
            string encoded = Rfc2047.Encode(s);
            Assert.Equal(s, Mk.Utils.Rfc2047.DecodeText(Encoding.ASCII.GetBytes(encoded)));
        }
    }

    // ------------------------------------------------------------------ dates

    [Theory]
    [InlineData("Mon, 05 Oct 2026 14:03:09 +0200")]
    [InlineData("5 Oct 2026 14:03 +0000")]
    [InlineData("Mon, 5 Oct 2026 14:03:09 -0530")]
    [InlineData("Mon, 05 Oct 2026 14:03:09 GMT")]
    [InlineData("Mon, 05 Oct 2026 14:03:09 EST")]
    [InlineData("Mon, 05 Oct 2026 14:03:09 PDT")]
    [InlineData("Mon, 05 Oct 26 14:03:09 +0000")]
    [InlineData("Mon, 05 Oct 99 14:03:09 +0000")]
    [InlineData("Mon, 05 Oct 2026 14:03:09 +0200 (CEST)")]
    [InlineData("Tue, 6 Oct 2026 01:02:03 UT")]
    public void Dates_agree_with_MimeKit(string text)
    {
        Assert.True(Mk.Utils.DateUtils.TryParse(Encoding.ASCII.GetBytes(text), out var expected), text);
        Assert.True(MimeDate.TryParse(text, out var actual), text);
        Assert.Equal(expected, actual);
        Assert.Equal(expected.Offset, actual.Offset);
    }

    // ------------------------------------------------------------------ transfer decoders

    public static IEnumerable<object[]> Base64Inputs() =>
        new[]
        {
            "SGVsbG8sIHdvcmxkIQ==",
            "SGVsbG8sIHdvcmxkIQ",
            "SGVs\r\nbG8s\r\nIHdv\r\ncmxk\r\nIQ==\r\n",
            "SGVs bG8s",
            "====",
            "",
            "QUJD",
            "QUJDRA==",
            "QUJDREU=",
            "QUJD!!!REVG",
        }.Select(s => new object[] { s });

    [Theory]
    [MemberData(nameof(Base64Inputs))]
    public void Base64_agrees_with_MimeKit(string input)
    {
        byte[] src = Encoding.ASCII.GetBytes(input);
        var decoder = new Mk.Encodings.Base64Decoder();
        var buffer = new byte[decoder.EstimateOutputLength(src.Length) + 8];
        int n = decoder.Decode(src, 0, src.Length, buffer);
        var expected = buffer.AsSpan(0, n).ToArray();

        var writer = new System.Buffers.ArrayBufferWriter<byte>();
        BodyDecoder.Decode(src, ContentTransferEncoding.Base64, writer, long.MaxValue);
        // MimeKit's streaming decoder does not flush an unpadded final quantum; we do (documented). Compare the common prefix.
        Assert.True(writer.WrittenSpan.StartsWith(expected), $"MimeKit {Convert.ToHexString(expected)} vs ours {Convert.ToHexString(writer.WrittenSpan)}");
        Assert.True(writer.WrittenCount - expected.Length <= 2);
    }

    public static IEnumerable<object[]> QuotedPrintableInputs() =>
        new[]
        {
            "plain text",
            "caf=C3=A9",
            "soft =\r\nbreak",
            "a=3Db",
            "tab\there",
            "lowercase =c3=a9",
            "two\r\nlines\r\n",
            "bare\nlf",
        }.Select(s => new object[] { s });

    [Theory]
    [MemberData(nameof(QuotedPrintableInputs))]
    public void Quoted_printable_agrees_with_MimeKit(string input)
    {
        byte[] src = Encoding.ASCII.GetBytes(input);
        var decoder = new Mk.Encodings.QuotedPrintableDecoder();
        var buffer = new byte[decoder.EstimateOutputLength(src.Length) + 8];
        int n = decoder.Decode(src, 0, src.Length, buffer);
        var expected = buffer.AsSpan(0, n).ToArray();

        var writer = new System.Buffers.ArrayBufferWriter<byte>();
        BodyDecoder.Decode(src, ContentTransferEncoding.QuotedPrintable, writer, long.MaxValue);
        Assert.Equal(Encoding.UTF8.GetString(expected).TrimEnd(' '), Encoding.UTF8.GetString(writer.WrittenSpan).TrimEnd(' '));
    }

    // ------------------------------------------------------------------ builder -> MimeKit

    [Fact]
    public void Content_type_parameters_agree_with_MimeKit()
    {
        foreach (string text in new[]
        {
            "text/plain; charset=utf-8",
            "multipart/mixed; boundary=\"a b\"",
            "application/octet-stream; name=\"a;b.txt\"",
            "application/x; name*0=abc; name*1=def",
            "application/x; name*=utf-8''caf%C3%A9",
            "application/x; name*0*=utf-8''caf%C3; name*1*=%A9",
            "text/html; Charset=ISO-8859-1; format=flowed",
            "application/x; a=1; b=\"two words\"; c=3",
        })
        {
            Assert.True(Mk.ContentType.TryParse(text, out var theirs), text);
            var ours = ContentType.Parse(text);
            Assert.Equal(theirs.MimeType, ours.MimeType);
            foreach (var p in theirs.Parameters)
            {
                Assert.Equal(p.Value, ours.Parameters[p.Name]);
            }

            Assert.Equal(theirs.Parameters.Count, ours.Parameters.Count);
        }
    }

    // ------------------------------------------------------------------ documented differences (pinned)

    [Fact]
    public void Documented_difference_quoted_printable_trailing_whitespace_is_stripped_per_rfc_2045()
    {
        byte[] src = "keep  \r\ntrailing   \r\nend"u8.ToArray();
        var decoder = new Mk.Encodings.QuotedPrintableDecoder();
        var buffer = new byte[decoder.EstimateOutputLength(src.Length) + 8];
        string mimeKit = Encoding.ASCII.GetString(buffer, 0, decoder.Decode(src, 0, src.Length, buffer));
        var writer = new System.Buffers.ArrayBufferWriter<byte>();
        BodyDecoder.Decode(src, ContentTransferEncoding.QuotedPrintable, writer, long.MaxValue);
        Assert.Equal("keep  \r\ntrailing   \r\nend", mimeKit);
        Assert.Equal("keep\r\ntrailing\r\nend", Encoding.ASCII.GetString(writer.WrittenSpan));
    }

    [Fact]
    public void Documented_difference_unpadded_base64_in_encoded_word_is_decoded_fully()
    {
        Assert.Equal("Hel", Mk.Utils.Rfc2047.DecodeText("=?utf-8?B?SGVsbG8?="u8.ToArray()));
        Assert.Equal("Hello", Rfc2047.Decode("=?utf-8?B?SGVsbG8?="));
    }

    [Fact]
    public void Documented_difference_stray_semicolon_in_address_list_is_tolerated()
    {
        Assert.False(Mk.InternetAddressList.TryParse("a@example.com,b@example.com;", out _));
        Assert.Equal(2, AddressList.Parse("a@example.com,b@example.com;").MailboxCount);
    }
}
