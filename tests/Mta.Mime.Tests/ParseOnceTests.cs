using System.Text;

namespace Mta.Mime.Tests;

/// <summary>
/// The submission path parses a message once and shares the parse between the sender check, the header repair and the content extraction,
/// and several parsers answer the common cases without building strings. Each shortcut must give exactly what the general code gives.
/// </summary>
public class ParseOnceTests
{
    private static IEnumerable<byte[]> Samples()
    {
        yield return T.Crlf(T.SimpleMessage);
        yield return T.Crlf(T.Multipart("b1", "Content-Type: text/plain; charset=utf-8\n\nplain part", "Content-Type: text/html\n\n<b>html</b>", "Content-Type: application/pdf; name=\"a b.pdf\"\nContent-Disposition: attachment; filename=\"a b.pdf\"\nContent-Transfer-Encoding: base64\n\nQUJDREVGRw=="));
        yield return T.Crlf("From: a@example.com\nSubject: =?utf-8?Q?Caf=C3=A9?=\nContent-Type: text/plain; charset=iso-8859-1\nContent-Transfer-Encoding: quoted-printable\n\ncaf=E9 =\n");
        yield return T.Crlf("Subject: no body separator");
        foreach (var (_, data) in NastyCorpus.All())
        {
            yield return data;
        }
    }

    [Fact]
    public void Extracting_from_an_already_parsed_message_equals_extracting_from_the_bytes()
    {
        foreach (byte[] raw in Samples())
        {
            var fromBytes = MessageContentExtractor.Extract(raw, 4096);
            var fromParsed = MessageContentExtractor.Extract(MimeMessage.Parse(raw), 4096);
            Assert.Equal(fromBytes.Subject, fromParsed.Subject);
            Assert.Equal(fromBytes.TextBody, fromParsed.TextBody);
            Assert.Equal(fromBytes.HtmlBody, fromParsed.HtmlBody);
            Assert.Equal(fromBytes.Attachments, fromParsed.Attachments);
            Assert.Equal(fromBytes.TextTruncated, fromParsed.TextTruncated);
            Assert.Equal(fromBytes.HtmlTruncated, fromParsed.HtmlTruncated);
            Assert.Equal(fromBytes.SubjectTruncated, fromParsed.SubjectTruncated);
            Assert.Equal(fromBytes.Anomalies, fromParsed.Anomalies);
        }
    }

    [Fact]
    public void Extracting_from_a_message_parsed_with_other_limits_uses_those_limits()
    {
        byte[] raw = T.Crlf("Subject: s\nContent-Type: text/plain\n\nbody\n");
        var limits = new MimeLimits { MaxHeaderCount = 1 };
        var viaBytes = MessageContentExtractor.Extract(raw, 4096, limits);
        var viaParsed = MessageContentExtractor.Extract(MimeMessage.Parse(raw, limits), 4096);
        Assert.Equal(viaBytes.Subject, viaParsed.Subject);   // Subject is the first header, kept; Content-Type was dropped by the limit in both
        Assert.Equal(viaBytes.TextBody, viaParsed.TextBody);
        Assert.Equal(viaBytes.Anomalies, viaParsed.Anomalies);
    }

    private static IEnumerable<byte[]> BodySamples()
    {
        foreach (byte[] sample in Samples())
        {
            yield return sample;
        }

        const string Head = "From: a@example.com\nSubject: s\n";
        yield return T.Crlf(Head + "Content-Type: text/plain; charset=utf-8\n\nplain ascii\n");
        yield return T.Crlf(Head + "Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\nCafé über € 😀\n");
        yield return T.Crlf(Head + "Content-Type: text/plain; charset=UTF-8\n\n﻿with a byte order mark\n");
        yield return T.Crlf(Head + "\nno content type, plain\n");
        yield return T.Crlf(Head + "\nno content type, café in utf-8\n");
        yield return T.Crlf(Head + "Content-Type: text/plain; charset=x-unknown\n\nunknown charset, café\n");
        yield return T.Crlf(Head + "Content-Type: text/plain; charset=us-ascii\n\nascii label, café\n");
        yield return T.Crlf(Head + "Content-Type: text/plain; charset=iso-8859-1\nContent-Transfer-Encoding: 8bit\n\nlatin1 é\n");
        yield return Concat(Encoding.ASCII.GetBytes("From: a@example.com\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"), [0x63, 0x61, 0x66, 0xE9, 0x0D, 0x0A]);
        yield return Concat(Encoding.ASCII.GetBytes("From: a@example.com\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"), [0x63, 0xC3, 0x28, 0x0D, 0x0A]);   // invalid UTF-8 labelled utf-8
        yield return Concat(Encoding.ASCII.GetBytes("From: a@example.com\r\n\r\n"), [0x63, 0xE9, 0x0D, 0x0A]);   // unlabelled latin-1
        yield return Concat(Encoding.ASCII.GetBytes("From: a@example.com\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"), [0x61, 0x00, 0x62, 0x0D, 0x0A]);   // NUL
        yield return T.Crlf(Head + "Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: quoted-printable\n\nCaf=C3=A9\n");
        yield return T.Crlf(Head + "Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: base64\n\nQ2Fm w6k=\n");
        yield return T.Crlf(Head + "Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: binary\n\nbinary\n");
        yield return T.Crlf(Head + "Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: x-weird\n\nweird\n");
        yield return T.Crlf(Head + "Content-Type: text/html; charset=utf-8\n\n<p>html café</p>\n");
        yield return T.Crlf(Head + "Content-Type: text/plain; charset=utf-8\nContent-Disposition: attachment; filename=\"a.txt\"\n\nattached text\n");
        yield return T.Crlf(T.Multipart("b2", "Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\nplain café", "Content-Type: text/html; charset=utf-8\n\n<b>html café</b>", "Content-Type: text/plain; charset=utf-8\n\nsecond plain part"));
        yield return T.Crlf(Head + "Content-Type: text/plain; charset=utf-8\n\n" + new string('x', 600) + " café " + new string('y', 600) + "\n");
    }

    private static byte[] Concat(byte[] a, byte[] b) => [.. a, .. b];

    [Fact]
    public void Bodies_taken_as_utf8_are_exactly_the_utf8_of_the_strings_the_plain_extraction_gives()
    {
        int bytesUsed = 0;
        foreach (byte[] raw in BodySamples())
        {
            foreach (int max in new[] { 4096, 64, 5, 0 })
            {
                var plain = MessageContentExtractor.Extract(MimeMessage.Parse(raw), max);
                var viaBytes = MessageContentExtractor.Extract(MimeMessage.Parse(raw), max, bodiesAsUtf8: true);
                string? text = viaBytes.TextBodyUtf8 is { } t ? Encoding.UTF8.GetString(t.Span) : viaBytes.TextBody;
                string? html = viaBytes.HtmlBodyUtf8 is { } h ? Encoding.UTF8.GetString(h.Span) : viaBytes.HtmlBody;
                Assert.Equal(plain.TextBody, text);
                Assert.Equal(plain.HtmlBody, html);
                Assert.Equal(plain.Subject, viaBytes.Subject);
                Assert.Equal(plain.Attachments, viaBytes.Attachments);
                Assert.Equal(plain.TextTruncated, viaBytes.TextTruncated);
                Assert.Equal(plain.HtmlTruncated, viaBytes.HtmlTruncated);
                Assert.Equal(plain.IsTruncated, viaBytes.IsTruncated);
                Assert.Equal(plain.Anomalies, viaBytes.Anomalies);
                Assert.True(viaBytes.TextBodyUtf8 is null || viaBytes.TextBody is null);
                Assert.True(viaBytes.HtmlBodyUtf8 is null || viaBytes.HtmlBody is null);
                if (viaBytes.TextBodyUtf8 is not null || viaBytes.HtmlBodyUtf8 is not null)
                {
                    bytesUsed++;
                }
            }
        }

        Assert.True(bytesUsed > 10, "the shortcut must be taken for the ordinary UTF-8 bodies");

        // Which bodies take it: the ones that need nothing done to them.
        Assert.NotNull(UtfOf("Content-Type: text/plain; charset=utf-8\n\nplain\n"));
        Assert.NotNull(UtfOf("Content-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: 8bit\n\ncafé\n"));
        Assert.NotNull(UtfOf("\nno header at all, ascii\n"));
        Assert.Null(UtfOf("Content-Type: text/plain; charset=iso-8859-1\nContent-Transfer-Encoding: 8bit\n\ncafé\n"));   // would be recoded
        Assert.Null(UtfOf("Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: base64\n\nQ2Fm\n"));   // decoded first
        Assert.Null(UtfOf("Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: quoted-printable\n\ncaf=C3=A9\n"));

        static ReadOnlyMemory<byte>? UtfOf(string headersAndBody) =>
            MessageContentExtractor.Extract(MimeMessage.Parse(T.Crlf("From: a@example.com\n" + headersAndBody)), 4096, bodiesAsUtf8: true).TextBodyUtf8;
    }

    private static string Describe(MimeMessage message)
    {
        var sb = new StringBuilder();
        sb.Append(message.Anomalies).Append(' ').Append(message.PartCount).Append(' ').Append(message.Headers.Count).Append(' ').Append(message.Headers.BodyOffset).Append('\n');
        foreach (MimeHeader h in message.Headers)
        {
            sb.Append(h.Id).Append('|').Append(h.Name).Append('|').Append(h.Offset).Append('|').Append(h.Value).Append('\n');
        }

        foreach (MimePart part in message.EnumerateParts())
        {
            sb.Append(part.Depth).Append(' ').Append(part.ContentType.MimeType).Append(' ').Append(part.ContentType.Charset).Append(' ').Append(part.ContentType.Boundary)
                .Append(' ').Append(part.TransferEncoding).Append(' ').Append(part.Anomalies).Append(' ').Append(part.Body.Length).Append('\n');
        }

        return sb.ToString();
    }

    [Fact]
    public void A_parse_with_lent_buffers_equals_a_plain_parse_and_the_buffers_can_be_reused()
    {
        var buffers = new MimeParseBuffers();
        var samples = Samples().ToList();

        // Header blocks of different sizes in a row (the lent array is reused, grown, forgotten when oversized), including hostile ones that outgrow the initial capacity.
        var manyFields = new StringBuilder();
        for (int i = 0; i < 300; i++)
        {
            manyFields.Append("X-Field-").Append(i).Append(": value ").Append(i).Append('\n');
        }

        samples.Add(T.Crlf(manyFields + "\nbody\n"));
        var hostile = new StringBuilder();
        for (int i = 0; i < 2500; i++)
        {
            hostile.Append("X-").Append(i).Append(": v\n");
        }

        samples.Add(T.Crlf(hostile + "\nbody\n"));
        samples.Add(T.Crlf("Subject: small\n\nx\n"));
        samples.Add([]);

        for (int round = 0; round < 3; round++)
        {
            foreach (byte[] raw in samples)
            {
                string expected = Describe(MimeMessage.Parse(raw));
                string actual = Describe(MimeMessage.Parse(raw, null, buffers));
                Assert.Equal(expected, actual);
                buffers.Release();
            }
        }
    }

    [Fact]
    public void Releasing_the_buffers_drops_what_the_records_pointed_at()
    {
        // The lent array must not keep the last message (which may sit in a pooled buffer) reachable through its header records.
        var buffers = new MimeParseBuffers();
        WeakReference weak = ParseIntoBuffers(buffers);
        buffers.Release();
        for (int i = 0; i < 4 && weak.IsAlive; i++)
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
        }

        Assert.False(weak.IsAlive);
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private static WeakReference ParseIntoBuffers(MimeParseBuffers buffers)
    {
        byte[] raw = T.Crlf(T.SimpleMessage);
        _ = MimeMessage.Parse(raw, null, buffers);
        return new WeakReference(raw);
    }

    [Fact]
    public void Content_types_that_repeat_are_shared_and_give_what_a_plain_parse_gives()
    {
        string[] values =
        [
            "text/plain; charset=utf-8", "text/plain; charset=UTF-8", "text/plain;charset=\"iso-8859-1\"", "text/html; charset=utf-8", "text/plain; format=flowed; delsp=yes; charset=us-ascii",
            "text/plain", "application/octet-stream", "not a content type", "text/", "/plain", "multipart/mixed; boundary=\"abc\"", "image/png; name=\"a.png\"", "text/plain; charset=utf-8; x-extra=1",
        ];
        var cache = new ContentTypeCache();   // a cache of its own: the shared one is also filled by every other test of the process
        foreach (string value in values)
        {
            var header = HeaderList.Parse(T.Crlf($"Content-Type: {value}\n\nbody\n")).Single();
            var first = ContentType.ParseHeader(header, MimeLimits.Default, cache);
            var second = ContentType.ParseHeader(header, MimeLimits.Default, cache);
            var plain = ContentType.Parse(value);
            Assert.Equal(plain.MimeType, first.MimeType);
            Assert.Equal(plain.Charset, first.Charset);
            Assert.Equal(plain.Anomalies, first.Anomalies);
            Assert.Equal(plain.Parameters.Select(p => (p.Name, p.Value)), first.Parameters.Select(p => (p.Name, p.Value)));
            bool shareable = !value.Contains("boundary", StringComparison.Ordinal) && !value.Contains("name=", StringComparison.Ordinal) && !value.Contains("x-extra", StringComparison.Ordinal);
            Assert.Equal(shareable, ReferenceEquals(first, second));
        }

        // Other limits give a result of their own (the limits shape the parse), never the shared object.
        var limitedHeader = HeaderList.Parse(T.Crlf("Content-Type: text/plain; charset=utf-8; format=flowed\n\nbody\n")).Single();
        var limited = ContentType.ParseHeader(limitedHeader, new MimeLimits { MaxParameters = 1 }, cache);
        Assert.Single(limited.Parameters);
        Assert.Equal(2, ContentType.ParseHeader(limitedHeader, MimeLimits.Default, cache).Parameters.Count);

        // A full table stops taking values and still parses everything correctly.
        var small = new ContentTypeCache(maxEntries: 3);
        for (int i = 0; i < 10; i++)
        {
            var h = HeaderList.Parse(T.Crlf($"Content-Type: text/plain; charset=x-{i}\n\nbody\n")).Single();
            Assert.Equal($"x-{i}", ContentType.ParseHeader(h, MimeLimits.Default, small).Charset);
        }

        Assert.Equal(3, small.Count);
    }

    [Fact]
    public void The_shared_content_type_cache_is_safe_to_use_from_many_threads_at_once()
    {
        // Fresh cache, many threads asking and adding the same and different values from the first call on: no lookup may fail half made, and every answer is the right type.
        for (int round = 0; round < 20; round++)
        {
            var cache = new ContentTypeCache(maxEntries: 64);
            var headers = Enumerable.Range(0, 24)
                .Select(i => HeaderList.Parse(T.Crlf($"Content-Type: text/plain; charset=x-{i % 12}\n\nbody\n")).Single())
                .ToArray();
            Parallel.For(0, 16, new ParallelOptions { MaxDegreeOfParallelism = 16 }, worker =>
            {
                for (int i = 0; i < 2000; i++)
                {
                    var h = headers[(worker + i) % headers.Length];
                    var parsed = ContentType.ParseHeader(h, MimeLimits.Default, cache);
                    Assert.Equal("text/plain", parsed.MimeType);
                    Assert.Equal($"x-{(worker + i) % headers.Length % 12}", parsed.Charset);
                }
            });
            Assert.True(cache.Count <= 12);
        }

        // The process-wide instance, the one parsing uses, under the same load.
        byte[] raw = T.Crlf("From: a@example.com\nContent-Type: text/plain; charset=utf-8\n\nbody\n");
        Parallel.For(0, 16, new ParallelOptions { MaxDegreeOfParallelism = 16 }, _ =>
        {
            for (int i = 0; i < 2000; i++)
            {
                Assert.Equal("utf-8", MimeMessage.Parse(raw).Root.ContentType.Charset);
            }
        });
    }

    private static MimeHeader FromHeader(string value)
    {
        var headers = HeaderList.Parse(Encoding.UTF8.GetBytes("From: " + value + "\r\n\r\n"));
        Assert.True(headers.TryGetFirst(HeaderId.From, out var h));
        return h;
    }

    public static TheoryData<string> AddressValues =>
    [
        "news@bench.test",
        "Tester <news@bench.test>",
        "  Tester   <news@bench.test>  ",
        "<news@bench.test>",
        "News@Bench.TEST",
        "John Q. Public <john.public+tag@mail.example.co.uk>",
        "O'Brien <ob@example.com>",
        "\"Quoted, Name\" <q@example.com>",
        "Name (comment) <c@example.com>",
        "c2@example.com (Comment)",
        "=?utf-8?Q?Caf=C3=A9?= <cafe@example.com>",
        "a@example.com, b@example.com",
        "a@example.com, b@example.org",
        "Group: a@example.com, b@example.com;",
        "Group: a@example.com, b@example.org;",
        "Undisclosed:;",
        "a@@example.com",
        "@example.com",
        "a@",
        "a@exa mple.com",
        "a b@example.com",
        "Name a@example.com",
        "<a@example.com> trailing",
        "leading <a@example.com> <b@example.com>",
        "<@route:a@example.com>",
        "a@[192.0.2.1]",
        "a@example..com",
        ".a@example.com",
        "a.@example.com",
        "user@münchen.example",
        "ünï <user@example.com>",
        "",
        " ",
        ";",
        ",",
        "<>",
        "<a@example.com",
        "a@example.com>",
        new string('a', 300) + "@example.com",
        "a@" + new string('b', 300) + ".com",
    ];

    [Theory]
    [MemberData(nameof(AddressValues))]
    public void The_common_domain_shortcut_agrees_with_the_full_address_parser(string value)
    {
        Assert.Equal(AddressList.Parse(FromHeader(value)).GetCommonDomain(out string? expectedDomain), AddressList.GetCommonDomain(FromHeader(value), null, out string? domain));
        Assert.Equal(expectedDomain, domain);
    }

    [Fact]
    public void The_common_domain_shortcut_agrees_with_the_full_parser_on_random_values()
    {
        const string alphabet = "abcXYZ019 .-_+@<>,;:\"()\\=?'[]!#";
        var random = new Random(20261013);
        for (int i = 0; i < 20_000; i++)
        {
            int length = random.Next(0, 24);
            var chars = new char[length];
            for (int c = 0; c < length; c++)
            {
                chars[c] = alphabet[random.Next(alphabet.Length)];
            }

            string value = new(chars);
            var header = FromHeader(value);
            var expected = AddressList.Parse(header).GetCommonDomain(out string? expectedDomain);
            var actual = AddressList.GetCommonDomain(header, null, out string? domain);
            Assert.True(expected == actual && expectedDomain == domain, $"value [{value}]: full parser {expected}/{expectedDomain}, shortcut {actual}/{domain}");
        }
    }

    [Fact]
    public void The_common_domain_shortcut_agrees_with_the_full_parser_on_address_shaped_values()
    {
        // Mostly well-formed "Display <local@domain>" values with small damage, so that the shortcut itself (not only the fallback) is exercised.
        const string local = "abcxyz019._+-";
        const string host = "abcxyz019.-";
        const string display = "AbcXyz .'-_";
        var random = new Random(77);
        string Pick(string set, int min, int max) => new(Enumerable.Range(0, random.Next(min, max + 1)).Select(_ => set[random.Next(set.Length)]).ToArray());
        int shortcutHits = 0;
        for (int i = 0; i < 20_000; i++)
        {
            string address = Pick(local, 1, 10) + "@" + Pick(host, 1, 12) + (random.Next(3) == 0 ? "." + Pick("abc", 2, 4) : "");
            string value = random.Next(4) switch
            {
                0 => address,
                1 => "<" + address + ">",
                2 => Pick(display, 1, 12) + " <" + address + ">",
                _ => Pick(display, 0, 6) + "<" + address + ">" + Pick(" x", 0, 2),
            };
            var header = FromHeader(value);
            var expected = AddressList.Parse(header).GetCommonDomain(out string? expectedDomain);
            var actual = AddressList.GetCommonDomain(header, null, out string? domain);
            Assert.True(expected == actual && expectedDomain == domain, $"value [{value}]: full parser {expected}/{expectedDomain}, shortcut {actual}/{domain}");
            shortcutHits += expected == CommonDomainResult.Single ? 1 : 0;
        }

        Assert.True(shortcutHits > 5_000, $"only {shortcutHits} of the generated values were valid addresses");
    }

    [Fact]
    public void The_common_domain_of_a_folded_value_is_still_found()
    {
        var headers = HeaderList.Parse(Encoding.UTF8.GetBytes("From: Long Display Name\r\n <news@bench.test>\r\n\r\n"));
        Assert.True(headers.TryGetFirst(HeaderId.From, out var h));
        Assert.Equal(CommonDomainResult.Single, AddressList.GetCommonDomain(h, null, out string? domain));
        Assert.Equal("bench.test", domain);
    }

    [Theory]
    [InlineData("text/plain; charset=utf-8")]
    [InlineData("TEXT/Plain; Charset=\"UTF-8\"")]
    [InlineData("multipart/mixed; boundary=abc")]
    [InlineData("multipart/alternative;\r\n boundary=\"x y\"")]
    [InlineData("text/html;charset=ISO-8859-1;format=flowed")]
    [InlineData("application/octet-stream; name*=utf-8''a%20b.bin")]
    [InlineData("application/x-custom; Name=Value; other=\"q\\\"uote\"")]
    [InlineData("  text/plain  ")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("garbage")]
    [InlineData("text/")]
    [InlineData("/plain")]
    [InlineData("text/plain (comment); charset=utf-8")]
    [InlineData("message/rfc822")]
    [InlineData("text/plain; charset=us-ascii; charset=utf-8")]
    public void A_content_type_read_from_the_header_equals_one_parsed_from_its_value(string value)
    {
        byte[] raw = Encoding.UTF8.GetBytes("Content-Type: " + value + "\r\n\r\nbody");
        var message = MimeMessage.Parse(raw);
        var expected = ContentType.Parse(HeaderList.Parse(raw).GetFirstValue(HeaderId.ContentType));
        var actual = message.Root.ContentType;
        Assert.Equal(expected.MediaType, actual.MediaType);
        Assert.Equal(expected.MediaSubtype, actual.MediaSubtype);
        Assert.Equal(expected.Parameters.ToList(), actual.Parameters.ToList());
        Assert.Equal(expected.Anomalies, actual.Anomalies);
        Assert.Equal(expected.Charset, actual.Charset);
    }

    [Fact]
    public void A_non_ascii_or_long_content_type_takes_the_general_path_and_gives_the_same_result()
    {
        string longParameter = "text/plain; name=\"" + new string('n', 600) + "\"";
        string nonAscii = "text/plain; name=\"café.txt\"";
        foreach (string value in new[] { longParameter, nonAscii })
        {
            byte[] raw = Encoding.UTF8.GetBytes("Content-Type: " + value + "\r\n\r\nbody");
            var expected = ContentType.Parse(HeaderList.Parse(raw).GetFirstValue(HeaderId.ContentType));
            var actual = MimeMessage.Parse(raw).Root.ContentType;
            Assert.Equal(expected.Parameters.ToList(), actual.Parameters.ToList());
            Assert.Equal(expected.MimeType, actual.MimeType);
        }
    }

    [Theory]
    [InlineData("7bit", ContentTransferEncoding.SevenBit)]
    [InlineData("8BIT", ContentTransferEncoding.EightBit)]
    [InlineData("Base64", ContentTransferEncoding.Base64)]
    [InlineData(" quoted-printable ", ContentTransferEncoding.QuotedPrintable)]
    [InlineData("quoted-printable (old)", ContentTransferEncoding.QuotedPrintable)]
    [InlineData("x-uuencode", ContentTransferEncoding.Unknown)]
    [InlineData("", ContentTransferEncoding.SevenBit)]
    public void A_transfer_encoding_read_from_the_header_is_what_parsing_its_value_gives(string value, ContentTransferEncoding expected)
    {
        byte[] raw = Encoding.UTF8.GetBytes("Content-Transfer-Encoding: " + value + "\r\n\r\nbody");
        Assert.Equal(expected, MimeMessage.Parse(raw).Root.TransferEncoding);
    }

    [Fact]
    public async Task Parameters_of_consecutive_headers_do_not_leak_into_each_other()
    {
        // The parameter parser reuses a per-thread work list; two headers in a row (and a failing one in between) must stay independent.
        byte[] first = T.Crlf("Content-Type: multipart/mixed; boundary=one; charset=utf-8\n\n--one\nContent-Type: text/plain; name=second; format=flowed\n\nx\n--one--\n");
        var message = MimeMessage.Parse(first);
        Assert.Equal(new[] { "boundary", "charset" }, message.Root.ContentType.Parameters.Select(p => p.Name));
        var child = Assert.Single(message.Root.Children);
        Assert.Equal(new[] { "name", "format" }, child.ContentType.Parameters.Select(p => p.Name));
        Assert.Equal("second", child.ContentType.Name);

        var parallel = Enumerable.Range(0, 8).Select(i => Task.Run(() =>
        {
            for (int n = 0; n < 500; n++)
            {
                var m = MimeMessage.Parse(Encoding.ASCII.GetBytes($"Content-Type: text/plain; name=n{i}-{n}; charset=us-ascii\r\n\r\nx"));
                Assert.Equal($"n{i}-{n}", m.Root.ContentType.Name);
                Assert.Equal(2, m.Root.ContentType.Parameters.Count);
            }
        })).ToArray();
        await Task.WhenAll(parallel);
    }

    [Fact]
    public void The_header_array_is_sized_for_the_block_and_still_grows_for_a_huge_one()
    {
        var small = HeaderList.Parse(T.Crlf("A: 1\nB: 2\n\nbody"));
        Assert.Equal(2, small.Count);

        string many = string.Concat(Enumerable.Range(0, 3000).Select(i => $"X-{i}: v\r\n"));
        var big = HeaderList.Parse(Encoding.ASCII.GetBytes(many + "\r\nbody"));
        Assert.Equal(1000, big.Count);   // the default MaxHeaderCount
        Assert.True((big.Anomalies & MimeAnomaly.TooManyHeaders) != 0);

        var folded = HeaderList.Parse(Encoding.ASCII.GetBytes("Subject: a\r\n b\r\n c\r\nTo: x@example.com\r\n\r\n"));
        Assert.Equal(2, folded.Count);   // folded lines are one field each, although the block has five lines
    }

    [Fact]
    public void An_editor_that_borrows_the_received_field_writes_the_same_bytes_as_one_that_copies()
    {
        byte[] message = T.Crlf(T.SimpleMessage);
        byte[] received = Encoding.ASCII.GetBytes("Received: from client.test ([127.0.0.1])\r\n\tby egg.local with ESMTP id abc;\r\n\tMon, 12 Oct 2026 08:00:00 +0000\r\n");
        var copying = new MessageHeaderEditor(message).Remove("Bcc").Prepend("Message-ID", "<x@y>").PrependRaw(received).ToArray();
        var borrowing = new MessageHeaderEditor(message).Remove("Bcc").Prepend("Message-ID", "<x@y>").PrependRawWithoutCopy(received).ToArray();
        Assert.Equal(copying, borrowing);
        Assert.StartsWith("Received: from client.test", Encoding.ASCII.GetString(borrowing));
    }

    [Fact]
    public void A_borrowed_field_is_validated_like_a_copied_one()
    {
        var editor = new MessageHeaderEditor(T.Crlf(T.SimpleMessage));
        Assert.Throws<HeaderInjectionException>(() => editor.PrependRawWithoutCopy(Encoding.ASCII.GetBytes("Received: x\r\nBcc: evil@example.com\r\n\r\n")));
        Assert.Throws<HeaderInjectionException>(() => editor.PrependRawWithoutCopy(Encoding.ASCII.GetBytes("no terminator")));
    }

    [Fact]
    public void Header_values_formatted_by_the_editor_are_unchanged_by_the_reused_builder()
    {
        // Prepend formats through a per-thread builder and pooled buffers; folding, UTF-8 and the injection checks must behave as before.
        string longValue = string.Join(' ', Enumerable.Repeat("word", 60));
        var editor = new MessageHeaderEditor(T.Crlf(T.SimpleMessage)).Prepend("X-Long", longValue).Prepend("X-Utf8", "café", allowUtf8: true);
        string text = Encoding.UTF8.GetString(editor.ToArray());
        Assert.StartsWith("X-Utf8: café\r\nX-Long: word", text);
        Assert.True(text.Split("\r\n")[1].Length <= 78 + 2);
        Assert.Throws<HeaderInjectionException>(() => new MessageHeaderEditor(T.Crlf(T.SimpleMessage)).Prepend("X-Bad", "a\r\nBcc: x"));
        Assert.StartsWith("X-After: ok\r\n", Encoding.UTF8.GetString(new MessageHeaderEditor(T.Crlf(T.SimpleMessage)).Prepend("X-After", "ok").ToArray()));   // after a failure the builder is clean again
    }
}
