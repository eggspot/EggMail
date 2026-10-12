using System.Text;

namespace Mta.Mime.Tests;

public class HeaderListTests
{
    [Fact]
    public void Splits_headers_and_body_without_copying()
    {
        var raw = T.Crlf(T.SimpleMessage);
        var memory = new ReadOnlyMemory<byte>(raw);
        var headers = HeaderList.Parse(memory);

        Assert.Equal(7, headers.Count);
        Assert.True(headers.HasSeparator);
        Assert.Equal(MimeAnomaly.None, headers.Anomalies);
        Assert.Equal("Hello world\r\n", T.Str(headers.Body));
        // Slices alias the original buffer: same backing array.
        Assert.True(System.Runtime.InteropServices.MemoryMarshal.TryGetArray(headers.Body, out var seg));
        Assert.Same(raw, seg.Array);
        Assert.Equal(raw.Length - 13, headers.BodyOffset);
    }

    [Fact]
    public void Preserves_order_and_exact_raw_bytes_including_folding()
    {
        var raw = T.Crlf("Subject: first\n  second\n\tthird\nX-Dup: 1\nX-Dup: 2\n\nbody");
        var headers = HeaderList.Parse(raw);

        Assert.Equal(3, headers.Count);
        Assert.Equal("Subject: first\r\n  second\r\n\tthird", T.Str(headers[0].Raw));
        Assert.Equal("X-Dup: 1", T.Str(headers[1].Raw));
        Assert.Equal("X-Dup: 2", T.Str(headers[2].Raw));
        Assert.Equal(0, headers[0].Offset);
        Assert.Equal(T.Str(headers[0].Raw).Length + 2, headers[0].LengthWithLineEnding);
    }

    [Fact]
    public void Unfolds_values_for_dkim()
    {
        var raw = T.Crlf("Subject: first\n  second\n\tthird\n\n");
        var header = HeaderList.Parse(raw)[0];

        Assert.Equal(" first  second\tthird", Encoding.ASCII.GetString(header.GetUnfoldedValueBytes()));
        Assert.Equal("first  second\tthird", header.Value);
        Assert.Equal(header.GetUnfoldedValueBytes().Length, header.GetUnfoldedValueLength());
        Span<byte> buf = stackalloc byte[64];
        int n = header.CopyUnfoldedValueTo(buf);
        Assert.Equal(" first  second\tthird", Encoding.ASCII.GetString(buf[..n]));
    }

    [Fact]
    public void Names_are_case_insensitive_and_identified()
    {
        var headers = HeaderList.Parse(T.Crlf("fRoM: a@b.example\nCONTENT-type: text/plain\nX-Custom: 1\n\n"));

        Assert.Equal(HeaderId.From, headers[0].Id);
        Assert.Equal(HeaderId.ContentType, headers[1].Id);
        Assert.Equal(HeaderId.Unknown, headers[2].Id);
        Assert.True(headers.TryGetFirst("from", out var h));
        Assert.Equal("fRoM", h.Name);
        Assert.True(headers.TryGetFirst("x-custom", out _));
        Assert.Equal(1, headers.CountOf("X-CUSTOM"));
        Assert.Equal(-1, headers.IndexOf("Nope"));
        Assert.Equal("a@b.example", headers.GetFirstValue(HeaderId.From));
    }

    [Theory]
    [InlineData("From: a@b\nSubject: x\n\nbody", MimeAnomaly.BareLf)]
    [InlineData("From: a@b\r\nX: a\rb\r\n\r\nbody", MimeAnomaly.BareCr)]
    [InlineData("From: a@b\r\nX: a\0b\r\n\r\nbody", MimeAnomaly.NulInHeaders)]
    [InlineData("From: a@b\r\nnot a header\r\n\r\nbody", MimeAnomaly.MissingColon)]
    [InlineData("From: a@b\r\nSubject: café\r\n\r\nbody", MimeAnomaly.NonAsciiHeaders)]
    [InlineData("From : a@b\r\n\r\nbody", MimeAnomaly.SpaceBeforeColon)]
    [InlineData("From: a@b\r\nSubject: x", MimeAnomaly.NoHeaderBodySeparator)]
    public void Reports_anomalies(string message, MimeAnomaly expected)
    {
        var headers = HeaderList.Parse(Encoding.UTF8.GetBytes(message));
        Assert.True(headers.Anomalies.HasAny(expected), $"expected {expected}, got {headers.Anomalies}");
    }

    [Fact]
    public void Clean_message_has_no_anomalies()
    {
        Assert.Equal(MimeAnomaly.None, HeaderList.Parse(T.Crlf(T.SimpleMessage)).Anomalies);
    }

    [Fact]
    public void Bare_cr_never_splits_a_header()
    {
        // A receiver that treated CR as a line break would see an injected Bcc header.
        var raw = T.Raw("Subject: hi\rBcc: evil@example.com\r\n\r\nbody");
        var headers = HeaderList.Parse(raw);

        Assert.Single(headers);
        Assert.Equal(-1, headers.IndexOf("Bcc"));
        Assert.True(headers.Anomalies.HasAny(MimeAnomaly.BareCr));
    }

    [Fact]
    public void Malformed_line_is_kept_in_the_list()
    {
        var headers = HeaderList.Parse(T.Crlf("junk line without colon\nFrom: a@b.example\n\n"));

        Assert.Equal(2, headers.Count);
        Assert.True(headers[0].IsMalformed);
        Assert.Equal(string.Empty, headers[0].Name);
        Assert.Equal("junk line without colon", T.Str(headers[0].Raw));
        Assert.False(headers[1].IsMalformed);
    }

    [Fact]
    public void Header_without_trailing_newline_at_eof()
    {
        var headers = HeaderList.Parse(T.Raw("From: a@b"));
        Assert.Single(headers);
        Assert.False(headers.HasSeparator);
        Assert.Equal(headers[0].Raw.Length, headers[0].LengthWithLineEnding);
        Assert.Equal(9, headers.BodyOffset);
    }

    [Fact]
    public void Empty_and_headerless_input()
    {
        Assert.Empty(HeaderList.Parse(ReadOnlyMemory<byte>.Empty));
        var h = HeaderList.Parse(T.Raw("\r\nbody only"));
        Assert.Empty(h);
        Assert.Equal("body only", T.Str(h.Body));
    }

    [Fact]
    public void Header_count_limit_is_enforced_and_body_is_still_found()
    {
        var sb = new StringBuilder();
        for (int i = 0; i < 10_000; i++)
        {
            sb.Append("X-H").Append(i).Append(": v\r\n");
        }

        sb.Append("\r\nbody");
        var headers = HeaderList.Parse(Encoding.ASCII.GetBytes(sb.ToString()), new MimeLimits { MaxHeaderCount = 100 });

        Assert.Equal(100, headers.Count);
        Assert.True(headers.Anomalies.HasAny(MimeAnomaly.TooManyHeaders));
        Assert.Equal("body", T.Str(headers.Body));
    }

    [Fact]
    public void Header_bytes_limit_is_enforced()
    {
        var sb = new StringBuilder();
        for (int i = 0; i < 1000; i++)
        {
            sb.Append("X-H").Append(i).Append(": ").Append('v', 100).Append("\r\n");
        }

        sb.Append("\r\nbody");
        var headers = HeaderList.Parse(Encoding.ASCII.GetBytes(sb.ToString()), new MimeLimits { MaxHeaderBytes = 10_000 });

        Assert.True(headers.Count < 100);
        Assert.True(headers.Anomalies.HasAny(MimeAnomaly.HeaderBlockTooLarge));
        Assert.Equal("body", T.Str(headers.Body));
    }

    [Fact]
    public void Long_line_is_flagged()
    {
        var raw = Encoding.ASCII.GetBytes("Subject: " + new string('a', 2000) + "\r\n\r\n");
        Assert.True(HeaderList.Parse(raw).Anomalies.HasAny(MimeAnomaly.HeaderLineTooLong));
    }

    [Fact]
    public void Huge_header_value_is_truncated_when_read_as_string()
    {
        var raw = Encoding.ASCII.GetBytes("Subject: " + new string('a', 200_000) + "\r\n\r\n");
        var h = HeaderList.Parse(raw)[0];
        Assert.Equal(999, h.GetValue(1000).Length); // 1000 bytes read, leading space trimmed
    }

    [Fact]
    public void Utf8_headers_are_decoded()
    {
        var headers = HeaderList.Parse(Encoding.UTF8.GetBytes("Subject: Grüße ☃\r\n\r\n"));
        Assert.Equal("Grüße ☃", headers[0].Value);
    }

    [Fact]
    public void Eight_bit_latin1_headers_fall_back_to_windows_1252()
    {
        var raw = new byte[] { (byte)'S', (byte)':', (byte)' ', 0xE9, (byte)'\r', (byte)'\n', (byte)'\r', (byte)'\n' };
        Assert.Equal("é", HeaderList.Parse(raw)[0].Value);
    }

    [Fact]
    public void FindBodyOffset_matches_parse()
    {
        foreach (string m in new[] { T.SimpleMessage, "A: b\n\nx", "A: b", "\n\nx", string.Empty })
        {
            var raw = T.Crlf(m);
            Assert.Equal(HeaderList.Parse(raw).BodyOffset, HeaderList.FindBodyOffset(raw));
        }

        var lf = Encoding.ASCII.GetBytes("A: b\n\nbody");
        Assert.Equal(HeaderList.Parse(lf).BodyOffset, HeaderList.FindBodyOffset(lf));
    }

    [Fact]
    public void Enumerates_without_allocation_pattern()
    {
        var headers = HeaderList.Parse(T.Crlf(T.SimpleMessage));
        int n = 0;
        foreach (var h in headers)
        {
            Assert.False(h.IsMalformed);
            n++;
        }

        Assert.Equal(headers.Count, n);
        Assert.Equal(headers.Count, ((IEnumerable<MimeHeader>)headers).Count());
        Assert.Throws<ArgumentOutOfRangeException>(() => headers[headers.Count]);
    }

    [Fact]
    public void Whitespace_only_line_is_a_continuation_not_the_separator()
    {
        var headers = HeaderList.Parse(T.Raw("Subject: a\r\n \r\nX: b\r\n\r\nbody"));
        Assert.Equal(2, headers.Count);
        Assert.Equal("body", T.Str(headers.Body));
    }
}
