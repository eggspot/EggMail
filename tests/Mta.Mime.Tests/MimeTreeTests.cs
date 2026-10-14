using System.Buffers;
using System.Text;

namespace Mta.Mime.Tests;

public class MimeTreeTests
{
    private static MimeMessage Parse(string text, MimeLimits? limits = null) => MimeMessage.Parse(T.Crlf(text), limits);

    [Fact]
    public void Single_part_message()
    {
        var msg = Parse(T.SimpleMessage);

        Assert.Equal(1, msg.PartCount);
        Assert.Equal("text/plain", msg.Root.ContentType.MimeType);
        Assert.Equal("utf-8", msg.Root.ContentType.Charset);
        Assert.Empty(msg.Root.Children);
        Assert.Equal(MimeAnomaly.None, msg.Anomalies);
        Assert.Equal("Hello world\r\n", msg.Root.GetText(1000, out bool truncated));
        Assert.False(truncated);
    }

    [Fact]
    public void Defaults_when_headers_are_missing()
    {
        var msg = Parse("From: a@example.com\n\nbody\n");
        Assert.Equal("text/plain", msg.Root.ContentType.MimeType);
        Assert.Equal(ContentTransferEncoding.SevenBit, msg.Root.TransferEncoding);
    }

    [Fact]
    public void Multipart_mixed_with_preamble_and_epilogue()
    {
        var msg = Parse(T.Multipart("BOUND", "Content-Type: text/plain\n\nfirst", "Content-Type: text/html\n\n<b>second</b>"));

        Assert.Equal(3, msg.PartCount);
        Assert.True(msg.Root.IsMultipart);
        Assert.Equal(2, msg.Root.Children.Count);
        Assert.Equal("preamble", T.Str(msg.Root.Preamble));
        Assert.Equal("epilogue\r\n", T.Str(msg.Root.Epilogue));
        Assert.Equal("first", T.Str(msg.Root.Children[0].Body));
        Assert.Equal("<b>second</b>", T.Str(msg.Root.Children[1].Body));
        Assert.Same(msg.Root, msg.Root.Children[0].Parent);
        Assert.Equal(1, msg.Root.Children[0].Depth);
        Assert.Equal(MimeAnomaly.None, msg.Anomalies);
    }

    [Fact]
    public void Part_slices_alias_the_original_buffer()
    {
        var raw = T.Crlf(T.Multipart("B", "Content-Type: text/plain\n\nhello"));
        var msg = MimeMessage.Parse(raw);
        var body = msg.Root.Children[0].Body;
        Assert.True(System.Runtime.InteropServices.MemoryMarshal.TryGetArray(body, out var seg));
        Assert.Same(raw, seg.Array);
    }

    [Fact]
    public void Nested_multipart()
    {
        var inner = "Content-Type: multipart/alternative; boundary=\"IN\"\n\n--IN\nContent-Type: text/plain\n\nplain\n--IN\nContent-Type: text/html\n\n<p>html</p>\n--IN--";
        var msg = Parse(T.Multipart("OUT", inner, "Content-Type: application/pdf\nContent-Disposition: attachment; filename=a.pdf\n\nPDFDATA"));

        Assert.Equal(5, msg.PartCount);
        var alt = msg.Root.Children[0];
        Assert.Equal("multipart/alternative", alt.ContentType.MimeType);
        Assert.Equal(2, alt.Children.Count);
        Assert.Equal("plain", T.Str(alt.Children[0].Body));
        Assert.Equal(2, alt.Children[0].Depth);
        Assert.Equal("a.pdf", msg.Root.Children[1].FileName);
        Assert.Equal(new[] { "multipart/mixed", "multipart/alternative", "text/plain", "text/html", "application/pdf" },
            msg.EnumerateParts().Select(p => p.ContentType.MimeType).ToArray());
    }

    [Fact]
    public void Message_rfc822_part_is_parsed_as_child()
    {
        var msg = Parse(T.Multipart("B", "Content-Type: message/rfc822\n\nFrom: inner@example.com\nSubject: inner\nContent-Type: text/plain\n\ninner body"));
        var part = msg.Root.Children[0];
        Assert.True(part.IsEmbeddedMessage);
        var inner = Assert.Single(part.Children);
        Assert.Equal("inner@example.com", inner.Headers.GetFirstValue(HeaderId.From));
        Assert.Equal("inner body", T.Str(inner.Body));
    }

    [Fact]
    public void Multipart_digest_children_default_to_message_rfc822()
    {
        string text = "Content-Type: multipart/digest; boundary=D\n\n--D\n\nFrom: x@example.com\nSubject: s\n\nbody\n--D--\n";
        var msg = Parse(text);
        var child = Assert.Single(msg.Root.Children);
        Assert.Equal("message/rfc822", child.ContentType.MimeType);
        Assert.Equal("x@example.com", Assert.Single(child.Children).Headers.GetFirstValue(HeaderId.From));
    }

    [Fact]
    public void Missing_close_delimiter()
    {
        var text = "Content-Type: multipart/mixed; boundary=B\n\n--B\nContent-Type: text/plain\n\nlast part runs to the end";
        var msg = Parse(text);
        Assert.True(msg.Anomalies.HasAny(MimeAnomaly.MissingCloseDelimiter));
        Assert.Equal("last part runs to the end", T.Str(Assert.Single(msg.Root.Children).Body));
    }

    [Fact]
    public void Missing_or_empty_boundary_leaves_an_opaque_leaf()
    {
        foreach (string ct in new[] { "multipart/mixed", "multipart/mixed; boundary=", "multipart/mixed; boundary=\"\"" })
        {
            var msg = Parse($"Content-Type: {ct}\n\n--B\nstuff\n--B--\n");
            Assert.Empty(msg.Root.Children);
            Assert.True(msg.Anomalies.HasAny(MimeAnomaly.MissingBoundary), ct);
        }
    }

    [Fact]
    public void No_delimiter_at_all()
    {
        var msg = Parse("Content-Type: multipart/mixed; boundary=B\n\njust text, no delimiters\n");
        Assert.Empty(msg.Root.Children);
        Assert.True(msg.Anomalies.HasAny(MimeAnomaly.MissingCloseDelimiter));
    }

    [Fact]
    public void Boundary_must_match_whole_line()
    {
        // "--BOUNDARYX" and a boundary mentioned mid-line must not split the part.
        var text = "Content-Type: multipart/mixed; boundary=BOUNDARY\n\n--BOUNDARY\nContent-Type: text/plain\n\nline\n--BOUNDARYX not a delimiter\nsee --BOUNDARY here\n--BOUNDARY--\n";
        var msg = Parse(text);
        var part = Assert.Single(msg.Root.Children);
        Assert.Equal("line\r\n--BOUNDARYX not a delimiter\r\nsee --BOUNDARY here", T.Str(part.Body));
    }

    [Fact]
    public void Delimiter_with_transport_padding_and_bare_lf()
    {
        var raw = T.Raw("Content-Type: multipart/mixed; boundary=B\n\n--B  \t\nContent-Type: text/plain\n\none\n--B\n\ntwo\n--B--  \n");
        var msg = MimeMessage.Parse(raw);
        Assert.Equal(2, msg.Root.Children.Count);
        Assert.Equal("one", T.Str(msg.Root.Children[0].Body));
        Assert.Equal("two", T.Str(msg.Root.Children[1].Body));
    }

    [Fact]
    public void Close_delimiter_at_end_of_data_without_newline()
    {
        var raw = T.Raw("Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\n\r\nx\r\n--B--");
        var msg = MimeMessage.Parse(raw);
        Assert.Equal("x", T.Str(Assert.Single(msg.Root.Children).Body));
        Assert.False(msg.Anomalies.HasAny(MimeAnomaly.MissingCloseDelimiter));
    }

    [Fact]
    public void Empty_parts_are_allowed()
    {
        var msg = Parse("Content-Type: multipart/mixed; boundary=B\n\n--B\n--B\n\n--B--\n");
        Assert.Equal(2, msg.Root.Children.Count);
        Assert.Equal(0, msg.Root.Children[0].Body.Length);
    }

    [Fact]
    public void Depth_limit_makes_deeper_multiparts_opaque()
    {
        var sb = new StringBuilder();
        const int depth = 40;
        for (int i = 0; i < depth; i++)
        {
            sb.Append($"Content-Type: multipart/mixed; boundary=b{i}\n\n--b{i}\n");
        }

        sb.Append("Content-Type: text/plain\n\ndeep\n");
        for (int i = depth - 1; i >= 0; i--)
        {
            sb.Append($"--b{i}--\n");
        }

        var msg = Parse(sb.ToString(), new MimeLimits { MaxDepth = 10 });
        Assert.True(msg.Anomalies.HasAny(MimeAnomaly.MaxDepthExceeded));
        Assert.True(msg.EnumerateParts().Max(p => p.Depth) <= 10);

        var unlimited = Parse(sb.ToString(), new MimeLimits { MaxDepth = 64 });
        Assert.False(unlimited.Anomalies.HasAny(MimeAnomaly.MaxDepthExceeded));
        Assert.Equal(depth + 1, unlimited.PartCount);
    }

    [Fact]
    public void Part_count_limit()
    {
        var parts = Enumerable.Repeat("Content-Type: text/plain\n\nx", 5000).ToArray();
        var msg = Parse(T.Multipart("B", parts), new MimeLimits { MaxParts = 50 });
        Assert.Equal(50, msg.PartCount);
        Assert.Equal(49, msg.Root.Children.Count);
        Assert.True(msg.Anomalies.HasAny(MimeAnomaly.TooManyParts));
    }

    [Fact]
    public void Duplicate_boundary_in_nested_multipart_is_opaque()
    {
        var inner = "Content-Type: multipart/mixed; boundary=\"SAME\"\n\ninner stuff";
        var msg = Parse(T.Multipart("SAME", inner));
        Assert.True(msg.Anomalies.HasAny(MimeAnomaly.DuplicateBoundary));
        Assert.All(msg.EnumerateParts(), p => Assert.True(p.Depth <= 2));
    }

    [Fact]
    public void Very_long_boundary_is_rejected()
    {
        string boundary = new string('b', 1000);
        var msg = Parse($"Content-Type: multipart/mixed; boundary={boundary}\n\n--{boundary}\n\nx\n--{boundary}--\n");
        Assert.Empty(msg.Root.Children);
        Assert.True(msg.Anomalies.HasAny(MimeAnomaly.MissingBoundary));
    }

    [Fact]
    public void Cte_on_a_multipart_is_ignored_for_structure()
    {
        var text = "Content-Type: multipart/mixed; boundary=B\nContent-Transfer-Encoding: base64\n\n--B\n\nx\n--B--\n";
        Assert.Single(Parse(text).Root.Children);
    }

    [Fact]
    public void Message_rfc822_with_encoding_is_not_descended()
    {
        var msg = Parse("Content-Type: message/rfc822\nContent-Transfer-Encoding: base64\n\nRnJvbTogeA0K\n");
        Assert.Empty(msg.Root.Children);
    }

    [Fact]
    public void Decodes_bodies_lazily()
    {
        string b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("café 世界"), Base64FormattingOptions.InsertLineBreaks);
        var msg = Parse($"Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: base64\n\n{b64}\n");
        Assert.Equal("café 世界", msg.Root.GetText(1000, out _));
        Assert.Equal(Encoding.UTF8.GetBytes("café 世界"), msg.Root.GetDecodedBytes());
        Assert.Equal(Encoding.UTF8.GetByteCount("café 世界"), msg.Root.GetDecodedLength());
    }

    [Fact]
    public void Charset_decoding_and_fallbacks()
    {
        var latin = MimeMessage.Parse(Concat("Content-Type: text/plain; charset=iso-8859-1\r\n\r\n", new byte[] { 0x63, 0x61, 0x66, 0xE9 }));
        Assert.Equal("café", latin.Root.GetText(100, out _));

        var unknown = MimeMessage.Parse(Concat("Content-Type: text/plain; charset=x-bogus\r\n\r\n", new byte[] { 0x63, 0xE9 }));
        var an = MimeAnomaly.None;
        Assert.Equal("cé", unknown.Root.GetText(100, out _, ref an));
        Assert.True(an.HasAny(MimeAnomaly.UnknownCharset));

        var noCharsetUtf8 = MimeMessage.Parse(Concat("\r\n", Encoding.UTF8.GetBytes("café")));
        Assert.Equal("café", noCharsetUtf8.Root.GetText(100, out _));

        var sjis = MimeMessage.Parse(Concat("Content-Type: text/plain; charset=shift_jis\r\n\r\n", new byte[] { 0x93, 0xFA, 0x96, 0x7B }));
        Assert.Equal("日本", sjis.Root.GetText(100, out _));
    }

    [Fact]
    public void Text_truncation_does_not_end_in_replacement_character()
    {
        var msg = MimeMessage.Parse(Concat("Content-Type: text/plain; charset=utf-8\r\n\r\n", Encoding.UTF8.GetBytes("ab€d")));
        string text = msg.Root.GetText(4, out bool truncated); // cuts inside the 3-byte euro sign
        Assert.True(truncated);
        Assert.Equal("ab", text);
    }

    [Fact]
    public void Decode_to_writer_respects_limit()
    {
        var msg = Parse("Content-Type: application/octet-stream\nContent-Transfer-Encoding: base64\n\n" + Convert.ToBase64String(new byte[5000]) + "\n");
        var w = new ArrayBufferWriter<byte>();
        var result = msg.Root.DecodeBodyTo(w, maxBytes: 100);
        Assert.True(result.Truncated);
        Assert.Equal(100, w.WrittenCount);
        Assert.Equal(5000, msg.Root.GetDecodedLength());
    }

    [Fact]
    public void Disposition_content_id_and_attachment_flags()
    {
        var msg = Parse(T.Multipart("B",
            "Content-Type: image/png\nContent-ID: <logo@cid>\nContent-Disposition: inline; filename=logo.png\n\nPNG",
            "Content-Type: application/zip; name=\"x.zip\"\n\nZIP",
            "Content-Type: text/plain\nContent-Disposition: attachment; filename=n.txt\n\nTXT",
            "Content-Type: text/plain\n\nbody"));
        var kids = msg.Root.Children;
        Assert.Equal("logo@cid", kids[0].ContentId);
        Assert.False(kids[0].IsAttachment);
        Assert.Equal("logo.png", kids[0].FileName);
        Assert.True(kids[1].IsAttachment); // non-text with a name
        Assert.Equal("x.zip", kids[1].FileName);
        Assert.True(kids[2].IsAttachment);
        Assert.False(kids[3].IsAttachment);
        Assert.Null(kids[3].ContentId);
    }

    [Fact]
    public void Header_anomalies_are_collected_per_part_and_overall()
    {
        var raw = T.Raw("Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nBad line\r\nContent-Type: text/plain\r\n\r\nx\r\n--B--\r\n");
        var msg = MimeMessage.Parse(raw);
        Assert.False(msg.Root.Anomalies.HasAny(MimeAnomaly.MissingColon));
        Assert.True(msg.Root.Children[0].Anomalies.HasAny(MimeAnomaly.MissingColon));
        Assert.True(msg.Anomalies.HasAny(MimeAnomaly.MissingColon));
    }

    [Fact]
    public void Boundary_scan_is_linear_on_adversarial_input()
    {
        // Lines that all start with "--" and share a long prefix with the boundary.
        string boundary = new string('a', 190);
        var sb = new StringBuilder();
        sb.Append("Content-Type: multipart/mixed; boundary=").Append(boundary).Append("\n\n");
        for (int i = 0; i < 20_000; i++)
        {
            sb.Append("--").Append('a', 189).Append("b\n");
        }

        string text = sb.ToString();
        var msg = HangGuard.Run(() => Parse(text));
        Assert.Empty(msg.Root.Children);
    }

    [Fact]
    public void Deep_nesting_bomb_is_bounded_in_depth_and_stack()
    {
        var sb = new StringBuilder();
        for (int i = 0; i < 3000; i++)
        {
            sb.Append($"Content-Type: multipart/mixed; boundary=b{i}\n\n--b{i}\n");
        }

        sb.Append("Content-Type: text/plain\n\nx\n");
        string text = sb.ToString();
        var msg = HangGuard.Run(() => Parse(text));
        Assert.True(msg.Anomalies.HasAny(MimeAnomaly.MaxDepthExceeded));
    }

    private static byte[] Concat(string head, byte[] tail) => Encoding.ASCII.GetBytes(head).Concat(tail).ToArray();
}
