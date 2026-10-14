using System.Buffers;
using System.Text;
using Mk = MimeKit;

namespace Mta.Mime.Tests;

/// <summary>
/// The 8BITMIME downgrade (RFC 6152): the result must be 7-bit, keep the MIME structure and decode to exactly the same content as
/// the original. MimeKit is the oracle for "same content"; the cases that cannot be downgraded must be refused with a reason.
/// </summary>
public class EightBitDowngraderTests
{
    static EightBitDowngraderTests() => MimeCharsets.RegisterCodePages();

    private static (EightBitDowngradeResult Result, byte[] Output) Run(byte[] input)
    {
        var writer = new ArrayBufferWriter<byte>();
        var result = EightBitDowngrader.Downgrade(input, writer);
        return (result, writer.WrittenSpan.ToArray());
    }

    private static Mk.MimeMessage MkLoad(byte[] raw)
    {
        using var ms = new MemoryStream(raw);
        return Mk.MimeMessage.Load(Mk.ParserOptions.Default, ms);
    }

    private static string Tree(Mk.MimeEntity? e) => e switch
    {
        Mk.Multipart mp => mp.ContentType.MimeType + "(" + string.Join(",", mp.Select(Tree)) + ")",
        Mk.MessagePart mpart => mpart.ContentType.MimeType + (mpart.Message is null ? "" : "(" + Tree(mpart.Message.Body) + ")"),
        null => "<null>",
        _ => e.ContentType.MimeType,
    };

    private static void CompareContent(Mk.MimeEntity? original, Mk.MimeEntity? downgraded, string path)
    {
        Assert.NotNull(original);
        Assert.NotNull(downgraded);
        switch (original)
        {
            case Mk.Multipart a:
                var b = Assert.IsAssignableFrom<Mk.Multipart>(downgraded);
                Assert.Equal(a.Count, b.Count);
                for (int i = 0; i < a.Count; i++)
                {
                    CompareContent(a[i], b[i], path + "/" + i);
                }

                break;
            case Mk.MessagePart ma:
                var mb = Assert.IsAssignableFrom<Mk.MessagePart>(downgraded);
                CompareContent(ma.Message?.Body, mb.Message?.Body, path + "/msg");
                Assert.Equal(ma.Message?.Subject, mb.Message?.Subject);
                break;
            case Mk.MimePart pa:
                var pb = Assert.IsAssignableFrom<Mk.MimePart>(downgraded);
                Assert.Equal(DecodeAll(pa), DecodeAll(pb));
                Assert.Equal(pa.ContentType.MimeType, pb.ContentType.MimeType);
                Assert.Equal(pa.ContentType.Charset, pb.ContentType.Charset);
                Assert.Equal(pa.FileName, pb.FileName);
                break;
        }
    }

    private static byte[] DecodeAll(Mk.MimePart part)
    {
        using var ms = new MemoryStream();
        part.Content?.DecodeTo(ms);
        return ms.ToArray();
    }

    private static void AssertDowngradedFaithfully(byte[] input)
    {
        var (result, output) = Run(input);
        Assert.Equal(EightBitDowngradeStatus.Downgraded, result.Status);
        int bodyOffset = HeaderList.FindBodyOffset(output);
        Assert.True(System.Text.Ascii.IsValid(output.AsSpan(bodyOffset)), "the body must be 7-bit");
        Assert.False(MessageInspector.HasEightBitBody(output));
        Assert.False(MessageInspector.ContainsBareLf(output));

        var before = MkLoad(input);
        var after = MkLoad(output);
        Assert.Equal(Tree(before.Body), Tree(after.Body));
        CompareContent(before.Body, after.Body, "root");
        Assert.Equal(before.Subject, after.Subject);
        Assert.Equal(before.MessageId, after.MessageId);

        // Our own parser agrees about the structure, and a second downgrade has nothing left to do.
        var ours = MimeMessage.Parse(output);
        Assert.Equal(Tree(after.Body), OurTree(ours.Root));
        Assert.Equal(EightBitDowngradeStatus.NotNeeded, Run(output).Result.Status);
    }

    private static string OurTree(MimePart p) => p.Children.Count == 0 ? p.ContentType.MimeType : p.ContentType.MimeType + "(" + string.Join(",", p.Children.Select(OurTree)) + ")";

    // ------------------------------------------------------------------ simple

    [Fact]
    public void An_ascii_body_needs_no_downgrade_and_writes_nothing()
    {
        var (result, output) = Run(T.Crlf(T.SimpleMessage));
        Assert.Equal(EightBitDowngradeStatus.NotNeeded, result.Status);
        Assert.Empty(output);
    }

    [Fact]
    public void An_8bit_text_body_becomes_quoted_printable_when_mostly_ascii()
    {
        byte[] input = T.Crlf("From: a@example.com\nTo: b@example.net\nSubject: hi\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\nCafé crème brûlée, a rather longer line of plain text so that most of it is ASCII.\nSecond line\n");
        var (result, output) = Run(input);
        Assert.Equal(EightBitDowngradeStatus.Downgraded, result.Status);
        string text = Encoding.ASCII.GetString(output);
        Assert.Contains("Content-Transfer-Encoding: quoted-printable\r\n", text, StringComparison.Ordinal);
        Assert.DoesNotContain("8bit", text, StringComparison.Ordinal);
        Assert.Contains("Caf=C3=A9 cr=C3=A8me", text, StringComparison.Ordinal);
        AssertDowngradedFaithfully(input);
    }

    [Fact]
    public void A_mostly_non_ascii_text_body_becomes_base64()
    {
        byte[] input = T.Crlf("From: a@example.com\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\n世界你好，这是一段很长的中文文本。\n");
        var (_, output) = Run(input);
        Assert.Contains("Content-Transfer-Encoding: base64\r\n", Encoding.ASCII.GetString(output), StringComparison.Ordinal);
        AssertDowngradedFaithfully(input);
    }

    [Fact]
    public void A_body_labelled_7bit_that_holds_8bit_bytes_is_encoded_too()
    {
        byte[] input = T.Crlf("From: a@example.com\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 7bit\n\nGrüße aus München\n");
        AssertDowngradedFaithfully(input);
    }

    [Fact]
    public void A_binary_labelled_attachment_becomes_base64()
    {
        var payload = new byte[300];
        new Random(5).NextBytes(payload);
        var sb = new List<byte>();
        sb.AddRange(Encoding.ASCII.GetBytes("From: a@example.com\r\nMIME-Version: 1.0\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n"));
        sb.AddRange(payload.Select(b => b == 0 ? (byte)0x80 : b));
        byte[] input = sb.ToArray();
        var (result, output) = Run(input);
        Assert.Equal(EightBitDowngradeStatus.Downgraded, result.Status);
        Assert.Contains("Content-Transfer-Encoding: base64\r\n", Encoding.ASCII.GetString(output), StringComparison.Ordinal);
        var ours = MimeMessage.Parse(output);
        Assert.Equal(input.AsSpan(input.Length - 300).ToArray(), ours.Root.GetDecodedBytes());
    }

    [Fact]
    public void A_message_without_any_mime_headers_gets_them_and_a_utf8_charset()
    {
        byte[] input = T.Crlf("From: a@example.com\nTo: b@example.net\nSubject: old style\n\nGrüße aus München, a longer line with mostly plain ASCII text around it.\n");
        var (result, output) = Run(input);
        Assert.Equal(EightBitDowngradeStatus.Downgraded, result.Status);
        string text = Encoding.ASCII.GetString(output);
        Assert.Contains("MIME-Version: 1.0\r\n", text, StringComparison.Ordinal);
        Assert.Contains("Content-Type: text/plain; charset=utf-8\r\n", text, StringComparison.Ordinal);
        Assert.Contains("Content-Transfer-Encoding: quoted-printable\r\n", text, StringComparison.Ordinal);
        var parsed = MkLoad(output);
        Assert.Equal("Grüße aus München, a longer line with mostly plain ASCII text around it.\r\n", Assert.IsType<Mk.TextPart>(parsed.Body).Text.ReplaceLineEndings("\r\n"));
    }

    [Fact]
    public void A_missing_content_type_with_a_non_utf8_body_gets_no_guessed_charset()
    {
        var bytes = new List<byte>(Encoding.ASCII.GetBytes("From: a@example.com\r\n\r\ncaf"));
        bytes.Add(0xE9);
        bytes.AddRange("\r\n"u8.ToArray());
        var (result, output) = Run(bytes.ToArray());
        Assert.Equal(EightBitDowngradeStatus.Downgraded, result.Status);
        string text = Encoding.ASCII.GetString(output);
        Assert.DoesNotContain("Content-Type", text, StringComparison.Ordinal);
        Assert.Contains("caf=E9", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Duplicate_transfer_encoding_fields_collapse_to_one()
    {
        byte[] input = T.Crlf("From: a@example.com\nMIME-Version: 1.0\nContent-Transfer-Encoding: 8bit\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\nÜber\n");
        var (_, output) = Run(input);
        string text = Encoding.ASCII.GetString(output);
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(text, "Content-Transfer-Encoding:"));
    }

    [Fact]
    public void Headers_with_utf8_are_left_alone_and_only_the_body_changes()
    {
        byte[] input = T.Crlf("From: Jürgen <j@example.com>\nSubject: Grüße\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\nÄpfel\n");
        var (result, output) = Run(input);
        Assert.Equal(EightBitDowngradeStatus.Downgraded, result.Status);
        int bodyOffset = HeaderList.FindBodyOffset(output);
        Assert.Contains("Subject: Grüße\r\n", Encoding.UTF8.GetString(output.AsSpan(0, bodyOffset)), StringComparison.Ordinal);
        Assert.True(MessageInspector.HasUtf8Headers(output));
        Assert.False(MessageInspector.HasEightBitBody(output));
    }

    // ------------------------------------------------------------------ multipart and nesting

    [Fact]
    public void Multipart_alternative_with_8bit_text_parts_keeps_boundaries_and_other_parts_byte_exact()
    {
        string source = "From: a@example.com\nTo: b@example.net\nSubject: alt\nMIME-Version: 1.0\nContent-Type: multipart/alternative; boundary=\"=_alt\"\n\nThis is a multi-part message.\n--=_alt\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\nGrüße\n--=_alt\nContent-Type: text/html; charset=utf-8\nContent-Transfer-Encoding: base64\n\nPHA+aHRtbCBib2R5PC9wPg==\n--=_alt--\n";
        byte[] input = T.Crlf(source);
        AssertDowngradedFaithfully(input);
        var (_, output) = Run(input);
        string text = Encoding.ASCII.GetString(output);
        Assert.Contains("--=_alt\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\nPHA+aHRtbCBib2R5PC9wPg==\r\n--=_alt--\r\n", text, StringComparison.Ordinal);
        Assert.StartsWith("From: a@example.com\r\nTo: b@example.net\r\nSubject: alt\r\n", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Nested_multiparts_with_mixed_attachments_downgrade_faithfully()
    {
        var png = new byte[]
        {
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0xFF, 0xFE, 0x80, 0x81,
        };
        var head = "From: a@example.com\r\nTo: b@example.net\r\nSubject: nested\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\nContent-Type: multipart/alternative; boundary=inner\r\n\r\n--inner\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nplain Grüße\r\n--inner\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n<p>Grüße</p>\r\n--inner--\r\n--outer\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: binary\r\nContent-Disposition: attachment; filename=\"x.png\"\r\n\r\n";
        var bytes = new List<byte>(Encoding.UTF8.GetBytes(head));
        bytes.AddRange(png);
        bytes.AddRange(Encoding.ASCII.GetBytes("\r\n--outer--\r\n"));
        AssertDowngradedFaithfully(bytes.ToArray());
    }

    [Fact]
    public void An_embedded_rfc822_message_is_downgraded_inside_without_touching_the_wrapper_type()
    {
        string source = "From: a@example.com\nSubject: fwd\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain\n\nsee attached\n--b\nContent-Type: message/rfc822\nContent-Transfer-Encoding: 8bit\n\nFrom: inner@example.org\nSubject: inner\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\ninner Grüße\n--b--\n";
        byte[] input = T.Crlf(source);
        AssertDowngradedFaithfully(input);
        var (_, output) = Run(input);
        string text = Encoding.ASCII.GetString(output);
        Assert.Contains("Content-Type: message/rfc822\r\nContent-Transfer-Encoding: 7bit\r\n", text, StringComparison.Ordinal);
        Assert.Contains("inner Gr=C3=BC=C3=9Fe", text, StringComparison.Ordinal);
    }

    [Fact]
    public void An_embedded_message_without_mime_headers_gets_them_so_that_its_encoding_means_something()
    {
        string source = "From: a@example.com\nMIME-Version: 1.0\nContent-Type: message/rfc822\n\nFrom: inner@example.org\nSubject: old style\n\ninner Grüße aus München, mostly plain ASCII text around the umlauts here.\n";
        byte[] input = T.Crlf(source);
        var (result, output) = Run(input);
        Assert.Equal(EightBitDowngradeStatus.Downgraded, result.Status);
        var inner = MimeMessage.Parse(output).Root.Children[0];
        Assert.True(inner.Headers.TryGetFirst(HeaderId.MimeVersion, out _));
        Assert.Equal("utf-8", inner.ContentType.Charset);
        Assert.Equal(ContentTransferEncoding.QuotedPrintable, inner.TransferEncoding);
        Assert.Contains("inner Grüße aus München", Encoding.UTF8.GetString(inner.GetDecodedBytes()), StringComparison.Ordinal);
    }

    [Fact]
    public void An_embedded_message_with_a_multipart_body_is_handled_recursively()
    {
        string source = "From: a@example.com\nMIME-Version: 1.0\nContent-Type: message/rfc822\n\nFrom: inner@example.org\nSubject: inner\nMIME-Version: 1.0\nContent-Type: multipart/alternative; boundary=ib\n\n--ib\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\ninner Grüße\n--ib\nContent-Type: text/html\n\n<i>x</i>\n--ib--\n";
        AssertDowngradedFaithfully(T.Crlf(source));
    }

    [Fact]
    public void A_truncated_multipart_without_a_closing_delimiter_is_still_downgraded()
    {
        string source = "From: a@example.com\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\nGrüße und mehr\n--b\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\ncut off Gr";
        var (result, output) = Run(T.Crlf(source));
        Assert.Equal(EightBitDowngradeStatus.Downgraded, result.Status);
        Assert.False(MessageInspector.HasEightBitBody(output));
    }

    [Fact]
    public void A_message_global_part_is_encoded_as_a_whole()
    {
        string source = "From: a@example.com\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain\n\nbounce\n--b\nContent-Type: message/global\nContent-Transfer-Encoding: 8bit\n\nFrom: jürgen@example.org\nSubject: Grüße\n\nbody\n--b--\n";
        var (result, output) = Run(T.Crlf(source));
        Assert.Equal(EightBitDowngradeStatus.Downgraded, result.Status);
        string text = Encoding.ASCII.GetString(output);
        Assert.Contains("Content-Type: message/global\r\nContent-Transfer-Encoding: quoted-printable\r\n", text, StringComparison.Ordinal);
        var ours = MimeMessage.Parse(output);
        var global = ours.Root.Children[1];
        string decoded = Encoding.UTF8.GetString(global.GetDecodedBytes());
        Assert.Contains("From: jürgen@example.org", decoded, StringComparison.Ordinal);
    }

    [Fact]
    public void A_message_global_delivery_status_part_is_encoded_as_text()
    {
        string source = "From: mailer-daemon@example.org\nMIME-Version: 1.0\nContent-Type: multipart/report; report-type=delivery-status; boundary=r\n\n--r\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: base64\n\nSGk=\n--r\nContent-Type: message/global-delivery-status\nContent-Transfer-Encoding: 8bit\n\nReporting-MTA: dns; egg.test\n\nFinal-Recipient: utf-8; jürgen@example.org\nAction: failed\nStatus: 5.6.7\n--r--\n";
        var (result, output) = Run(T.Crlf(source));
        Assert.Equal(EightBitDowngradeStatus.Downgraded, result.Status);
        Assert.False(MessageInspector.HasEightBitBody(output));
        var ours = MimeMessage.Parse(output);
        Assert.Contains("Final-Recipient: utf-8; jürgen@example.org", Encoding.UTF8.GetString(ours.Root.Children[1].GetDecodedBytes()), StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------ refusals

    [Fact]
    public void An_embedded_message_with_8bit_header_fields_cannot_be_downgraded()
    {
        string source = "From: a@example.com\nMIME-Version: 1.0\nContent-Type: message/rfc822\n\nFrom: jürgen@example.org\nSubject: Grüße\n\nbody Grüße\n";
        var (result, _) = Run(T.Crlf(source));
        Assert.Equal(EightBitDowngradeStatus.Impossible, result.Status);
        Assert.Contains("header", result.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_part_with_8bit_header_fields_cannot_be_downgraded()
    {
        string source = "From: a@example.com\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain; name=\"Grüße.txt\"\nContent-Transfer-Encoding: 8bit\n\nGrüße\n--b--\n";
        var (result, _) = Run(T.Crlf(source));
        Assert.Equal(EightBitDowngradeStatus.Impossible, result.Status);
        Assert.Contains("header", result.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_quoted_printable_part_that_contains_8bit_bytes_cannot_be_downgraded()
    {
        string source = "From: a@example.com\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: quoted-printable\n\nGrüße\n";
        var (result, _) = Run(T.Crlf(source));
        Assert.Equal(EightBitDowngradeStatus.Impossible, result.Status);
        Assert.Contains("transfer encoding", result.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void An_8bit_preamble_cannot_be_downgraded()
    {
        string source = "From: a@example.com\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=b\n\nVorspann Grüße\n--b\nContent-Type: text/plain\n\nascii\n--b--\n";
        var (result, _) = Run(T.Crlf(source));
        Assert.Equal(EightBitDowngradeStatus.Impossible, result.Status);
        Assert.Contains("preamble", result.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void An_8bit_multipart_without_a_usable_boundary_cannot_be_downgraded()
    {
        string source = "From: a@example.com\nMIME-Version: 1.0\nContent-Type: multipart/mixed\n\nGrüße\n";
        var (result, _) = Run(T.Crlf(source));
        Assert.Equal(EightBitDowngradeStatus.Impossible, result.Status);
    }

    [Fact]
    public void An_unparsed_message_rfc822_part_beyond_the_depth_limit_cannot_be_downgraded()
    {
        var sb = new StringBuilder("From: a@example.com\nMIME-Version: 1.0\n");
        for (int i = 0; i < 4; i++)
        {
            sb.Append("Content-Type: message/rfc822\n\n");
        }

        sb.Append("Subject: x\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\nGrüße\n");
        var writer = new ArrayBufferWriter<byte>();
        var result = EightBitDowngrader.Downgrade(T.Crlf(sb.ToString()), writer, new MimeLimits { MaxDepth = 2 });
        Assert.Equal(EightBitDowngradeStatus.Impossible, result.Status);
    }

    [Fact]
    public void Another_message_type_with_8bit_content_cannot_be_downgraded()
    {
        string source = "From: a@example.com\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: message/external-body; access-type=anon-ftp\nContent-Transfer-Encoding: 8bit\n\nGrüße\n--b--\n";
        var (result, _) = Run(T.Crlf(source));
        Assert.Equal(EightBitDowngradeStatus.Impossible, result.Status);
        Assert.Contains("message/external-body", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void A_soft_line_break_cannot_forge_a_mime_boundary()
    {
        // 'é' (=C3=A9) and 69 x fill 75 columns; the first '-' of the boundary-looking text would start the next line.
        string source = "From: a@example.com\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=bnd\n\n--bnd\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\né" + new string('x', 69) + "--bnd\nsecond\n--bnd--\n";
        byte[] input = T.Crlf(source);
        var (result, output) = Run(input);
        Assert.Equal(EightBitDowngradeStatus.Downgraded, result.Status);
        Assert.Contains("=\r\n=2D-bnd", Encoding.ASCII.GetString(output), StringComparison.Ordinal);
        Assert.Single(MimeMessage.Parse(output).Root.Children);
        Assert.Single(Assert.IsType<Mk.Multipart>(MkLoad(output).Body));
        AssertDowngradedFaithfully(input);
    }

    [Theory]
    [InlineData(60)]
    [InlineData(68)]
    [InlineData(69)]
    [InlineData(70)]
    [InlineData(74)]
    public void Quoted_printable_never_starts_a_line_with_two_dashes_after_a_soft_break(int filler)
    {
        string text = "é" + new string('x', filler) + "--bnd--\r\nnext";
        var writer = new ArrayBufferWriter<byte>();
        TransferEncoder.WriteQuotedPrintable(Encoding.UTF8.GetBytes(text), writer);
        foreach (string line in Encoding.ASCII.GetString(writer.WrittenSpan).Split("\r\n"))
        {
            Assert.False(line.StartsWith("--", StringComparison.Ordinal), line);
            Assert.True(line.Length <= 76);
        }
    }

    // ------------------------------------------------------------------ random structures

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(9)]
    [InlineData(10)]
    [InlineData(11)]
    [InlineData(12)]
    public void Random_8bit_trees_downgrade_to_the_same_content(int seed)
    {
        var rng = new Random(seed);
        int boundaries = 0;
        for (int round = 0; round < 25; round++)
        {
            var ms = new MemoryStream();
            Write(ms, "From: a@example.com\r\nTo: b@example.net\r\nSubject: random\r\nMessage-ID: <r@example.com>\r\nMIME-Version: 1.0\r\n");
            Generate(ms, rng, 0, ref boundaries, root: true, enclosing: null);
            byte[] input = ms.ToArray();
            var (result, output) = Run(input);
            if (result.Status == EightBitDowngradeStatus.NotNeeded)
            {
                continue;
            }

            Assert.Equal(EightBitDowngradeStatus.Downgraded, result.Status);
            Assert.False(MessageInspector.HasEightBitBody(output));
            var before = MkLoad(input);
            var after = MkLoad(output);
            Assert.Equal(Tree(before.Body), Tree(after.Body));
            CompareContent(before.Body, after.Body, $"seed {seed} round {round}");
        }
    }

    private static void Write(Stream s, string text) => s.Write(Encoding.UTF8.GetBytes(text));

    private static void Generate(MemoryStream s, Random rng, int depth, ref int boundaries, bool root, string? enclosing)
    {
        int kind = depth < 3 ? rng.Next(5) : 3 + rng.Next(2);
        if (kind <= 1)
        {
            string boundary = $"bnd{boundaries++}x{rng.Next(1000)}";
            Write(s, $"Content-Type: multipart/{(rng.Next(2) == 0 ? "mixed" : "alternative")}; boundary=\"{boundary}\"\r\n\r\n");
            if (rng.Next(2) == 0)
            {
                Write(s, "This is a multi-part message in MIME format.\r\n");
            }

            int children = rng.Next(1, 4);
            for (int i = 0; i < children; i++)
            {
                Write(s, "--" + boundary + "\r\n");
                Generate(s, rng, depth + 1, ref boundaries, root: false, enclosing: boundary);
                Write(s, "\r\n");
            }

            Write(s, "--" + boundary + "--\r\n");
            return;
        }

        if (kind == 2)
        {
            Write(s, "Content-Type: message/rfc822\r\n\r\nFrom: inner@example.org\r\nSubject: inner\r\nMIME-Version: 1.0\r\n");
            Generate(s, rng, depth + 1, ref boundaries, root: false, enclosing: enclosing);
            return;
        }

        if (kind == 3)
        {
            string[] samples = ["Grüße aus München", "plain ascii only", "日本語のテキスト", "Ünïcödé line with ünïcödé words and trailing space ", "=3D looks like QP"];
            string cte = new[] { "8bit", "7bit", "8bit" }[rng.Next(3)];
            Write(s, $"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: {cte}\r\n\r\n");
            int lines = rng.Next(1, 5);
            for (int i = 0; i < lines; i++)
            {
                string line = samples[rng.Next(samples.Length)];
                if (enclosing is not null && rng.Next(2) == 0)
                {
                    // The enclosing boundary in the middle of a line, at a column where a soft break would put it at the start of one.
                    line = "é" + new string('x', rng.Next(66, 73)) + "--" + enclosing + "--";
                }

                Write(s, line + (i == lines - 1 && !root ? "" : "\r\n"));
            }

            return;
        }

        var payload = new byte[rng.Next(1, 200)];
        rng.NextBytes(payload);
        Write(s, "Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n");
        // No CR/LF/NUL oddities needed: a binary entity may contain anything but must not contain a delimiter line.
        s.Write(payload.Select(b => b == (byte)'-' ? (byte)0x81 : b).ToArray());
    }
}
