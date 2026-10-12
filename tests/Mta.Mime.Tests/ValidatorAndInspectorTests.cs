using System.Buffers;
using System.Text;

namespace Mta.Mime.Tests;

public class ValidatorAndInspectorTests
{
    private static MessageValidationResult Validate(string text, MimeLimits? limits = null, MessageValidationOptions? options = null) =>
        MessageValidator.Validate(T.Crlf(text), limits, options);

    [Fact]
    public void Clean_message_has_no_errors()
    {
        var r = Validate(T.SimpleMessage);
        Assert.False(r.HasErrors);
        Assert.Empty(r.Issues);
        Assert.Null(r.WorstSeverity);
        Assert.Equal(7, r.HeaderCount);
    }

    [Fact]
    public void Missing_from()
    {
        var r = Validate("Subject: x\nDate: Mon, 05 Oct 2026 14:03:09 +0000\nMessage-ID: <a@b>\n\nbody");
        Assert.True(r.Has(MessageIssueCode.MissingFrom));
        Assert.True(r.HasErrors);
        Assert.Equal(IssueSeverity.Error, r.WorstSeverity);
    }

    [Theory]
    [InlineData("From", "a@example.com")]
    [InlineData("Subject", "s")]
    [InlineData("Date", "Mon, 05 Oct 2026 14:03:09 +0000")]
    [InlineData("To", "x@example.net")]
    [InlineData("Message-ID", "<a@b>")]
    [InlineData("Content-Type", "text/plain")]
    [InlineData("Reply-To", "x@example.net")]
    [InlineData("MIME-Version", "1.0")]
    public void Duplicate_singleton_headers(string name, string value)
    {
        var r = Validate($"From: a@example.com\nSubject: s\nDate: Mon, 05 Oct 2026 14:03:09 +0000\nTo: x@example.net\nMessage-ID: <a@b>\nContent-Type: text/plain\nReply-To: x@example.net\nMIME-Version: 1.0\n{name}: {value}\n\nbody");
        var issue = Assert.Single(r.Issues, i => i.Code == MessageIssueCode.DuplicateSingletonHeader);
        Assert.Equal(name, issue.HeaderName);
        Assert.Equal(IssueSeverity.Error, issue.Severity);
    }

    [Fact]
    public void Received_and_other_headers_may_repeat()
    {
        var r = Validate("From: a@example.com\nReceived: a\nReceived: b\nX-Foo: 1\nX-Foo: 2\n\nbody");
        Assert.False(r.Has(MessageIssueCode.DuplicateSingletonHeader));
        Assert.Equal(2, r.ReceivedCount);
    }

    [Fact]
    public void Invalid_from_and_multiple_from_mailboxes()
    {
        Assert.True(Validate("From: not an address at all\n\nx").Has(MessageIssueCode.InvalidFrom));
        Assert.True(Validate("From: a@example.com, b@example.com\n\nx").Has(MessageIssueCode.MultipleFromWithoutSender));
        Assert.False(Validate("From: a@example.com, b@example.com\nSender: a@example.com\n\nx").Has(MessageIssueCode.MultipleFromWithoutSender));
    }

    [Fact]
    public void Date_and_message_id_checks()
    {
        var r = Validate("From: a@example.com\n\nx");
        Assert.True(r.Has(MessageIssueCode.MissingDate));
        Assert.True(r.Has(MessageIssueCode.MissingMessageId));
        Assert.True(Validate("From: a@example.com\nDate: yesterday\n\nx").Has(MessageIssueCode.InvalidDate));
    }

    [Fact]
    public void Line_endings_and_control_bytes()
    {
        Assert.True(MessageValidator.Validate(Encoding.ASCII.GetBytes("From: a@example.com\nSubject: x\n\nbody\n")).Has(MessageIssueCode.BareLineFeed));
        var cr = MessageValidator.Validate(Encoding.ASCII.GetBytes("From: a@example.com\r\nSubject: x\r\n\r\nbo\rdy\r\n"));
        Assert.True(cr.Has(MessageIssueCode.BareCarriageReturn));
        Assert.True(cr.HasErrors);
        var nulHeader = MessageValidator.Validate(Encoding.ASCII.GetBytes("From: a@example.com\r\nSubject: x\0\r\n\r\nbody"));
        Assert.True(nulHeader.Has(MessageIssueCode.NulInHeaders));
        Assert.True(nulHeader.HasErrors);
        var nulBody = MessageValidator.Validate(Encoding.ASCII.GetBytes("From: a@example.com\r\n\r\nbo\0dy"));
        Assert.True(nulBody.Has(MessageIssueCode.NulInBody));
        Assert.False(nulBody.Has(MessageIssueCode.NulInHeaders));
    }

    [Fact]
    public void Line_length_and_header_limits()
    {
        Assert.True(Validate("From: a@example.com\nSubject: " + new string('a', 1500) + "\n\nx").Has(MessageIssueCode.HeaderLineTooLong));
        var body = Validate("From: a@example.com\n\n" + new string('a', 1500));
        Assert.True(body.Has(MessageIssueCode.BodyLineTooLong));
        Assert.False(body.HasErrors || body.Issues.Any(i => i.Severity == IssueSeverity.Error && i.Code == MessageIssueCode.BodyLineTooLong));

        string many = "From: a@example.com\n" + string.Concat(Enumerable.Range(0, 300).Select(i => $"X-{i}: v\n")) + "\nbody";
        Assert.True(Validate(many, new MimeLimits { MaxHeaderCount = 100 }).Has(MessageIssueCode.TooManyHeaders));
        Assert.True(Validate(many, new MimeLimits { MaxHeaderBytes = 500 }).Has(MessageIssueCode.HeaderBlockTooLarge));
    }

    [Fact]
    public void Malformed_headers_and_missing_separator()
    {
        Assert.True(Validate("From: a@example.com\nthis is junk\n\nx").Has(MessageIssueCode.MalformedHeader));
        Assert.True(Validate("From: a@example.com\nSubject: x").Has(MessageIssueCode.NoHeaderBodySeparator));
    }

    [Fact]
    public void Eight_bit_and_utf8_are_informational()
    {
        var utf8Headers = MessageValidator.Validate(Encoding.UTF8.GetBytes("From: a@example.com\r\nSubject: café\r\n\r\nx"));
        Assert.Equal(IssueSeverity.Info, Assert.Single(utf8Headers.Issues, i => i.Code == MessageIssueCode.Utf8Headers).Severity);
        var eightBitBody = MessageValidator.Validate(Encoding.UTF8.GetBytes("From: a@example.com\r\n\r\ncafé"));
        Assert.Equal(IssueSeverity.Info, Assert.Single(eightBitBody.Issues, i => i.Code == MessageIssueCode.EightBitBody).Severity);
    }

    [Fact]
    public void Mail_loop_detection()
    {
        string hops = string.Concat(Enumerable.Repeat("Received: from a by b\n", 120));
        Assert.True(Validate("From: a@example.com\n" + hops + "\nx").Has(MessageIssueCode.TooManyReceivedHeaders));
        Assert.False(Validate("From: a@example.com\n" + hops + "\nx", options: new MessageValidationOptions { MaxReceivedHeaders = 500 }).Has(MessageIssueCode.TooManyReceivedHeaders));
    }

    [Fact]
    public void Mime_structure_problems()
    {
        var r = Validate("From: a@example.com\nContent-Type: multipart/mixed; boundary=B\n\n--B\n\nx\n");
        Assert.True(r.Has(MessageIssueCode.MimeStructure));
        Assert.True(r.Anomalies.HasAny(MimeAnomaly.MissingCloseDelimiter));
        var off = Validate("From: a@example.com\nContent-Type: multipart/mixed; boundary=B\n\n--B\n\nx\n", options: new MessageValidationOptions { CheckMimeStructure = false });
        Assert.False(off.Has(MessageIssueCode.MimeStructure));
    }

    [Fact]
    public void Validation_never_throws_on_garbage()
    {
        var rng = new Random(7);
        for (int i = 0; i < 300; i++)
        {
            var data = new byte[rng.Next(0, 400)];
            rng.NextBytes(data);
            Assert.NotNull(MessageValidator.Validate(data));
        }
    }

    // ---- inspector and line endings

    [Fact]
    public void Inspector_reports_facts()
    {
        var m = MessageInspector.Inspect(Encoding.UTF8.GetBytes("A: b\nC: café\r\n\r\nbody é\r\n" + new string('x', 300) + "\r\nx\ry\0"));
        Assert.True(m.HasBareLf);
        Assert.True(m.HasBareCr);
        Assert.True(m.HasNul);
        Assert.True(m.HasNonAsciiHeaders);
        Assert.True(m.HasNonAsciiBody);
        Assert.True(m.HasHeaderBodySeparator);
        Assert.Equal(300, m.LongestBodyLine);
        Assert.Equal(8, m.LongestHeaderLine); // "C: caf" + 2 bytes for the accented letter
        Assert.Equal("A: b\nC: café\r\n\r\n".Length + 1, m.HeaderLength);
    }

    [Fact]
    public void Inspector_clean_message()
    {
        var m = MessageInspector.Inspect(T.Crlf(T.SimpleMessage));
        Assert.False(m.HasBareLf || m.HasBareCr || m.HasNul || m.HasNonAsciiHeaders || m.HasNonAsciiBody);
    }

    [Fact]
    public void Inspector_handles_empty_and_unterminated()
    {
        Assert.False(MessageInspector.Inspect(default).HasHeaderBodySeparator);
        Assert.True(MessageInspector.Inspect("A: b\r\nC: d"u8).LongestHeaderLine == 4);
    }

    [Theory]
    [InlineData("a\r\nb", false, false)]
    [InlineData("a\nb", true, false)]
    [InlineData("a\rb", false, true)]
    [InlineData("a\r\n\nb", true, false)]
    [InlineData("a\r", false, true)]
    [InlineData("\n", true, false)]
    [InlineData("\r\r\n", false, true)]
    [InlineData("", false, false)]
    public void Detects_bare_lf_and_cr(string text, bool bareLf, bool bareCr)
    {
        var bytes = Encoding.ASCII.GetBytes(text);
        Assert.Equal(bareLf, MessageInspector.ContainsBareLf(bytes));
        Assert.Equal(bareCr, MessageInspector.ContainsBareCr(bytes));
    }

    [Theory]
    [InlineData("a\nb\n", "a\r\nb\r\n")]
    [InlineData("a\r\nb\r\n", "a\r\nb\r\n")]
    [InlineData("a\rb", "a\r\nb")]
    [InlineData("a\r\n\nb\r", "a\r\n\r\nb\r\n")]
    [InlineData("\n\n", "\r\n\r\n")]
    [InlineData("\r\r\n", "\r\n\r\n")]
    [InlineData("", "")]
    [InlineData("plain", "plain")]
    public void Normalizes_to_crlf(string input, string expected)
    {
        Assert.Equal(expected, Encoding.ASCII.GetString(LineEndings.ToCrlf(Encoding.ASCII.GetBytes(input))));
    }

    [Fact]
    public void Bare_cr_handling_options()
    {
        var input = Encoding.ASCII.GetBytes("a\rb\nc");
        Assert.Equal("a\rb\r\nc", Encoding.ASCII.GetString(LineEndings.ToCrlf(input, BareCrHandling.Keep)));
        Assert.Equal("ab\r\nc", Encoding.ASCII.GetString(LineEndings.ToCrlf(input, BareCrHandling.Remove)));
        Assert.True(LineEndings.NeedsNormalization(input));
        Assert.False(LineEndings.NeedsNormalization(Encoding.ASCII.GetBytes("a\r\nb")));
        Assert.True(LineEndings.NeedsNormalization(Encoding.ASCII.GetBytes("a\rb")));
        Assert.False(LineEndings.NeedsNormalization(Encoding.ASCII.GetBytes("a\rb"), BareCrHandling.Keep));
    }

    [Fact]
    public void Normalization_result_has_no_bare_line_endings_for_random_input()
    {
        var rng = new Random(11);
        for (int i = 0; i < 500; i++)
        {
            var data = new byte[rng.Next(0, 200)];
            for (int j = 0; j < data.Length; j++)
            {
                data[j] = (byte)"ab\r\n"[rng.Next(4)];
            }

            var result = LineEndings.ToCrlf(data);
            Assert.False(MessageInspector.ContainsBareLf(result));
            Assert.False(MessageInspector.ContainsBareCr(result));
            Assert.Equal(result, LineEndings.ToCrlf(result)); // idempotent
        }
    }

    [Fact]
    public void Writes_normalized_output_to_a_buffer_writer()
    {
        var w = new ArrayBufferWriter<byte>();
        LineEndings.ToCrlf("x\ny"u8, w);
        Assert.Equal("x\r\ny", Encoding.ASCII.GetString(w.WrittenSpan));
    }

    [Fact]
    public void Detects_utf8_and_eight_bit()
    {
        Assert.False(MessageInspector.HasUtf8Headers(T.Crlf(T.SimpleMessage)));
        Assert.False(MessageInspector.HasUtf8OrEightBitBody(T.Crlf(T.SimpleMessage)));
        var utf8 = Encoding.UTF8.GetBytes("Subject: café\r\n\r\nplain");
        Assert.True(MessageInspector.HasUtf8Headers(utf8));
        Assert.True(MessageInspector.HasValidUtf8Headers(utf8));
        Assert.False(MessageInspector.HasUtf8OrEightBitBody(utf8));
        var latin1 = new byte[] { (byte)'S', (byte)':', (byte)' ', 0xE9, (byte)'\r', (byte)'\n', (byte)'\r', (byte)'\n', 0xE9 };
        Assert.True(MessageInspector.HasUtf8Headers(latin1));
        Assert.False(MessageInspector.HasValidUtf8Headers(latin1));
        Assert.True(MessageInspector.HasUtf8OrEightBitBody(latin1));
        // 8-bit bytes in the body must not be mistaken for header bytes
        Assert.False(MessageInspector.HasUtf8Headers("S: x\r\n\r\né"u8.ToArray()));
    }
}
