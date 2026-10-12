namespace Mta.Mime.Tests;

public class StructuredFieldTests
{
    [Fact]
    public void Parses_content_type_with_parameters()
    {
        var ct = ContentType.Parse("Text/HTML; charset=\"UTF-8\"; format=flowed");

        Assert.Equal("text", ct.MediaType);
        Assert.Equal("html", ct.MediaSubtype);
        Assert.Equal("text/html", ct.MimeType);
        Assert.Equal("utf-8", ct.Charset);
        Assert.Equal("flowed", ct.Parameters["FORMAT"]);
        Assert.True(ct.IsText);
        Assert.True(ct.Matches("TEXT", "*"));
    }

    [Fact]
    public void Missing_or_empty_content_type_is_text_plain()
    {
        Assert.Equal("text/plain", ContentType.Parse(null).MimeType);
        Assert.Equal("text/plain", ContentType.Parse("  ").MimeType);
    }

    [Theory]
    [InlineData("garbage")]
    [InlineData("text/")]
    [InlineData("/plain")]
    [InlineData("text plain")]
    [InlineData(";charset=x")]
    public void Invalid_content_type_becomes_octet_stream(string value)
    {
        var ct = ContentType.Parse(value);
        Assert.Equal("application/octet-stream", ct.MimeType);
        Assert.True(ct.Anomalies.HasAny(MimeAnomaly.InvalidContentType));
    }

    [Fact]
    public void Comments_and_folding_are_ignored()
    {
        var ct = ContentType.Parse("multipart/mixed (a comment (nested)); boundary=abc (another)");
        Assert.Equal("multipart/mixed", ct.MimeType);
        Assert.Equal("abc", ct.Boundary);
    }

    [Fact]
    public void Quoted_pairs_in_parameters()
    {
        var ct = ContentType.Parse("application/x; name=\"a \\\"quoted\\\" \\\\ name\"");
        Assert.Equal("a \"quoted\" \\ name", ct.Name);
    }

    [Fact]
    public void Unquoted_value_may_contain_slash_and_equals()
    {
        var ct = ContentType.Parse("multipart/mixed; boundary=a/b=c");
        Assert.Equal("a/b=c", ct.Boundary);
    }

    [Fact]
    public void Rfc2231_extended_value_with_charset()
    {
        var ct = ContentType.Parse("application/octet-stream; name*=utf-8'en'caf%C3%A9%20menu.txt");
        Assert.Equal("café menu.txt", ct.Name);
        var p = Assert.Single(ct.Parameters);
        Assert.Equal("utf-8", p.Charset);
        Assert.Equal("en", p.Language);
    }

    [Fact]
    public void Rfc2231_continuations_are_joined_in_order()
    {
        var ct = ContentType.Parse("application/x; name*1=\"-two\"; name*0=\"one\"; name*2*=%5Bthree%5D");
        Assert.Equal("one-two[three]", ct.Name);
    }

    [Fact]
    public void Rfc2231_extended_continuations_with_charset_in_first_section()
    {
        var ct = ContentType.Parse("application/x; filename*0*=iso-8859-1''caf%E9; filename*1*=%20menu.txt");
        Assert.Equal("café menu.txt", ct.Parameters["filename"]);
    }

    [Fact]
    public void Rfc2231_extended_form_wins_over_simple_fallback()
    {
        var ct = ContentType.Parse("application/x; name=\"fallback.txt\"; name*=utf-8''real%E2%98%83.txt");
        Assert.Equal("real☃.txt", ct.Name);
        Assert.Single(ct.Parameters);
    }

    [Fact]
    public void Rfc2231_gap_stops_at_the_gap()
    {
        var ct = ContentType.Parse("application/x; name*0=a; name*2=c");
        Assert.Equal("a", ct.Name);
        Assert.True(ct.Anomalies.HasAny(MimeAnomaly.InvalidParameterContinuation));
    }

    [Fact]
    public void Rfc2231_huge_section_numbers_are_not_continuations()
    {
        var ct = ContentType.Parse("application/x; name*999999999=a");
        Assert.Single(ct.Parameters);
        Assert.Equal("name*999999999", ct.Parameters[0].Name);
    }

    [Fact]
    public void Rfc2231_unknown_charset_falls_back()
    {
        var ct = ContentType.Parse("application/x; name*=x-nonsense''caf%C3%A9");
        Assert.Equal("café", ct.Name);
        Assert.True(ct.Anomalies.HasAny(MimeAnomaly.UnknownCharset));
    }

    [Fact]
    public void Rfc2047_encoded_word_in_parameter_is_decoded()
    {
        var ct = ContentType.Parse("application/x; name=\"=?utf-8?B?Y2Fmw6kudHh0?=\"");
        Assert.Equal("café.txt", ct.Name);
    }

    [Fact]
    public void Parameter_count_is_limited()
    {
        var value = "text/plain" + string.Concat(Enumerable.Range(0, 500).Select(i => $"; p{i}=v"));
        var ct = ContentType.Parse(value, new MimeLimits { MaxParameters = 10 });
        Assert.Equal(10, ct.Parameters.Count);
        Assert.True(ct.Anomalies.HasAny(MimeAnomaly.TooManyParameters));
    }

    [Fact]
    public void Garbage_between_parameters_is_skipped()
    {
        var ct = ContentType.Parse("text/plain;;; ; charset=utf-8; =novalue; junk; boundary");
        Assert.Equal("utf-8", ct.Charset);
    }

    [Fact]
    public void Content_type_round_trips_through_header_value()
    {
        var ct = new ContentType("application", "pdf");
        Assert.Equal("application/pdf", ct.ToHeaderValue());
        var parsed = ContentType.Parse("application/pdf; name=\"my file.pdf\"");
        Assert.Equal("application/pdf; name=\"my file.pdf\"", parsed.ToHeaderValue());
        Assert.Throws<ArgumentException>(() => new ContentType("te xt", "plain"));
    }

    [Fact]
    public void Disposition_parses_filename_and_size()
    {
        var d = ContentDisposition.Parse("Attachment; filename=\"report.pdf\"; size=12345");

        Assert.NotNull(d);
        Assert.True(d.IsAttachment);
        Assert.False(d.IsInline);
        Assert.Equal("report.pdf", d.FileName);
        Assert.Equal(12345L, d.Size);
    }

    [Fact]
    public void Disposition_with_extended_filename()
    {
        var d = ContentDisposition.Parse("inline; filename*=UTF-8''%E2%82%AC%20rates.txt");
        Assert.True(d!.IsInline);
        Assert.Equal("€ rates.txt", d.FileName);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(";filename=x")]
    public void Disposition_without_token_is_null(string value) => Assert.Null(ContentDisposition.Parse(value));

    [Theory]
    [InlineData("7bit", ContentTransferEncoding.SevenBit)]
    [InlineData("8BIT", ContentTransferEncoding.EightBit)]
    [InlineData("binary", ContentTransferEncoding.Binary)]
    [InlineData(" Base64 ", ContentTransferEncoding.Base64)]
    [InlineData("quoted-printable", ContentTransferEncoding.QuotedPrintable)]
    [InlineData("Quoted-Printable (comment)", ContentTransferEncoding.QuotedPrintable)]
    [InlineData("", ContentTransferEncoding.SevenBit)]
    [InlineData("x-uuencode", ContentTransferEncoding.Unknown)]
    public void Parses_transfer_encoding(string value, ContentTransferEncoding expected) =>
        Assert.Equal(expected, ContentTransferEncodings.Parse(value));

    [Theory]
    [InlineData("1.0", 1, 0, true)]
    [InlineData(" 1.0 ", 1, 0, true)]
    [InlineData("1.0 (Generated by Mailer)", 1, 0, true)]
    [InlineData("(c) 1 . 0", 1, 0, true)]
    [InlineData("2.1", 2, 1, false)]
    [InlineData("1.00", 1, 0, true)]
    public void Parses_mime_version(string value, int major, int minor, bool supported)
    {
        Assert.True(MimeVersion.TryParse(value, out var v));
        Assert.Equal(new MimeVersion(major, minor), v);
        Assert.Equal(supported, v.IsSupported);
    }

    [Theory]
    [InlineData("")]
    [InlineData("1")]
    [InlineData("1.")]
    [InlineData(".0")]
    [InlineData("1.0.1")]
    [InlineData("one.zero")]
    [InlineData("99999.0")]
    [InlineData("1.0 trailing")]
    public void Rejects_bad_mime_version(string value) => Assert.False(MimeVersion.TryParse(value, out _));

    [Fact]
    public void Mime_version_formats_and_null_is_rejected()
    {
        Assert.Equal("1.0", MimeVersion.Version10.ToString());
        Assert.False(MimeVersion.TryParse((string?)null, out _));
    }

    [Fact]
    public void Transfer_encoding_tokens()
    {
        Assert.Equal("base64", ContentTransferEncoding.Base64.ToToken());
        Assert.Equal("7bit", ContentTransferEncoding.Unknown.ToToken());
    }

    [Fact]
    public void Pathological_comment_nesting_terminates()
    {
        string value = "text/plain " + new string('(', 100_000) + "x";
        var ct = ContentType.Parse(value);
        Assert.Equal("text/plain", ct.MimeType);
    }
}
