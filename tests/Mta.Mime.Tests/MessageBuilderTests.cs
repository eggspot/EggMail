using System.Buffers;
using System.Text;
using Mta.Core;

namespace Mta.Mime.Tests;

public class MessageBuilderTests
{
    private sealed class FixedClock(DateTimeOffset now) : IClock
    {
        public DateTimeOffset UtcNow { get; } = now;

        public long Timestamp => 0;
    }

    private static readonly DateTimeOffset Now = new(2026, 10, 5, 12, 0, 0, TimeSpan.Zero);

    private static MessageBuilder NewBuilder(MessageBuilderOptions? options = null)
    {
        var b = new MessageBuilder(options ?? new MessageBuilderOptions { MessageIdDomain = "mail.example.com", Clock = new FixedClock(Now) })
        {
            From = Mailbox.Create("Alice", "alice@example.com"),
            Subject = "Hello",
            TextBody = "Hi there",
        };
        b.To.Add(Mailbox.Create("Bob", "bob@example.net"));
        return b;
    }

    [Fact]
    public void Builds_a_minimal_text_message()
    {
        var (bytes, info) = NewBuilder().Build();
        string text = Encoding.ASCII.GetString(bytes);

        Assert.StartsWith("Date: Mon, 05 Oct 2026 12:00:00 +0000\r\nFrom: Alice <alice@example.com>\r\n", text);
        Assert.Contains("To: Bob <bob@example.net>\r\n", text);
        Assert.Contains("Subject: Hello\r\n", text);
        Assert.Contains("MIME-Version: 1.0\r\n", text);
        Assert.Contains("Content-Type: text/plain; charset=us-ascii\r\n", text);
        Assert.Contains("Content-Transfer-Encoding: 7bit\r\n", text);
        Assert.EndsWith("\r\n\r\nHi there\r\n", text);
        Assert.Matches(@"^<[0-9a-f]{32}@mail\.example\.com>$", info.MessageId);
        Assert.Contains("Message-ID: " + info.MessageId + "\r\n", text);
        Assert.Equal(bytes.Length, info.Length);
        Assert.Equal(Now, info.Date);
    }

    [Fact]
    public void Message_id_is_time_ordered_and_unique()
    {
        var clock = new FixedClock(Now);
        string a = MessageBuilder.GenerateMessageId("example.com", clock);
        string b = MessageBuilder.GenerateMessageId("example.com", clock);
        Assert.NotEqual(a, b);
        Assert.Equal(Now, Ids.GetTimestamp(Guid.ParseExact(a[1..a.IndexOf('@')], "N")));
        Assert.Throws<MessageBuildException>(() => MessageBuilder.GenerateMessageId("not a domain"));
    }

    [Fact]
    public void Output_is_crlf_only_with_no_bare_lf_or_cr()
    {
        var b = NewBuilder();
        b.TextBody = "line1\nline2\rline3\r\nline4";
        var (bytes, _) = b.Build();
        Assert.False(MessageInspector.ContainsBareLf(bytes));
        Assert.False(MessageInspector.ContainsBareCr(bytes));
        var parsed = MimeMessage.Parse(bytes);
        Assert.Equal("line1\r\nline2\r\nline3\r\nline4\r\n", parsed.Root.GetText(1000, out _));
    }

    [Fact]
    public void Subject_is_rfc2047_encoded_and_folded()
    {
        var b = NewBuilder();
        b.Subject = "Grüße aus München – " + string.Concat(Enumerable.Repeat("sehr lange Betreffzeile ", 8));
        var (bytes, _) = b.Build();
        string text = Encoding.ASCII.GetString(bytes);

        var headers = HeaderList.Parse(bytes);
        Assert.Equal(b.Subject.TrimEnd(), headers.TryGetFirst("Subject", out var h) ? h.DecodedValue : null);
        Assert.All(text.Split("\r\n"), line => Assert.True(line.Length <= 78, line));
        Assert.True(h.Raw.Length > 78); // it was folded
        Assert.True(System.Text.Ascii.IsValid(bytes));
    }

    [Fact]
    public void Utf8_headers_when_allowed()
    {
        var b = NewBuilder(new MessageBuilderOptions { MessageIdDomain = "example.com", Clock = new FixedClock(Now), AllowUtf8Headers = true });
        b.Subject = "Grüße";
        var (bytes, _) = b.Build();
        Assert.Contains("Subject: Grüße\r\n", Encoding.UTF8.GetString(bytes));
        Assert.True(MessageInspector.HasUtf8Headers(bytes));
    }

    [Fact]
    public void Text_and_html_make_multipart_alternative()
    {
        var b = NewBuilder();
        b.HtmlBody = "<p>Hi <b>there</b></p>";
        var (bytes, _) = b.Build();
        var msg = MimeMessage.Parse(bytes);

        Assert.Equal("multipart/alternative", msg.Root.ContentType.MimeType);
        Assert.Equal(new[] { "text/plain", "text/html" }, msg.Root.Children.Select(c => c.ContentType.MimeType).ToArray());
        Assert.Equal("Hi there", msg.Root.Children[0].GetText(100, out _));
        Assert.Equal("<p>Hi <b>there</b></p>", msg.Root.Children[1].GetText(100, out _));
        Assert.Equal(MimeAnomaly.None, msg.Anomalies);
    }

    [Fact]
    public void Html_only()
    {
        var b = NewBuilder();
        b.TextBody = null;
        b.HtmlBody = "<p>x</p>";
        var msg = MimeMessage.Parse(b.Build().Content);
        Assert.Equal("text/html", msg.Root.ContentType.MimeType);
    }

    [Fact]
    public void No_body_gives_an_empty_text_part()
    {
        var b = NewBuilder();
        b.TextBody = null;
        var msg = MimeMessage.Parse(b.Build().Content);
        Assert.Equal("text/plain", msg.Root.ContentType.MimeType);
        Assert.Equal(string.Empty, msg.Root.GetText(100, out _));
    }

    [Fact]
    public void Attachments_and_inline_resources_build_mixed_related_alternative()
    {
        var b = NewBuilder();
        b.HtmlBody = "<img src=\"cid:logo@x\">";
        b.Attachments.Add(new BuilderAttachment("logo.png", "image/png", new byte[] { 1, 2, 3, 4, 5 }) { IsInline = true, ContentId = "<logo@x>" });
        b.Attachments.Add(new BuilderAttachment("..\\evil/dir/report é.pdf", "application/pdf", Enumerable.Range(0, 5000).Select(i => (byte)i).ToArray()));
        var (bytes, _) = b.Build();
        var msg = MimeMessage.Parse(bytes);

        Assert.Equal("multipart/mixed", msg.Root.ContentType.MimeType);
        var alt = msg.Root.Children[0];
        Assert.Equal("multipart/alternative", alt.ContentType.MimeType);
        var related = alt.Children[1];
        Assert.Equal("multipart/related", related.ContentType.MimeType);
        Assert.Equal("text/html", related.Children[0].ContentType.MimeType);
        var logo = related.Children[1];
        Assert.Equal("logo@x", logo.ContentId);
        Assert.True(logo.Disposition!.IsInline);
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, logo.GetDecodedBytes());
        var pdf = msg.Root.Children[1];
        Assert.Equal("report é.pdf", pdf.FileName); // directories removed
        Assert.True(pdf.IsAttachment);
        Assert.Equal(5000, pdf.GetDecodedBytes().Length);
        Assert.Equal(MimeAnomaly.None, msg.Anomalies);
        Assert.False(MessageInspector.Inspect(bytes).HasBareLf);
        Assert.True(MessageInspector.Inspect(bytes).LongestBodyLine <= 76);
    }

    [Fact]
    public void Inline_resource_without_content_id_gets_one()
    {
        var b = NewBuilder();
        b.HtmlBody = "<p/>";
        b.Attachments.Add(new BuilderAttachment("a.png", "image/png", new byte[] { 1 }) { IsInline = true });
        var msg = MimeMessage.Parse(b.Build().Content);
        var inline = msg.EnumerateParts().Single(p => p.ContentType.MimeType == "image/png");
        Assert.Matches(@"^[0-9a-f]{32}@mail\.example\.com$", inline.ContentId);
    }

    [Fact]
    public void Inline_without_html_becomes_a_regular_attachment()
    {
        var b = NewBuilder();
        b.Attachments.Add(new BuilderAttachment("a.png", "image/png", new byte[] { 1 }) { IsInline = true });
        var msg = MimeMessage.Parse(b.Build().Content);
        Assert.Equal("multipart/mixed", msg.Root.ContentType.MimeType);
        Assert.Equal(2, msg.Root.Children.Count);
    }

    [Fact]
    public void Non_ascii_text_uses_quoted_printable_or_base64()
    {
        var b = NewBuilder();
        b.TextBody = "Café crème brûlée, présenté à la carte avec beaucoup de texte ASCII pour rester majoritairement ASCII.";
        var msg = MimeMessage.Parse(b.Build().Content);
        Assert.Equal(ContentTransferEncoding.QuotedPrintable, msg.Root.TransferEncoding);
        Assert.Equal(b.TextBody, msg.Root.GetText(1000, out _).TrimEnd('\r', '\n'));

        b.TextBody = "世界你好世界你好";
        msg = MimeMessage.Parse(b.Build().Content);
        Assert.Equal(ContentTransferEncoding.Base64, msg.Root.TransferEncoding);
        Assert.Equal(b.TextBody, msg.Root.GetText(1000, out _).TrimEnd('\r', '\n'));
    }

    [Fact]
    public void Eight_bit_body_when_allowed()
    {
        var b = NewBuilder(new MessageBuilderOptions { MessageIdDomain = "example.com", Clock = new FixedClock(Now), Allow8BitBody = true });
        b.TextBody = "Café";
        var (bytes, _) = b.Build();
        var msg = MimeMessage.Parse(bytes);
        Assert.Equal(ContentTransferEncoding.EightBit, msg.Root.TransferEncoding);
        Assert.True(MessageInspector.HasEightBitBody(bytes));
        Assert.Equal("Café\r\n", msg.Root.GetText(100, out _));
    }

    [Fact]
    public void Long_lines_never_exceed_998_bytes()
    {
        foreach (var (text, html) in new[]
        {
            (new string('a', 5000), (string?)null),
            (string.Concat(Enumerable.Repeat("word ", 3000)), "<p>" + new string('x', 4000) + "</p>"),
            (new string('é', 3000), null),
            ("with\0nul and \u0001 control", null),
        })
        {
            var b = NewBuilder();
            b.TextBody = text;
            b.HtmlBody = html;
            var (bytes, _) = b.Build();
            Assert.True(MessageInspector.Inspect(bytes).LongestBodyLine <= 998);
            Assert.False(MessageInspector.Inspect(bytes).HasNul);
            var msg = MimeMessage.Parse(bytes);
            Assert.Equal(text, msg.EnumerateParts().First(p => p.ContentType.MimeSubtypeIs("plain")).GetText(100_000, out _).TrimEnd('\r', '\n'));
        }
    }

    [Fact]
    public void Header_folding_is_at_most_78_columns_for_long_recipient_lists()
    {
        var b = NewBuilder();
        for (int i = 0; i < 40; i++)
        {
            b.Cc.Add(Mailbox.Create($"Person Number {i}", $"person{i}@subdomain.example.org"));
        }

        var (bytes, _) = b.Build();
        Assert.All(Encoding.ASCII.GetString(bytes).Split("\r\n"), line => Assert.True(line.Length <= 78, line));
        var list = AddressList.Parse(HeaderList.Parse(bytes).GetFirstValue("Cc"));
        Assert.Equal(40, list.MailboxCount);
    }

    [Fact]
    public void Bcc_is_not_written_by_default()
    {
        var b = NewBuilder();
        b.Bcc.Add(Mailbox.Create(null, "secret@example.org"));
        Assert.DoesNotContain("secret@example.org", Encoding.ASCII.GetString(b.Build().Content));
        b.IncludeBccHeader = true;
        Assert.Contains("Bcc: secret@example.org", Encoding.ASCII.GetString(b.Build().Content));
    }

    [Fact]
    public void Reply_to_sender_in_reply_to_and_references()
    {
        var b = NewBuilder();
        b.ReplyTo.Add(Mailbox.Create("Support", "support@example.com"));
        b.Sender = Mailbox.Create(null, "bounce@example.com");
        b.InReplyTo = "orig@example.org";
        b.References.Add("<r1@example.org>");
        b.References.Add("r2@example.org");
        b.MessageId = "fixed-id@mail.example.com";
        var (bytes, info) = b.Build();
        var h = HeaderList.Parse(bytes);
        Assert.Equal("Support <support@example.com>", h.GetFirstValue("Reply-To"));
        Assert.Equal("bounce@example.com", h.GetFirstValue("Sender"));
        Assert.Equal("<orig@example.org>", h.GetFirstValue("In-Reply-To"));
        Assert.Equal("<r1@example.org> <r2@example.org>", h.GetFirstValue("References"));
        Assert.Equal("<fixed-id@mail.example.com>", info.MessageId);
    }

    [Fact]
    public void Custom_headers_follow_the_policy()
    {
        var b = NewBuilder();
        b.AddHeader("X-Campaign", "spring é");
        b.AddHeader("List-Unsubscribe", "<mailto:u@example.com>");
        var h = HeaderList.Parse(b.Build().Content);
        Assert.Equal("spring é", h.TryGetFirst("X-Campaign", out var x) ? x.DecodedValue : null);
        Assert.Equal("<mailto:u@example.com>", h.GetFirstValue("List-Unsubscribe"));

        foreach (string denied in new[] { "From", "to", "Subject", "Return-Path", "Received", "DKIM-Signature", "Authentication-Results", "Content-Type", "Message-ID", "X-Mta-Internal", "Resent-From", "MIME-Version" })
        {
            Assert.Throws<MessageBuildException>(() => b.AddHeader(denied, "x"));
        }
    }

    [Fact]
    public void Allow_list_restricts_custom_headers()
    {
        var policy = new HeaderPolicy();
        policy.Allowed.Add("X-Tag");
        policy.Allowed.Add("List-*");
        var b = NewBuilder(new MessageBuilderOptions { MessageIdDomain = "example.com", Clock = new FixedClock(Now), HeaderPolicy = policy });
        b.AddHeader("x-tag", "1");
        b.AddHeader("List-Id", "<l.example.com>");
        Assert.Throws<MessageBuildException>(() => b.AddHeader("X-Other", "1"));
        Assert.Throws<MessageBuildException>(() => b.AddHeader("From", "x@y.example")); // deny list still applies
        Assert.Equal(2, b.CustomHeaders.Count);
    }

    [Fact]
    public void Allow_all_policy_has_no_deny_list()
    {
        var b = NewBuilder(new MessageBuilderOptions { MessageIdDomain = "example.com", Clock = new FixedClock(Now), HeaderPolicy = HeaderPolicy.AllowAll() });
        b.AddHeader("Received", "from x");
        Assert.Single(b.CustomHeaders);
    }

    [Theory]
    [InlineData("X-Test", "value\r\nBcc: evil@example.com")]
    [InlineData("X-Test", "value\nBcc: evil@example.com")]
    [InlineData("X-Test", "value\rBcc: evil@example.com")]
    [InlineData("X-Test", "va\0lue")]
    [InlineData("X-Test", "va\u0001lue")]
    [InlineData("X-Test", "va\u007flue")]
    [InlineData("X-Te\r\nst", "value")]
    [InlineData("X-Te\nst", "value")]
    [InlineData("X-Te\0st", "value")]
    [InlineData("X-Te st", "value")]
    [InlineData("X-Te:st", "value")]
    [InlineData("", "value")]
    [InlineData("X-Tést", "value")]
    public void Header_injection_is_rejected(string name, string value)
    {
        var b = NewBuilder();
        Assert.Throws<HeaderInjectionException>(() => b.AddHeader(name, value));
    }

    [Fact]
    public void Injection_through_subject_and_addresses_is_rejected()
    {
        foreach (string evil in new[] { "x\r\nBcc: e@x.example", "x\nBcc: e@x.example", "x\0y", "x\ry" })
        {
            var b = NewBuilder();
            b.Subject = evil;
            Assert.Throws<HeaderInjectionException>(() => b.Build());

            b = NewBuilder();
            b.From = Mailbox.Create(evil, "alice@example.com");
            Assert.Throws<HeaderInjectionException>(() => b.Build());

            b = NewBuilder();
            b.MessageId = evil;
            Assert.ThrowsAny<Exception>(() => b.Build());

            b = NewBuilder();
            b.InReplyTo = evil;
            Assert.ThrowsAny<Exception>(() => b.Build());

            Assert.ThrowsAny<Exception>(() => new BuilderAttachment(evil, "image/png", default));
            Assert.ThrowsAny<Exception>(() => new BuilderAttachment("a.png", evil, default));
        }
    }

    [Fact]
    public void Unicode_line_separators_are_rejected_in_raw_utf8_headers()
    {
        var b = NewBuilder(new MessageBuilderOptions { MessageIdDomain = "example.com", AllowUtf8Headers = true });
        b.Subject = "a\u2028b";
        Assert.Throws<HeaderInjectionException>(() => b.Build());
    }

    [Fact]
    public void Missing_from_is_a_build_error()
    {
        var b = NewBuilder();
        b.From = null;
        Assert.Throws<MessageBuildException>(() => b.Build());
    }

    [Fact]
    public void Invalid_message_id_domain_is_a_build_error()
    {
        var b = NewBuilder(new MessageBuilderOptions { MessageIdDomain = "bad domain" });
        Assert.Throws<MessageBuildException>(() => b.Build());
    }

    [Fact]
    public void Attachment_content_type_must_be_valid_and_not_multipart()
    {
        Assert.Throws<ArgumentException>(() => new BuilderAttachment("a", "multipart/mixed", default));
        Assert.Throws<ArgumentException>(() => new BuilderAttachment("a", "garbage", default));
    }

    [Fact]
    public void Unfoldable_token_is_a_build_error_not_a_long_line_when_encoding_is_off()
    {
        // With raw UTF-8 headers nothing is RFC 2047 encoded, so a 1200 byte word cannot be folded.
        var b = NewBuilder(new MessageBuilderOptions { MessageIdDomain = "example.com", Clock = new FixedClock(Now), AllowUtf8Headers = true });
        b.Subject = new string('a', 1200);
        Assert.Throws<MessageBuildException>(() => b.Build());
    }

    [Fact]
    public void Custom_header_with_long_ascii_word_is_encoded_so_it_folds()
    {
        var b = NewBuilder();
        b.AddHeader("X-Long", new string('a', 1200));
        var (bytes, _) = b.Build();
        Assert.True(MessageInspector.Inspect(bytes).LongestHeaderLine <= 998);
        Assert.Equal(new string('a', 1200), HeaderList.Parse(bytes).TryGetFirst("X-Long", out var h) ? h.DecodedValue : null);
    }

    [Fact]
    public void Writes_to_buffer_writer_and_info_matches()
    {
        var writer = new ArrayBufferWriter<byte>();
        var info = NewBuilder().WriteTo(writer);
        Assert.Equal(writer.WrittenCount, info.Length);
    }

    [Fact]
    public void Boundaries_are_unique_per_message()
    {
        var b = NewBuilder();
        b.HtmlBody = "<p/>";
        string first = MimeMessage.Parse(b.Build().Content).Root.ContentType.Boundary!;
        string second = MimeMessage.Parse(b.Build().Content).Root.ContentType.Boundary!;
        Assert.NotEqual(first, second);
    }
}

internal static class BuilderTestExtensions
{
    public static bool MimeSubtypeIs(this ContentType ct, string subtype) => ct.MediaSubtype == subtype;
}
