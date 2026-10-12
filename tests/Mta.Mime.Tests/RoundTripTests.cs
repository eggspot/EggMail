using System.Text;
using Mta.Core;
using Mk = MimeKit;

namespace Mta.Mime.Tests;

/// <summary>Build with <see cref="MessageBuilder"/>, then parse with both MimeKit and Mta.Mime and compare to the model.</summary>
public class RoundTripTests
{
    private sealed class FixedClock(DateTimeOffset now) : IClock
    {
        public DateTimeOffset UtcNow { get; } = now;

        public long Timestamp => 0;
    }

    private static readonly DateTimeOffset Now = new(2026, 10, 12, 8, 30, 15, TimeSpan.Zero);

    private static MessageBuilder Builder(bool utf8Headers = false, bool eightBit = false) =>
        new(new MessageBuilderOptions { MessageIdDomain = "mail.example.com", Clock = new FixedClock(Now), AllowUtf8Headers = utf8Headers, Allow8BitBody = eightBit });

    private static Mk.MimeMessage MkParse(byte[] raw)
    {
        using var ms = new MemoryStream(raw);
        return Mk.MimeMessage.Load(ms);
    }

    public static IEnumerable<object[]> Models()
    {
        yield return new object[] { "ascii text only", "Hello", "Plain body", null!, 0 };
        yield return new object[] { "utf8 text", "Grüße aus München – 世界", "Café crème € 100\nline two\n", null!, 0 };
        yield return new object[] { "html only", "H", null!, "<p>café 世界</p>", 0 };
        yield return new object[] { "alternative", "Alt", "plain é", "<p>html é</p>", 0 };
        yield return new object[] { "attachment", "Att", "see attached", null!, 1 };
        yield return new object[] { "alternative plus attachments", "Mix", "plain", "<p>html</p>", 3 };
        yield return new object[] { "long lines", "Long", new string('x', 3000) + "\n" + new string('é', 2000), "<p>" + new string('y', 5000) + "</p>", 0 };
        yield return new object[] { "long subject", string.Concat(Enumerable.Repeat("Sehr langer Betreff mit Ümlauten ", 12)).Trim(), "x", null!, 0 };
        yield return new object[] { "empty body", "Empty", "", null!, 0 };
    }

    [Theory]
    [MemberData(nameof(Models))]
    public void Builder_output_is_read_back_identically_by_MimeKit_and_Mta_Mime(string label, string subject, string? text, string? html, int attachmentCount)
    {
        var builder = Builder();
        builder.From = Mailbox.Create("Alice Élise", "alice@example.com");
        builder.To.Add(Mailbox.Create("Bob, the \"Builder\"", "bob@example.net"));
        builder.To.Add(Mailbox.Create(null, "carol@example.org"));
        builder.Cc.Add(Mailbox.Create("Däve", "dave@example.org"));
        builder.Subject = subject;
        builder.TextBody = text;
        builder.HtmlBody = html;
        var payloads = new List<byte[]>();
        for (int i = 0; i < attachmentCount; i++)
        {
            var payload = new byte[1000 + (i * 777)];
            new Random(i).NextBytes(payload);
            payloads.Add(payload);
            builder.Attachments.Add(new BuilderAttachment($"file {i} é.bin", "application/octet-stream", payload));
        }

        var (bytes, info) = builder.Build();

        // wire format sanity
        Assert.True(Ascii(bytes), label);
        Assert.False(MessageInspector.ContainsBareLf(bytes));
        Assert.False(MessageInspector.ContainsBareCr(bytes));
        var inspection = MessageInspector.Inspect(bytes);
        Assert.True(inspection.LongestHeaderLine <= 998 && inspection.LongestBodyLine <= 998, label);
        Assert.False(MessageValidator.Validate(bytes).HasErrors, label);
        Assert.Equal(MimeAnomaly.None, MimeMessage.Parse(bytes).Anomalies);

        // MimeKit
        var theirs = MkParse(bytes);
        Assert.Equal(subject, theirs.Subject);
        Assert.Equal(info.MessageId.Trim('<', '>'), theirs.MessageId);
        Assert.Equal(Now, theirs.Date);
        Assert.Equal("Alice Élise", theirs.From.Mailboxes.Single().Name);
        Assert.Equal(new[] { "Bob, the \"Builder\"", "" }, theirs.To.Mailboxes.Select(m => m.Name).ToArray());
        Assert.Equal("Däve", theirs.Cc.Mailboxes.Single().Name);
        if (text is not null)
        {
            Assert.Equal(NormalizeText(text), NormalizeText(theirs.TextBody ?? string.Empty));
        }

        if (html is not null)
        {
            Assert.Equal(NormalizeText(html), NormalizeText(theirs.HtmlBody ?? string.Empty));
        }

        var theirAttachments = theirs.Attachments.OfType<Mk.MimePart>().ToList();
        Assert.Equal(attachmentCount, theirAttachments.Count);
        for (int i = 0; i < attachmentCount; i++)
        {
            Assert.Equal($"file {i} é.bin", theirAttachments[i].FileName);
            using var ms = new MemoryStream();
            theirAttachments[i].Content!.DecodeTo(ms);
            Assert.Equal(payloads[i], ms.ToArray());
        }

        // Mta.Mime
        var content = MessageContentExtractor.Extract(bytes);
        Assert.Equal(subject, content.Subject);
        if (!string.IsNullOrEmpty(text))
        {
            Assert.Equal(NormalizeText(text), NormalizeText(content.TextBody!));
        }

        if (html is not null)
        {
            Assert.Equal(NormalizeText(html), NormalizeText(content.HtmlBody!));
        }

        Assert.Equal(attachmentCount, content.Attachments.Count);
        for (int i = 0; i < attachmentCount; i++)
        {
            Assert.Equal($"file {i} é.bin", content.Attachments[i].FileName);
            Assert.Equal(payloads[i].Length, content.Attachments[i].Size);
        }

        var headers = HeaderList.Parse(bytes);
        Assert.Equal("Alice Élise", AddressList.Parse(headers.GetFirstValue(HeaderId.From)).Mailboxes.Single().DisplayName);
        Assert.Equal(new[] { "Bob, the \"Builder\"", null }, AddressList.Parse(headers.GetFirstValue(HeaderId.To)).Mailboxes.Select(m => m.DisplayName).ToArray());
        Assert.True(MimeDate.TryParse(headers.GetFirstValue(HeaderId.Date), out var parsedDate));
        Assert.Equal(Now, parsedDate);
    }

    [Fact]
    public void Inline_related_resources_round_trip()
    {
        var builder = Builder();
        builder.From = Mailbox.Create(null, "alice@example.com");
        builder.Subject = "inline";
        builder.TextBody = "plain";
        builder.HtmlBody = "<img src=\"cid:logo@mail.example.com\">";
        builder.Attachments.Add(new BuilderAttachment("logo.png", "image/png", new byte[] { 0x89, 0x50, 0x4E, 0x47, 1, 2, 3 }) { IsInline = true, ContentId = "logo@mail.example.com" });
        builder.Attachments.Add(new BuilderAttachment("a.pdf", "application/pdf", new byte[] { 1, 2, 3 }));
        var bytes = builder.Build().Content;

        var theirs = MkParse(bytes);
        var image = theirs.BodyParts.OfType<Mk.MimePart>().Single(p => p.ContentType.MimeType == "image/png");
        Assert.Equal("logo@mail.example.com", image.ContentId);
        Assert.True(image.ContentDisposition!.Disposition == "inline");
        var mixed = Assert.IsType<Mk.Multipart>(theirs.Body);
        var alternative = Assert.IsAssignableFrom<Mk.Multipart>(mixed[0]);
        Assert.Equal("multipart/alternative", alternative.ContentType.MimeType);
        Assert.Equal("multipart/related", alternative[1].ContentType.MimeType);
        Assert.Single(theirs.Attachments);

        var content = MessageContentExtractor.Extract(bytes);
        Assert.Equal(2, content.Attachments.Count);
        Assert.Contains(content.Attachments, a => a.ContentId == "logo@mail.example.com" && a.IsInline);
        Assert.Contains(content.Attachments, a => a.FileName == "a.pdf" && !a.IsInline);
    }

    [Fact]
    public void Utf8_headers_mode_round_trips_through_MimeKit()
    {
        var builder = Builder(utf8Headers: true, eightBit: true);
        builder.From = Mailbox.Create("Renée", "renee@example.com");
        builder.To.Add(Mailbox.Parse("用户 <用户@example.com>"));
        builder.Subject = "Grüße 世界";
        builder.TextBody = "Café 世界";
        var bytes = builder.Build().Content;

        Assert.True(MessageInspector.HasUtf8Headers(bytes));
        Assert.True(MessageInspector.HasValidUtf8Headers(bytes));
        var theirs = MkParse(bytes);
        Assert.Equal("Grüße 世界", theirs.Subject);
        Assert.Equal("Renée", theirs.From.Mailboxes.Single().Name);
        var content = MessageContentExtractor.Extract(bytes);
        Assert.Equal("Grüße 世界", content.Subject);
        Assert.StartsWith("Café 世界", content.TextBody, StringComparison.Ordinal);
    }

    [Fact]
    public void Editor_output_still_parses_in_MimeKit_with_trace_headers_first()
    {
        var bytes = Builder().Also(b =>
        {
            b.From = Mailbox.Create(null, "alice@example.com");
            b.Subject = "trace";
            b.TextBody = "body";
        }).Build().Content;

        var edited = new MessageHeaderEditor(bytes)
            .PrependReceived("from client.example.com by mx.example.net with ESMTP; Mon, 12 Oct 2026 08:30:15 +0000")
            .PrependReturnPath("alice@example.com")
            .Remove("Message-ID")
            .ToArray();

        var theirs = MkParse(edited);
        Assert.Equal(new[] { "Return-Path", "Received" }, theirs.Headers.Take(2).Select(h => h.Field).ToArray());
        Assert.Null(theirs.MessageId);
        Assert.Equal("trace", theirs.Subject);
        Assert.Equal("body", theirs.TextBody!.Trim());
    }

    private static bool Ascii(byte[] bytes) => System.Text.Ascii.IsValid(bytes);

    private static string NormalizeText(string s) => s.Replace("\r\n", "\n", StringComparison.Ordinal).Trim();
}

internal static class FluentExtensions
{
    public static T Also<T>(this T value, Action<T> action)
    {
        action(value);
        return value;
    }
}
