using System.Text;
using System.Text.Unicode;
using MimeKit;
using Mta.Core;
using Mta.Dsn;

namespace Mta.Dsn.Tests;

public class DsnBuilderTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 12, 8, 0, 0, TimeSpan.Zero);
    private static readonly byte[] Original = Encoding.ASCII.GetBytes("From: sender@example.org\r\nTo: rcpt@dest.example\r\nSubject: Hello\r\nMessage-ID: <abc@example.org>\r\n\r\nBody line 1\r\nBody line 2\r\n");

    private static DsnRequest Request(DsnAction action = DsnAction.Failed, DsnReturnContent ret = DsnReturnContent.Headers, string? diagnostic = "550 5.1.1 <rcpt@dest.example>: Recipient address rejected: User unknown") => new()
    {
        ReportingMta = "mx.eggmail.test",
        To = EmailAddress.Parse("sender@example.org"),
        Action = action,
        ArrivalDate = Now.AddHours(-2),
        Now = Now,
        OriginalMessage = Original,
        ReturnContent = ret,
        UniqueToken = "fixedtoken",
        Recipients = [new DsnRecipient(EmailAddress.Parse("rcpt@dest.example"), action == DsnAction.Failed ? "5.1.1" : "4.4.1", diagnostic, "mx.dest.example", Now.AddMinutes(-1), Now.AddDays(1))],
    };

    private static MimeMessage Parse(byte[] raw)
    {
        using var ms = new MemoryStream(raw);
        return MimeMessage.Load(ms);
    }

    [Fact]
    public void Failure_report_is_a_valid_multipart_report()
    {
        var msg = Parse(DsnBuilder.Build(Request()));
        Assert.Equal("Undelivered Mail Returned to Sender", msg.Subject);
        Assert.Equal("mailer-daemon@mx.eggmail.test", msg.From.Mailboxes.Single().Address);
        Assert.Equal("sender@example.org", msg.To.Mailboxes.Single().Address);
        Assert.Equal("auto-replied", msg.Headers["Auto-Submitted"]);
        var report = Assert.IsType<MultipartReport>(msg.Body!);
        Assert.Equal("delivery-status", report.ReportType);
        Assert.Equal(3, report.Count);
        Assert.IsType<TextPart>(report[0]);
        var status = Assert.IsType<MessageDeliveryStatus>(report[1]);
        Assert.Equal("mx.eggmail.test", status.StatusGroups[0]["Reporting-MTA"]!.Replace("dns; ", ""));
        var rcpt = status.StatusGroups[1];
        Assert.Equal("rfc822; rcpt@dest.example", rcpt["Final-Recipient"]);
        Assert.Equal("failed", rcpt["Action"]);
        Assert.Equal("5.1.1", rcpt["Status"]);
        Assert.Contains("User unknown", rcpt["Diagnostic-Code"]);
        Assert.Equal("dns; mx.dest.example", rcpt["Remote-MTA"]);
        var headers = Assert.IsType<TextRfc822Headers>(report[2]);
        using var hs = new MemoryStream();
        headers.WriteTo(hs);
        string returned = Encoding.ASCII.GetString(hs.ToArray());
        Assert.Contains("Message-ID: <abc@example.org>", returned);
        Assert.DoesNotContain("Body line", returned);   // headers only by default
    }

    [Fact]
    public void Full_return_includes_the_message_and_truncates_at_a_line_boundary()
    {
        var msg = Parse(DsnBuilder.Build(Request(ret: DsnReturnContent.Full)));
        var report = (MultipartReport)msg.Body!;
        var rfc822 = Assert.IsType<MessagePart>(report[2]);
        Assert.Contains("Body line 2", rfc822.Message!.TextBody ?? rfc822.Message.Body?.ToString() ?? "");

        var big = new byte[200_000];
        Array.Fill(big, (byte)'x');
        for (int i = 70; i < big.Length; i += 71) { big[i] = (byte)'\n'; }
        var req = new DsnRequest
        {
            ReportingMta = "mx", To = EmailAddress.Parse("s@example.org"), Action = DsnAction.Failed, ArrivalDate = Now, Now = Now,
            OriginalMessage = Encoding.ASCII.GetBytes("Subject: x\r\n\r\n").Concat(big).ToArray(), ReturnContent = DsnReturnContent.Full, MaxReturnedBytes = 5000,
            Recipients = [new DsnRecipient(EmailAddress.Parse("r@d.example"), "5.1.1")],
        };
        byte[] built = DsnBuilder.Build(req);
        Assert.True(built.Length < 12_000);
    }

    [Theory]
    [InlineData(DsnAction.Delayed, "Delayed Mail (still being retried)", "delayed")]
    [InlineData(DsnAction.Delivered, "Successful Mail Delivery Report", "delivered")]
    [InlineData(DsnAction.Relayed, "Mail Delivery Status Report", "relayed")]
    public void Other_actions(DsnAction action, string subject, string actionField)
    {
        var msg = Parse(DsnBuilder.Build(Request(action)));
        Assert.Equal(subject, msg.Subject);
        var status = (MessageDeliveryStatus)((MultipartReport)msg.Body!)[1];
        Assert.Equal(actionField, status.StatusGroups[1]["Action"]);
        if (action == DsnAction.Delayed)
        {
            Assert.True(status.StatusGroups[1].Contains("Will-Retry-Until"));
        }
    }

    [Fact]
    public void Hostile_diagnostics_cannot_inject_headers_or_parts()
    {
        var req = Request(diagnostic: "550 nope\r\nBcc: attacker@evil.example\r\n\r\n--=_dsn_fixedtoken\r\nContent-Type: text/html\r\n\r\n<script>");
        var msg = Parse(DsnBuilder.Build(req));
        Assert.Null(msg.Headers["Bcc"]);
        var report = (MultipartReport)msg.Body!;
        Assert.Equal(3, report.Count);
        var status = (MessageDeliveryStatus)report[1];
        Assert.False(status.StatusGroups[1].Contains("Bcc"));
    }

    [Fact]
    public void Non_ascii_recipient_text_is_base64_encoded_in_the_human_part()
    {
        var req = new DsnRequest
        {
            ReportingMta = "mx.test", To = EmailAddress.Parse("s@example.org"), Action = DsnAction.Failed, ArrivalDate = Now, Now = Now, OriginalMessage = Original,
            Recipients = [new DsnRecipient(EmailAddress.Parse("üser@bücher.example"), "5.1.1", "550 Käse unbekannt")],
        };
        var msg = Parse(DsnBuilder.Build(req));
        var text = (TextPart)((MultipartReport)msg.Body!)[0];
        Assert.Contains("Käse unbekannt", text.Text);
    }

    private static DsnRequest International(string[] recipients, string diagnostic = "553 5.6.7 the receiving server does not support SMTPUTF8", byte[]? original = null, DsnReturnContent ret = DsnReturnContent.Headers, string to = "sender@example.org") => new()
    {
        ReportingMta = "mx.eggmail.test",
        To = EmailAddress.Parse(to),
        Action = DsnAction.Failed,
        ArrivalDate = Now,
        Now = Now,
        OriginalMessage = original ?? Original,
        ReturnContent = ret,
        UniqueToken = "fixedtoken",
        Recipients = recipients.Select(r => new DsnRecipient(EmailAddress.Parse(r), "5.6.7", diagnostic, "mx.dest.example", Now)).ToList(),
    };

    [Fact]
    public void An_internationalized_recipient_gets_a_global_delivery_status_with_the_utf8_address_type()
    {
        byte[] dsn = DsnBuilder.Build(International(["пользователь@dest.example", "plain@dest.example"]));

        var parsed = Mta.Mime.MimeMessage.Parse(dsn);
        var status = parsed.Root.Children[1];
        Assert.Equal("message/global-delivery-status", status.ContentType.MimeType);
        string text = Encoding.UTF8.GetString(status.Body.Span);
        Assert.Contains("Final-Recipient: utf-8; пользователь@dest.example\r\n", text, StringComparison.Ordinal);
        Assert.Contains("Final-Recipient: rfc822; plain@dest.example\r\n", text, StringComparison.Ordinal);   // ASCII addresses keep the RFC 3464 type
        Assert.Contains("Status: 5.6.7", text, StringComparison.Ordinal);
        Assert.Equal(3, parsed.Root.Children.Count);
        Assert.Equal("text/rfc822-headers", parsed.Root.Children[2].ContentType.MimeType);   // the original had ASCII headers

        var report = InboundReportParser.Parse(dsn);
        Assert.Equal(2, report.Recipients.Count);
        Assert.Contains(report.Recipients, r => r.FinalRecipient == "пользователь@dest.example" && r.IsPermanentFailure && r.Status == "5.6.7");
    }

    [Fact]
    public void A_report_about_ascii_recipients_is_a_plain_rfc3464_report()
    {
        byte[] dsn = DsnBuilder.Build(Request());
        var parsed = Mta.Mime.MimeMessage.Parse(dsn);
        Assert.Equal("message/delivery-status", parsed.Root.Children[1].ContentType.MimeType);
        Assert.False(Mta.Mime.MessageInspector.HasEightBitBody(dsn));
        Assert.False(Mta.Mime.MessageInspector.HasUtf8Headers(dsn));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Reports_use_crlf_line_endings_only_so_they_can_be_transmitted(bool international)
    {
        byte[] dsn = DsnBuilder.Build(international ? International(["пользователь@dest.example"]) : Request());
        var inspection = Mta.Mime.MessageInspector.Inspect(dsn);
        Assert.False(inspection.HasBareLf);
        Assert.False(inspection.HasBareCr);
        Assert.False(inspection.HasNul);
    }

    [Fact]
    public void Utf8_diagnostic_text_from_a_remote_server_also_switches_to_the_global_form()
    {
        var req = Request(diagnostic: "550 5.1.1 Benutzer nicht gefunden: Käse");
        var parsed = Mta.Mime.MimeMessage.Parse(DsnBuilder.Build(req));
        var status = parsed.Root.Children[1];
        Assert.Equal("message/global-delivery-status", status.ContentType.MimeType);
        Assert.Contains("Diagnostic-Code: smtp; 550 5.1.1 Benutzer nicht gefunden: Käse", Encoding.UTF8.GetString(status.Body.Span), StringComparison.Ordinal);
        Assert.Contains("Final-Recipient: rfc822; rcpt@dest.example", Encoding.UTF8.GetString(status.Body.Span), StringComparison.Ordinal);
    }

    [Fact]
    public void A_returned_original_with_utf8_headers_is_message_global_headers_or_message_global()
    {
        byte[] original = Encoding.UTF8.GetBytes("From: Jürgen <j@example.org>\r\nTo: rcpt@dest.example\r\nSubject: Grüße\r\nMessage-ID: <u@example.org>\r\n\r\nGrüße aus München\r\n");

        var headersOnly = Mta.Mime.MimeMessage.Parse(DsnBuilder.Build(International(["rcpt@dest.example"], original: original)));
        Assert.Equal("message/global-delivery-status", headersOnly.Root.Children[1].ContentType.MimeType);
        var returnedHeaders = headersOnly.Root.Children[2];
        Assert.Equal("message/global-headers", returnedHeaders.ContentType.MimeType);
        Assert.Contains("Subject: Grüße", Encoding.UTF8.GetString(returnedHeaders.Body.Span), StringComparison.Ordinal);
        Assert.DoesNotContain("aus München", Encoding.UTF8.GetString(returnedHeaders.Body.Span), StringComparison.Ordinal);

        var full = Mta.Mime.MimeMessage.Parse(DsnBuilder.Build(International(["rcpt@dest.example"], original: original, ret: DsnReturnContent.Full)));
        var returned = full.Root.Children[2];
        Assert.Equal("message/global", returned.ContentType.MimeType);
        Assert.Contains("aus München", Encoding.UTF8.GetString(returned.Body.Span), StringComparison.Ordinal);
    }

    [Fact]
    public void An_internationalized_sender_puts_utf8_in_the_report_headers()
    {
        byte[] dsn = DsnBuilder.Build(International(["rcpt@dest.example"], to: "пользователь@example.org"));
        Assert.True(Mta.Mime.MessageInspector.HasValidUtf8Headers(dsn));
        var parsed = Mta.Mime.MimeMessage.Parse(dsn);
        Assert.Contains("To: <пользователь@example.org>", Encoding.UTF8.GetString(parsed.Headers.HeaderBlock.Span), StringComparison.Ordinal);
    }

    [Fact]
    public void The_global_report_survives_the_8bit_to_7bit_conversion_and_still_parses()
    {
        byte[] dsn = DsnBuilder.Build(International(["пользователь@dest.example"]));
        var writer = new System.Buffers.ArrayBufferWriter<byte>();
        var result = Mta.Mime.EightBitDowngrader.Downgrade(dsn, writer);
        Assert.Equal(Mta.Mime.EightBitDowngradeStatus.Downgraded, result.Status);

        var report = InboundReportParser.Parse(writer.WrittenMemory);
        Assert.Contains(report.Recipients, r => r.FinalRecipient == "пользователь@dest.example" && r.IsPermanentFailure);
    }

    [Fact]
    public void Control_and_bidi_characters_in_remote_text_are_replaced_and_long_text_is_cut_on_a_character_boundary()
    {
        string diagnostic = "550 5.1.1 bad\u202Etxt.exe\u0007\u0085\u2067mix " + new string('x', 880) + "\U0001F600\U0001F600";
        byte[] dsn = DsnBuilder.Build(International(["rcpt@dest.example"], diagnostic: diagnostic));
        string text = Encoding.UTF8.GetString(dsn);
        Assert.DoesNotContain('\u202E', text);
        Assert.DoesNotContain('\u2067', text);
        Assert.DoesNotContain('\u0007', text);
        Assert.DoesNotContain('\u0085', text);
        Assert.DoesNotContain('\uFFFD', text);   // no half character was written
        var status = Mta.Mime.MimeMessage.Parse(dsn).Root.Children[1];
        Assert.Contains("bad txt.exe", Encoding.UTF8.GetString(status.Body.Span), StringComparison.Ordinal);
    }

    [Fact]
    public void A_returned_line_longer_than_the_limit_is_not_cut_in_the_middle_of_a_utf8_sequence()
    {
        byte[] original = Encoding.UTF8.GetBytes("X-Long: " + new string('é', 3000) + "\r\n\r\nbody");
        var req = International(["rcpt@dest.example"], original: original);
        var small = new DsnRequest
        {
            ReportingMta = req.ReportingMta, To = req.To, Action = req.Action, ArrivalDate = req.ArrivalDate, Now = req.Now, OriginalMessage = original,
            MaxReturnedBytes = 1001, UniqueToken = "t", Recipients = req.Recipients,
        };
        byte[] dsn = DsnBuilder.Build(small);
        Assert.True(Utf8.IsValid(dsn.AsSpan(dsn.AsSpan().IndexOf("X-Long: "u8))), "the report must stay valid UTF-8");
    }

    [Fact]
    public void Requires_at_least_one_recipient()
    {
        var req = new DsnRequest { ReportingMta = "mx", To = EmailAddress.Parse("s@example.org"), Action = DsnAction.Failed, ArrivalDate = Now, Now = Now, Recipients = [] };
        Assert.Throws<ArgumentOutOfRangeException>(() => DsnBuilder.Build(req));
    }
}
