using System.Text;
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

    [Fact]
    public void Requires_at_least_one_recipient()
    {
        var req = new DsnRequest { ReportingMta = "mx", To = EmailAddress.Parse("s@example.org"), Action = DsnAction.Failed, ArrivalDate = Now, Now = Now, Recipients = [] };
        Assert.Throws<ArgumentOutOfRangeException>(() => DsnBuilder.Build(req));
    }
}
