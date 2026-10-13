using System.Text;
using Mta.Core;
using Mta.Host.Submission;
using Mta.Mime;
using Mta.Policy;
using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Host.Tests;

/// <summary>
/// The one path into the queue. The message is parsed once and that parse serves the sender check, the header repair and the history
/// content; these tests pin that the result is what the three separate passes used to produce.
/// </summary>
public class SubmissionServiceTests : IAsyncLifetime
{
    private static readonly Guid TenantId = Guid.Parse("a0000000-0000-7000-8000-000000000042");
    private static readonly byte[] Received = Encoding.ASCII.GetBytes("Received: from client.test ([127.0.0.1])\r\n\tby egg.test with ESMTPSA id abc;\r\n\tMon, 12 Oct 2026 08:00:00 +0000\r\n");

    private InMemoryStorage _storage = null!;
    private SubmissionService _service = null!;
    private Tenant _tenant = null!;

    public async Task InitializeAsync()
    {
        _storage = new InMemoryStorage(new StorageOptions());
        await _storage.InitializeAsync(default);
        var now = DateTimeOffset.UtcNow;
        _tenant = new Tenant(TenantId, "Acme", "acme", true, now, false);
        await _storage.Config.UpsertTenantAsync(_tenant, default);
        await _storage.Config.UpsertDomainAsync(new DomainRecord(Ids.New(), TenantId, "example.org", DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
        _service = new SubmissionService(_storage, SystemClock.Instance, new SenderPolicy(), new StorageOptions(), new SubmissionOptions { MessageIdDomain = "egg.test", MaxMessageBytes = 100_000, MaxRecipients = 100 });
    }

    public async Task DisposeAsync() => await _storage.DisposeAsync();

    private static byte[] Crlf(string text) => Encoding.UTF8.GetBytes(text.Replace("\n", "\r\n", StringComparison.Ordinal));

    private SubmissionRequest Request(byte[] message, params string[] recipients) => new()
    {
        Tenant = _tenant,
        Source = MessageSource.Smtp,
        EnvelopeFrom = EmailAddress.Parse("bounce@example.org"),
        Recipients = recipients.Select(r => EmailAddress.Parse(r)).ToList(),
        Message = message,
        ReceivedHeader = Received,
    };

    private async Task<(SubmissionResult Result, string Raw, IReadOnlyList<ClaimedDelivery> Deliveries)> SubmitAsync(string message, params string[] recipients)
    {
        var result = await _service.SubmitAsync(Request(Crlf(message), recipients.Length == 0 ? ["rcpt@dest.example"] : recipients), default);
        if (!result.IsAccepted)
        {
            return (result, "", []);
        }

        var claimed = await _storage.Deliveries.ClaimAsync("test", 1000, DateTimeOffset.UtcNow.AddSeconds(1), TimeSpan.FromMinutes(1), default);
        string raw = Encoding.UTF8.GetString((await _storage.Deliveries.GetRawAsync(result.MessageId, default))!);
        return (result, raw, claimed);
    }

    private const string Plain = "From: Acme <news@example.org>\nTo: rcpt@dest.example\nSubject: Hello\nDate: Mon, 12 Oct 2026 08:00:00 +0000\nMessage-ID: <given@example.org>\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\nbody text\n";

    [Fact]
    public async Task A_complete_message_is_stored_with_only_the_received_field_added()
    {
        var (result, raw, deliveries) = await SubmitAsync(Plain);
        Assert.Equal(SubmissionStatus.Accepted, result.Status);
        Assert.Equal("Received: from client.test ([127.0.0.1])\r\n\tby egg.test with ESMTPSA id abc;\r\n\tMon, 12 Oct 2026 08:00:00 +0000\r\n" + Plain.Replace("\n", "\r\n"), raw);
        Assert.Equal("example.org", Assert.Single(deliveries).SendingDomain);
    }

    [Fact]
    public async Task A_missing_message_id_and_date_are_added_above_the_original_fields_and_below_received()
    {
        var (_, raw, _) = await SubmitAsync("From: news@example.org\nTo: rcpt@dest.example\nSubject: Hello\n\nbody\n");
        string[] lines = raw.Split("\r\n");
        Assert.StartsWith("Received: from client.test", lines[0]);
        Assert.StartsWith("Date: ", lines[3]);
        Assert.StartsWith("Message-ID: <", lines[4]);
        Assert.EndsWith("@egg.test>", lines[4]);
        Assert.Equal("From: news@example.org", lines[5]);
    }

    [Fact]
    public async Task Bcc_is_removed_whatever_its_case_spacing_or_position()
    {
        foreach (string bcc in new[] { "Bcc: hidden@dest.example", "BCC: hidden@dest.example", "bcc : hidden@dest.example", "Bcc: a@dest.example,\n b@dest.example" })
        {
            var (_, raw, _) = await SubmitAsync("From: news@example.org\nTo: rcpt@dest.example\n" + bcc + "\nSubject: s\nDate: Mon, 12 Oct 2026 08:00:00 +0000\nMessage-ID: <m@example.org>\n\nbody\n");
            Assert.DoesNotContain("hidden@", raw);
            Assert.DoesNotContain("b@dest.example", raw);
            Assert.DoesNotContain("bcc", raw, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task A_message_without_bcc_is_not_touched_beyond_the_added_fields()
    {
        var (_, raw, _) = await SubmitAsync("From: news@example.org\nX-Bccish: keep\nTo: rcpt@dest.example\nSubject: s\nDate: Mon, 12 Oct 2026 08:00:00 +0000\nMessage-ID: <m@example.org>\n\nbody\n");
        Assert.Contains("X-Bccish: keep\r\n", raw);
    }

    [Fact]
    public async Task Bcc_behind_the_header_limit_is_still_removed()
    {
        // The parsed header list stops at 1000 fields; the stored copy must not keep a Bcc just because the parse never saw it.
        var sb = new StringBuilder("From: news@example.org\nTo: rcpt@dest.example\nSubject: s\nDate: Mon, 12 Oct 2026 08:00:00 +0000\nMessage-ID: <m@example.org>\n");
        for (int i = 0; i < 1100; i++)
        {
            sb.Append("X-Pad-").Append(i).Append(": v\n");
        }

        sb.Append("Bcc: late-hidden@dest.example\n\nbody\n");
        var (result, raw, _) = await SubmitAsync(sb.ToString());
        Assert.True(result.IsAccepted);
        Assert.DoesNotContain("late-hidden@", raw);
        Assert.Contains("X-Pad-1099: v", raw);
    }

    [Fact]
    public async Task The_history_content_is_what_extracting_the_stored_message_gives()
    {
        string message = "From: =?utf-8?Q?Ren=C3=A9e?= <news@example.org>\nTo: rcpt@dest.example\nSubject: =?utf-8?Q?Caf=C3=A9?= party\nMIME-Version: 1.0\n" +
                         "Content-Type: multipart/mixed; boundary=\"b\"\n\n--b\nContent-Type: text/plain; charset=utf-8\n\nplain text\n--b\nContent-Type: text/html\n\n<p>html</p>\n" +
                         "--b\nContent-Type: application/pdf; name=\"report.pdf\"\nContent-Disposition: attachment; filename=\"report.pdf\"\nContent-Transfer-Encoding: base64\n\nQUJDREVGRw==\n--b--\n";
        var (result, raw, _) = await SubmitAsync(message);
        var stored = MessageContentExtractor.Extract(Encoding.UTF8.GetBytes(raw), new StorageOptions().Content.MaxStoredBodyBytes);
        var content = (await _storage.History.GetAsync(TenantId, result.MessageId, default))!.Content!;
        Assert.Equal("Café party", content.Subject);
        Assert.Equal(stored.Subject, content.Subject);
        Assert.Equal(stored.TextBody, content.Text);
        Assert.Equal(stored.HtmlBody, content.Html);
        var attachment = Assert.Single(content.Attachments);
        Assert.Equal("report.pdf", attachment.FileName);
        Assert.Equal("application/pdf", attachment.ContentType);
    }

    [Theory]
    [InlineData("From: news@example.org", "example.org")]
    [InlineData("From: News <NEWS@EXAMPLE.ORG>", "example.org")]
    [InlineData("From: \"Doe, Jane\" <jane@example.org>", "example.org")]
    [InlineData("From: =?utf-8?Q?Caf=C3=A9?= <news@example.org>", "example.org")]
    [InlineData("From: Display Name Long Enough To Fold\n <news@example.org>", "example.org")]
    [InlineData("From: news@mail.example.org", "example.org")]
    [InlineData("From: a@example.org, b@Example.Org", "example.org")]
    public async Task The_sending_domain_comes_from_the_from_header(string fromLine, string expectedSendingDomain)
    {
        var (result, _, deliveries) = await SubmitAsync(fromLine + "\nTo: rcpt@dest.example\nSubject: s\nDate: Mon, 12 Oct 2026 08:00:00 +0000\nMessage-ID: <m@example.org>\n\nbody\n");
        Assert.True(result.IsAccepted, result.Detail);
        Assert.Equal(expectedSendingDomain, Assert.Single(deliveries).SendingDomain);
    }

    [Theory]
    [InlineData("To: rcpt@dest.example", "message has no From header")]
    [InlineData("From: nobody", "the From header has no valid address")]
    [InlineData("From: ", "the From header has no valid address")]
    [InlineData("From: a@example.org, b@other.example", "the From header must use a single domain")]
    [InlineData("From: Group: a@example.org, b@other.example;", "the From header must use a single domain")]
    public async Task A_from_header_that_cannot_name_one_sending_domain_is_refused(string line, string detail)
    {
        var (result, _, _) = await SubmitAsync(line + "\nSubject: s\n\nbody\n");
        Assert.Equal(SubmissionStatus.Invalid, result.Status);
        Assert.Equal(detail, result.Detail);
    }

    [Fact]
    public async Task A_sender_domain_of_another_tenant_is_rejected_by_the_policy()
    {
        var (result, _, _) = await SubmitAsync("From: news@other.example\nTo: rcpt@dest.example\nSubject: s\n\nbody\n");
        Assert.Equal(SubmissionStatus.Rejected, result.Status);
        Assert.Equal("sender_domain_not_registered", result.Rejection!.ApiErrorCode);
    }

    [Fact]
    public async Task Duplicate_recipients_are_queued_once()
    {
        var (_, _, deliveries) = await SubmitAsync(Plain, "b@dest.example", "a@dest.example", "b@dest.example", "c@dest.example", "a@dest.example");
        Assert.Equal(["a@dest.example", "b@dest.example", "c@dest.example"], deliveries.Select(d => d.Recipient.ToString()).Order().ToArray());
    }

    [Fact]
    public async Task Duplicates_are_removed_in_a_long_recipient_list_too()
    {
        string[] recipients = Enumerable.Range(0, 40).Select(i => $"r{i % 25}@dest.example").ToArray();
        var (result, _, deliveries) = await SubmitAsync(Plain, recipients);
        Assert.True(result.IsAccepted);
        Assert.Equal(25, deliveries.Count);
        Assert.Equal(25, deliveries.Select(d => d.Recipient.ToString()).Distinct().Count());
    }

    [Fact]
    public async Task Recipients_that_differ_only_in_case_of_the_local_part_stay_separate()
    {
        var (_, _, deliveries) = await SubmitAsync(Plain, "Sam@dest.example", "sam@dest.example");
        Assert.Equal(2, deliveries.Count);
    }

    [Fact]
    public async Task Limits_on_size_and_recipients_are_enforced()
    {
        Assert.Equal(SubmissionStatus.TooLarge, (await _service.SubmitAsync(Request(new byte[200_000], "a@dest.example"), default)).Status);

        var none = await _service.SubmitAsync(Request(Crlf(Plain)), default);
        Assert.Equal(SubmissionStatus.Invalid, none.Status);
        Assert.Equal("no recipients", none.Detail);

        var tooMany = await _service.SubmitAsync(Request(Crlf(Plain), Enumerable.Range(0, 101).Select(i => $"r{i}@dest.example").ToArray()), default);
        Assert.Equal(SubmissionStatus.Invalid, tooMany.Status);
        Assert.Equal("too many recipients", tooMany.Detail);
    }

    [Fact]
    public async Task The_message_memory_is_not_kept_after_the_call()
    {
        // The SMTP layer hands over memory that is only valid during the call; what is stored must be a copy.
        byte[] message = Crlf(Plain);
        var result = await _service.SubmitAsync(Request(message, "rcpt@dest.example"), default);
        Array.Clear(message);
        string raw = Encoding.UTF8.GetString((await _storage.Deliveries.GetRawAsync(result.MessageId, default))!);
        Assert.Contains("Subject: Hello", raw);
        var detail = await _storage.History.GetAsync(TenantId, result.MessageId, default);
        Assert.Equal("Hello", detail!.Content!.Subject);
        Assert.Contains("body text", detail.Content.Text);
    }

    [Fact]
    public async Task Requests_with_a_single_segment_message_and_a_borrowed_received_field_do_not_alias_each_other()
    {
        // Two submissions sharing the same borrowed Received array, one after the other, store independent copies.
        var first = await _service.SubmitAsync(Request(Crlf(Plain), "a@dest.example"), default);
        var second = await _service.SubmitAsync(Request(Crlf(Plain.Replace("Hello", "Second")), "b@dest.example"), default);
        string rawFirst = Encoding.UTF8.GetString((await _storage.Deliveries.GetRawAsync(first.MessageId, default))!);
        string rawSecond = Encoding.UTF8.GetString((await _storage.Deliveries.GetRawAsync(second.MessageId, default))!);
        Assert.Contains("Subject: Hello", rawFirst);
        Assert.Contains("Subject: Second", rawSecond);
    }
}
