using System.Text;
using System.Text.Json;
using Mta.RemoteMta.Tests.Harness;
using Mta.Storage;

namespace Mta.RemoteMta.Tests.Scenarios;

/// <summary>A delivery over its whole life on the fake clock: five days of retries take no time, and every step is checked.</summary>
public class DeliveryTimelineTests
{
    [Fact]
    public async Task A_peer_that_never_accepts_gets_the_retry_ladder_for_five_days_and_then_the_message_expires_with_a_bounce_that_says_so()
    {
        await using var lab = new MtaLab();
        var peer = Personalities.Postfix();
        peer.OnEndOfData = (_, _) => Step.Reply(451, "4.3.0", "Temporary local problem, try again later");
        var mx = lab.AddMta("mx.dest.example", peer);
        lab.Mx("dest.example", 10, "mx.dest.example");
        var sender = lab.AddSenderSide();
        await lab.SubscribeWebhookAsync("message.deferred", "message.expired");
        var start = lab.Clock.UtcNow;

        var id = await lab.SendAsync(["rcpt@dest.example"], lifetime: TimeSpan.FromDays(5));
        var delays = new List<TimeSpan>();
        int deferrals = 0;
        while (true)
        {
            await Wait.UntilAsync(async () =>
            {
                var events = await lab.EventsAsync(id);
                return events.Count(e => e.Type == MessageEventType.Deferred) > deferrals || events.Any(e => e.Type == MessageEventType.Expired);
            }, "the next deferral or the expiry");
            if ((await lab.EventsAsync(id)).Any(e => e.Type == MessageEventType.Expired))
            {
                break;
            }

            deferrals++;
            var due = await lab.WaitForRetryScheduleAsync(id, deferrals);
            delays.Add(due - lab.Clock.UtcNow);
            lab.Advance(due - lab.Clock.UtcNow);
        }

        // 2m, 5m, 15m, 30m, 1h, 2h, 4h, then every 4h; the last attempt is pulled forward to a minute before the lifetime ends.
        Assert.Equal([2, 5, 15, 30, 60, 120, 240, 240, 240], delays.Take(9).Select(d => (int)d.TotalMinutes));
        Assert.All(delays.Skip(7).SkipLast(1), d => Assert.Equal(TimeSpan.FromHours(4), d));
        Assert.InRange(deferrals, 30, 40);
        Assert.True(lab.Clock.UtcNow - start <= TimeSpan.FromDays(5) + TimeSpan.FromMinutes(1));
        Assert.Empty(mx.Messages);

        var expired = (await lab.EventsAsync(id)).Single(e => e.Type == MessageEventType.Expired);
        Assert.Contains("expired", expired.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("451", expired.Message);
        Assert.False(await lab.Storage.Config.IsSuppressedAsync(MtaLab.Tenant, "rcpt@dest.example", default));   // five days of 451 say nothing about the address

        // The sender is told, with the last thing the remote said.
        await sender.WaitForMessagesAsync(1);
        string dsn = sender.Messages.Single().Text;
        Assert.Contains("Action: failed", dsn);
        Assert.Contains("Final-Recipient: rfc822; rcpt@dest.example", dsn);
        Assert.Contains("Temporary local problem", dsn);

        // The webhook stream tells the same story: attempt numbers count up and each deferral names the next try.
        var payloads = (await lab.WebhookPayloadsAsync()).Select(p => JsonDocument.Parse(p).RootElement).ToArray();
        var deferredPayloads = payloads.Where(p => p.GetProperty("type").GetString() == "message.deferred").Select(p => p.GetProperty("data")).ToArray();
        Assert.Equal(deferrals, deferredPayloads.Length);
        Assert.Equal(Enumerable.Range(1, deferrals), deferredPayloads.Select(d => d.GetProperty("attempt").GetInt32()).Order());
        Assert.All(deferredPayloads, d => Assert.True(d.TryGetProperty("next_attempt_at", out _)));
        Assert.Single(payloads, p => p.GetProperty("type").GetString() == "message.expired");
    }

    [Fact]
    public async Task A_message_whose_lifetime_ran_out_while_the_engine_was_waiting_expires_without_another_attempt()
    {
        await using var lab = new MtaLab();
        var peer = Personalities.Postfix();
        peer.OnRcpt = (_, rcpt) => Personalities.PostfixReplies.Greylisted(rcpt, "dest.example");
        var mx = lab.AddMta("mx.dest.example", peer);
        lab.Mx("dest.example", 10, "mx.dest.example");
        lab.AddSenderSide();

        var id = await lab.SendAsync(["rcpt@dest.example"], lifetime: TimeSpan.FromHours(1));
        await lab.WaitForRetryScheduleAsync(id);
        int connections = mx.ConnectionCount;

        lab.Advance(TimeSpan.FromHours(2));
        await lab.WaitForEventAsync(id, MessageEventType.Expired);

        Assert.Equal(connections, mx.ConnectionCount);
    }

    [Fact]
    public async Task A_bounce_for_a_message_from_the_http_api_is_not_mailed_but_published_as_a_webhook()
    {
        await using var lab = new MtaLab();
        var peer = Personalities.Gmail();
        peer.OnRcpt = (_, _) => Personalities.GmailReplies.NoSuchUser;
        lab.AddMta("mx.dest.example", peer);
        lab.Mx("dest.example", 10, "mx.dest.example");
        var sender = lab.AddSenderSide();
        await lab.SubscribeWebhookAsync("message.bounced");

        var id = await lab.SendAsync(["rcpt@dest.example"], source: MessageSource.Api);
        await lab.WaitForEventAsync(id, MessageEventType.Bounced);
        await lab.SettleAsync();

        Assert.Empty(sender.Messages);   // API senders learn from webhooks, not from mail (DeliveryOptions.GenerateDsnForApiSubmissions is off)
        var payload = JsonDocument.Parse(Assert.Single(await lab.WebhookPayloadsAsync())).RootElement.GetProperty("data");
        Assert.Equal("rcpt@dest.example", payload.GetProperty("recipient").GetString());
        Assert.Equal(550, payload.GetProperty("smtp_code").GetInt32());
        Assert.Equal("5.1.1", payload.GetProperty("enhanced_code").GetString());
        Assert.Contains("does not exist", payload.GetProperty("response").GetString());
    }

    // ---------------------------------------------------------------------------- 8BITMIME and SMTPUTF8

    private const string Headers = "From: sender@example.org\r\nTo: rcpt@dest.example\r\nSubject: Hello\r\nMessage-ID: <t@example.org>\r\nDate: Mon, 12 Oct 2026 08:00:00 +0000\r\n";

    private static byte[] EightBit() => Encoding.UTF8.GetBytes(Headers + "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nGrüße aus München, a mostly ASCII line.\r\n");

    [Theory]
    [InlineData("helo-only")]
    [InlineData("no-8bitmime")]
    public async Task An_8bit_message_is_converted_to_7bit_for_a_peer_that_cannot_take_8bit_and_the_peer_sees_pure_ascii(string kind)
    {
        var peer = Personalities.Exim();
        if (kind == "helo-only")
        {
            peer.Esmtp = false;
        }
        else
        {
            peer.EightBitMime = false;
        }

        await using var lab = new MtaLab();
        var mx = lab.AddMta("mx.dest.example", peer);
        lab.Mx("dest.example", 10, "mx.dest.example");

        var id = await lab.SendAsync(["rcpt@dest.example"], raw: EightBit());
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        var message = Assert.Single(mx.Messages);
        Assert.All(message.Body, b => Assert.True(b < 0x80));
        Assert.Contains("Content-Transfer-Encoding: quoted-printable", message.Text);
        Assert.Null(message.BodyParameter);
    }

    [Fact]
    public async Task An_8bit_message_goes_unchanged_with_body_8bitmime_to_a_peer_that_offers_it()
    {
        await using var lab = new MtaLab();
        var mx = lab.AddMta("mx.dest.example", Personalities.Gmail());
        lab.Mx("dest.example", 10, "mx.dest.example");
        byte[] raw = EightBit();

        var id = await lab.SendAsync(["rcpt@dest.example"], raw: raw);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        var message = Assert.Single(mx.Messages);
        Assert.Equal("8BITMIME", message.BodyParameter);
        Assert.Equal(raw, message.Body);
    }

    [Fact]
    public async Task A_message_with_utf8_headers_is_bounced_by_a_peer_without_smtputf8_with_5_6_9_and_the_second_mx_that_has_it_delivers_instead()
    {
        await using var lab = new MtaLab();
        var legacy = Personalities.Exim();
        legacy.SmtpUtf8 = false;
        var legacyMta = lab.AddMta("mx1.dest.example", legacy);
        var modern = lab.AddMta("mx2.dest.example", Personalities.Postfix());
        lab.Mx("dest.example", 10, "mx1.dest.example").Mx("dest.example", 20, "mx2.dest.example");
        byte[] raw = Encoding.UTF8.GetBytes("From: sender@example.org\r\nTo: rcpt@dest.example\r\nSubject: Grüße\r\nMessage-ID: <u@example.org>\r\nDate: Mon, 12 Oct 2026 08:00:00 +0000\r\n\r\nbody\r\n");

        var id = await lab.SendAsync(["rcpt@dest.example"], raw: raw);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Empty(legacyMta.Messages);
        Assert.Single(modern.Messages);
        Assert.True(modern.Messages[0].SmtpUtf8);
    }

    [Fact]
    public async Task A_message_with_utf8_headers_to_the_only_peer_that_lacks_smtputf8_is_a_permanent_failure_that_does_not_suppress_the_recipient()
    {
        await using var lab = new MtaLab();
        var legacy = Personalities.Exim();
        legacy.SmtpUtf8 = false;
        lab.AddMta("mx.dest.example", legacy);
        lab.Mx("dest.example", 10, "mx.dest.example");
        lab.AddSenderSide();
        byte[] raw = Encoding.UTF8.GetBytes("From: sender@example.org\r\nTo: rcpt@dest.example\r\nSubject: Grüße\r\nMessage-ID: <u@example.org>\r\nDate: Mon, 12 Oct 2026 08:00:00 +0000\r\n\r\nbody\r\n");

        var id = await lab.SendAsync(["rcpt@dest.example"], raw: raw);
        var events = await lab.WaitForEventAsync(id, MessageEventType.Bounced);

        Assert.Equal("5.6.9", events.Single(e => e.Type == MessageEventType.Bounced).EnhancedCode);
        Assert.False(await lab.Storage.Config.IsSuppressedAsync(MtaLab.Tenant, "rcpt@dest.example", default));
    }
}
