using Mta.RemoteMta.Tests.Harness;
using Mta.Storage;

namespace Mta.RemoteMta.Tests.Scenarios;

/// <summary>
/// 5xx answers in the shapes that Gmail, Microsoft, Postfix and Exim send: the delivery fails for good and the sender is told, but only a refusal
/// that is about the recipient's address puts the address on the suppression list. A policy, reputation, authentication or content refusal is about us, not the recipient.
/// </summary>
public class PermanentRefusalTests
{
    private sealed record Case(Func<MtaPersonality> Peer, Step Refusal, string Stage, int Code, string? Enhanced, bool SuppressesRecipient);

    private static readonly Dictionary<string, Case> Cases = new()
    {
        ["gmail-unauthenticated-sender"] = new(() => Personalities.Gmail(), Personalities.GmailReplies.Unauthenticated, "end-of-data", 550, "5.7.26", false),
        ["gmail-likely-spam"] = new(() => Personalities.Gmail(), Personalities.GmailReplies.LikelySpam, "end-of-data", 550, "5.7.1", false),
        ["gmail-low-ip-reputation"] = new(() => Personalities.Gmail(), Personalities.GmailReplies.LowIpReputation, "end-of-data", 550, "5.7.1", false),
        ["gmail-no-such-user"] = new(() => Personalities.Gmail(), Personalities.GmailReplies.NoSuchUser, "rcpt", 550, "5.1.1", true),
        ["outlook-dnsbl-at-mail-from"] = new(() => Personalities.Outlook(), Personalities.OutlookReplies.BlockedByDnsbl, "mail", 550, "5.7.1", false),
        ["outlook-banned-ip-at-rcpt"] = new(() => Personalities.Outlook(), Personalities.OutlookReplies.BannedIp, "rcpt", 550, "5.7.606", false),
        ["outlook-dmarc-reject"] = new(() => Personalities.Outlook(), Personalities.OutlookReplies.DmarcReject, "end-of-data", 550, "5.7.509", false),
        ["outlook-recipient-not-found"] = new(() => Personalities.Outlook(), Personalities.OutlookReplies.RecipientNotFound, "rcpt", 550, "5.1.10", true),
        ["postfix-client-blocked-at-mail-from"] = new(() => Personalities.Postfix(), Personalities.PostfixReplies.ClientBlocked, "mail", 554, "5.7.1", false),
        ["postfix-relay-denied"] = new(() => Personalities.Postfix(), Personalities.PostfixReplies.RelayDenied("rcpt@dest.example"), "rcpt", 554, "5.7.1", false),
        ["postfix-user-unknown"] = new(() => Personalities.Postfix(), Personalities.PostfixReplies.UserUnknown("rcpt@dest.example"), "rcpt", 550, "5.1.1", true),
        ["postfix-554-at-data"] = new(() => Personalities.Postfix(), Step.Reply(554, "5.5.1", "Error: no valid recipients"), "data", 554, "5.5.1", false),
        ["exim-administrative-prohibition"] = new(() => Personalities.Exim(), Personalities.EximReplies.AdministrativeProhibition, "rcpt", 550, null, false),
        ["exim-unrouteable-address"] = new(() => Personalities.Exim(), Personalities.EximReplies.UnroutableAddress, "rcpt", 550, null, true),
        ["exim-sender-verify-failed-at-mail-from"] = new(() => Personalities.Exim(), Personalities.EximReplies.SenderVerifyFailed, "mail", 550, null, false),
        ["bare-554-without-enhanced-code-after-the-data"] = new(() => Personalities.Plain(), Step.Reply(554, null, "Transaction failed"), "end-of-data", 554, null, false),
        ["554-no-smtp-service-in-the-banner"] = new(() => Personalities.Plain(), Step.Reply(554, "5.7.1", "Service unavailable; Client host [203.0.113.7] blocked").Then(Step.Close()), "banner", 554, "5.7.1", false),
    };

    public static TheoryData<string> CaseNames => new(Cases.Keys);

    [Theory]
    [MemberData(nameof(CaseNames))]
    public async Task A_permanent_refusal_bounces_the_message_and_suppresses_the_recipient_only_when_the_address_is_the_problem(string name)
    {
        var c = Cases[name];
        var peer = c.Peer();
        switch (c.Stage)
        {
            case "banner": peer.Greeting = _ => c.Refusal; break;
            case "mail": peer.OnMail = (_, _, _) => c.Refusal; break;
            case "rcpt": peer.OnRcpt = (_, _) => c.Refusal; break;
            case "data": peer.OnData = _ => c.Refusal; break;
            default: peer.OnEndOfData = (_, _) => c.Refusal; break;
        }

        await using var lab = new MtaLab();
        var mx = lab.AddMta("mx.dest.example", peer);
        lab.Mx("dest.example", 10, "mx.dest.example");
        var sender = lab.AddSenderSide();

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var events = await lab.WaitForEventAsync(id, MessageEventType.Bounced);

        var bounced = events.Single(e => e.Type == MessageEventType.Bounced);
        Assert.Equal(c.Code, bounced.SmtpCode);
        Assert.Equal(c.Enhanced, bounced.EnhancedCode);
        Assert.Empty(mx.Messages);
        Assert.DoesNotContain(events, e => e.Type == MessageEventType.Deferred);
        await Wait.UntilAsync(async () => await lab.Storage.Config.IsSuppressedAsync(MtaLab.Tenant, "rcpt@dest.example", default) == c.SuppressesRecipient || !c.SuppressesRecipient, "the suppression to be recorded");
        Assert.Equal(c.SuppressesRecipient, await lab.Storage.Config.IsSuppressedAsync(MtaLab.Tenant, "rcpt@dest.example", default));

        // The sender is told, with the remote's own words, in a delivery status notification that goes back through the same pipeline.
        await sender.WaitForMessagesAsync(1);
        var dsn = Assert.Single(sender.Messages);
        Assert.Equal(string.Empty, dsn.Sender);
        Assert.Equal(["sender@example.org"], dsn.Recipients);
        Assert.Contains("multipart/report", dsn.Text);
        Assert.Contains("Final-Recipient: rfc822; rcpt@dest.example", dsn.Text);
        Assert.Contains("Action: failed", dsn.Text);
        Assert.Contains("Diagnostic-Code: smtp;", dsn.Text);
        Assert.Contains(c.Code.ToString(), dsn.Text);
        if (c.Enhanced is not null)
        {
            Assert.Contains("Status: " + c.Enhanced, dsn.Text);
        }
    }

    [Fact]
    public async Task A_permanent_refusal_of_one_recipient_does_not_stop_the_others_in_the_same_transaction()
    {
        var peer = Personalities.Gmail();
        peer.OnRcpt = (_, rcpt) => rcpt.StartsWith("blocked@", StringComparison.Ordinal) ? Personalities.GmailReplies.LikelySpam : null;
        await using var lab = new MtaLab();
        var mx = lab.AddMta("mx.dest.example", peer);
        lab.Mx("dest.example", 10, "mx.dest.example");
        lab.AddSenderSide();

        var id = await lab.SendAsync(["blocked@dest.example", "fine@dest.example"]);
        var events = await lab.WaitForEventAsync(id, MessageEventType.Delivered);
        await lab.WaitForEventAsync(id, MessageEventType.Bounced);

        Assert.Equal(["fine@dest.example"], Assert.Single(mx.Messages).Recipients);
        Assert.False(await lab.Storage.Config.IsSuppressedAsync(MtaLab.Tenant, "blocked@dest.example", default));
        Assert.Equal("fine@dest.example", events.Single(e => e.Type == MessageEventType.Delivered).Recipient);
    }

    [Fact]
    public async Task A_banner_refusal_of_the_first_mx_does_not_stop_the_second_mx_from_taking_the_message()
    {
        await using var lab = new MtaLab();
        var first = Personalities.Plain("mx1.dest.example");
        first.Greeting = _ => Step.Reply(554, "5.7.1", "Service unavailable; Client host blocked").Then(Step.Close());
        var firstMta = lab.AddMta("mx1.dest.example", first);
        var secondMta = lab.AddMta("mx2.dest.example", Personalities.Plain("mx2.dest.example"));
        lab.Mx("dest.example", 10, "mx1.dest.example").Mx("dest.example", 20, "mx2.dest.example");

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var events = await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Equal(1, firstMta.ConnectionCount);
        Assert.Single(secondMta.Messages);
        Assert.Equal("mx2.dest.example", events.Single(e => e.Type == MessageEventType.Delivered).MxHost);
    }
}
