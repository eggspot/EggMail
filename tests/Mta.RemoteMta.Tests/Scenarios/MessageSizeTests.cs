using System.Text;
using Mta.RemoteMta.Tests.Harness;
using Mta.Storage;

namespace Mta.RemoteMta.Tests.Scenarios;

/// <summary>Size limits: the SIZE extension, 552 at MAIL, 552 after the data, and a mailbox that is merely full.</summary>
public class MessageSizeTests
{
    private static byte[] Message(int bodyBytes) =>
        Encoding.ASCII.GetBytes("From: sender@example.org\r\nTo: rcpt@dest.example\r\nSubject: big\r\nMessage-ID: <big@example.org>\r\nDate: Mon, 12 Oct 2026 08:00:00 +0000\r\n\r\n"
            + string.Concat(Enumerable.Repeat(new string('x', 70) + "\r\n", bodyBytes / 72 + 1)));

    private static async Task<(MtaLab Lab, FakeMta Mx)> StartAsync(MtaPersonality peer)
    {
        var lab = new MtaLab();
        var mx = lab.AddMta("mx.dest.example", peer);
        lab.Mx("dest.example", 10, "mx.dest.example");
        lab.AddSenderSide();
        await Task.CompletedTask;
        return (lab, mx);
    }

    [Fact]
    public async Task A_message_larger_than_the_advertised_SIZE_is_refused_locally_with_552_5_3_4_and_nothing_is_sent_to_the_peer()
    {
        var peer = Personalities.Postfix();
        peer.SizeAdvertised = 2_000;
        var (lab, mx) = await StartAsync(peer);
        await using var _ = lab;

        var id = await lab.SendAsync(["rcpt@dest.example"], raw: Message(5_000));
        var events = await lab.WaitForEventAsync(id, MessageEventType.Bounced);

        var bounced = events.Single(e => e.Type == MessageEventType.Bounced);
        Assert.Equal(552, bounced.SmtpCode);
        Assert.Equal("5.3.4", bounced.EnhancedCode);
        Assert.DoesNotContain("MAIL", mx.Sessions.Single().Verbs);   // the engine knew the limit from EHLO and never started the transaction
        Assert.False(await lab.Storage.Config.IsSuppressedAsync(MtaLab.Tenant, "rcpt@dest.example", default));   // a size problem is about the message, not the address
    }

    [Fact]
    public async Task A_message_within_the_advertised_SIZE_declares_its_size_and_is_delivered()
    {
        var peer = Personalities.Postfix();
        peer.SizeAdvertised = 20_000;
        peer.OnMail = (_, _, parameters) => parameters.TryGetValue("SIZE", out string? size) && int.Parse(size) is > 4_000 and < 6_000 ? null : Step.Reply(555, "5.5.4", "SIZE not declared as expected");
        var (lab, mx) = await StartAsync(peer);
        await using var _ = lab;

        var id = await lab.SendAsync(["rcpt@dest.example"], raw: Message(5_000));
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Single(mx.Messages);
    }

    [Fact]
    public async Task A_peer_that_does_not_advertise_SIZE_and_refuses_after_the_data_with_552_makes_a_permanent_bounce_without_suppression()
    {
        var peer = Personalities.Exim();
        peer.SizeAdvertised = null;
        peer.SizeEnforced = 3_000;
        var (lab, mx) = await StartAsync(peer);
        await using var _ = lab;

        var id = await lab.SendAsync(["rcpt@dest.example"], raw: Message(5_000));
        var events = await lab.WaitForEventAsync(id, MessageEventType.Bounced);

        Assert.Equal(552, events.Single(e => e.Type == MessageEventType.Bounced).SmtpCode);
        Assert.Empty(mx.Messages);
        Assert.False(await lab.Storage.Config.IsSuppressedAsync(MtaLab.Tenant, "rcpt@dest.example", default));
        Assert.DoesNotContain(await lab.EventsAsync(id), e => e.Type is MessageEventType.Deferred or MessageEventType.PossibleDuplicate);
    }

    [Fact]
    public async Task A_552_at_mail_from_to_a_declared_size_is_permanent_and_leaves_the_connection_usable_for_the_next_message()
    {
        var peer = Personalities.Postfix();
        peer.SizeAdvertised = 0;   // "SIZE" without a limit: the client declares the size, the peer enforces its own
        peer.SizeEnforced = 3_000;
        var (lab, mx) = await StartAsync(peer);
        await using var _ = lab;

        var big = await lab.SendAsync(["rcpt@dest.example"], raw: Message(5_000));
        var events = await lab.WaitForEventAsync(big, MessageEventType.Bounced);
        var small = await lab.SendAsync(["rcpt@dest.example"], raw: Message(500));
        await lab.WaitForEventAsync(small, MessageEventType.Delivered);

        Assert.Equal(552, events.Single(e => e.Type == MessageEventType.Bounced).SmtpCode);
        Assert.Single(mx.Messages);
        Assert.Equal(1, mx.ConnectionCount);   // 552 at MAIL is an ordinary answer; the connection went back to the pool
    }

    [Fact]
    public async Task A_full_mailbox_452_4_2_2_is_retried_not_bounced_and_delivered_when_space_is_back()
    {
        var peer = Personalities.Postfix();
        bool full = true;
        peer.OnRcpt = (_, rcpt) => full ? Personalities.PostfixReplies.MailboxFull(rcpt) : null;
        var (lab, mx) = await StartAsync(peer);
        await using var _ = lab;

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var due = await lab.WaitForRetryScheduleAsync(id);
        full = false;
        lab.Advance(due - lab.Clock.UtcNow);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Single(mx.Messages);
        Assert.DoesNotContain(await lab.EventsAsync(id), e => e.Type == MessageEventType.Bounced);
        Assert.False(await lab.Storage.Config.IsSuppressedAsync(MtaLab.Tenant, "rcpt@dest.example", default));
    }
}
