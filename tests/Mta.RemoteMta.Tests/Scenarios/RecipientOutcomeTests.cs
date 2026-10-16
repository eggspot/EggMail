using System.Collections.Concurrent;
using Mta.RemoteMta.Tests.Harness;
using Mta.Storage;

namespace Mta.RemoteMta.Tests.Scenarios;

/// <summary>One transaction, several recipients, different answers: each recipient ends in exactly one state and nothing is sent twice.</summary>
public class RecipientOutcomeTests
{
    private static async Task<(MtaLab Lab, FakeMta Mx, FakeMta Sender)> StartAsync(MtaPersonality peer, LabSettings? settings = null)
    {
        var lab = new MtaLab(settings);
        var mx = lab.AddMta("mx.dest.example", peer);
        lab.Mx("dest.example", 10, "mx.dest.example");
        var sender = lab.AddSenderSide();
        await Task.CompletedTask;
        return (lab, mx, sender);
    }

    [Fact]
    public async Task One_transaction_with_an_accepted_a_refused_and_a_deferred_recipient_ends_in_delivered_bounced_and_deferred_and_the_deferred_one_is_sent_alone_later()
    {
        var peer = Personalities.Postfix();
        int grey = 0;
        peer.OnRcpt = (_, rcpt) => rcpt switch
        {
            "gone@dest.example" => Personalities.PostfixReplies.UserUnknown(rcpt),
            "grey@dest.example" when Interlocked.Increment(ref grey) == 1 => Personalities.PostfixReplies.Greylisted(rcpt, "dest.example"),
            _ => null,
        };
        var (lab, mx, _) = await StartAsync(peer);
        await using var _lab = lab;

        var id = await lab.SendAsync(["ok@dest.example", "gone@dest.example", "grey@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);
        await lab.WaitForEventAsync(id, MessageEventType.Bounced);
        var due = await lab.WaitForRetryScheduleAsync(id);

        var first = Assert.Single(mx.Messages);
        Assert.Equal(["ok@dest.example"], first.Recipients);   // the transaction carried only the recipient that was accepted
        Assert.True(await lab.Storage.Config.IsSuppressedAsync(MtaLab.Tenant, "gone@dest.example", default));
        Assert.False(await lab.Storage.Config.IsSuppressedAsync(MtaLab.Tenant, "grey@dest.example", default));

        lab.Advance(due - lab.Clock.UtcNow);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered, 2);

        Assert.Equal(2, mx.Messages.Count);
        Assert.Equal(["grey@dest.example"], mx.Messages[1].Recipients);   // and not the recipients that were already done
        var events = await lab.EventsAsync(id);
        Assert.Equal(["grey@dest.example", "ok@dest.example"], events.Where(e => e.Type == MessageEventType.Delivered).Select(e => e.Recipient!).Order());
    }

    [Fact]
    public async Task A_peer_that_accepts_only_two_recipients_per_transaction_with_452_gets_the_rest_in_later_transactions()
    {
        var peer = Personalities.Postfix();
        peer.MaxRecipientsPerTransaction = 2;
        var (lab, mx, _) = await StartAsync(peer);
        await using var _lab = lab;
        string[] recipients = ["a@dest.example", "b@dest.example", "c@dest.example", "d@dest.example", "e@dest.example"];

        var id = await lab.SendAsync(recipients);
        await lab.AdvanceUntilAsync(() => lab.EventsAsync(id).Result.Count(e => e.Type == MessageEventType.Delivered) == 5, TimeSpan.FromMinutes(1), "all five recipients to be delivered");

        var events = await lab.EventsAsync(id);
        Assert.Equal(recipients, events.Where(e => e.Type == MessageEventType.Delivered).Select(e => e.Recipient!).Order());
        Assert.All(mx.Messages, m => Assert.True(m.Recipients.Count <= 2));
        Assert.Equal(recipients, mx.Messages.SelectMany(m => m.Recipients).Order());   // each recipient got the message exactly once
        Assert.DoesNotContain(events, e => e.Type is MessageEventType.Bounced or MessageEventType.Expired or MessageEventType.PossibleDuplicate);
        foreach (string r in recipients)
        {
            Assert.False(await lab.Storage.Config.IsSuppressedAsync(MtaLab.Tenant, r, default));
        }
    }

    [Fact]
    public async Task A_421_in_the_middle_of_the_recipient_list_defers_the_whole_group_without_sending_anything_and_it_goes_through_on_the_retry()
    {
        var peer = Personalities.Postfix();
        bool failing = true;
        peer.OnRcpt = (_, rcpt) => failing && rcpt.StartsWith("b@", StringComparison.Ordinal) ? Step.Reply(421, "4.3.2", "System shutting down").Then(Step.Close()) : null;
        var (lab, mx, _) = await StartAsync(peer);
        await using var _lab = lab;

        var id = await lab.SendAsync(["a@dest.example", "b@dest.example", "c@dest.example"]);
        var due = await lab.WaitForRetryScheduleAsync(id, 1);

        var events = await lab.EventsAsync(id);
        Assert.Equal(3, events.Count(e => e.Type == MessageEventType.Deferred));   // every recipient, with the reason the peer gave
        Assert.All(events.Where(e => e.Type == MessageEventType.Deferred), e => Assert.Equal(421, e.SmtpCode));
        Assert.Empty(mx.Messages);
        Assert.DoesNotContain(events, e => e.Type is MessageEventType.PossibleDuplicate or MessageEventType.Bounced);

        failing = false;
        lab.Advance(due - lab.Clock.UtcNow);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered, 3);

        var message = Assert.Single(mx.Messages);
        Assert.Equal(["a@dest.example", "b@dest.example", "c@dest.example"], message.Recipients.Order());
    }

    [Fact]
    public async Task A_421_after_the_data_command_defers_without_flagging_a_possible_duplicate_because_the_message_was_never_sent()
    {
        var peer = Personalities.Postfix();
        int calls = 0;
        peer.OnData = _ => Interlocked.Increment(ref calls) == 1 ? Step.Reply(421, "4.4.2", "Timeout waiting for data, closing").Then(Step.Close()) : null;
        var (lab, mx, _) = await StartAsync(peer);
        await using var _lab = lab;

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var due = await lab.WaitForRetryScheduleAsync(id);
        lab.Advance(due - lab.Clock.UtcNow);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Single(mx.Messages);
        Assert.DoesNotContain(await lab.EventsAsync(id), e => e.Type == MessageEventType.PossibleDuplicate);
    }

    [Fact]
    public async Task All_recipients_refused_temporarily_leaves_the_connection_usable_and_the_next_message_reuses_it()
    {
        var peer = Personalities.Postfix();
        peer.OnRcpt = (_, rcpt) => rcpt.StartsWith("later@", StringComparison.Ordinal) ? Personalities.PostfixReplies.Greylisted(rcpt, "dest.example") : null;
        var (lab, mx, _) = await StartAsync(peer);
        await using var _lab = lab;

        var greylisted = await lab.SendAsync(["later@dest.example"]);
        await lab.WaitForEventAsync(greylisted, MessageEventType.Deferred);
        var fine = await lab.SendAsync(["now@dest.example"]);
        await lab.WaitForEventAsync(fine, MessageEventType.Delivered);

        Assert.Equal(1, mx.ConnectionCount);
        Assert.Single(mx.Messages);
        Assert.Contains("RSET", mx.Sessions.Single().Verbs);   // the aborted transaction was cleared before the connection was reused
    }

    [Fact]
    public async Task Recipients_for_two_domains_are_sent_in_separate_transactions_to_their_own_peers()
    {
        await using var lab = new MtaLab();
        var one = lab.AddMta("mx.one.example", Personalities.Gmail());
        var two = lab.AddMta("mx.two.example", Personalities.Outlook());
        lab.Mx("one.example", 10, "mx.one.example").Mx("two.example", 10, "mx.two.example");

        var id = await lab.SendAsync(["a@one.example", "b@two.example", "c@one.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered, 3);

        Assert.Equal(["a@one.example", "c@one.example"], Assert.Single(one.Messages).Recipients.Order());
        Assert.Equal(["b@two.example"], Assert.Single(two.Messages).Recipients);
    }

    [Fact]
    public async Task Concurrent_messages_to_one_peer_are_each_delivered_exactly_once()
    {
        var peer = Personalities.Postfix();
        var (lab, mx, _) = await StartAsync(peer);
        await using var _lab = lab;
        var ids = new ConcurrentBag<Guid>();

        foreach (int i in Enumerable.Range(0, 20))
        {
            ids.Add(await lab.SendAsync([$"r{i}@dest.example"], subject: "burst " + i));
        }

        // More messages than the destination's starting concurrency: the surplus waits on the throttle, which runs on the fake clock.
        foreach (var id in ids)
        {
            await lab.AdvanceUntilAsync(() => lab.EventsAsync(id).Result.Any(e => e.Type == MessageEventType.Delivered), TimeSpan.FromSeconds(3), $"message {id:N} to be delivered");
        }

        Assert.Equal(20, mx.Messages.Count);
        Assert.Equal(20, mx.Messages.SelectMany(m => m.Recipients).Distinct().Count());
    }
}
