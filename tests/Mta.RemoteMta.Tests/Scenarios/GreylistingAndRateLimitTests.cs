using System.Collections.Concurrent;
using Mta.Policy;
using Mta.RemoteMta.Tests.Harness;
using Mta.Storage;

namespace Mta.RemoteMta.Tests.Scenarios;

/// <summary>Temporary refusals that mean "come back later" or "slow down": how the engine schedules the retry and how it adapts its rate to the destination.</summary>
public class GreylistingAndRateLimitTests
{
    private static readonly TimeSpan Minute = TimeSpan.FromMinutes(1);

    private static MtaLab NewLabWithPeer(MtaPersonality peer, out FakeMta mx, LabSettings? settings = null)
    {
        var lab = new MtaLab(settings);
        mx = lab.AddMta("mx.dest.example", peer);
        lab.Mx("dest.example", 10, "mx.dest.example");
        return lab;
    }

    [Theory]
    [InlineData("postfix")]
    [InlineData("exim")]
    public async Task Greylisting_at_rcpt_is_retried_after_the_minimum_greylist_delay_and_not_before_then_accepted(string flavour)
    {
        var peer = flavour == "postfix" ? Personalities.Postfix() : Personalities.Exim();
        var firstSeen = new ConcurrentDictionary<string, bool>();
        peer.OnRcpt = (_, rcpt) => firstSeen.TryAdd(rcpt, true)
            ? flavour == "postfix" ? Personalities.PostfixReplies.Greylisted(rcpt, "dest.example") : Personalities.EximReplies.Greylisted
            : null;
        await using var lab = NewLabWithPeer(peer, out var mx);

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var due = await lab.WaitForRetryScheduleAsync(id);

        var deferred = (await lab.EventsAsync(id)).Single(e => e.Type == MessageEventType.Deferred);
        Assert.Equal(450, deferred.SmtpCode);
        Assert.Contains("Greylisted", deferred.Message);
        Assert.Equal(TimeSpan.FromMinutes(5), due - lab.Clock.UtcNow);   // base delay of 2 minutes raised to the greylist floor, jitter off
        Assert.Empty(mx.Messages);

        lab.Advance(4 * Minute);
        await lab.SettleAsync();
        Assert.Empty(mx.Messages);   // one minute early: the engine did look and did not retry
        Assert.DoesNotContain(await lab.EventsAsync(id), e => e.Type == MessageEventType.Delivered);

        lab.Advance(Minute);
        var events = await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Equal(["rcpt@dest.example"], Assert.Single(mx.Messages).Recipients);
        Assert.Single(events, e => e.Type == MessageEventType.Deferred);
        Assert.False(await lab.Storage.Config.IsSuppressedAsync(MtaLab.Tenant, "rcpt@dest.example", default));
    }

    [Fact]
    public async Task Greylisting_after_the_data_is_retried_and_the_second_transaction_carries_the_same_message_once()
    {
        var peer = Personalities.Postfix();
        int verdicts = 0;
        peer.OnEndOfData = (_, _) => Interlocked.Increment(ref verdicts) == 1 ? Step.Reply(451, "4.7.1", "Greylisted, please try again in 300 seconds") : null;
        await using var lab = NewLabWithPeer(peer, out var mx);

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var due = await lab.WaitForRetryScheduleAsync(id);

        Assert.Equal(TimeSpan.FromMinutes(5), due - lab.Clock.UtcNow);   // the server's own hint (300 s) equals the greylist floor
        Assert.Empty(mx.Messages);   // a refused message is not stored by the peer
        Assert.DoesNotContain(await lab.EventsAsync(id), e => e.Type == MessageEventType.PossibleDuplicate);   // the verdict arrived: nothing is in doubt

        lab.Advance(5 * Minute);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);
        Assert.Single(mx.Messages);
        Assert.DoesNotContain(await lab.EventsAsync(id), e => e.Type == MessageEventType.PossibleDuplicate);
    }

    [Fact]
    public async Task A_server_retry_hint_longer_than_the_schedule_is_obeyed()
    {
        var peer = Personalities.Postfix();
        int verdicts = 0;
        peer.OnEndOfData = (_, _) => Interlocked.Increment(ref verdicts) == 1 ? Step.Reply(451, "4.3.0", "Temporary system problem, please try again in 3600 seconds") : null;
        await using var lab = NewLabWithPeer(peer, out _);

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var due = await lab.WaitForRetryScheduleAsync(id);

        Assert.Equal(TimeSpan.FromHours(1), due - lab.Clock.UtcNow);
    }

    [Fact]
    public async Task A_421_rate_limit_from_a_gmail_like_peer_backs_off_ten_minutes_and_cuts_the_destinations_rate()
    {
        var peer = Personalities.Gmail();
        int rcpts = 0;
        peer.OnRcpt = (_, _) => Interlocked.Increment(ref rcpts) == 1 ? Personalities.GmailReplies.RateLimited.Then(Step.Close()) : null;
        await using var lab = NewLabWithPeer(peer, out var mx);
        var key = new ThrottleKey("dest.example");

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var due = await lab.WaitForRetryScheduleAsync(id);

        var deferred = (await lab.EventsAsync(id)).Single(e => e.Type == MessageEventType.Deferred);
        Assert.Equal(421, deferred.SmtpCode);
        Assert.Equal("4.7.28", deferred.EnhancedCode);
        Assert.Equal(TimeSpan.FromMinutes(10), due - lab.Clock.UtcNow);
        var snapshot = lab.Throttle.GetSnapshot(key)!;
        Assert.True(snapshot.Penalized);
        Assert.True(snapshot.MessagesPerMinute < 120, $"rate should have been halved from 120, is {snapshot.MessagesPerMinute}");
        Assert.True(snapshot.ConcurrencyLimit < 5);

        lab.Advance(10 * Minute);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);
        Assert.Single(mx.Messages);
        Assert.False(await lab.Storage.Config.IsSuppressedAsync(MtaLab.Tenant, "rcpt@dest.example", default));
    }

    public static TheoryData<string> ThrottleReplies => new() { "outlook-server-busy", "outlook-ip-reputation", "postfix-too-much-mail", "exim-rate-limit" };

    [Theory]
    [MemberData(nameof(ThrottleReplies))]
    public async Task Provider_throttling_replies_are_all_read_as_slow_down_and_deferred_ten_minutes(string kind)
    {
        var peer = kind.StartsWith("outlook", StringComparison.Ordinal) ? Personalities.Outlook() : kind.StartsWith("postfix", StringComparison.Ordinal) ? Personalities.Postfix() : Personalities.Exim();
        Step refusal = kind switch
        {
            "outlook-server-busy" => Personalities.OutlookReplies.ServerBusy,
            "outlook-ip-reputation" => Personalities.OutlookReplies.TemporarilyRateLimited,
            "postfix-too-much-mail" => Personalities.PostfixReplies.TooMuchMail,
            _ => Personalities.EximReplies.RateLimited,
        };
        int calls = 0;
        peer.OnMail = (_, _, _) => Interlocked.Increment(ref calls) == 1 ? refusal : null;
        await using var lab = NewLabWithPeer(peer, out var mx);

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var due = await lab.WaitForRetryScheduleAsync(id);

        Assert.Equal(TimeSpan.FromMinutes(10), due - lab.Clock.UtcNow);
        Assert.True(lab.Throttle.GetSnapshot(new ThrottleKey("dest.example"))!.Penalized);
        lab.Advance(10 * Minute);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);
        Assert.Single(mx.Messages);
    }

    [Fact]
    public async Task Repeated_throttling_stretches_the_retry_delay_along_the_ladder_up_to_the_eight_hour_cap()
    {
        var peer = Personalities.Gmail();
        peer.OnRcpt = (_, _) => Personalities.GmailReplies.RateLimited.Then(Step.Close());
        await using var lab = NewLabWithPeer(peer, out var mx);

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var delays = new List<TimeSpan>();
        for (int attempt = 1; attempt <= 7; attempt++)
        {
            var due = await lab.WaitForRetryScheduleAsync(id, attempt);
            delays.Add(due - lab.Clock.UtcNow);
            lab.Advance(due - lab.Clock.UtcNow);
        }

        // Scheduled delay after the n-th failure doubled (throttle multiplier), at least ten minutes, never more than eight hours.
        Assert.Equal(
            [10, 10, 30, 60, 120, 240, 480],
            delays.Select(d => (int)d.TotalMinutes));
        Assert.Empty(mx.Messages);
    }

    [Fact]
    public async Task A_destination_concurrency_ceiling_keeps_the_extra_messages_waiting_without_connecting_and_everything_arrives()
    {
        var release = new TaskCompletionSource();
        var peer = Personalities.Postfix();
        int verdicts = 0;
        peer.OnEndOfData = (_, _) => Interlocked.Increment(ref verdicts) <= 2 ? Step.After(release.Task, Step.Reply(250, "2.0.0", "Ok: queued")) : null;
        var throttle = new DestinationThrottleOptions { Defaults = new ThrottleLimits(2, 600, 100), InitialConcurrentConnections = 2 };
        await using var lab = NewLabWithPeer(peer, out var mx, new LabSettings { Throttle = throttle });

        var ids = new List<Guid>();
        for (int i = 0; i < 5; i++)
        {
            ids.Add(await lab.SendAsync([$"r{i}@dest.example"]));
        }

        await Wait.UntilAsync(() => mx.ConnectionCount >= 2, "two connections to be open");
        await lab.SettleAsync();

        // The engine hands the surplus groups back one by one; wait for the settled state instead of reading it once.
        await Wait.UntilAsync(async () => await lab.QueueAsync() is { Leased: 2, Queued: 3 }, "two leased deliveries and three held in the queue");   // held: back in the queue with a later due time, no attempt counted
        Assert.Equal(2, mx.ConnectionCount);   // the other three groups were held by the throttle, not refused by the peer
        Assert.Equal(2, mx.MaxConcurrentConnectionsSeen);
        foreach (var id in ids)
        {
            Assert.DoesNotContain(await lab.EventsAsync(id), e => e.Type is MessageEventType.Deferred or MessageEventType.Bounced);   // a throttle hold is not an attempt
        }

        release.SetResult();
        foreach (var id in ids)
        {
            await lab.AdvanceUntilAsync(() => lab.EventsAsync(id).Result.Any(e => e.Type == MessageEventType.Delivered), TimeSpan.FromSeconds(3), $"message {id:N} to be delivered");
        }

        Assert.Equal(5, mx.Messages.Count);
        Assert.True(mx.MaxConcurrentConnectionsSeen <= 2);
    }

    [Fact]
    public async Task A_peer_that_refuses_connections_beyond_its_limit_with_421_gets_the_rest_later_and_nothing_is_lost()
    {
        var release = new TaskCompletionSource();
        var peer = Personalities.Postfix();
        peer.MaxConcurrentConnections = 1;
        int verdicts = 0;
        peer.OnEndOfData = (_, _) => Interlocked.Increment(ref verdicts) == 1 ? Step.After(release.Task, Step.Reply(250, "2.0.0", "Ok: queued")) : null;
        await using var lab = NewLabWithPeer(peer, out var mx);

        var held = await lab.SendAsync(["first@dest.example"]);
        await Wait.UntilAsync(() => mx.Sessions.Any(s => s.Verbs.Contains("DATA")), "the first message to reach the peer");
        var refused = new[] { await lab.SendAsync(["second@dest.example"]), await lab.SendAsync(["third@dest.example"]) };
        foreach (var id in refused)
        {
            await lab.WaitForEventAsync(id, MessageEventType.Deferred);
        }

        foreach (var id in refused)
        {
            var deferred = (await lab.EventsAsync(id)).Single(e => e.Type == MessageEventType.Deferred);
            Assert.Equal(421, deferred.SmtpCode);
            Assert.Contains("Too many connections", deferred.Message);
        }

        release.SetResult();
        await lab.WaitForEventAsync(held, MessageEventType.Delivered);
        foreach (var id in refused)
        {
            await lab.AdvanceUntilAsync(() => lab.EventsAsync(id).Result.Any(e => e.Type == MessageEventType.Delivered), TimeSpan.FromMinutes(1), $"message {id:N} to be delivered");
        }

        Assert.Equal(3, mx.Messages.Count);
        Assert.All(new[] { "first@dest.example", "second@dest.example", "third@dest.example" }, r => Assert.Contains(mx.Messages, m => m.Recipients.Contains(r)));
    }
}
