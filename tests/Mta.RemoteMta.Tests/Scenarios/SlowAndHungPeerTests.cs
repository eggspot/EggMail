using System.Text.Json;
using Mta.RemoteMta.Tests.Harness;
using Mta.Smtp.Client;
using Mta.Storage;

namespace Mta.RemoteMta.Tests.Scenarios;

/// <summary>
/// Peers that are slow, silent or that vanish at the worst moment. Time-outs are shortened to a second for the one stage under test (the others keep their RFC 5321 values),
/// and the assertions are about outcomes: what was sent, what was stored by the peer, and whether a possible duplicate is flagged.
/// </summary>
public class SlowAndHungPeerTests
{
    private static readonly TimeSpan Short = TimeSpan.FromSeconds(1);

    private static LabSettings WithClient(TimeSpan? banner = null, TimeSpan? dataInitiation = null, TimeSpan? endOfData = null, TimeSpan? command = null) => new()
    {
        Client = new SmtpClientOptions
        {
            HeloName = "egg.test",
            BannerTimeout = banner ?? TimeSpan.FromMinutes(5),
            DataInitiationTimeout = dataInitiation ?? TimeSpan.FromMinutes(2),
            EndOfDataTimeout = endOfData ?? TimeSpan.FromMinutes(10),
            CommandTimeout = command ?? TimeSpan.FromMinutes(5),
        },
    };

    private static MtaLab SingleMx(MtaPersonality peer, out FakeMta mx, LabSettings? settings = null)
    {
        var lab = new MtaLab(settings);
        mx = lab.AddMta("mx.dest.example", peer);
        lab.Mx("dest.example", 10, "mx.dest.example");
        return lab;
    }

    // --------------------------------------------------------------------------------------------- before the data

    [Fact]
    public async Task A_peer_that_never_sends_a_banner_is_given_up_on_and_the_next_mx_takes_the_message()
    {
        await using var lab = new MtaLab(WithClient(banner: Short));
        var silent = Personalities.Plain("mx1.dest.example");
        silent.Greeting = _ => Step.Hang();
        var first = lab.AddMta("mx1.dest.example", silent);
        var second = lab.AddMta("mx2.dest.example", Personalities.Plain("mx2.dest.example"));
        lab.Mx("dest.example", 10, "mx1.dest.example").Mx("dest.example", 20, "mx2.dest.example");

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var events = await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Equal(1, first.ConnectionCount);
        Assert.Single(second.Messages);
        Assert.Equal("mx2.dest.example", events.Single(e => e.Type == MessageEventType.Delivered).MxHost);
    }

    [Fact]
    public async Task A_banner_that_trickles_in_one_byte_at_a_time_is_read_to_the_end()
    {
        var peer = Personalities.Postfix();
        peer.Greeting = _ => Step.Drip("220-mx.dest.example welcome\r\n220 ESMTP Postfix, patience please\r\n");
        await using var lab = SingleMx(peer, out var mx);

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Single(mx.Messages);
    }

    [Fact]
    public async Task A_tarpit_banner_that_never_ends_its_multiline_greeting_defers_the_message_and_does_not_hang_the_engine()
    {
        var peer = Personalities.Postfix();
        bool tarpit = true;
        peer.Greeting = _ => tarpit ? Step.Raw("220-mx.dest.example ESMTP\r\n220-we are very slow today\r\n").Then(Step.Hang()) : null!;
        await using var lab = SingleMx(peer, out var mx, WithClient(banner: Short));

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var due = await lab.WaitForRetryScheduleAsync(id);

        Assert.Empty(mx.Messages);
        // The engine is still serving others while it waited.
        await lab.SettleAsync();

        tarpit = false;
        lab.Advance(due - lab.Clock.UtcNow);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);
    }

    [Fact]
    public async Task A_peer_that_accepts_the_recipient_and_never_answers_data_defers_without_a_duplicate_flag_because_nothing_was_sent()
    {
        var peer = Personalities.Postfix();
        bool hang = true;
        peer.OnData = _ => hang ? Step.Hang() : null;
        await using var lab = SingleMx(peer, out var mx, WithClient(dataInitiation: Short));

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var due = await lab.WaitForRetryScheduleAsync(id);

        Assert.Empty(mx.Messages);
        Assert.DoesNotContain(await lab.EventsAsync(id), e => e.Type == MessageEventType.PossibleDuplicate);

        hang = false;
        lab.Advance(due - lab.Clock.UtcNow);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);
        Assert.Single(mx.Messages);
    }

    [Fact]
    public async Task A_peer_that_stops_answering_in_the_middle_of_the_envelope_defers_the_whole_group_untouched()
    {
        var peer = Personalities.Postfix();
        peer.Pipelining = false;
        bool hang = true;
        peer.OnRcpt = (_, rcpt) => hang && rcpt.StartsWith("b@", StringComparison.Ordinal) ? Step.Hang() : null;
        await using var lab = SingleMx(peer, out var mx, WithClient(command: Short));

        var id = await lab.SendAsync(["a@dest.example", "b@dest.example"]);
        var due = await lab.WaitForRetryScheduleAsync(id);

        Assert.Empty(mx.Messages);
        Assert.DoesNotContain(await lab.EventsAsync(id), e => e.Type == MessageEventType.PossibleDuplicate);

        hang = false;
        lab.Advance(due - lab.Clock.UtcNow);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered, 2);
        Assert.Equal(["a@dest.example", "b@dest.example"], Assert.Single(mx.Messages).Recipients.Order());
    }

    // ----------------------------------------------------------------------------- after the end of the data

    public static TheoryData<string> LostVerdicts => new() { "silence", "close", "reset" };

    [Theory]
    [MemberData(nameof(LostVerdicts))]
    public async Task When_the_verdict_after_the_end_of_data_never_arrives_the_delivery_is_retried_and_flagged_as_a_possible_duplicate(string how)
    {
        var peer = Personalities.Postfix();
        bool lose = true;
        peer.OnEndOfData = (_, ctx) =>
        {
            if (!lose)
            {
                return null;
            }

            ctx.Keep = true;   // the peer queued the message and then lost the connection or the thread
            return how switch { "silence" => Step.Hang(), "close" => Step.Close(), _ => Step.Abort() };
        };
        await using var lab = SingleMx(peer, out var mx, WithClient(endOfData: Short));
        await lab.SubscribeWebhookAsync("message.deferred", "message.delivered");

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var due = await lab.WaitForRetryScheduleAsync(id);

        Assert.Single(mx.Messages);   // the peer has it
        Assert.Contains(await lab.EventsAsync(id), e => e.Type == MessageEventType.PossibleDuplicate);

        lose = false;
        lab.Advance(due - lab.Clock.UtcNow);
        var events = await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Equal(2, mx.Messages.Count);   // and now it has it twice: that is the at-least-once guarantee, and the flag is how the receiver of the webhook knows
        Assert.Single(events, e => e.Type == MessageEventType.Delivered);
        var payloads = (await lab.WebhookPayloadsAsync()).Select(p => JsonDocument.Parse(p).RootElement.GetProperty("data")).ToArray();
        Assert.Equal(2, payloads.Length);
        Assert.All(payloads, d => Assert.True(d.GetProperty("possible_duplicate").GetBoolean()));
    }

    [Fact]
    public async Task An_explicit_421_as_the_verdict_is_a_refusal_and_not_a_possible_duplicate()
    {
        var peer = Personalities.Postfix();
        int calls = 0;
        peer.OnEndOfData = (_, _) => Interlocked.Increment(ref calls) == 1 ? Step.Reply(421, "4.3.2", "System going down, message not accepted").Then(Step.Close()) : null;
        await using var lab = SingleMx(peer, out var mx);

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var due = await lab.WaitForRetryScheduleAsync(id);
        Assert.Empty(mx.Messages);
        Assert.DoesNotContain(await lab.EventsAsync(id), e => e.Type == MessageEventType.PossibleDuplicate);

        lab.Advance(due - lab.Clock.UtcNow);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);
        Assert.Single(mx.Messages);
        Assert.DoesNotContain(await lab.EventsAsync(id), e => e.Type == MessageEventType.PossibleDuplicate);
    }

    [Fact]
    public async Task A_flagged_delivery_stays_flagged_through_later_deferrals_until_it_is_delivered()
    {
        var peer = Personalities.Postfix();
        int calls = 0;
        peer.OnEndOfData = (_, ctx) =>
        {
            int n = Interlocked.Increment(ref calls);
            if (n == 1)
            {
                ctx.Keep = true;
                return Step.Close();
            }

            return n == 2 ? Personalities.PostfixReplies.TooMuchMail : null;
        };
        await using var lab = SingleMx(peer, out _);
        await lab.SubscribeWebhookAsync("message.deferred", "message.delivered");

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        for (int attempt = 1; attempt <= 2; attempt++)
        {
            var due = await lab.WaitForRetryScheduleAsync(id, attempt);
            lab.Advance(due - lab.Clock.UtcNow);
        }

        await lab.WaitForEventAsync(id, MessageEventType.Delivered);
        var flags = (await lab.WebhookPayloadsAsync()).Select(p => JsonDocument.Parse(p).RootElement.GetProperty("data").TryGetProperty("possible_duplicate", out var f) && f.GetBoolean()).ToArray();
        Assert.Equal([true, true, true], flags);   // the first deferral, the one after the clean refusal, and the final delivery
    }
}
