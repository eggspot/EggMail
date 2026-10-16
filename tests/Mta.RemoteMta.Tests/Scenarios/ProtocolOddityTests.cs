using Mta.RemoteMta.Tests.Harness;
using Mta.Storage;

namespace Mta.RemoteMta.Tests.Scenarios;

/// <summary>Peers that do not follow the protocol: long and many-lined replies, garbage, sloppy line endings, unsolicited replies. The engine must neither crash, nor lose the message, nor claim a delivery it did not get.</summary>
public class ProtocolOddityTests
{
    private static MtaLab SingleMx(MtaPersonality peer, out FakeMta mx)
    {
        var lab = new MtaLab();
        mx = lab.AddMta("mx.dest.example", peer);
        lab.Mx("dest.example", 10, "mx.dest.example");
        return lab;
    }

    // --------------------------------------------------------------------------- tolerated sloppiness

    [Fact]
    public async Task A_reply_line_close_to_the_length_limit_is_accepted()
    {
        var peer = Personalities.Postfix();
        peer.OnEndOfData = (_, _) => Step.Reply(250, "2.0.0", "Ok: queued as 4F2E5C0A21 " + new string('x', 3_900));
        await using var lab = SingleMx(peer, out var mx);

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var events = await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Single(mx.Messages);
        Assert.True(events.Single(e => e.Type == MessageEventType.Delivered).Message!.Length <= 1000);   // the stored text is bounded however long the reply was
    }

    [Fact]
    public async Task A_greeting_of_a_hundred_lines_is_accepted()
    {
        var peer = Personalities.Postfix();
        peer.Greeting = _ => Step.Reply(220, null, Enumerable.Range(0, 100).Select(i => $"line {i} of a very chatty greeting").ToArray());
        await using var lab = SingleMx(peer, out var mx);

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Single(mx.Messages);
    }

    [Fact]
    public async Task Replies_that_end_in_a_bare_line_feed_are_understood()
    {
        var peer = Personalities.Postfix();
        peer.OnMail = (_, _, _) => Step.Raw("250 2.1.0 Ok with a bare LF\n");
        await using var lab = SingleMx(peer, out var mx);

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Single(mx.Messages);
    }

    [Fact]
    public async Task A_greeting_that_is_only_a_code_is_a_greeting()
    {
        var peer = Personalities.Postfix();
        peer.Greeting = _ => Step.Raw("220\r\n");
        await using var lab = SingleMx(peer, out var mx);

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Single(mx.Messages);
    }

    [Fact]
    public async Task Capability_lines_with_nonsense_values_do_not_stop_a_delivery()
    {
        var peer = Personalities.Exim();
        peer.ExtraCapabilities.AddRange(["SIZE banana", "AUTH", "XFOO bar baz", "STARTTLS-ish", "8BITMIME-ISH"]);
        await using var lab = SingleMx(peer, out var mx);

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Single(mx.Messages);
    }

    // ------------------------------------------------------------------------------- garbage and limits

    public static TheoryData<string> GarbageGreetings => new()
    {
        "Hello stranger\r\n",
        "SSH-2.0-OpenSSH_9.6\r\n",
        "HTTP/1.1 400 Bad Request\r\n",
        "999 not a real reply\r\n",
        "220-first\r\n221 second\r\n",
        "2200 five\r\n",
        "\u0000\u0001\u0002ÿþ\r\n",
    };

    [Theory]
    [MemberData(nameof(GarbageGreetings))]
    public async Task A_peer_that_answers_with_garbage_is_a_temporary_problem_not_a_bounce_and_not_a_delivery(string garbage)
    {
        var peer = Personalities.Postfix();
        bool garbled = true;
        peer.Greeting = _ => garbled ? Step.Raw(garbage).Then(Step.Close()) : null!;
        await using var lab = SingleMx(peer, out var mx);

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var due = await lab.WaitForRetryScheduleAsync(id);

        var events = await lab.EventsAsync(id);
        Assert.DoesNotContain(events, e => e.Type is MessageEventType.Bounced or MessageEventType.Delivered);
        Assert.Empty(mx.Messages);

        garbled = false;
        lab.Advance(due - lab.Clock.UtcNow);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);
    }

    [Fact]
    public async Task A_reply_line_over_the_length_limit_is_refused_as_a_protocol_error()
    {
        var peer = Personalities.Postfix();
        peer.OnMail = (_, _, _) => Step.Reply(250, "2.1.0", new string('y', 5_000));
        await using var lab = SingleMx(peer, out var mx);

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Deferred);

        Assert.Empty(mx.Messages);
    }

    [Fact]
    public async Task A_multiline_reply_of_a_thousand_lines_is_refused_as_a_protocol_error_before_it_fills_memory()
    {
        var peer = Personalities.Postfix();
        peer.Greeting = _ => Step.Reply(220, null, Enumerable.Range(0, 1_000).Select(i => "spam " + i).ToArray());
        await using var lab = SingleMx(peer, out var mx);

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Deferred);

        Assert.Empty(mx.Messages);
    }

    [Fact]
    public async Task An_extra_unsolicited_reply_throws_the_conversation_out_of_step_and_the_engine_never_mistakes_that_for_a_delivery()
    {
        var peer = Personalities.Postfix();
        peer.Pipelining = false;
        bool extra = true;
        peer.OnMail = (_, _, _) => extra ? Step.Raw("250 2.1.0 Ok\r\n250 2.1.0 and another one nobody asked for\r\n") : null;
        await using var lab = SingleMx(peer, out var mx);

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var due = await lab.WaitForRetryScheduleAsync(id);

        var events = await lab.EventsAsync(id);
        Assert.DoesNotContain(events, e => e.Type is MessageEventType.Delivered or MessageEventType.Bounced);
        Assert.Empty(mx.Messages);

        extra = false;
        lab.Advance(due - lab.Clock.UtcNow);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);
        Assert.Single(mx.Messages);
    }

    [Fact]
    public async Task Garbage_where_the_verdict_after_the_data_should_be_is_treated_like_a_lost_verdict_and_flagged_as_a_possible_duplicate()
    {
        var peer = Personalities.Postfix();
        bool garbled = true;
        peer.OnEndOfData = (_, ctx) =>
        {
            if (!garbled)
            {
                return null;
            }

            ctx.Keep = true;
            return Step.Raw("this is not a reply\r\n").Then(Step.Close());
        };
        await using var lab = SingleMx(peer, out var mx);

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var due = await lab.WaitForRetryScheduleAsync(id);

        Assert.Single(mx.Messages);
        Assert.Contains(await lab.EventsAsync(id), e => e.Type == MessageEventType.PossibleDuplicate);

        garbled = false;
        lab.Advance(due - lab.Clock.UtcNow);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);
        Assert.Equal(2, mx.Messages.Count);
    }

    [Fact]
    public async Task A_peer_that_answers_a_positive_code_where_an_intermediate_one_is_required_does_not_get_the_message()
    {
        var peer = Personalities.Postfix();
        peer.OnData = _ => Step.Reply(250, "2.0.0", "Ok, whatever");   // not 354
        await using var lab = SingleMx(peer, out var mx);

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Deferred);

        Assert.Empty(mx.Messages);
        Assert.DoesNotContain(await lab.EventsAsync(id), e => e.Type is MessageEventType.Delivered or MessageEventType.Bounced);
    }

    [Fact]
    public async Task A_mail_body_with_a_lone_cr_or_nul_is_never_put_on_the_wire_and_the_sender_hears_about_it()
    {
        await using var lab = SingleMx(Personalities.Postfix(), out var mx);
        lab.AddSenderSide();
        byte[] raw = System.Text.Encoding.ASCII.GetBytes("From: sender@example.org\r\nTo: rcpt@dest.example\r\nSubject: bad\r\nMessage-ID: <n@example.org>\r\nDate: Mon, 12 Oct 2026 08:00:00 +0000\r\n\r\nbody with a lone CR\rmore body\r\n");

        var id = await lab.SendAsync(["rcpt@dest.example"], raw: raw);
        var events = await lab.WaitForEventAsync(id, MessageEventType.Bounced);

        Assert.Empty(mx.Messages);
        Assert.False(await lab.Storage.Config.IsSuppressedAsync(MtaLab.Tenant, "rcpt@dest.example", default));
        Assert.Equal(554, events.Single(e => e.Type == MessageEventType.Bounced).SmtpCode);
    }
}
