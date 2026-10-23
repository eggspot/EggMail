using Mta.RemoteMta.Tests.Harness;
using Mta.Smtp.Client;
using Mta.Storage;

namespace Mta.RemoteMta.Tests.Scenarios;

public class ConnectionReuseTests
{
    private static MtaLab SingleMx(MtaPersonality peer, out FakeMta mx, LabSettings? settings = null)
    {
        var lab = new MtaLab(settings);
        mx = lab.AddMta("mx.dest.example", peer);
        lab.Mx("dest.example", 10, "mx.dest.example");
        return lab;
    }

    private static async Task DeliverAsync(MtaLab lab, string recipient)
    {
        var id = await lab.SendAsync([recipient]);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);
    }

    [Fact]
    public async Task Consecutive_messages_to_one_peer_share_a_connection_with_an_rset_after_each_transaction_and_a_noop_before_each_reuse()
    {
        await using var lab = SingleMx(Personalities.Postfix(), out var mx);

        await DeliverAsync(lab, "one@dest.example");
        await DeliverAsync(lab, "two@dest.example");
        await DeliverAsync(lab, "three@dest.example");

        Assert.Equal(1, mx.ConnectionCount);
        Assert.Equal(3, mx.Messages.Count);
        var verbs = mx.Sessions.Single().Verbs;
        Assert.Equal(1, verbs.Count(v => v == "EHLO"));
        Assert.Equal(3, verbs.Count(v => v == "RSET"));
        Assert.Equal(2, verbs.Count(v => v == "NOOP"));
        Assert.True(verbs.ToList().IndexOf("NOOP") > verbs.ToList().IndexOf("RSET"));
    }

    [Fact]
    public async Task A_peer_that_closed_the_idle_connection_is_noticed_and_the_next_message_uses_a_new_one_without_any_deferral()
    {
        await using var lab = SingleMx(Personalities.Postfix(), out var mx);
        await DeliverAsync(lab, "one@dest.example");

        mx.DropOpenConnections();
        var id = await lab.SendAsync(["two@dest.example"]);
        var events = await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Equal(2, mx.ConnectionCount);
        Assert.DoesNotContain(events, e => e.Type == MessageEventType.Deferred);
        Assert.Equal(2, mx.Messages.Count);
    }

    [Fact]
    public async Task A_connection_idle_longer_than_the_pool_timeout_is_not_reused_without_even_a_noop()
    {
        await using var lab = SingleMx(Personalities.Postfix(), out var mx, new LabSettings { PoolIdleTimeout = TimeSpan.FromSeconds(30) });
        await DeliverAsync(lab, "one@dest.example");

        lab.Advance(TimeSpan.FromSeconds(31));
        await DeliverAsync(lab, "two@dest.example");

        Assert.Equal(2, mx.ConnectionCount);
        Assert.DoesNotContain("NOOP", mx.Sessions[0].Verbs);
    }

    [Fact]
    public async Task A_connection_inside_the_idle_timeout_is_reused()
    {
        await using var lab = SingleMx(Personalities.Postfix(), out var mx, new LabSettings { PoolIdleTimeout = TimeSpan.FromSeconds(30) });
        await DeliverAsync(lab, "one@dest.example");

        lab.Advance(TimeSpan.FromSeconds(20));
        await DeliverAsync(lab, "two@dest.example");

        Assert.Equal(1, mx.ConnectionCount);
    }

    [Fact]
    public async Task A_peer_that_dies_on_the_rset_between_transactions_costs_a_connection_and_not_a_message()
    {
        var peer = Personalities.Postfix();
        int housekeeping = 0;
        peer.OnHousekeeping = (_, _) => Interlocked.Increment(ref housekeeping) == 1 ? Step.Close() : null;
        await using var lab = SingleMx(peer, out var mx);

        await DeliverAsync(lab, "one@dest.example");
        await DeliverAsync(lab, "two@dest.example");

        Assert.Equal(2, mx.ConnectionCount);
        Assert.Equal(2, mx.Messages.Count);
    }

    [Fact]
    public async Task A_peer_that_refuses_the_noop_probe_is_not_trusted_with_the_next_message()
    {
        var peer = Personalities.Postfix();
        peer.OnHousekeeping = (_, line) => line.StartsWith("NOOP", StringComparison.OrdinalIgnoreCase) ? Step.Reply(500, "5.5.1", "NOOP not understood") : null;
        await using var lab = SingleMx(peer, out var mx);

        await DeliverAsync(lab, "one@dest.example");
        await DeliverAsync(lab, "two@dest.example");

        Assert.Equal(2, mx.ConnectionCount);
        Assert.Equal(2, mx.Messages.Count);
    }

    [Fact]
    public async Task A_peer_that_allows_two_messages_per_connection_costs_the_third_a_deferral_not_its_delivery()
    {
        var peer = Personalities.Postfix();
        peer.MaxMessagesPerConnection = 2;
        await using var lab = SingleMx(peer, out var mx);

        await DeliverAsync(lab, "one@dest.example");
        await DeliverAsync(lab, "two@dest.example");
        var third = await lab.SendAsync(["three@dest.example"]);
        var due = await lab.WaitForRetryScheduleAsync(third);
        lab.Advance(due - lab.Clock.UtcNow);
        await lab.WaitForEventAsync(third, MessageEventType.Delivered);

        Assert.Equal(3, mx.Messages.Count);
        Assert.Equal(2, mx.ConnectionCount);
        Assert.DoesNotContain(await lab.EventsAsync(third), e => e.Type is MessageEventType.PossibleDuplicate or MessageEventType.Bounced);
    }

    [Fact]
    public async Task With_the_maximum_set_to_the_peers_limit_the_third_message_goes_out_on_a_new_connection_without_a_deferral()
    {
        var peer = Personalities.Postfix();
        peer.MaxMessagesPerConnection = 2;
        await using var lab = SingleMx(peer, out var mx, new LabSettings { MaxMessagesPerConnection = 2 });

        await DeliverAsync(lab, "one@dest.example");
        await DeliverAsync(lab, "two@dest.example");
        var third = await lab.SendAsync(["three@dest.example"]);
        var events = await lab.WaitForEventAsync(third, MessageEventType.Delivered);

        Assert.Equal(3, mx.Messages.Count);
        Assert.Equal(2, mx.ConnectionCount);
        Assert.DoesNotContain(events, e => e.Type == MessageEventType.Deferred);
        Assert.Equal("QUIT", mx.Sessions[0].Verbs[^1]);
    }

    [Fact]
    public async Task A_peer_that_offers_pipelining_receives_the_envelope_in_one_go()
    {
        await using var lab = SingleMx(Personalities.Postfix(), out var mx);

        await DeliverAsync(lab, "one@dest.example");

        Assert.True(mx.Sessions.Single().PipelinedCommands >= 2, "MAIL, RCPT and DATA arrive behind each other");
    }

    [Fact]
    public async Task A_peer_without_pipelining_never_sees_a_command_before_the_reply_to_the_previous_one_has_been_sent()
    {
        var peer = Personalities.Exim();
        peer.Pipelining = false;
        peer.ExtraCapabilities.Clear();
        await using var lab = SingleMx(peer, out var mx);

        var id = await lab.SendAsync(["a@dest.example", "b@dest.example", "c@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered, 3);

        Assert.Equal(0, mx.Sessions.Single().PipelinedCommands);
        Assert.Equal(["a@dest.example", "b@dest.example", "c@dest.example"], Assert.Single(mx.Messages).Recipients.Order());
    }

    [Fact]
    public async Task With_chunking_preferred_and_offered_the_message_travels_in_bdat_chunks_and_arrives_intact()
    {
        var settings = new LabSettings { Client = new SmtpClientOptions { HeloName = "egg.test", PreferChunking = true, BdatChunkSize = 1024 } };
        await using var lab = SingleMx(Personalities.Postfix(), out var mx, settings);
        byte[] raw = System.Text.Encoding.ASCII.GetBytes("From: sender@example.org\r\nTo: rcpt@dest.example\r\nSubject: chunky\r\nMessage-ID: <c@example.org>\r\nDate: Mon, 12 Oct 2026 08:00:00 +0000\r\n\r\n"
            + string.Concat(Enumerable.Range(0, 100).Select(i => $"line {i} of the body, long enough to need several chunks to send it all\r\n")) + ".a line that starts with a dot\r\n");

        var id = await lab.SendAsync(["rcpt@dest.example"], raw: raw);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        var message = Assert.Single(mx.Messages);
        Assert.True(message.Chunked);
        Assert.Equal(raw, message.Body);
        Assert.Contains("BDAT", mx.Sessions.Single().Verbs);
        Assert.DoesNotContain("DATA", mx.Sessions.Single().Verbs);
    }

    [Fact]
    public async Task With_chunking_preferred_but_not_offered_the_message_goes_with_data_and_dot_stuffing()
    {
        var settings = new LabSettings { Client = new SmtpClientOptions { HeloName = "egg.test", PreferChunking = true } };
        var peer = Personalities.Exim();
        peer.Chunking = false;
        await using var lab = SingleMx(peer, out var mx, settings);
        byte[] raw = System.Text.Encoding.ASCII.GetBytes("From: sender@example.org\r\nTo: rcpt@dest.example\r\nSubject: dots\r\nMessage-ID: <d@example.org>\r\nDate: Mon, 12 Oct 2026 08:00:00 +0000\r\n\r\n.leading dot\r\n..two dots\r\n.\r\nafter a lone dot\r\n");

        var id = await lab.SendAsync(["rcpt@dest.example"], raw: raw);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        var message = Assert.Single(mx.Messages);
        Assert.False(message.Chunked);
        Assert.Equal(raw, message.Body);
    }
}
