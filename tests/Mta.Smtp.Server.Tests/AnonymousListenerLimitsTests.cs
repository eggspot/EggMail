using System.Net;
using System.Text;
using Mta.Core;
using Mta.Smtp.Protocol;

namespace Mta.Smtp.Server.Tests;

/// <summary>An anonymous listener (port 25) must not be able to starve the others: its own connection and memory shares, a share per client network, and a limit on how long a session lives.</summary>
public class AnonymousListenerLimitsTests
{
    private sealed class TestClock : IClock
    {
        private long _ticks;
        public DateTimeOffset UtcNow => DateTimeOffset.UnixEpoch.AddSeconds(_ticks / (double)System.Diagnostics.Stopwatch.Frequency);
        public long Timestamp => Interlocked.Read(ref _ticks);
        public void Advance(TimeSpan by) => Interlocked.Add(ref _ticks, (long)(by.TotalSeconds * System.Diagnostics.Stopwatch.Frequency));
    }

    private sealed class Handler : ISmtpServerHandler
    {
        public List<SmtpReply> Refused { get; } = [];
        public List<bool> Reservations { get; } = [];
        public List<string> Received { get; } = [];
        public bool ReserveOnRcpt;

        public ValueTask<SmtpReply?> OnConnectedAsync(SmtpSessionContext session, CancellationToken ct) => ValueTask.FromResult<SmtpReply?>(null);

        public ValueTask<SmtpAuthResult> AuthenticateAsync(SmtpSessionContext session, string authorizationId, string userName, string password, CancellationToken ct) => ValueTask.FromResult(SmtpAuthResult.Failed);

        public ValueTask<SmtpReply> OnMailFromAsync(SmtpSessionContext session, MailFromInfo mail, CancellationToken ct) => ValueTask.FromResult(SmtpReplies.SenderOk);

        public ValueTask<SmtpReply> OnRcptToAsync(SmtpSessionContext session, MailFromInfo mail, EmailAddress recipient, RcptParameters parameters, CancellationToken ct)
        {
            if (ReserveOnRcpt)
            {
                lock (Reservations)
                {
                    Reservations.Add(session.TryReserveMemory(600));
                }
            }

            return ValueTask.FromResult(SmtpReplies.RecipientOk);
        }

        public ValueTask<SmtpReply> OnMessageAsync(SmtpMessage message, CancellationToken ct)
        {
            lock (Received)
            {
                Received.Add(Encoding.UTF8.GetString(message.ReceivedHeader.Span));
            }

            return ValueTask.FromResult(SmtpReply.Create(250, "2.0.0", "Accepted"));
        }

        public void OnMessageRefused(SmtpSessionContext session, SmtpReply reply)
        {
            lock (Refused)
            {
                Refused.Add(reply);
            }
        }

        public void OnDisconnected(SmtpSessionContext session)
        {
        }
    }

    private static (SmtpServer Server, int Port) Start(Handler handler, SmtpListenerOptions listener, IClock? clock = null, int maxConnections = 2000)
    {
        var server = new SmtpServer(new SmtpServerOptions { Hostname = "mx.test", MaxConnections = maxConnections, DataTimeout = TimeSpan.FromSeconds(20), Listeners = [listener] }, handler, clock);
        server.Start();
        return (server, server.LocalEndPoints[listener.Name].Port);
    }

    private static SmtpListenerOptions Open(Action<SmtpListenerOptionsBuilder>? tune = null)
    {
        var b = new SmtpListenerOptionsBuilder();
        tune?.Invoke(b);
        return new SmtpListenerOptions
        {
            Name = "open", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.Plain, AuthRequired = false, Role = ListenerRole.Inbound,
            MaxConnections = b.MaxConnections, MaxInFlightBytes = b.MaxInFlightBytes, MaxInFlightBytesPerRemote = b.MaxInFlightBytesPerRemote, MaxSessionDuration = b.MaxSessionDuration, MaxMessageSize = b.MaxMessageSize,
        };
    }

    private sealed class SmtpListenerOptionsBuilder
    {
        public int? MaxConnections;
        public long? MaxInFlightBytes;
        public long? MaxInFlightBytesPerRemote;
        public TimeSpan? MaxSessionDuration;
        public long? MaxMessageSize;
    }

    private static async Task<RawClient> OpenAsync(int port)
    {
        var c = await RawClient.ConnectAsync(port);
        await c.ExpectAsync(220);
        await c.CommandAsync("EHLO client.test", 250);
        return c;
    }

    // ------------------------------------------------------------------ connections

    [Fact]
    public async Task A_listeners_own_connection_cap_is_below_the_servers_so_the_rest_stays_for_others()
    {
        var handler = new Handler();
        var (server, port) = Start(handler, Open(b => b.MaxConnections = 2));
        await using var _ = server;
        using RawClient one = await OpenAsync(port);
        using RawClient two = await OpenAsync(port);

        using var third = await RawClient.ConnectAsync(port);
        var refusal = await third.ReadReplyAsync();

        Assert.Equal(421, refusal!.Code);
        one.Dispose();
        await Task.Delay(100);
        for (int i = 0; i < 50; i++)   // the slot is given back when the server notices the close
        {
            using var again = await RawClient.ConnectAsync(port);
            if ((await again.ReadReplyAsync())!.Code == 220)
            {
                return;
            }

            await Task.Delay(50);
        }

        Assert.Fail("The connection slot was not given back.");
    }

    [Fact]
    public void The_per_address_connection_cap_counts_an_ipv6_client_by_its_64_bit_prefix_and_a_mapped_address_as_ipv4()
    {
        var limiter = new ConnectionLimiter(maxTotal: 100, maxPerIp: 2);

        Assert.True(limiter.TryAcquire(IPAddress.Parse("2001:db8:1:2::1")));
        Assert.True(limiter.TryAcquire(IPAddress.Parse("2001:db8:1:2:ffff::2")));
        Assert.False(limiter.TryAcquire(IPAddress.Parse("2001:db8:1:2:abcd::3")));   // a third address of the same /64
        Assert.True(limiter.TryAcquire(IPAddress.Parse("2001:db8:1:3::1")));          // the next /64 has its own

        Assert.True(limiter.TryAcquire(IPAddress.Parse("203.0.113.9")));
        Assert.True(limiter.TryAcquire(IPAddress.Parse("::ffff:203.0.113.9")));
        Assert.False(limiter.TryAcquire(IPAddress.Parse("203.0.113.9")));
    }

    // ------------------------------------------------------------------ memory

    private static async Task StartPartialBodyAsync(RawClient c, int bytes)
    {
        await c.CommandAsync("MAIL FROM:<a@sender.test>", 250);
        await c.CommandAsync("RCPT TO:<b@example.org>", 250);
        await c.CommandAsync("DATA", 354);
        await c.SendAsync("Subject: s\r\n\r\n" + new string('x', bytes));
    }

    private static async Task<int> TrySendWholeAsync(RawClient c, int bytes)
    {
        await c.CommandAsync("MAIL FROM:<a@sender.test>", 250);
        await c.CommandAsync("RCPT TO:<b@example.org>", 250);
        await c.CommandAsync("DATA", 354);
        await c.SendAsync("Subject: s\r\n\r\n" + new string('x', bytes) + "\r\n.\r\n");
        return (await c.ReadReplyAsync())!.Code;
    }

    [Theory]
    [InlineData(true)]    // the listener's own share
    [InlineData(false)]   // the share of one client network
    public async Task A_sender_that_holds_the_listeners_memory_share_makes_another_get_452_and_everything_is_given_back(bool listenerShare)
    {
        var handler = new Handler();
        var (server, port) = Start(handler, Open(b =>
        {
            if (listenerShare) { b.MaxInFlightBytes = 55_000; } else { b.MaxInFlightBytesPerRemote = 55_000; }
        }));
        await using var _ = server;
        using RawClient holder = await OpenAsync(port);
        using RawClient other = await OpenAsync(port);
        await StartPartialBodyAsync(holder, 30_000);
        for (int i = 0; i < 1000 && server.Budget.Used < 30_000; i++)   // until the server has taken the holder's bytes into its budget
        {
            await Task.Delay(10);
        }

        Assert.True(server.Budget.Used >= 30_000, "the holder's bytes were not counted");
        int code = await TrySendWholeAsync(other, 30_000);

        Assert.Equal(452, code);
        await holder.SendAsync("\r\n.\r\n");
        await holder.ExpectAsync(250);
        for (int i = 0; i < 1000 && server.Budget.Used > 0; i++)   // the reply is flushed before the session gives its bytes back
        {
            await Task.Delay(10);
        }

        Assert.Equal(0, server.Budget.Used);
        Assert.Equal(250, await TrySendWholeAsync(other, 1_000));   // the shares are free again
    }

    [Fact]
    public async Task Memory_a_handler_reserves_for_its_own_copies_comes_from_the_same_budget_and_is_given_back_when_the_transaction_ends()
    {
        var handler = new Handler { ReserveOnRcpt = true };
        var (server, port) = Start(handler, Open(b => b.MaxInFlightBytes = 1000));
        await using var _ = server;
        using RawClient c = await OpenAsync(port);
        await c.CommandAsync("MAIL FROM:<a@sender.test>", 250);
        await c.CommandAsync("RCPT TO:<b@example.org>", 250);
        await c.CommandAsync("RCPT TO:<c@example.org>", 250);   // 600 + 600 is over 1000
        await c.CommandAsync("RSET", 250);
        await c.CommandAsync("MAIL FROM:<a@sender.test>", 250);
        await c.CommandAsync("RCPT TO:<b@example.org>", 250);

        Assert.Equal([true, false, true], handler.Reservations);
    }

    // ------------------------------------------------------------------ session age

    [Fact]
    public async Task A_session_older_than_the_limit_is_closed_after_the_next_command_and_noop_does_not_keep_it_alive()
    {
        var clock = new TestClock();
        var handler = new Handler();
        var (server, port) = Start(handler, Open(b => b.MaxSessionDuration = TimeSpan.FromMinutes(1)), clock);
        await using var _ = server;
        using RawClient c = await OpenAsync(port);
        await c.CommandAsync("NOOP", 250);

        clock.Advance(TimeSpan.FromMinutes(2));
        await c.CommandAsync("NOOP", 250);   // the command that arrives is answered; then the limit is seen
        var closing = await c.ReadReplyAsync();

        Assert.Equal((421, "4.4.2"), (closing!.Code, closing.EnhancedCode));
        Assert.True(await c.WaitForCloseAsync());
    }

    [Fact]
    public async Task Empty_bdat_chunks_do_not_keep_a_session_alive_past_the_limit_either()
    {
        var clock = new TestClock();
        var handler = new Handler();
        var (server, port) = Start(handler, Open(b => b.MaxSessionDuration = TimeSpan.FromMinutes(1)), clock);
        await using var _ = server;
        using RawClient c = await OpenAsync(port);
        await c.CommandAsync("MAIL FROM:<a@sender.test>", 250);
        await c.CommandAsync("RCPT TO:<b@example.org>", 250);
        await c.CommandAsync("BDAT 0", 250);

        clock.Advance(TimeSpan.FromMinutes(2));
        await c.CommandAsync("BDAT 0", 250);
        var closing = await c.ReadReplyAsync();

        Assert.Equal(421, closing!.Code);
        Assert.True(await c.WaitForCloseAsync());
        Assert.Contains(handler.Refused, r => r.Code == 421);   // the message that was being sent is reported as refused
    }

    // ------------------------------------------------------------------ what the handler is told, and sizes

    [Fact]
    public async Task The_handler_is_told_when_a_message_dies_in_the_dialog_a_bare_lf_a_bdat_reset_or_a_vanished_client()
    {
        var handler = new Handler();
        var (server, port) = Start(handler, Open());
        await using var _ = server;

        using (RawClient bare = await OpenAsync(port))
        {
            await bare.CommandAsync("MAIL FROM:<a@sender.test>", 250);
            await bare.CommandAsync("RCPT TO:<b@example.org>", 250);
            await bare.CommandAsync("DATA", 354);
            await bare.SendAsync("Subject: s\r\n\r\nline\nbare\r\n.\r\n");
            await bare.ExpectAsync(500);
        }

        using (RawClient reset = await OpenAsync(port))
        {
            await reset.CommandAsync("MAIL FROM:<a@sender.test>", 250);
            await reset.CommandAsync("RCPT TO:<b@example.org>", 250);
            await reset.SendAsync("BDAT 5\r\nhello");
            await reset.ExpectAsync(250);
            await reset.CommandAsync("RSET", 250);
        }

        using (RawClient gone = await OpenAsync(port))
        {
            await gone.CommandAsync("MAIL FROM:<a@sender.test>", 250);
            await gone.CommandAsync("RCPT TO:<b@example.org>", 250);
            await gone.CommandAsync("DATA", 354);
            await gone.SendAsync("Subject: s\r\n\r\nhalf");
        }

        for (int i = 0; i < 100 && handler.Refused.Count < 3; i++)
        {
            await Task.Delay(50);
        }

        Assert.Contains(handler.Refused, r => r.Code == 500);   // the bare LF
        Assert.Contains(handler.Refused, r => r.Code == 250);   // the BDAT sequence ended by RSET
        Assert.True(handler.Refused.Count >= 3);                // and the client that went away
    }

    [Fact]
    public async Task A_bdat_sequence_larger_than_the_listeners_limit_is_refused_at_its_last_chunk()
    {
        var handler = new Handler();
        var (server, port) = Start(handler, Open(b => b.MaxMessageSize = 2000));
        await using var _ = server;
        using RawClient c = await OpenAsync(port);
        await c.CommandAsync("MAIL FROM:<a@sender.test>", 250);
        await c.CommandAsync("RCPT TO:<b@example.org>", 250);
        string chunk = new('x', 1500);

        await c.SendAsync($"BDAT {chunk.Length}\r\n{chunk}");
        await c.ExpectAsync(250);   // 1500 so far: within the limit
        await c.SendAsync($"BDAT {chunk.Length} LAST\r\n{chunk}");
        var refusal = await c.ExpectAsync(552);

        Assert.Equal("5.3.4", refusal.EnhancedCode);
        Assert.Empty(handler.Received);
    }

    [Fact]
    public async Task A_helo_name_outside_ascii_is_not_written_into_the_received_header()
    {
        var handler = new Handler();
        var (server, port) = Start(handler, Open());
        await using var _ = server;
        using var c = await RawClient.ConnectAsync(port);
        await c.ExpectAsync(220);
        var ehlo = await c.SendAndReadAsync("EHLO müller.example");
        if (ehlo!.Code != 250)
        {
            await c.CommandAsync("EHLO plain.example", 250);   // the parser did not take the name at all: nothing to write
            return;
        }

        await c.CommandAsync("MAIL FROM:<a@sender.test>", 250);
        await c.CommandAsync("RCPT TO:<b@example.org>", 250);
        await c.CommandAsync("DATA", 354);
        await c.SendAsync("Subject: s\r\n\r\nbody\r\n.\r\n");
        await c.ExpectAsync(250);

        string received = Assert.Single(handler.Received);
        Assert.All(received, ch => Assert.True(ch < 0x7F, "non-ASCII in the trace field: " + received));
    }
}

internal static class RawClientExtensions
{
    public static async Task<SmtpReply?> SendAndReadAsync(this RawClient c, string line)
    {
        await c.SendLineAsync(line);
        return await c.ReadReplyAsync();
    }
}
