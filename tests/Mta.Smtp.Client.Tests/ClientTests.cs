using System.Net;
using System.Text;
using Mta.Core;
using Mta.Smtp.Protocol;
using Mta.Smtp.Server;

namespace Mta.Smtp.Client.Tests;

public class ClientTests
{
    private static readonly SmtpClientOptions Options = new() { HeloName = "client.test", BannerTimeout = TimeSpan.FromSeconds(3), CommandTimeout = TimeSpan.FromSeconds(3), EndOfDataTimeout = TimeSpan.FromSeconds(3), DataBlockTimeout = TimeSpan.FromSeconds(3), DataInitiationTimeout = TimeSpan.FromSeconds(3) };

    private static byte[] Msg(string body = "Hello\r\n") => Encoding.UTF8.GetBytes("From: a@b.example\r\nTo: c@d.example\r\nSubject: t\r\n\r\n" + body);

    private static SmtpEnvelope Env(params string[] rcpt) =>
        new(EmailAddress.Parse("sender@example.org"), rcpt.Select(r => EmailAddress.Parse(r)).ToArray(), false, false);

    private static SmtpTlsPolicy AcceptAnyCert(bool require = false) => new() { Mode = SmtpTlsMode.StartTls, Require = require, TargetHost = "localhost", ValidationCallback = (_, _, _, _) => true };

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public async Task Sends_message_to_real_server(bool pipelining, bool chunking)
    {
        await using var server = new RealServer();
        var options = new SmtpClientOptions { HeloName = "client.test", Pipelining = pipelining, PreferChunking = chunking, BdatChunkSize = 40 };
        await using var conn = await SmtpClientConnection.ConnectAsync(server.Target(SmtpTlsPolicy.Disabled), options);
        Assert.Equal(220, conn.Banner.Code);
        Assert.True(conn.Capabilities.Pipelining);
        string body = "Line one\r\n.starts with a dot\r\n..two dots\r\nlast line without much\r\n";
        var result = await conn.SendAsync(Env("rcpt@dest.example"), Msg(body));
        Assert.True(result.Delivered);
        Assert.True(result.EndOfDataSent);
        Assert.Equal(250, result.FinalReply!.Code);
        var m = Assert.Single(server.Handler.Messages);
        Assert.Equal("sender@example.org", m.From.ToString());
        Assert.Equal(Encoding.UTF8.GetString(Msg(body)), Encoding.UTF8.GetString(m.Body));
    }

    [Fact]
    public async Task Partial_recipient_acceptance()
    {
        await using var server = new RealServer();
        server.Handler.RcptPolicy = r => r.LocalPart == "bad" ? SmtpReply.Create(550, "5.1.1", "no such user") : null;
        await using var conn = await SmtpClientConnection.ConnectAsync(server.Target(SmtpTlsPolicy.Disabled), Options);
        var result = await conn.SendAsync(Env("good@dest.example", "bad@dest.example", "good2@dest.example"), Msg());
        Assert.True(result.Delivered);
        Assert.Equal([true, false, true], result.Recipients.Select(r => r.Accepted).ToArray());
        Assert.Equal(550, result.Recipients[1].Reply.Code);
        Assert.Equal(["good@dest.example", "good2@dest.example"], Assert.Single(server.Handler.Messages).To);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task All_recipients_rejected_aborts_cleanly_and_connection_is_reusable_or_closed(bool pipelining)
    {
        await using var server = new RealServer();
        server.Handler.RcptPolicy = r => SmtpReply.Create(550, "5.1.1", "no");
        var options = new SmtpClientOptions { HeloName = "client.test", Pipelining = pipelining };
        await using var conn = await SmtpClientConnection.ConnectAsync(server.Target(SmtpTlsPolicy.Disabled), options);
        var result = await conn.SendAsync(Env("a@dest.example", "b@dest.example"), Msg());
        Assert.False(result.Delivered);
        Assert.All(result.Recipients, r => Assert.False(r.Accepted));
        Assert.Empty(server.Handler.Messages);
        if (conn.IsReusable)
        {
            server.Handler.RcptPolicy = null;
            var again = await conn.SendAsync(Env("ok@dest.example"), Msg());
            Assert.True(again.Delivered);
        }
    }

    [Fact]
    public async Task Starttls_upgrade_with_capture_of_tls_details()
    {
        await using var server = new RealServer();
        await using var conn = await SmtpClientConnection.ConnectAsync(server.Target(AcceptAnyCert(require: true)), Options);
        Assert.True(conn.TlsSession.Used);
        Assert.True(conn.TlsSession.StartTlsAdvertised);
        Assert.Contains("CN=localhost", conn.TlsSession.PeerSubject);
        Assert.NotNull(conn.TlsSession.CipherSuite);
        Assert.False(conn.TlsSession.Verified); // self-signed
        Assert.NotEqual(System.Net.Security.SslPolicyErrors.None, conn.TlsSession.PolicyErrors);
        Assert.False(conn.Capabilities.StartTls);   // post-TLS capability list
        var result = await conn.SendAsync(Env("r@dest.example"), Msg());
        Assert.True(result.Delivered);
    }

    [Fact]
    public async Task Required_tls_with_strict_validation_fails_for_self_signed()
    {
        await using var server = new RealServer();
        var policy = new SmtpTlsPolicy { Mode = SmtpTlsMode.StartTls, Require = true, TargetHost = "localhost", ValidationCallback = (_, _, _, e) => e == System.Net.Security.SslPolicyErrors.None };
        var ex = await Assert.ThrowsAsync<SmtpTlsException>(async () => await SmtpClientConnection.ConnectAsync(server.Target(policy), Options));
        Assert.Equal(TlsFailure.HandshakeFailed, ex.Failure);
    }

    [Fact]
    public async Task Stripped_starttls_is_detected_when_required_and_recorded_when_opportunistic()
    {
        await using var peer = new ScriptedServer(async c =>
        {
            await c.SendAsync("220 plain.test ESMTP\r\n");
            Assert.StartsWith("EHLO", await c.ReadLineAsync());
            await c.SendAsync("250-plain.test\r\n250 PIPELINING\r\n");   // no STARTTLS offered
            Assert.StartsWith("MAIL", await c.ReadLineAsync());
            await c.HoldOpenAsync(200);
        });
        var ex = await Assert.ThrowsAsync<SmtpTlsException>(async () => await SmtpClientConnection.ConnectAsync(peer.Target(AcceptAnyCert(require: true)), Options));
        Assert.Equal(TlsFailure.NotAdvertised, ex.Failure);

        await using var conn = await SmtpClientConnection.ConnectAsync(peer.Target(AcceptAnyCert(require: false)), Options);
        Assert.False(conn.TlsSession.Used);
        Assert.False(conn.TlsSession.StartTlsAdvertised);
        Assert.True(conn.TlsSession.PlaintextFallback);
    }

    [Fact]
    public async Task Server_injecting_data_after_starttls_reply_is_rejected()
    {
        await using var peer = new ScriptedServer(async c =>
        {
            await c.SendAsync("220 evil.test ESMTP\r\n");
            await c.ReadLineAsync();
            await c.SendAsync("250-evil.test\r\n250 STARTTLS\r\n");
            await c.ReadLineAsync();
            await c.SendAsync("220 Go ahead\r\n250 2.0.0 injected reply\r\n"); // plaintext smuggled behind the 220
            await c.HoldOpenAsync(300);
        });
        var ex = await Assert.ThrowsAsync<SmtpTlsException>(async () => await SmtpClientConnection.ConnectAsync(peer.Target(AcceptAnyCert()), Options));
        Assert.Equal(TlsFailure.HandshakeFailed, ex.Failure);
    }

    [Fact]
    public async Task Banner_rejection_and_connection_failures()
    {
        await using var peer = new ScriptedServer(async c => await c.SendAsync("554 5.3.2 go away\r\n"));
        var ex = await Assert.ThrowsAsync<SmtpGreetingRejectedException>(async () => await SmtpClientConnection.ConnectAsync(peer.Target(), Options));
        Assert.Equal(554, ex.Reply.Code);
        Assert.Equal(SmtpStage.Banner, ex.Stage);

        // Closed port.
        var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int closed = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        var refused = await Assert.ThrowsAsync<SmtpConnectionException>(async () =>
            await SmtpClientConnection.ConnectAsync(new SmtpRemoteTarget { Host = "x", Address = IPAddress.Loopback, Port = closed }, Options));
        Assert.Equal(SmtpStage.Connect, refused.Stage);
    }

    [Fact]
    public async Task Silent_server_times_out_at_banner()
    {
        await using var peer = new ScriptedServer(async c => await c.HoldOpenAsync(2000));
        var options = new SmtpClientOptions { HeloName = "c.test", BannerTimeout = TimeSpan.FromMilliseconds(300) };
        var ex = await Assert.ThrowsAsync<SmtpConnectionException>(async () => await SmtpClientConnection.ConnectAsync(peer.Target(), options));
        Assert.True(ex.TimedOut);
        Assert.Equal(SmtpStage.Banner, ex.Stage);
    }

    [Fact]
    public async Task Connection_lost_after_end_of_data_reports_possible_duplicate()
    {
        await using var peer = new ScriptedServer(async c =>
        {
            await c.SendAsync("220 x ESMTP\r\n");
            await c.ReadLineAsync();
            await c.SendAsync("250 x\r\n");
            await c.ReadLineAsync(); // MAIL
            await c.SendAsync("250 ok\r\n");
            await c.ReadLineAsync(); // RCPT
            await c.SendAsync("250 ok\r\n");
            await c.ReadLineAsync(); // DATA
            await c.SendAsync("354 go\r\n");
            await c.ReadDataAsync();
            c.Abort();               // dies without answering the final dot
        });
        var options = new SmtpClientOptions { HeloName = "c.test", Pipelining = false };
        await using var conn = await SmtpClientConnection.ConnectAsync(peer.Target(SmtpTlsPolicy.Disabled), options);
        var ex = await Assert.ThrowsAsync<SmtpConnectionException>(async () => await conn.SendAsync(Env("r@dest.example"), Msg()));
        Assert.True(ex.EndOfDataSent);
        Assert.False(conn.IsReusable);
    }

    [Fact]
    public async Task Connection_lost_before_end_of_data_is_not_a_possible_duplicate()
    {
        await using var peer = new ScriptedServer(async c =>
        {
            await c.SendAsync("220 x ESMTP\r\n");
            await c.ReadLineAsync();
            await c.SendAsync("250 x\r\n");
            await c.ReadLineAsync();
            c.Abort(); // dies on MAIL
        });
        var options = new SmtpClientOptions { HeloName = "c.test", Pipelining = false };
        await using var conn = await SmtpClientConnection.ConnectAsync(peer.Target(SmtpTlsPolicy.Disabled), options);
        var ex = await Assert.ThrowsAsync<SmtpConnectionException>(async () => await conn.SendAsync(Env("r@dest.example"), Msg()));
        Assert.False(ex.EndOfDataSent);
    }

    [Fact]
    public async Task Final_reply_variants_are_reported_not_thrown()
    {
        await using var server = new RealServer();
        await using var conn = await SmtpClientConnection.ConnectAsync(server.Target(SmtpTlsPolicy.Disabled), Options);
        server.Handler.MessageReply = () => SmtpReply.Create(554, "5.7.1", "spam");
        var r1 = await conn.SendAsync(Env("r@dest.example"), Msg());
        Assert.False(r1.Delivered);
        Assert.Equal(554, r1.FinalReply!.Code);
        server.Handler.MessageReply = () => SmtpReply.Create(451, "4.7.1", "greylisted");
        var r2 = await conn.SendAsync(Env("r@dest.example"), Msg());
        Assert.True(r2.FinalReply!.IsTransient);
        Assert.True(conn.IsReusable);
    }

    [Fact]
    public async Task Local_failures_do_not_touch_the_wire()
    {
        await using var server = new RealServer(o => new SmtpServerOptions { Hostname = o.Hostname, Certificates = o.Certificates, Listeners = o.Listeners, MaxMessageSize = 1000, AuthFailureDelay = TimeSpan.Zero, SmtpUtf8 = false });
        await using var conn = await SmtpClientConnection.ConnectAsync(server.Target(SmtpTlsPolicy.Disabled), Options);
        var big = await conn.SendAsync(Env("r@dest.example"), Msg(new string('x', 5000) + "\r\n"));
        Assert.Equal(LocalFailure.MessageTooLarge, big.LocalFailure);
        var utf8 = await conn.SendAsync(new SmtpEnvelope(EmailAddress.Parse("s@example.org"), [EmailAddress.Parse("üser@bücher.example")], true, false), Msg());
        Assert.Equal(LocalFailure.Smtputf8NotSupported, utf8.LocalFailure);
        Assert.Empty(server.Handler.Messages);
        var ok = await conn.SendAsync(Env("r@dest.example"), Msg());
        Assert.True(ok.Delivered);
    }

    [Theory]
    [InlineData("bare\nlf\r\n")]
    [InlineData("bare\rcr\r\n")]
    public async Task Malformed_message_is_refused_locally_and_connection_dropped(string body)
    {
        await using var server = new RealServer();
        await using var conn = await SmtpClientConnection.ConnectAsync(server.Target(SmtpTlsPolicy.Disabled), Options);
        var r = await conn.SendAsync(Env("r@dest.example"), Msg(body));
        Assert.Equal(LocalFailure.MalformedMessage, r.LocalFailure);
        Assert.False(conn.IsReusable);
        Assert.Empty(server.Handler.Messages);
    }

    [Fact]
    public async Task Relay_auth_over_implicit_tls_and_refusal_without_tls()
    {
        await using var server = new RealServer();
        var implicitTls = new SmtpTlsPolicy { Mode = SmtpTlsMode.Implicit, Require = true, TargetHost = "localhost", ValidationCallback = (_, _, _, _) => true };
        await using (var conn = await SmtpClientConnection.ConnectAsync(server.Target(implicitTls, new SmtpCredentials { UserName = "relay", Password = "secret" }, implicitTls: true), Options))
        {
            Assert.True(conn.TlsSession.Used);
            var r = await conn.SendAsync(Env("r@dest.example"), Msg());
            Assert.True(r.Delivered);
        }

        var bad = await Assert.ThrowsAsync<SmtpGreetingRejectedException>(async () =>
            await SmtpClientConnection.ConnectAsync(server.Target(implicitTls, new SmtpCredentials { UserName = "relay", Password = "wrong" }, implicitTls: true), Options));
        Assert.Equal(535, bad.Reply.Code);

        // Credentials are never sent in clear: a peer without STARTTLS makes the client refuse to authenticate.
        await using var plainPeer = new ScriptedServer(async c =>
        {
            await c.SendAsync("220 x ESMTP\r\n");
            await c.ReadLineAsync();
            await c.SendAsync("250-x\r\n250 AUTH PLAIN LOGIN\r\n");
            await c.HoldOpenAsync(500);
        });
        var refused = await Assert.ThrowsAsync<SmtpTlsException>(async () =>
            await SmtpClientConnection.ConnectAsync(new SmtpRemoteTarget { Host = "p", Address = IPAddress.Loopback, Port = plainPeer.Port, Credentials = new SmtpCredentials { UserName = "u", Password = "p" } }, Options));
        Assert.Equal(TlsFailure.NotAdvertised, refused.Failure);
    }

    [Fact]
    public async Task Pool_reuses_connections_and_discards_broken_ones()
    {
        await using var server = new RealServer();
        await using var pool = new SmtpConnectionPool(Options);
        var target = server.Target(SmtpTlsPolicy.Disabled);
        for (int i = 0; i < 5; i++)
        {
            await using var lease = await pool.RentAsync(target);
            var r = await lease.Connection.SendAsync(Env("r@dest.example"), Msg($"msg {i}\r\n"));
            Assert.True(r.Delivered);
        }

        Assert.Equal(1, server.Handler.Connections);
        Assert.Equal(5, server.Handler.Messages.Count);
        Assert.Equal(1, pool.IdleConnections);

        await using (var lease = await pool.RentAsync(target))
        {
            lease.Discard();
        }

        Assert.Equal(0, pool.IdleConnections);
        await using var again = await pool.RentAsync(target);
        Assert.Equal(2, server.Handler.Connections);
    }

    [Fact]
    public async Task Concurrent_senders_through_pool()
    {
        await using var server = new RealServer();
        await using var pool = new SmtpConnectionPool(Options, maxIdlePerTarget: 4);
        var target = server.Target(SmtpTlsPolicy.Disabled);
        await Task.WhenAll(Enumerable.Range(0, 40).Select(async i =>
        {
            await using var lease = await pool.RentAsync(target);
            var r = await lease.Connection.SendAsync(Env($"r{i}@dest.example"), Msg($"m{i}\r\n"));
            Assert.True(r.Delivered);
        }));
        Assert.Equal(40, server.Handler.Messages.Count);
        Assert.True(server.Handler.Connections <= 40);
    }

    /// <summary>A peer that answers normally up to the point where it stops answering: after RCPT, or after it has read the whole message.</summary>
    private static ScriptedServer Peer(bool silentAtRcpt, bool bdat, TaskCompletionSource reached)
    {
        return new ScriptedServer(async c =>
        {
            await c.SendAsync("220 scripted ESMTP\r\n");
            while (true)
            {
                string line = await c.ReadLineAsync();
                string verb = line.Split(' ')[0].ToUpperInvariant();
                switch (verb)
                {
                    case "EHLO":
                        await c.SendAsync(bdat ? "250-scripted\r\n250 CHUNKING\r\n" : "250 scripted\r\n");
                        break;
                    case "MAIL":
                        await c.SendAsync("250 ok\r\n");
                        break;
                    case "RCPT":
                        if (silentAtRcpt)
                        {
                            reached.TrySetResult();
                            await c.HoldOpenAsync(30_000);
                            return;
                        }

                        await c.SendAsync("250 ok\r\n");
                        break;
                    case "DATA":
                        await c.SendAsync("354 go\r\n");
                        await c.ReadDataAsync();
                        reached.TrySetResult(); // the whole message including the dot is in; the verdict never comes
                        await c.HoldOpenAsync(30_000);
                        return;
                    case "BDAT":
                        int size = int.Parse(line.Split(' ')[1], System.Globalization.CultureInfo.InvariantCulture);
                        await c.ReadBytesAsync(size);
                        if (line.EndsWith("LAST", StringComparison.OrdinalIgnoreCase))
                        {
                            reached.TrySetResult();
                            await c.HoldOpenAsync(30_000);
                            return;
                        }

                        await c.SendAsync("250 chunk\r\n");
                        break;
                    default:
                        await c.SendAsync("250 ok\r\n");
                        break;
                }
            }
        });
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EndOfDataStarted_is_false_when_cancelled_before_the_message_ends_and_true_when_waiting_for_the_verdict(bool bdat)
    {
        var options = new SmtpClientOptions { HeloName = "client.test", PreferChunking = bdat, BdatChunkSize = 1 << 20, CommandTimeout = TimeSpan.FromSeconds(20), EndOfDataTimeout = TimeSpan.FromSeconds(20), DataBlockTimeout = TimeSpan.FromSeconds(20) };

        // Cancelled while the peer has not answered RCPT: nothing of the message was sent, so nothing can have been accepted.
        var silent = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using (var peer = Peer(silentAtRcpt: true, bdat, silent))
        {
            await using var conn = await SmtpClientConnection.ConnectAsync(peer.Target(SmtpTlsPolicy.Disabled), options);
            using var cts = new CancellationTokenSource();
            Task<SmtpSendResult> send = conn.SendAsync(Env("r@dest.example"), Msg(), cts.Token).AsTask();
            await silent.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await cts.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => send);
            Assert.False(conn.EndOfDataStarted);
        }

        // Cancelled while waiting for the final reply: the server may have accepted the message.
        var waiting = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using (var peer = Peer(silentAtRcpt: false, bdat, waiting))
        {
            await using var conn = await SmtpClientConnection.ConnectAsync(peer.Target(SmtpTlsPolicy.Disabled), options);
            using var cts = new CancellationTokenSource();
            Task<SmtpSendResult> send = conn.SendAsync(Env("r@dest.example"), Msg(), cts.Token).AsTask();
            await waiting.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await cts.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => send);
            Assert.True(conn.EndOfDataStarted);
        }
    }

    [Fact]
    public async Task EndOfDataStarted_is_reset_for_every_transaction()
    {
        await using var server = new RealServer();
        await using var conn = await SmtpClientConnection.ConnectAsync(server.Target(SmtpTlsPolicy.Disabled), Options);
        Assert.False(conn.EndOfDataStarted);
        Assert.True((await conn.SendAsync(Env("r@dest.example"), Msg())).Delivered);
        Assert.True(conn.EndOfDataStarted);
        var refused = await conn.SendAsync(Env("r@dest.example"), Msg("bare\nlf\r\n")); // refused locally before the end of data
        Assert.Equal(LocalFailure.MalformedMessage, refused.LocalFailure);
        Assert.False(conn.EndOfDataStarted);
    }
}
