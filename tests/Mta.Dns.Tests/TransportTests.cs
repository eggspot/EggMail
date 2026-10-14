using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace Mta.Dns.Tests;

public class TransportTests
{
    private static DnsResolverOptions Options(params IPEndPoint[] servers) => new()
    {
        Servers = servers,
        AttemptTimeout = TimeSpan.FromMilliseconds(250),
        MaxAttemptTimeout = TimeSpan.FromMilliseconds(500),
        BackoffMultiplier = 1.5,
        Attempts = 2,
    };

    private static byte[] Query(string name = "example.com", DnsRecordType type = DnsRecordType.A, ushort? id = null)
    {
        ushort queryId = id ?? (ushort)Random.Shared.Next(1, 65535);
        return DnsMessageWriter.BuildQuery(queryId, name, type, DnsQueryOptions.Default);
    }

    private static Task<byte[][]> Answer(ServerQuery q, string ip = "192.0.2.1") =>
        LoopbackDnsServer.Reply(PacketBuilder.ReplyTo(q.Bytes).A("example.com", ip).Build());

    private static string AddressOf(ReadOnlyMemory<byte> response) =>
        ((ARecord)DnsMessageReader.Parse(response.Span).Answers[0]).Address.ToString();

    [Fact]
    public async Task Answers_over_udp()
    {
        using var server = new LoopbackDnsServer(q => Answer(q));
        var transport = new UdpTcpDnsTransport(Options(server.Endpoint));
        var query = Query();
        var response = await transport.ExchangeAsync(query, CancellationToken.None);
        Assert.Equal("192.0.2.1", AddressOf(response));
        Assert.Equal(1, server.UdpQueries);
        Assert.Equal(0, server.TcpQueries);
    }

    [Fact]
    public async Task Truncated_udp_response_is_retried_over_tcp()
    {
        using var server = new LoopbackDnsServer(q => q.IsTcp
            ? LoopbackDnsServer.Reply(PacketBuilder.ReplyTo(q.Bytes).A("example.com", "192.0.2.1").A("example.com", "192.0.2.2").A("example.com", "192.0.2.3").Build())
            : LoopbackDnsServer.Reply(PacketBuilder.ReplyTo(q.Bytes).Truncated().Build()));
        var transport = new UdpTcpDnsTransport(Options(server.Endpoint));
        var response = await transport.ExchangeAsync(Query(), CancellationToken.None);
        var message = DnsMessageReader.Parse(response.Span);
        Assert.False(message.Truncated);
        Assert.Equal(3, message.Answers.Count);
        Assert.Equal(1, server.UdpQueries);
        Assert.Equal(1, server.TcpQueries);
    }

    [Fact]
    public async Task Large_tcp_response_over_64k_framing_is_read_completely()
    {
        using var server = new LoopbackDnsServer(q =>
        {
            if (!q.IsTcp)
            {
                return LoopbackDnsServer.Reply(PacketBuilder.ReplyTo(q.Bytes).Truncated().Build());
            }

            var b = PacketBuilder.ReplyTo(q.Bytes);
            for (int i = 0; i < 400; i++)
            {
                b.Txt("example.com", new string((char)('a' + i % 26), 120));
            }

            return LoopbackDnsServer.Reply(b.Build());
        });
        var transport = new UdpTcpDnsTransport(Options(server.Endpoint) with { AttemptTimeout = TimeSpan.FromSeconds(3), MaxAttemptTimeout = TimeSpan.FromSeconds(3) });
        var response = await transport.ExchangeAsync(Query(type: DnsRecordType.TXT), CancellationToken.None);
        Assert.Equal(400, DnsMessageReader.Parse(response.Span).Answers.Count);
    }

    [Fact]
    public async Task Truncation_without_tcp_fallback_is_an_error()
    {
        using var server = new LoopbackDnsServer(q => LoopbackDnsServer.Reply(PacketBuilder.ReplyTo(q.Bytes).Truncated().Build()));
        var transport = new UdpTcpDnsTransport(Options(server.Endpoint) with { EnableTcpFallback = false });
        var ex = await Assert.ThrowsAsync<DnsException>(async () => await transport.ExchangeAsync(Query(), CancellationToken.None));
        Assert.Equal(DnsFailureReason.ResponseMismatch, ex.Reason);
        Assert.Equal(0, server.TcpQueries);
    }

    [Fact]
    public async Task A_lost_datagram_is_retried_on_the_same_server()
    {
        using var server = new LoopbackDnsServer(q => q.Sequence == 1 ? LoopbackDnsServer.Silent() : Answer(q));
        var transport = new UdpTcpDnsTransport(Options(server.Endpoint));
        var response = await transport.ExchangeAsync(Query(), CancellationToken.None);
        Assert.Equal("192.0.2.1", AddressOf(response));
        Assert.Equal(2, server.UdpQueries);
    }

    [Fact]
    public async Task Fails_over_to_the_next_server_and_remembers_the_working_one()
    {
        using var dead = new LoopbackDnsServer(_ => LoopbackDnsServer.Silent());
        using var alive = new LoopbackDnsServer(q => Answer(q, "192.0.2.77"));
        var transport = new UdpTcpDnsTransport(Options(dead.Endpoint, alive.Endpoint));

        var first = await transport.ExchangeAsync(Query(), CancellationToken.None);
        Assert.Equal("192.0.2.77", AddressOf(first));
        Assert.Equal(1, dead.UdpQueries);

        var second = await transport.ExchangeAsync(Query(), CancellationToken.None);
        Assert.Equal("192.0.2.77", AddressOf(second));
        Assert.Equal(1, dead.UdpQueries); // the preferred server is now the live one
        Assert.Equal(2, alive.UdpQueries);
    }

    [Fact]
    public async Task A_closed_port_fails_over_quickly_or_by_timeout()
    {
        IPEndPoint closed;
        using (var probe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
        {
            probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            closed = (IPEndPoint)probe.LocalEndPoint!;
        }

        using var alive = new LoopbackDnsServer(q => Answer(q));
        var transport = new UdpTcpDnsTransport(Options(closed, alive.Endpoint));
        var response = await transport.ExchangeAsync(Query(), CancellationToken.None);
        Assert.Equal("192.0.2.1", AddressOf(response));
    }

    [Fact]
    public async Task When_every_server_is_silent_it_gives_up_with_a_timeout_after_all_attempts()
    {
        using var a = new LoopbackDnsServer(_ => LoopbackDnsServer.Silent());
        using var b = new LoopbackDnsServer(_ => LoopbackDnsServer.Silent());
        var transport = new UdpTcpDnsTransport(Options(a.Endpoint, b.Endpoint));
        var ex = await Assert.ThrowsAsync<DnsException>(async () => await transport.ExchangeAsync(Query(), CancellationToken.None));
        Assert.Equal(DnsFailureReason.Timeout, ex.Reason);
        Assert.Equal(2, a.UdpQueries);
        Assert.Equal(2, b.UdpQueries);
        // 2 servers x 2 attempts (the timeout grows with the backoff multiplier); elapsed time is deliberately not asserted.
    }

    [Fact]
    public async Task Datagrams_with_a_wrong_id_or_question_or_port_are_ignored_not_trusted()
    {
        IPEndPoint? seenClient = null;
        LoopbackDnsServer? serverRef = null;
        using var server = new LoopbackDnsServer(q =>
        {
            seenClient = q.Remote;
            var wrongId = PacketBuilder.ReplyTo(q.Bytes).A("example.com", "203.0.113.1");
            wrongId.Id ^= 0x5555;
            var wrongQuestion = PacketBuilder.Response(BinaryPrimitives.ReadUInt16BigEndian(q.Bytes), "evil.example", DnsRecordType.A).A("evil.example", "203.0.113.2").Build();
            var rightButWrongPort = PacketBuilder.ReplyTo(q.Bytes).A("example.com", "203.0.113.3").Build();
            serverRef!.SendFromOtherPort(q.Remote, rightButWrongPort);
            return LoopbackDnsServer.Reply(
                [0x00, 0x01, 0x02],
                wrongId.Build(),
                wrongQuestion,
                PacketBuilder.ReplyTo(q.Bytes).A("example.com", "192.0.2.1").Build());
        });
        serverRef = server;
        var transport = new UdpTcpDnsTransport(Options(server.Endpoint));
        var response = await transport.ExchangeAsync(Query(), CancellationToken.None);
        Assert.Equal("192.0.2.1", AddressOf(response));
        Assert.NotNull(seenClient);
    }

    [Fact]
    public async Task Only_forged_answers_means_timeout_not_acceptance()
    {
        using var server = new LoopbackDnsServer(q =>
        {
            var forged = PacketBuilder.ReplyTo(q.Bytes).A("example.com", "203.0.113.1");
            forged.Id ^= 1;
            return LoopbackDnsServer.Reply(forged.Build());
        });
        var transport = new UdpTcpDnsTransport(Options(server.Endpoint) with { Attempts = 1 });
        var ex = await Assert.ThrowsAsync<DnsException>(async () => await transport.ExchangeAsync(Query(), CancellationToken.None));
        Assert.Equal(DnsFailureReason.Timeout, ex.Reason);
    }

    [Fact]
    public async Task Tcp_response_that_does_not_match_is_rejected()
    {
        using var server = new LoopbackDnsServer(q =>
        {
            if (!q.IsTcp)
            {
                return LoopbackDnsServer.Reply(PacketBuilder.ReplyTo(q.Bytes).Truncated().Build());
            }

            var wrong = PacketBuilder.ReplyTo(q.Bytes).A("example.com", "203.0.113.1");
            wrong.Id ^= 0x0101;
            return LoopbackDnsServer.Reply(wrong.Build());
        });
        var transport = new UdpTcpDnsTransport(Options(server.Endpoint) with { Attempts = 1 });
        var ex = await Assert.ThrowsAsync<DnsException>(async () => await transport.ExchangeAsync(Query(), CancellationToken.None));
        Assert.Equal(DnsFailureReason.ResponseMismatch, ex.Reason);
    }

    [Fact]
    public async Task Tcp_connection_closed_early_is_a_network_failure()
    {
        using var server = new LoopbackDnsServer(q => q.IsTcp ? LoopbackDnsServer.Silent() : LoopbackDnsServer.Reply(PacketBuilder.ReplyTo(q.Bytes).Truncated().Build()));
        var transport = new UdpTcpDnsTransport(Options(server.Endpoint) with { Attempts = 1 });
        var ex = await Assert.ThrowsAsync<DnsException>(async () => await transport.ExchangeAsync(Query(), CancellationToken.None));
        Assert.True(ex.Reason is DnsFailureReason.Timeout or DnsFailureReason.Network);
    }

    [Fact]
    public async Task Servfail_moves_on_to_the_next_server_without_retrying_the_failing_one()
    {
        using var broken = new LoopbackDnsServer(q => LoopbackDnsServer.Reply(PacketBuilder.ReplyTo(q.Bytes, rcode: 2).Build()));
        using var good = new LoopbackDnsServer(q => Answer(q, "192.0.2.5"));
        var transport = new UdpTcpDnsTransport(Options(broken.Endpoint, good.Endpoint) with { Attempts = 3 });
        var response = await transport.ExchangeAsync(Query(), CancellationToken.None);
        Assert.Equal("192.0.2.5", AddressOf(response));
        Assert.Equal(1, broken.UdpQueries);
    }

    [Fact]
    public async Task If_every_server_says_servfail_the_servfail_response_is_returned()
    {
        using var a = new LoopbackDnsServer(q => LoopbackDnsServer.Reply(PacketBuilder.ReplyTo(q.Bytes, rcode: 2).Build()));
        using var b = new LoopbackDnsServer(q => LoopbackDnsServer.Reply(PacketBuilder.ReplyTo(q.Bytes, rcode: 5).Build()));
        var transport = new UdpTcpDnsTransport(Options(a.Endpoint, b.Endpoint) with { Attempts = 3 });
        var response = await transport.ExchangeAsync(Query(), CancellationToken.None);
        Assert.Equal(DnsRcode.Refused, DnsMessageReader.Parse(response.Span).Rcode);
        Assert.Equal(1, a.UdpQueries);
        Assert.Equal(1, b.UdpQueries);
    }

    [Fact]
    public async Task Nxdomain_is_a_final_answer_not_a_failure()
    {
        using var a = new LoopbackDnsServer(q => LoopbackDnsServer.Reply(PacketBuilder.ReplyTo(q.Bytes, rcode: 3).Build()));
        using var b = new LoopbackDnsServer(q => Answer(q));
        var transport = new UdpTcpDnsTransport(Options(a.Endpoint, b.Endpoint));
        var response = await transport.ExchangeAsync(Query(), CancellationToken.None);
        Assert.Equal(DnsRcode.NameError, DnsMessageReader.Parse(response.Span).Rcode);
        Assert.Equal(0, b.UdpQueries);
    }

    [Fact]
    public async Task Cancellation_stops_waiting_promptly()
    {
        using var server = new LoopbackDnsServer(_ => LoopbackDnsServer.Silent());
        var transport = new UdpTcpDnsTransport(Options(server.Endpoint) with { AttemptTimeout = TimeSpan.FromSeconds(30), MaxAttemptTimeout = TimeSpan.FromSeconds(30) });
        using var cts = new CancellationTokenSource(100);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await transport.ExchangeAsync(Query(), cts.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await transport.ExchangeAsync(Query(), new CancellationToken(true)));
    }

    [Fact]
    public async Task Each_query_uses_a_fresh_source_port()
    {
        var ports = new System.Collections.Concurrent.ConcurrentBag<int>();
        using var server = new LoopbackDnsServer(q =>
        {
            ports.Add(q.Remote.Port);
            return Answer(q);
        });
        var transport = new UdpTcpDnsTransport(Options(server.Endpoint));
        for (int i = 0; i < 20; i++)
        {
            await transport.ExchangeAsync(Query(), CancellationToken.None);
        }

        Assert.True(ports.Distinct().Count() >= 15, $"only {ports.Distinct().Count()} distinct source ports in 20 queries");
    }

    [Fact]
    public async Task Zero_x_20_requires_the_exact_case_echo()
    {
        // The server lower-cases the question: with 0x20 on the answer is not accepted.
        using var lowering = new LoopbackDnsServer(q => LoopbackDnsServer.Reply(PacketBuilder.Response(BinaryPrimitives.ReadUInt16BigEndian(q.Bytes), "example.com", DnsRecordType.A).A("example.com", "192.0.2.1").Build()));
        var query = DnsMessageWriter.BuildQuery(77, "ExAmPlE.CoM", DnsRecordType.A, DnsQueryOptions.Default);
        var strict = new UdpTcpDnsTransport(Options(lowering.Endpoint) with { Use0x20 = true, Attempts = 1 });
        var ex = await Assert.ThrowsAsync<DnsException>(async () => await strict.ExchangeAsync(query, CancellationToken.None));
        Assert.Equal(DnsFailureReason.Timeout, ex.Reason);

        var lenient = new UdpTcpDnsTransport(Options(lowering.Endpoint) with { Use0x20 = false });
        Assert.Equal("192.0.2.1", AddressOf(await lenient.ExchangeAsync(query, CancellationToken.None)));

        using var echoing = new LoopbackDnsServer(q => Answer(q));
        var strictOk = new UdpTcpDnsTransport(Options(echoing.Endpoint) with { Use0x20 = true });
        Assert.Equal("192.0.2.1", AddressOf(await strictOk.ExchangeAsync(query, CancellationToken.None)));
    }

    [Fact]
    public async Task Works_over_ipv6_loopback_when_available()
    {
        if (!Socket.OSSupportsIPv6)
        {
            return;
        }

        LoopbackDnsServer server;
        try
        {
            server = new LoopbackDnsServer(q => Answer(q), IPAddress.IPv6Loopback);
        }
        catch (SocketException)
        {
            return;
        }

        using (server)
        {
            var transport = new UdpTcpDnsTransport(Options(server.Endpoint));
            Assert.Equal("192.0.2.1", AddressOf(await transport.ExchangeAsync(Query(), CancellationToken.None)));
        }
    }

    [Fact]
    public async Task Many_concurrent_exchanges_each_get_their_own_answer()
    {
        using var server = new LoopbackDnsServer(q =>
        {
            ushort id = BinaryPrimitives.ReadUInt16BigEndian(q.Bytes);
            return LoopbackDnsServer.Reply(PacketBuilder.ReplyTo(q.Bytes).A("example.com", $"10.0.{id >> 8}.{id & 0xFF}").Build());
        });
        var transport = new UdpTcpDnsTransport(Options(server.Endpoint) with { AttemptTimeout = TimeSpan.FromSeconds(5), MaxAttemptTimeout = TimeSpan.FromSeconds(5) });
        var tasks = Enumerable.Range(1, 100).Select(async i =>
        {
            var response = await transport.ExchangeAsync(Query(id: (ushort)(i * 300)), CancellationToken.None);
            Assert.Equal($"10.0.{(i * 300) >> 8}.{(i * 300) & 0xFF}", AddressOf(response));
        });
        await Task.WhenAll(tasks);
    }

    [Fact]
    public async Task A_malformed_query_is_an_argument_error()
    {
        using var server = new LoopbackDnsServer(q => Answer(q));
        var transport = new UdpTcpDnsTransport(Options(server.Endpoint));
        await Assert.ThrowsAsync<ArgumentException>(async () => await transport.ExchangeAsync(new byte[] { 1, 2, 3 }, CancellationToken.None));
    }

    [Fact]
    public async Task Full_stack_client_over_loopback_resolves_a_cname_chain()
    {
        using var server = new LoopbackDnsServer(q =>
        {
            var b = PacketBuilder.ReplyTo(q.Bytes);
            b.Cname("www.example.com", "edge.example.net").A("edge.example.net", "198.51.100.9");
            return LoopbackDnsServer.Reply(b.Build());
        });
        var client = new DnsClient(new UdpTcpDnsTransport(Options(server.Endpoint)), Options(server.Endpoint));
        var r = await client.QueryAsync("WWW.Example.com", DnsRecordType.A);
        Assert.True(r.IsSuccess);
        Assert.Equal(2, r.Answers.Count);
        Assert.Equal("198.51.100.9", r.Get<ARecord>().Single().Address.ToString());
        Assert.False(r.AuthenticatedData);
    }
}
