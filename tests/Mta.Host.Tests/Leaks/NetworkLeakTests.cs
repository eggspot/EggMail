using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Mta.Core;
using Mta.Dns;
using Mta.Smtp.Client;
using Mta.Smtp.Protocol;
using Mta.Smtp.Server;
using Mta.TestSupport;
using Xunit.Abstractions;

namespace Mta.Host.Tests.Leaks;

/// <summary>
/// Accelerated lifecycle, leaks: the network hot paths repeated thousands of times in-process. DNS lookups (fake transport and the real UDP
/// transport against a loopback responder), SMTP sessions opened and closed against the real server with the real client (plain, STARTTLS with a
/// full TLS handshake each, and through the connection pool), each judged by "no growth between batches" of the managed heap, threads, descriptors,
/// timers, outstanding pooled arrays and the component's own counters (open sessions, cached answers, idle pooled connections).
/// </summary>
[Collection(LeakCollection.Name)]
public sealed class NetworkLeakTests(ITestOutputHelper output)
{
    private static int Cheap => Accelerated.Scaled(2500);

    private static int TlsHandshakes => Accelerated.Scaled(100);

    [Fact]
    public async Task Leak_dns_lookups_through_the_caching_client_do_not_grow()
    {
        var clock = new VirtualClock();
        var transport = new AnsweringTransport();
        var client = new DnsClient(transport, new DnsResolverOptions { MaxCacheEntries = 500, EdnsUdpPayloadSize = 1232 }, clock);

        using var probe = new LeakProbe(output.WriteLine);
        probe.TrackArrayPoolBalance();
        probe.Track("cached DNS answers", () => client.CachedEntryCount, absolute: 0);
        int n = 0;
        LeakReport report = await probe.RunAsync(async _ =>
        {
            // Distinct names (the cache must stay at its bound), repeated names (hits), a name that does not exist (negative entry), a virtual second per lookup (entries expire).
            int i = Interlocked.Increment(ref n);
            clock.Advance(TimeSpan.FromSeconds(1));
            DnsResponse a = await client.QueryAsync($"host{i}.example.test", DnsRecordType.A);
            Assert.Single(a.Answers);
            await client.QueryAsync("fixed.example.test", DnsRecordType.A);
            DnsResponse missing = await client.QueryAsync($"missing{i % 50}.nx.test", DnsRecordType.A);
            Assert.True(missing.IsNxDomain);
        }, Cheap);
        report.AssertNoGrowth();
        Assert.True(client.CachedEntryCount <= 500);
    }

    [Fact]
    public async Task Leak_dns_lookups_through_the_real_udp_transport_do_not_grow()
    {
        using var responder = new UdpResponder();
        var options = new DnsResolverOptions { Servers = [responder.EndPoint], MaxCacheEntries = 0, EdnsUdpPayloadSize = 1232, AttemptTimeout = TimeSpan.FromSeconds(10), MaxAttemptTimeout = TimeSpan.FromSeconds(10), Attempts = 1 };
        var client = new DnsClient(new UdpTcpDnsTransport(options), options);

        using var probe = new LeakProbe(output.WriteLine);
        probe.TrackArrayPoolBalance();
        int n = 0;
        LeakReport report = await probe.RunAsync(async _ =>
        {
            DnsResponse a = await client.QueryAsync($"host{Interlocked.Increment(ref n)}.example.test", DnsRecordType.A);
            Assert.Single(a.Answers);
        }, Accelerated.Scaled(1000));
        report.AssertNoGrowth();
    }

    [Fact]
    public async Task Leak_smtp_sessions_opened_and_closed_do_not_grow()
    {
        await using var server = new Peer();
        SmtpClientOptions options = ClientOptions();
        SmtpRemoteTarget target = server.Target(SmtpTlsPolicy.Disabled);

        using var probe = new LeakProbe(output.WriteLine);
        probe.TrackArrayPoolBalance();
        probe.Track("server sessions open", () => server.Server.ActiveConnections, absolute: 2);
        LeakReport report = await probe.RunAsync(async _ =>
        {
            await using SmtpClientConnection connection = await SmtpClientConnection.ConnectAsync(target, options);
            SmtpSendResult result = await connection.SendAsync(Envelope(), Message());
            Assert.True(result.Delivered);
            await connection.QuitAsync();
        }, Accelerated.Scaled(500));
        report.AssertNoGrowth();
        Assert.True(server.Handler.Messages >= 2000);
    }

    [Fact]
    public async Task Leak_smtp_sessions_without_a_quit_do_not_grow()
    {
        // The client just goes away (the abrupt close of a real network): the server must release the session, its buffers and its socket all the same.
        await using var server = new Peer();
        SmtpClientOptions options = ClientOptions();
        SmtpRemoteTarget target = server.Target(SmtpTlsPolicy.Disabled);

        using var probe = new LeakProbe(output.WriteLine);
        probe.TrackArrayPoolBalance();
        probe.Track("server sessions open", () => server.Server.ActiveConnections, absolute: 2);
        LeakReport report = await probe.RunAsync(async _ =>
        {
            await using SmtpClientConnection connection = await SmtpClientConnection.ConnectAsync(target, options);
            Assert.Equal(220, connection.Banner.Code);
        }, Accelerated.Scaled(500));
        report.AssertNoGrowth();
    }

    [Fact]
    public async Task Leak_smtp_starttls_sessions_with_a_full_handshake_each_do_not_grow()
    {
        await using var server = new Peer();
        SmtpClientOptions options = ClientOptions();
        SmtpRemoteTarget target = server.Target(new SmtpTlsPolicy { Mode = SmtpTlsMode.StartTls, Require = true, TargetHost = "localhost", ValidationCallback = (_, _, _, _) => true });

        using var probe = new LeakProbe(output.WriteLine);
        probe.TrackArrayPoolBalance();
        probe.Track("server sessions open", () => server.Server.ActiveConnections, absolute: 2);
        LeakReport report = await probe.RunAsync(async _ =>
        {
            await using SmtpClientConnection connection = await SmtpClientConnection.ConnectAsync(target, options);
            Assert.True(connection.TlsSession.Used);
            SmtpSendResult result = await connection.SendAsync(Envelope(), Message());
            Assert.True(result.Delivered);
            await connection.QuitAsync();
        }, TlsHandshakes);
        report.AssertNoGrowth();
    }

    [Fact]
    public async Task Leak_smtp_connection_pool_rent_and_return_cycles_do_not_grow()
    {
        await using var server = new Peer();
        SmtpClientOptions options = ClientOptions();
        var clock = new VirtualClock();
        await using var pool = new SmtpConnectionPool(options, clock, maxMessagesPerConnection: 50);
        SmtpRemoteTarget target = server.Target(SmtpTlsPolicy.Disabled);

        using var probe = new LeakProbe(output.WriteLine);
        probe.TrackArrayPoolBalance();
        probe.Track("idle pooled connections", () => pool.IdleConnections, absolute: 1);
        probe.Track("server sessions open", () => server.Server.ActiveConnections, absolute: 2);
        LeakReport report = await probe.RunAsync(async _ =>
        {
            await using PooledConnection lease = await pool.RentAsync(target);
            SmtpSendResult result = await lease.Connection.SendAsync(Envelope(), Message());
            Assert.True(result.Delivered);
        }, Cheap);
        report.AssertNoGrowth();
        Assert.True(pool.IdleConnections <= 2);
    }

    private static SmtpClientOptions ClientOptions() => new()
    {
        HeloName = "client.test",
        BannerTimeout = TimeSpan.FromSeconds(60),
        CommandTimeout = TimeSpan.FromSeconds(60),
        EndOfDataTimeout = TimeSpan.FromSeconds(60),
        DataBlockTimeout = TimeSpan.FromSeconds(60),
        DataInitiationTimeout = TimeSpan.FromSeconds(60),
    };

    private static SmtpEnvelope Envelope() => new(EmailAddress.Parse("sender@example.org"), [EmailAddress.Parse("rcpt@dest.example")], false, false);

    private static byte[] Message() => Encoding.UTF8.GetBytes("From: a@b.example\r\nTo: c@d.example\r\nSubject: leak check\r\n\r\nHello\r\n");

    /// <summary>A server on loopback with the real SMTP server and a handler that accepts everything and keeps nothing.</summary>
    private sealed class Peer : IAsyncDisposable
    {
        public Peer()
        {
            Handler = new CountingHandler();
            Server = new SmtpServer(new SmtpServerOptions
            {
                Hostname = "mx.remote.test",
                Certificates = new EcdsaCertificate(),
                AuthFailureDelay = TimeSpan.Zero,
                MaxConnectionsPerIp = 10_000,
                Listeners = [new SmtpListenerOptions { Name = "mx", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.StartTls, AuthRequired = false, Role = ListenerRole.Bounce }],
            }, Handler);
            Server.Start();
            Port = Server.LocalEndPoints["mx"].Port;
        }

        public SmtpServer Server { get; }

        public CountingHandler Handler { get; }

        public int Port { get; }

        public SmtpRemoteTarget Target(SmtpTlsPolicy tls) => new() { Host = "localhost", Address = IPAddress.Loopback, Port = Port, Tls = tls };

        public ValueTask DisposeAsync() => Server.DisposeAsync();
    }

    private sealed class CountingHandler : ISmtpServerHandler
    {
        private long _messages;

        public long Messages => Interlocked.Read(ref _messages);

        public ValueTask<SmtpReply?> OnConnectedAsync(SmtpSessionContext session, CancellationToken ct) => ValueTask.FromResult<SmtpReply?>(null);

        public ValueTask<SmtpAuthResult> AuthenticateAsync(SmtpSessionContext session, string authorizationId, string userName, string password, CancellationToken ct) =>
            ValueTask.FromResult(SmtpAuthResult.Failed);

        public ValueTask<SmtpReply> OnMailFromAsync(SmtpSessionContext session, MailFromInfo mail, CancellationToken ct) => ValueTask.FromResult(SmtpReplies.SenderOk);

        public ValueTask<SmtpReply> OnRcptToAsync(SmtpSessionContext session, MailFromInfo mail, EmailAddress recipient, RcptParameters p, CancellationToken ct) =>
            ValueTask.FromResult(SmtpReplies.RecipientOk);

        public ValueTask<SmtpReply> OnMessageAsync(SmtpMessage message, CancellationToken ct)
        {
            Interlocked.Increment(ref _messages);
            return ValueTask.FromResult(SmtpReply.Create(250, "2.0.0", "Queued"));
        }

        public void OnDisconnected(SmtpSessionContext session)
        {
        }
    }

    /// <summary>A P-256 certificate (a handshake costs a fraction of an RSA-2048 one, which is all this test needs of it).</summary>
    private sealed class EcdsaCertificate : IServerCertificateProvider
    {
        private readonly X509Certificate2 _certificate;

        public EcdsaCertificate()
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256);
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName("localhost");
            request.CertificateExtensions.Add(san.Build());
            using X509Certificate2 temporary = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
            _certificate = X509CertificateLoader.LoadPkcs12(temporary.Export(X509ContentType.Pfx, "x"), "x", X509KeyStorageFlags.Exportable);
        }

        public X509Certificate2? GetCertificate(string? serverName) => _certificate;
    }

    /// <summary>Answers every A question with one record, without any network (and every name under <c>nx.test</c> with NXDOMAIN).</summary>
    private sealed class AnsweringTransport : IDnsTransport
    {
        public ValueTask<ReadOnlyMemory<byte>> ExchangeAsync(ReadOnlyMemory<byte> query, CancellationToken cancellationToken) =>
            ValueTask.FromResult<ReadOnlyMemory<byte>>(Reply(query.Span));
    }

    /// <summary>A DNS responder on a loopback UDP port; answers like <see cref="AnsweringTransport"/>.</summary>
    private sealed class UdpResponder : IDisposable
    {
        private readonly UdpClient _socket = new(new IPEndPoint(IPAddress.Loopback, 0));
        private readonly CancellationTokenSource _stop = new();
        private readonly Task _loop;

        public UdpResponder()
        {
            _loop = Task.Run(async () =>
            {
                try
                {
                    while (!_stop.IsCancellationRequested)
                    {
                        UdpReceiveResult received = await _socket.ReceiveAsync(_stop.Token);
                        await _socket.SendAsync(Reply(received.Buffer), received.RemoteEndPoint, _stop.Token);
                    }
                }
                catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
                {
                }
            });
        }

        public IPEndPoint EndPoint => (IPEndPoint)_socket.Client.LocalEndPoint!;

        public void Dispose()
        {
            _stop.Cancel();
            _socket.Dispose();
            _loop.GetAwaiter().GetResult();
            _stop.Dispose();
        }
    }

    /// <summary>The query's header and question copied into a response with one A record (or, under nx.test, NXDOMAIN).</summary>
    private static byte[] Reply(ReadOnlySpan<byte> query)
    {
        int end = 12;
        while (query[end] != 0)
        {
            end += query[end] + 1;
        }

        int nameEnd = end;
        end += 1 + 4;   // the root label, type and class
        bool nx = Encoding.ASCII.GetString(query[12..nameEnd]).EndsWith("\u0002nx\u0004test", StringComparison.Ordinal);
        byte[] answer = [0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 1, 0x2C, 0, 4, 192, 0, 2, 1];   // pointer to the question name, A, IN, TTL 300, 192.0.2.1
        byte[] response = new byte[end + (nx ? 0 : answer.Length)];
        query[..end].CopyTo(response);
        response[2] = 0x81;                       // QR, RD
        response[3] = (byte)(nx ? 0x83 : 0x80);   // RA, rcode NXDOMAIN or NOERROR
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(6, 2), (ushort)(nx ? 0 : 1));   // ANCOUNT
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(8, 2), 0);                      // NSCOUNT
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(10, 2), 0);                     // ARCOUNT
        if (!nx)
        {
            answer.CopyTo(response, end);
        }

        return response;
    }
}
