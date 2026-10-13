using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Mta.Core;
using Mta.Delivery;
using Mta.Dns;
using Mta.Dsn;
using Mta.Policy;
using Mta.Smtp.Client;
using Mta.Smtp.Protocol;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Storage.InMemory;
using Mta.Tls;

namespace Mta.Delivery.Tests;

/// <summary>A receiving MTA on loopback whose answers the tests control.</summary>
internal sealed class RemoteServer : ISmtpServerHandler, IServerCertificateProvider
{
    public sealed record Received(string Sender, string[] Recipients, byte[] Body, bool Tls, SmtpBodyType BodyType = SmtpBodyType.SevenBit, bool SmtpUtf8 = false);

    private readonly X509Certificate2 _certificate;
    public List<Received> Messages { get; } = [];
    public Func<string, SmtpReply?>? OnRecipient { get; set; }
    public Func<SmtpMessage, SmtpReply?>? OnMessage { get; set; }
    public int Connections;

    public RemoteServer()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=mx.dest.example", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var temp = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        _certificate = X509CertificateLoader.LoadPkcs12(temp.Export(X509ContentType.Pfx, "x"), "x", X509KeyStorageFlags.Exportable);
    }

    public X509Certificate2? GetCertificate(string? serverName) => _certificate;

    public ValueTask<SmtpReply?> OnConnectedAsync(SmtpSessionContext session, CancellationToken ct)
    {
        Interlocked.Increment(ref Connections);
        return ValueTask.FromResult<SmtpReply?>(null);
    }

    public ValueTask<SmtpAuthResult> AuthenticateAsync(SmtpSessionContext session, string authorizationId, string userName, string password, CancellationToken ct) =>
        ValueTask.FromResult(SmtpAuthResult.Failed);

    public ValueTask<SmtpReply> OnMailFromAsync(SmtpSessionContext session, MailFromInfo mail, CancellationToken ct) => ValueTask.FromResult(SmtpReplies.SenderOk);

    public ValueTask<SmtpReply> OnRcptToAsync(SmtpSessionContext session, MailFromInfo mail, EmailAddress recipient, RcptParameters parameters, CancellationToken ct) =>
        ValueTask.FromResult(OnRecipient?.Invoke(recipient.ToString()) ?? SmtpReplies.RecipientOk);

    public ValueTask<SmtpReply> OnMessageAsync(SmtpMessage message, CancellationToken ct)
    {
        if (OnMessage?.Invoke(message) is { } reply)
        {
            return ValueTask.FromResult(reply);
        }

        lock (Messages)
        {
            Messages.Add(new Received(message.Sender.ToString(), message.Recipients.Select(r => r.ToString()).ToArray(), message.ToArray(), message.Session.TlsActive, message.Parameters.BodyType, message.Parameters.SmtpUtf8));
        }

        return ValueTask.FromResult(SmtpReply.Create(250, "2.0.0", "Accepted"));
    }

    public void OnDisconnected(SmtpSessionContext session)
    {
    }
}

/// <summary>The whole outbound pipeline over in-memory storage, a static DNS and a loopback remote server.</summary>
internal sealed class DeliveryFixture : IAsyncDisposable
{
    public static readonly Guid Tenant = Guid.Parse("a0000000-0000-7000-8000-000000000001");

    private readonly CancellationTokenSource _stop = new();
    private Task _run = Task.CompletedTask;
    private readonly SmtpServer _server;

    public RemoteServer Remote { get; } = new();
    public InMemoryStorage Storage { get; }
    public StaticDnsResolver Dns { get; } = new();
    public DeliveryEngine Engine { get; }
    public DeliveryOptions Options { get; }
    public DeliveryServices Services { get; private set; }
    public int Port { get; }

    public DeliveryFixture(Func<DeliveryOptions, DeliveryOptions>? tweak = null, bool serverTls = false, bool startEngine = true, Func<DeliveryServices, IDkimSignerProvider>? dkim = null, SendingLimitsOptions? limits = null, VerpCodec? verp = null, bool eightBitMime = true, bool smtpUtf8 = true, Mta.Tls.TlsRpt.TlsRptCollector? tlsReports = null, Func<StaticDnsResolver, Mta.Tls.OutboundTlsPolicyResolver>? tlsResolver = null)
    {
        var clock = SystemClock.Instance;
        Storage = new InMemoryStorage(new StorageOptions { History = new HistoryOptions { Mode = HistoryMode.Full } }, clock);
        Storage.InitializeAsync(CancellationToken.None).GetAwaiter().GetResult();

        _server = new SmtpServer(new SmtpServerOptions
        {
            Hostname = "mx.dest.example",
            EightBitMime = eightBitMime,
            SmtpUtf8 = smtpUtf8,
            Certificates = serverTls ? Remote : null,
            Listeners = [new SmtpListenerOptions { Name = "mx", BindAddress = IPAddress.Loopback, Port = 0, Mode = serverTls ? ListenerMode.StartTls : ListenerMode.Plain, AuthRequired = false, Role = ListenerRole.Bounce }],
        }, Remote);
        _server.Start();
        Port = _server.LocalEndPoints["mx"].Port;

        Dns.AddMx("dest.example", 10, "mx.dest.example").AddA("mx.dest.example", "127.0.0.1");

        Options = new DeliveryOptions { Owner = "test", Hostname = "egg.test", RemotePort = Port, IdlePoll = TimeSpan.FromMilliseconds(30), ExpirySweepInterval = TimeSpan.FromMilliseconds(100), BounceDomain = null };
        if (tweak is not null)
        {
            Options = tweak(Options);
        }

        var health = new RouteHealth(clock);
        Services = new DeliveryServices
        {
            Storage = Storage,
            Clock = clock,
            Mx = new MxResolver(Dns, new MxResolverOptions { ExcludeSpecialAddresses = false }),
            Tls = tlsResolver?.Invoke(Dns) ?? new OutboundTlsPolicyResolver(null, null),
            TlsReports = tlsReports,
            TlsPolicies = new TlsPolicyTable(OutboundTlsConfiguration.Default),
            Pool = new SmtpConnectionPool(new SmtpClientOptions { HeloName = "egg.test", ConnectTimeout = TimeSpan.FromSeconds(5) }, clock),
            Routes = new RoutePlanner(health),
            Throttle = new DestinationThrottle(clock),
            Limits = new SendingLimits(clock, null, limits),
            Retry = new RetrySchedule(),
        };
        if (dkim is not null || verp is not null)
        {
            Services = new DeliveryServices
            {
                Storage = Services.Storage, Clock = Services.Clock, Mx = Services.Mx, Tls = Services.Tls, TlsPolicies = Services.TlsPolicies, Pool = Services.Pool,
                Routes = Services.Routes, Throttle = Services.Throttle, Limits = Services.Limits, Retry = Services.Retry, Dkim = dkim?.Invoke(Services) ?? NoDkimSignerProvider.Instance, Verp = verp, TlsReports = Services.TlsReports,
            };
        }

        var processor = new DeliveryProcessor(Services, Options, new DsnService(Storage, clock, Options));
        Engine = new DeliveryEngine(processor, Services, Options);
        if (startEngine)
        {
            StartEngine();
        }
    }

    public CancellationToken Stopping => _stop.Token;

    public void StartEngine() => _run = Task.Run(() => Engine.RunAsync(_stop.Token));

    public ValueTask DisposeServerForTestAsync() => _server.DisposeAsync();

    public async Task<Guid> EnqueueAsync(string[] to, string from = "sender@example.org", MessageSource source = MessageSource.Smtp, string? subject = "Hello", string? sendingDomain = "example.org", TimeSpan? lifetime = null)
    {
        var now = DateTimeOffset.UtcNow;
        string raw = $"From: {from}\r\nTo: {string.Join(", ", to)}\r\nSubject: {subject}\r\nMessage-ID: <{Guid.NewGuid():N}@example.org>\r\nDate: Mon, 12 Oct 2026 08:00:00 +0000\r\n\r\nBody line\r\n";
        var id = Ids.New(now);
        await Storage.Intake.AcceptAsync(new AcceptedMessage
        {
            MessageId = id,
            TenantId = Tenant,
            Source = source,
            EnvelopeFrom = EmailAddress.Parse(from),
            Recipients = to.Select(t => new AcceptedRecipient(Ids.New(now), EmailAddress.Parse(t))).ToList(),
            Raw = System.Text.Encoding.ASCII.GetBytes(raw),
            ReceivedAt = now,
            ExpiresAt = now + (lifetime ?? TimeSpan.FromDays(5)),
            SendingDomain = sendingDomain,
        }, CancellationToken.None);
        Engine.Wake();
        return id;
    }

    /// <summary>Queues an arbitrary raw message (CRLF lines) for the given recipients.</summary>
    public async Task<Guid> EnqueueRawAsync(byte[] raw, string[] to, string from = "sender@example.org", bool smtpUtf8 = false, string? sendingDomain = "example.org", MessageSource source = MessageSource.Smtp)
    {
        var now = DateTimeOffset.UtcNow;
        var id = Ids.New(now);
        await Storage.Intake.AcceptAsync(new AcceptedMessage
        {
            MessageId = id,
            TenantId = Tenant,
            Source = source,
            EnvelopeFrom = EmailAddress.Parse(from),
            Recipients = to.Select(t => new AcceptedRecipient(Ids.New(now), EmailAddress.Parse(t))).ToList(),
            Raw = raw,
            ReceivedAt = now,
            ExpiresAt = now + TimeSpan.FromDays(5),
            SendingDomain = sendingDomain,
            SmtpUtf8 = smtpUtf8,
        }, CancellationToken.None);
        Engine.Wake();
        return id;
    }

    public async Task<IReadOnlyList<MessageEvent>> EventsAsync(Guid messageId) => await Storage.History.GetEventsAsync(Tenant, messageId, CancellationToken.None);

    public static async Task WaitAsync(Func<bool> condition, int timeoutMs = 10_000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline)
            {
                throw new TimeoutException("condition not met in time");
            }

            await Task.Delay(20);
        }
    }

    public async Task<IReadOnlyList<MessageEvent>> WaitForEventAsync(Guid messageId, MessageEventType type, int count = 1)
    {
        IReadOnlyList<MessageEvent> events = [];
        await WaitAsync(() =>
        {
            events = EventsAsync(messageId).GetAwaiter().GetResult();
            return events.Count(e => e.Type == type) >= count;
        });
        return events;
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        try { await _run; } catch (OperationCanceledException) { }
        await Services.Pool.DisposeAsync();
        await _server.DisposeAsync();
        await Storage.DisposeAsync();
    }
}
