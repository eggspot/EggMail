using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using Mta.Core;
using Mta.Dns;
using Mta.Host.Configuration;
using Mta.Host.Hosting;
using Mta.Host.Submission;
using Mta.Smtp.Protocol;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.TestSupport;

namespace Mta.Integration.Tests.Lifecycle;

/// <summary>
/// A receiving MTA whose answers the test scripts. Every accepted message is recorded with the virtual instant it arrived at, so a test can
/// compare the instants of the attempts with the retry schedule.
/// </summary>
internal sealed class ScriptedRemote(IClock clock) : ISmtpServerHandler
{
    public sealed record Mail(string Sender, string[] Recipients, string Subject, byte[] Body, DateTimeOffset At);

    private readonly ConcurrentQueue<Mail> _accepted = new();
    private long _connections;
    private long _dataCommands;

    /// <summary>Accepted messages in the order they arrived.</summary>
    public IReadOnlyCollection<Mail> Accepted => _accepted;

    /// <summary>Connections opened to this remote (a refused connection is not counted: nobody is listening).</summary>
    public long Connections => Interlocked.Read(ref _connections);

    /// <summary>Messages whose end-of-data the remote saw (accepted or not).</summary>
    public long DataCommands => Interlocked.Read(ref _dataCommands);

    /// <summary>The reply to <c>RCPT TO</c> (null accepts).</summary>
    public Func<string, SmtpReply?>? Rcpt { get; set; }

    /// <summary>The reply to the end of the message data, given the subject and the recipients (null accepts).</summary>
    public Func<string, IReadOnlyList<string>, SmtpReply?>? Message { get; set; }

    /// <summary>Awaited between the end of the data and the reply (an attempt that is in flight for as long as the test wants).</summary>
    public Func<CancellationToken, Task>? BeforeReply { get; set; }

    public ValueTask<SmtpReply?> OnConnectedAsync(SmtpSessionContext session, CancellationToken ct)
    {
        Interlocked.Increment(ref _connections);
        return ValueTask.FromResult<SmtpReply?>(null);
    }

    public ValueTask<SmtpAuthResult> AuthenticateAsync(SmtpSessionContext session, string authorizationId, string userName, string password, CancellationToken ct) =>
        ValueTask.FromResult(SmtpAuthResult.Failed);

    public ValueTask<SmtpReply> OnMailFromAsync(SmtpSessionContext session, MailFromInfo mail, CancellationToken ct) => ValueTask.FromResult(SmtpReplies.SenderOk);

    public ValueTask<SmtpReply> OnRcptToAsync(SmtpSessionContext session, MailFromInfo mail, EmailAddress recipient, RcptParameters p, CancellationToken ct) =>
        ValueTask.FromResult(Rcpt?.Invoke(recipient.ToString()) ?? SmtpReplies.RecipientOk);

    public async ValueTask<SmtpReply> OnMessageAsync(SmtpMessage message, CancellationToken ct)
    {
        Interlocked.Increment(ref _dataCommands);
        byte[] body = message.ToArray();
        string subject = Regex.Match(Encoding.UTF8.GetString(body), @"^Subject: (.+?)\r?$", RegexOptions.Multiline).Groups[1].Value;
        string[] recipients = message.Recipients.Select(r => r.ToString()).ToArray();
        if (BeforeReply is { } gate)
        {
            await gate(ct).ConfigureAwait(false);
        }

        if (Message?.Invoke(subject, recipients) is { } refusal)
        {
            return refusal;
        }

        _accepted.Enqueue(new Mail(message.Sender.ToString(), recipients, subject, body, clock.UtcNow));
        return SmtpReply.Create(250, "2.0.0", "Accepted");
    }

    public void OnDisconnected(SmtpSessionContext session)
    {
    }
}

/// <summary>
/// The whole pipeline (the real <see cref="EggMailRuntime"/> with its <see cref="Mta.Delivery.DeliveryEngine"/>, SMTP client, retry schedule, DSN service, webhook fan-out and
/// the storage under test) driven by a virtual clock. The engine really runs; the test moves time to the next instant at which something is due and waits until the engine is idle again,
/// so days pass in seconds and every assertion is on virtual instants, never on elapsed time.
/// </summary>
internal sealed class LifecycleHarness : IAsyncDisposable
{
    public static readonly Guid TenantId = Guid.Parse("a0000000-0000-7000-8000-000000000001");
    public const string Sender = "news@example.org";

    private readonly Func<StorageOptions, IClock, IStorage> _createStorage;
    private readonly StorageOptions _storageOptions;
    private readonly Func<IStorage, IStorage>? _wrap;
    private readonly Guid _domainId;
    private readonly LifecycleHarness? _sharedWith;
    private SmtpServer? _remoteServer;
    private CancellationTokenSource? _stop;
    private Task _engine = Task.CompletedTask;
    private long _lastMaintenanceDay = long.MinValue;

    public LifecycleHarness(StorageOptions storageOptions, Func<StorageOptions, IClock, IStorage> createStorage, Func<IStorage, IStorage>? wrap = null, bool flakyProxy = false, LifecycleHarness? sharedWith = null)
    {
        _sharedWith = sharedWith;
        _domainId = sharedWith?._domainId ?? Ids.New();
        Clock = sharedWith?.Clock ?? new VirtualClock();
        Dns = sharedWith?.Dns ?? new StaticDnsResolver();
        _storageOptions = storageOptions;
        _createStorage = createStorage;
        _wrap = wrap;
        Started = sharedWith?.Started ?? Clock.UtcNow;
        if (sharedWith is not null)
        {
            // A second process over the same database, talking to the same remote with the same virtual time.
            Remote = sharedWith.Remote;
            ServerPort = sharedWith.ServerPort;
            Proxy = sharedWith.Proxy;
            RemotePort = sharedWith.RemotePort;
            return;
        }

        Remote = new ScriptedRemote(Clock);
        Dns.AddMx("dest.example", 10, "mx.dest.example").AddA("mx.dest.example", "127.0.0.1");
        Dns.AddMx("example.org", 10, "mx.example.org").AddA("mx.example.org", "127.0.0.1");
        using var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        ServerPort = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        Proxy = flakyProxy ? new FlakyProxy(ServerPort, 0, seed: 1) { SwallowReply = true } : null;
        RemotePort = Proxy?.Port ?? ServerPort;
    }

    public VirtualClock Clock { get; }

    public RecordingLog Log { get; } = new();

    public ScriptedRemote Remote { get; }

    public StaticDnsResolver Dns { get; }

    /// <summary>The port the delivery engine connects to: the remote's own, or the flaky proxy's in front of it.</summary>
    public int RemotePort { get; }

    public int ServerPort { get; }

    /// <summary>Cuts the connection after the end of the data was forwarded (set <see cref="FlakyProxy.DropProbability"/>); null unless asked for.</summary>
    public FlakyProxy? Proxy { get; }

    public bool RemoteIsUp => (_sharedWith ?? this)._remoteServer is not null;

    public EggMailRuntime Runtime { get; private set; } = null!;

    public IStorage Storage => Runtime.Storage;

    public MtaConfig Config { get; private set; } = null!;

    public Action<MtaConfigBuilder>? Tune { get; set; }

    /// <summary>The virtual instant the test started at.</summary>
    public DateTimeOffset Started { get; }

    public void StartRemote()
    {
        if (_sharedWith is not null)
        {
            _sharedWith.StartRemote();
            return;
        }

        if (_remoteServer is not null)
        {
            return;
        }

        var server = new SmtpServer(new SmtpServerOptions
        {
            Hostname = "mx.dest.example",
            Listeners = [new SmtpListenerOptions { Name = "mx", BindAddress = IPAddress.Loopback, Port = ServerPort, Mode = ListenerMode.Plain, AuthRequired = false, Role = ListenerRole.Bounce }],
        }, Remote);
        server.Start();
        _remoteServer = server;
    }

    /// <summary>Nobody listens on the port any more: the next connection is refused.</summary>
    public async Task StopRemoteAsync()
    {
        if (_sharedWith is not null)
        {
            await _sharedWith.StopRemoteAsync();
            return;
        }

        if (_remoteServer is { } server)
        {
            _remoteServer = null;
            await server.StopAsync(TimeSpan.FromMilliseconds(200));
            await server.DisposeAsync();
        }
    }

    /// <summary>Creates the storage and the runtime over the files or database of the backend (the same data when called again after <see cref="StopRuntimeAsync"/>) and starts the engine.</summary>
    public async Task StartRuntimeAsync(bool startEngine = true)
    {
        var builder = new MtaConfigBuilder();
        Tune?.Invoke(builder);
        Config = new MtaConfig
        {
            Hostname = "egg.test",
            Storage = _storageOptions,
            Smtp = new SmtpSection { Listeners = new Dictionary<string, ListenerSection>() },
            Webhooks = builder.Webhooks ?? new Mta.Webhooks.WebhookOptions(),
            Delivery = new DeliverySection
            {
                BounceDomain = "bounces.egg.test", RemotePort = RemotePort, AllowPrivateMxAddresses = true, PollInterval = TimeSpan.FromMilliseconds(10),
                ClaimLease = builder.ClaimLease ?? TimeSpan.FromMinutes(15), Workers = 8,
                Throttle = new ThrottleSection { MaxConnections = 16, InitialConnections = 16, MaxMessagesPerMinute = 600_000, InitialMessagesPerMinute = 600_000, MaxMessagesPerConnection = 1000 },
            },
        };
        IStorage storage = _createStorage(_storageOptions, Clock);
        await storage.InitializeAsync(default);
        if (_wrap is not null)
        {
            storage = _wrap(storage);
        }

        Runtime = await EggMailRuntime.CreateAsync(Config, storage, Clock, Log, default, Dns);
        var now = Clock.UtcNow;
        await storage.Config.UpsertTenantAsync(new Tenant(TenantId, "Acme", "acme", true, now, false), default);
        await storage.Config.UpsertDomainAsync(new DomainRecord(_domainId, TenantId, "example.org", DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
        if (startEngine)
        {
            StartEngine();
        }
    }

    public void StartEngine()
    {
        _stop = new CancellationTokenSource();
        CancellationToken token = _stop.Token;
        _engine = Task.Run(() => Runtime.Delivery.RunAsync(token));
    }

    /// <summary>A graceful stop of the engine (it releases the leases it holds), then the runtime and the storage are closed.</summary>
    public async Task StopRuntimeAsync()
    {
        if (_stop is not null)
        {
            await _stop.CancelAsync();
            try { await _engine; } catch (OperationCanceledException) { }
            _stop.Dispose();
            _stop = null;
        }

        await Runtime.DisposeAsync();
        await Runtime.Storage.DisposeAsync();
    }

    public async ValueTask DisposeAsync()
    {
        await StopRuntimeAsync();
        if (_sharedWith is not null)
        {
            return;   // the remote and the proxy belong to the first process
        }

        await StopRemoteAsync();
        if (Proxy is not null)
        {
            await Proxy.DisposeAsync();
        }
    }

    /// <summary>Submits a message from the tenant's verified domain over the same service the SMTP listener and the API use. Its lifetime is the queue lifetime, counted from the virtual now.</summary>
    public async Task<Guid> SubmitAsync(string[] recipients, string subject = "lifecycle", string? sender = Sender, string? idempotencyKey = null)
    {
        var tenant = (await Storage.Config.GetTenantAsync(TenantId, default))!;
        var from = sender is null ? EmailAddress.Null : EmailAddress.Parse(sender);
        string text = $"From: <{Sender}>\r\nTo: {string.Join(", ", recipients)}\r\nSubject: {subject}\r\nMessage-ID: <{Guid.NewGuid():N}@example.org>\r\nDate: {Clock.UtcNow:R}\r\n\r\nbody of {subject}\r\n";
        var result = await Runtime.Submission.SubmitAsync(new SubmissionRequest
        {
            Tenant = tenant,
            Source = MessageSource.Smtp,
            EnvelopeFrom = from,
            Recipients = recipients.Select(r => EmailAddress.Parse(r)).ToList(),
            Message = Encoding.ASCII.GetBytes(text),
            IdempotencyKey = idempotencyKey,
        }, default);
        Assert.True(result.IsAccepted, $"submission refused: {result.Status} {result.Detail}");
        Runtime.Delivery.Wake();
        return result.MessageId;
    }

    // Driving time

    /// <summary>Nothing is claimed or running and nothing is due at the virtual now.</summary>
    public async Task<bool> IsIdleAsync()
    {
        QueueStats stats = await Storage.Deliveries.GetQueueStatsAsync(default);
        return Runtime.Delivery.PendingGroups == 0 && stats.Leased == 0 && (stats.OldestDueAt is null || stats.OldestDueAt > Clock.UtcNow);
    }

    /// <summary>Waits (polling, with a deadline far above any plausible load) until the engine has nothing left to do at the virtual now.</summary>
    public async Task SettleAsync(int timeoutSeconds = 90)
    {
        var deadline = DateTime.UtcNow.AddSeconds(timeoutSeconds);
        int stable = 0;
        while (stable < 3)
        {
            stable = await IsIdleAsync() ? stable + 1 : 0;
            if (stable < 3)
            {
                Assert.True(DateTime.UtcNow < deadline, "the engine did not become idle at " + Clock.UtcNow.ToString("u") + "\n" + string.Join('\n', Log.Lines.TakeLast(15)));
                await Task.Delay(5);
            }
        }
    }

    /// <summary>
    /// Waits until idle, then moves the virtual clock to the next instant at which a delivery is due and wakes the engine. False when nothing is queued any more. The maintenance job runs once per virtual
    /// day, as the host's maintenance service does (on PostgreSQL it also creates the day partitions ahead).
    /// </summary>
    public async Task<bool> StepAsync()
    {
        await SettleAsync();
        QueueStats stats = await Storage.Deliveries.GetQueueStatsAsync(default);
        if (stats.OldestDueAt is not { } due)
        {
            return false;
        }

        if (due > Clock.UtcNow)
        {
            Clock.Set(due);
        }

        await MaintainOncePerDayAsync();
        Runtime.Delivery.Wake();
        return true;
    }

    public async Task MaintainOncePerDayAsync()
    {
        long day = Clock.UtcNow.UtcTicks / TimeSpan.TicksPerDay;
        if (day != _lastMaintenanceDay)
        {
            _lastMaintenanceDay = day;
            await Storage.Maintenance.RunAsync(Clock.UtcNow, default);
        }
    }

    /// <summary>Steps until nothing is queued (a bound on the number of steps turns a runaway into a failure).</summary>
    public async Task RunUntilQuietAsync(int maxSteps = 5000)
    {
        for (int i = 0; i < maxSteps; i++)
        {
            if (!await StepAsync())
            {
                return;
            }
        }

        Assert.Fail($"the queue never became quiet in {maxSteps} steps (virtual now {Clock.UtcNow:u})");
    }

    /// <summary>Steps until the virtual clock reaches <paramref name="until"/> or nothing is queued; the clock then stands at <paramref name="until"/>.</summary>
    public async Task RunUntilAsync(DateTimeOffset until, int maxSteps = 5000)
    {
        for (int i = 0; i < maxSteps; i++)
        {
            await SettleAsync();
            QueueStats stats = await Storage.Deliveries.GetQueueStatsAsync(default);
            if (stats.OldestDueAt is not { } due || due > until)
            {
                break;
            }

            await StepAsync();
        }

        await SettleAsync();
        if (Clock.UtcNow < until)
        {
            Clock.Set(until);
            await MaintainOncePerDayAsync();
            Runtime.Delivery.Wake();
            await SettleAsync();
        }
    }

    // Reading what happened

    public async Task<IReadOnlyList<MessageEvent>> EventsAsync(Guid messageId) =>
        (await Storage.History.GetEventsAsync(TenantId, messageId, default)).OrderBy(e => e.At).ToList();

    public async Task<IReadOnlyList<MessageSummary>> AllMessagesAsync()
    {
        var all = new List<MessageSummary>();
        string? cursor = null;
        do
        {
            var page = await Storage.History.SearchAsync(new MessageQuery(TenantId, Limit: 200, Cursor: cursor), default);
            all.AddRange(page.Items);
            cursor = page.NextCursor;
        }
        while (cursor is not null);
        return all;
    }

    /// <summary>The delivery status notifications the remote received for the sender (null sender, addressed to the sender).</summary>
    public IReadOnlyList<ScriptedRemote.Mail> Bounces => Remote.Accepted.Where(m => m.Sender.Length == 0 && m.Recipients.Contains(Sender)).ToList();

    public static SmtpReply Temporary(string text = "Try again later") => SmtpReply.Create(451, "4.3.0", text);

    public static SmtpReply Greylisted() => SmtpReply.Create(451, "4.7.1", "Greylisted, please try again in 5 minutes");

    public static SmtpReply NoSuchUser() => SmtpReply.Create(550, "5.1.1", "No such user");

    /// <summary>The recipients that reached each final state in the message's events (a recipient with two finals is a bug).</summary>
    public static Dictionary<string, MessageEventType> FinalStates(IEnumerable<MessageEvent> events)
    {
        var finals = new Dictionary<string, MessageEventType>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in events.Where(e => e.Type is MessageEventType.Delivered or MessageEventType.Bounced or MessageEventType.Expired or MessageEventType.Suppressed or MessageEventType.Cancelled && e.Recipient is not null))
        {
            Assert.False(finals.ContainsKey(e.Recipient!), $"{e.Recipient} reached a second final state {e.Type} after {finals.GetValueOrDefault(e.Recipient!)}");
            finals[e.Recipient!] = e.Type;
        }

        return finals;
    }

    /// <summary>Sums a counter over the stored hourly rows of the tenant (after a flush).</summary>
    public async Task<long> StatAsync(Func<StatRow, long> counter)
    {
        await Storage.Stats.FlushAsync(default);
        var rows = await Storage.Stats.QueryAsync(TenantId, Started.AddDays(-1), Clock.UtcNow.AddDays(1), daily: false, default);
        return rows.Sum(counter);
    }
}

/// <summary>The few runtime settings a lifecycle test changes.</summary>
internal sealed class MtaConfigBuilder
{
    public Mta.Webhooks.WebhookOptions? Webhooks { get; set; }

    public TimeSpan? ClaimLease { get; set; }
}
