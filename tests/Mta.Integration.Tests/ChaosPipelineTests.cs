using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using Mta.Core;
using Mta.Dns;
using Mta.Host.Configuration;
using Mta.Host.Hosting;
using Mta.Host.Security;
using Mta.Smtp.Protocol;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Storage.Sqlite;

namespace Mta.Integration.Tests;

internal sealed class RecordingLog : IMtaLog
{
    public ConcurrentQueue<string> Lines { get; } = new();

    public bool IsEnabled(MtaLogLevel level) => true;

    public void Write(MtaLogLevel level, string source, string message, Exception? exception = null) =>
        Lines.Enqueue($"{DateTime.UtcNow:HH:mm:ss.fff} {level} {source}: {message}{(exception is null ? string.Empty : " | " + exception.GetType().Name + ": " + exception.Message)}");
}

/// <summary>An unreliable receiving MTA: random temporary and permanent refusals at RCPT and after DATA.</summary>
internal sealed class ChaosInternet(int seed, RecordingLog? log = null) : ISmtpServerHandler
{
    private void L(SmtpSessionContext s, string what) => log?.Write(MtaLogLevel.Debug, "remote", $"[{s.SessionId.ToString()[^6..]}] {what}");

    private readonly Random _random = new(seed);
    private readonly object _gate = new();

    /// <summary>(subject, recipient) accepted for delivery, in order.</summary>
    public ConcurrentQueue<(string Subject, string Recipient)> Accepted { get; } = new();

    public ValueTask<SmtpReply?> OnConnectedAsync(SmtpSessionContext session, CancellationToken ct)
    {
        L(session, "connected");
        return ValueTask.FromResult<SmtpReply?>(null);
    }

    public ValueTask<SmtpAuthResult> AuthenticateAsync(SmtpSessionContext session, string authorizationId, string userName, string password, CancellationToken ct) =>
        ValueTask.FromResult(SmtpAuthResult.Failed);

    public ValueTask<SmtpReply> OnMailFromAsync(SmtpSessionContext session, MailFromInfo mail, CancellationToken ct) => ValueTask.FromResult(SmtpReplies.SenderOk);

    public ValueTask<SmtpReply> OnRcptToAsync(SmtpSessionContext session, MailFromInfo mail, EmailAddress recipient, RcptParameters p, CancellationToken ct)
    {
        L(session, "rcpt " + recipient);
        if (recipient.LocalPart.StartsWith("gone", StringComparison.Ordinal))
        {
            return ValueTask.FromResult(SmtpReply.Create(550, "5.1.1", "No such user"));
        }

        double roll = Roll();
        if (roll < 0.10)
        {
            return ValueTask.FromResult(SmtpReply.Create(451, "4.2.1", "Mailbox busy, try later"));
        }

        return ValueTask.FromResult(SmtpReplies.RecipientOk);
    }

    public ValueTask<SmtpReply> OnMessageAsync(SmtpMessage message, CancellationToken ct)
    {
        L(message.Session, "message");
        double roll = Roll();
        if (roll < 0.08)
        {
            return ValueTask.FromResult(SmtpReply.Create(451, "4.7.1", "Greylisted"));
        }

        string text = Encoding.UTF8.GetString(message.ToArray());
        string subject = Regex.Match(text, @"^Subject: (.+?)\r?$", RegexOptions.Multiline).Groups[1].Value;
        foreach (var r in message.Recipients)
        {
            Accepted.Enqueue((subject, r.ToString()));
        }

        return ValueTask.FromResult(SmtpReply.Create(250, "2.0.0", "Accepted"));
    }

    public void OnDisconnected(SmtpSessionContext session) => L(session, "disconnected");

    private double Roll()
    {
        lock (_gate)
        {
            return _random.NextDouble();
        }
    }
}


/// <summary>
/// A TCP proxy in front of the remote MTA that sometimes cuts the connection right after the end of the message data was forwarded,
/// so the sender never sees the final reply although the remote accepted the message (the case behind <c>possible_duplicate</c>).
/// </summary>
internal sealed class FlakyProxy : IAsyncDisposable
{
    private readonly System.Net.Sockets.TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly int _targetPort;
    private readonly double _dropProbability;
    private readonly Random _random;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _accept;
    public int Drops;

    public FlakyProxy(int targetPort, double dropProbability, int seed)
    {
        _targetPort = targetPort;
        _dropProbability = dropProbability;
        _random = new Random(seed);
        _listener.Start();
        _accept = Task.Run(AcceptLoopAsync);
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    private async Task AcceptLoopAsync()
    {
        try
        {
            while (!_cts.IsCancellationRequested)
            {
                var client = await _listener.AcceptTcpClientAsync(_cts.Token);
                _ = Task.Run(() => HandleAsync(client));
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or System.Net.Sockets.SocketException)
        {
        }
    }

    private async Task HandleAsync(System.Net.Sockets.TcpClient client)
    {
        using var upstream = new System.Net.Sockets.TcpClient();
        try
        {
            await upstream.ConnectAsync(IPAddress.Loopback, _targetPort, _cts.Token);
            var c = client.GetStream();
            var u = upstream.GetStream();
            var down = Task.Run(async () => { try { await u.CopyToAsync(c, _cts.Token); } catch { } finally { client.Dispose(); } });
            byte[] buffer = new byte[16 * 1024];
            byte[] tail = [];
            while (true)
            {
                int n = await c.ReadAsync(buffer, _cts.Token);
                if (n == 0)
                {
                    break;
                }

                await u.WriteAsync(buffer.AsMemory(0, n), _cts.Token);
                await u.FlushAsync(_cts.Token);
                byte[] window = [.. tail, .. buffer.AsSpan(0, n).ToArray()];
                tail = window.Length > 4 ? window[^4..] : window;
                if (window.AsSpan().IndexOf("\r\n.\r\n"u8) >= 0 && NextDrop())
                {
                    await Task.Delay(30);   // let the remote finish and accept the message
                    Interlocked.Increment(ref Drops);
                    client.Client.LingerState = new System.Net.Sockets.LingerOption(true, 0);
                    break;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or System.Net.Sockets.SocketException or OperationCanceledException or ObjectDisposedException)
        {
        }
        finally
        {
            client.Dispose();
        }
    }

    private bool NextDrop()
    {
        lock (_random)
        {
            return _random.NextDouble() < _dropProbability;
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync();
        _listener.Stop();
        try { await _accept; } catch { }
    }
}

/// <summary>
/// A randomized run of the whole pipeline against an unreliable remote. The invariants are the product's promises: every accepted
/// recipient reaches exactly one final state, nothing that was reported delivered is missing at the remote, nothing is delivered
/// twice, and every hard bounce is reported back to the sender.
/// </summary>
public sealed class ChaosPipelineTests : IAsyncLifetime
{
    private static readonly Guid TenantId = Guid.Parse("a0000000-0000-7000-8000-000000000001");

    private readonly string _dir = Directory.CreateTempSubdirectory("eggmail-chaos-").FullName;
    private readonly CancellationTokenSource _stop = new();
    private ChaosInternet _internet = null!;
    private readonly RecordingLog _log = new();
    private SmtpServer _remote = null!;
    private FlakyProxy _proxy = null!;
    private EggMailRuntime _runtime = null!;
    private Task _engine = Task.CompletedTask;
    private int _submissionPort;
    private int _seed;

    public async Task InitializeAsync()
    {
        _seed = int.TryParse(Environment.GetEnvironmentVariable("EGGMAIL_CHAOS_SEED"), out int s) ? s : Environment.TickCount;
        _internet = new ChaosInternet(_seed, _log);
        _remote = new SmtpServer(new SmtpServerOptions
        {
            Hostname = "mx.chaos.example",
            Listeners = [new SmtpListenerOptions { Name = "mx", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.Plain, AuthRequired = false, Role = ListenerRole.Bounce }],
        }, _internet);
        _remote.Start();
        _proxy = new FlakyProxy(_remote.LocalEndPoints["mx"].Port, 0.04, _seed + 2);
        int remotePort = _proxy.Port;

        var dns = new StaticDnsResolver();
        foreach (string domain in new[] { "dest1.example", "dest2.example", "dest3.example", "example.org" })
        {
            dns.AddMx(domain, 10, "mx." + domain).AddA("mx." + domain, "127.0.0.1");
        }

        var config = new MtaConfig
        {
            Hostname = "egg.test",
            Storage = new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = _dir } },
            Smtp = new SmtpSection { Listeners = new Dictionary<string, ListenerSection> { ["submission"] = new() { Port = 0, BindAddress = "127.0.0.1", Mode = ListenerMode.StartTls, AuthRequired = true } } },
            Delivery = new DeliverySection
            {
                BounceDomain = "bounces.egg.test", RemotePort = remotePort, AllowPrivateMxAddresses = true, PollInterval = TimeSpan.FromMilliseconds(20),
                RetryDelays = [TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(200)], Workers = 32,
                Throttle = new ThrottleSection { MaxConnections = 16, InitialConnections = 16, MaxMessagesPerMinute = 600_000, InitialMessagesPerMinute = 600_000, MaxMessagesPerConnection = 1000 },
            },
        };
        var storage = SqliteStorage.Create(config.Storage);
        await storage.InitializeAsync(default);
        _runtime = await EggMailRuntime.CreateAsync(config, storage, SystemClock.Instance, _log, default, dns);

        var now = DateTimeOffset.UtcNow;
        await storage.Config.UpsertTenantAsync(new Tenant(TenantId, "Acme", "acme", true, now, false), default);
        await storage.Config.UpsertDomainAsync(new DomainRecord(Ids.New(), TenantId, "example.org", DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
        await storage.Config.UpsertSmtpCredentialAsync(new SmtpCredential(Ids.New(), TenantId, "acme-user", PasswordHasher.Hash("s3cret", 2000), true, now), default);
        _runtime.SmtpServer.Start();
        _submissionPort = _runtime.SmtpServer.LocalEndPoints["submission"].Port;
        _engine = Task.Run(() => _runtime.Delivery.RunAsync(_stop.Token));
    }

    public async Task DisposeAsync()
    {
        await _stop.CancelAsync();
        try { await _engine; } catch (OperationCanceledException) { }
        await _runtime.SmtpServer.StopAsync(TimeSpan.FromSeconds(2));
        await _proxy.DisposeAsync();
        await _remote.DisposeAsync();
        await _runtime.DisposeAsync();
        await _runtime.Storage.DisposeAsync();
        Directory.Delete(_dir, recursive: true);
    }

    [Fact]
    public async Task Every_recipient_reaches_exactly_one_final_state_and_nothing_is_lost_or_duplicated()
    {
        int messages = int.TryParse(Environment.GetEnvironmentVariable("EGGMAIL_CHAOS_MESSAGES"), out int m) ? m : 150;
        var rng = new Random(_seed + 1);
        var plan = new List<(string Subject, string[] Recipients)>();
        for (int i = 0; i < messages; i++)
        {
            int count = rng.Next(1, 4);
            var rcpts = new HashSet<string>();
            while (rcpts.Count < count)
            {
                string domain = $"dest{rng.Next(1, 4)}.example";
                string local = rng.NextDouble() < 0.08 ? $"gone{rng.Next(1000)}" : $"user{rng.Next(1000)}";
                rcpts.Add($"{local}@{domain}");
            }

            plan.Add(($"chaos-{i}", rcpts.ToArray()));
        }

        // Submit over SMTP from several connections at once.
        var queue = new ConcurrentQueue<(string Subject, string[] Recipients)>(plan);
        var senders = Enumerable.Range(0, 8).Select(_ => Task.Run(async () =>
        {
            using var client = new SmtpClient { CheckCertificateRevocation = false, ServerCertificateValidationCallback = (_, _, _, _) => true };
            await client.ConnectAsync("127.0.0.1", _submissionPort, SecureSocketOptions.StartTls);
            await client.AuthenticateAsync("acme-user", "s3cret");
            while (queue.TryDequeue(out var item))
            {
                var msg = new MimeMessage();
                msg.From.Add(MailboxAddress.Parse("news@example.org"));
                foreach (string r in item.Recipients)
                {
                    msg.To.Add(MailboxAddress.Parse(r));
                }

                msg.Subject = item.Subject;
                msg.Body = new TextPart("plain") { Text = "chaos body\r\n" };
                await client.SendAsync(msg);
            }

            await client.DisconnectAsync(true);
        })).ToArray();
        await Task.WhenAll(senders);

        // Wait for the queue (including the bounce messages it generates) to drain.
        var deadline = DateTime.UtcNow.AddSeconds(90);
        QueueStats stats;
        int stable = 0;
        do
        {
            await Task.Delay(100);
            stats = await _runtime.Storage.Deliveries.GetQueueStatsAsync(default);
            stable = stats is { Queued: 0, Leased: 0, Deferred: 0 } ? stable + 1 : 0;
            if (DateTime.UtcNow >= deadline && Environment.GetEnvironmentVariable("EGGMAIL_CHAOS_LOGFILE") is { Length: > 0 } logFile)
            {
                File.WriteAllLines(logFile, _log.Lines);
            }

            Assert.True(DateTime.UtcNow < deadline, $"queue did not drain (seed {_seed}): {stats}; pending groups {_runtime.Delivery.PendingGroups}\n" + string.Join('\n', (await _runtime.Storage.Maintenance.GetHealthAsync(default)).Details.Where(d => d.Key.StartsWith("writer.")).Select(d => d.Key + "=" + d.Value)) + "\n" + string.Join('\n', _log.Lines.TakeLast(25)));
        }
        while (stable < 10);

        Assert.True(_proxy.Drops > 0, "the run never cut a connection after end-of-data, so possible_duplicate was not exercised" + $" (seed {_seed})");

        // Final states per (message, recipient).
        var summaries = new List<MessageSummary>();
        string? cursor = null;
        do
        {
            var page = await _runtime.Storage.History.SearchAsync(new MessageQuery(TenantId, Limit: 200, Cursor: cursor), default);
            summaries.AddRange(page.Items);
            cursor = page.NextCursor;
        }
        while (cursor is not null);

        var finals = new Dictionary<(string Subject, string Recipient), List<MessageEventType>>();
        var flagged = new HashSet<(string Subject, string Recipient)>();
        foreach (var summary in summaries)
        {
            var events = await _runtime.Storage.History.GetEventsAsync(TenantId, summary.MessageId, default);
            foreach (var e in events.Where(e => e.Type == MessageEventType.PossibleDuplicate && e.Recipient is not null))
            {
                flagged.Add((summary.Subject ?? string.Empty, e.Recipient!));
            }

            foreach (var e in events.Where(e => e.Type is MessageEventType.Delivered or MessageEventType.Bounced or MessageEventType.Expired or MessageEventType.Suppressed && e.Recipient is not null))
            {
                string subject = summary.Subject ?? string.Empty;
                (finals.TryGetValue((subject, e.Recipient!), out var list) ? list : finals[(subject, e.Recipient!)] = []).Add(e.Type);
            }
        }

        string context = $" (seed {_seed})";
        foreach (var (subject, recipients) in plan)
        {
            foreach (string r in recipients)
            {
                Assert.True(finals.TryGetValue((subject, r), out var states), $"no final state for {subject} -> {r}{context}");
                var state = Assert.Single(states!);
                bool gone = r.StartsWith("gone", StringComparison.Ordinal);
                // A second message to an address that already bounced is suppressed instead of tried again.
                if (gone)
                {
                    Assert.True(state is MessageEventType.Bounced or MessageEventType.Suppressed, $"{subject} -> {r} ended as {state}{context}");
                }
                else
                {
                    Assert.Equal(MessageEventType.Delivered, state);
                }
            }
        }

        // The remote saw each delivered recipient exactly once and no bounced one.
        var seen = _internet.Accepted.Where(a => a.Subject.StartsWith("chaos-", StringComparison.Ordinal)).GroupBy(a => a).ToDictionary(g => g.Key, g => g.Count());
        foreach (var (subject, recipients) in plan)
        {
            foreach (string r in recipients)
            {
                bool gone = r.StartsWith("gone", StringComparison.Ordinal);
                seen.TryGetValue((subject, r), out int times);
                if (gone)
                {
                    Assert.True(times == 0, $"{subject} -> {r} was accepted although it bounced{context}");
                }
                else if (times > 1)
                {
                    // Delivered more than once is only allowed where a connection was lost after the data was sent, and it must be flagged.
                    Assert.True(flagged.Contains((subject, r)), $"{subject} -> {r} accepted {times} times without a possible_duplicate flag{context}");
                }
                else
                {
                    Assert.Equal(1, times);
                }
            }
        }

        // Every hard bounce is explained to the sender in a delivery status notification that the remote accepted.
        var bounced = plan.SelectMany(p => p.Recipients).Where(r => r.StartsWith("gone", StringComparison.Ordinal)).Distinct().ToList();
        Assert.True(bounced.Count == 0 || _internet.Accepted.Any(a => a.Recipient == "news@example.org"), "bounce messages reached the sender" + context);
        foreach (string address in bounced)
        {
            Assert.True(await _runtime.Storage.Config.IsSuppressedAsync(TenantId, address, default), $"{address} was not suppressed{context}");
        }
    }
}
