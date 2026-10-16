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

    /// <summary>Messages whose subject this accepts are answered only after <see cref="SlowDelay"/>, so a sender's claim can run out before the reply arrives (null: none).</summary>
    public Func<string, bool>? IsSlow { get; set; }

    public TimeSpan SlowDelay { get; set; } = TimeSpan.FromSeconds(4);

    /// <summary>The final reply of every accepted message is held back this long after the message was recorded as accepted (zero: none).</summary>
    public TimeSpan ReplyDelay { get; set; }

    public async ValueTask<SmtpReply> OnMessageAsync(SmtpMessage message, CancellationToken ct)
    {
        L(message.Session, "message");
        double roll = Roll();
        if (roll < 0.08)
        {
            return SmtpReply.Create(451, "4.7.1", "Greylisted");
        }

        string text = Encoding.UTF8.GetString(message.ToArray());
        string subject = Regex.Match(text, @"^Subject: (.+?)\r?$", RegexOptions.Multiline).Groups[1].Value;
        if (IsSlow?.Invoke(subject) == true)
        {
            await Task.Delay(SlowDelay, ct);
        }

        foreach (var r in message.Recipients)
        {
            Accepted.Enqueue((subject, r.ToString()));
        }

        if (ReplyDelay > TimeSpan.Zero)
        {
            // The message is accepted, the answer is on its way: a sender killed now never learns that it was.
            try
            {
                await Task.Delay(ReplyDelay, ct);
            }
            catch (OperationCanceledException)
            {
            }
        }

        return SmtpReply.Create(250, "2.0.0", "Accepted");
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
    private double _dropProbability;
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

    /// <summary>The chance that a message is cut after its end-of-data was forwarded (the lifecycle tests switch it on and off).</summary>
    /// <summary>When set, the remote's answer to a message that is cut is held back until the remote has given it, so the sender certainly never sees it (the default is a 30 ms head start that usually, not always, loses the race).</summary>
    public bool SwallowReply { get; set; }

    public double DropProbability { get => Volatile.Read(ref _dropProbability); set => Volatile.Write(ref _dropProbability, value); }

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
            bool cutting = false;
            var replySeen = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var down = Task.Run(async () =>
            {
                try
                {
                    byte[] reply = new byte[16 * 1024];
                    while (true)
                    {
                        int read = await u.ReadAsync(reply, _cts.Token);
                        if (read == 0)
                        {
                            break;
                        }

                        if (Volatile.Read(ref cutting))
                        {
                            replySeen.TrySetResult();   // the remote has answered; the sender will never hear it
                            continue;
                        }

                        await c.WriteAsync(reply.AsMemory(0, read), _cts.Token);
                    }
                }
                catch
                {
                }
                finally
                {
                    client.Dispose();
                }
            });
            byte[] buffer = new byte[16 * 1024];
            byte[] tail = [];
            while (true)
            {
                int n = await c.ReadAsync(buffer, _cts.Token);
                if (n == 0)
                {
                    break;
                }

                byte[] window = [.. tail, .. buffer.AsSpan(0, n).ToArray()];
                tail = window.Length > 4 ? window[^4..] : window;
                bool drop = window.AsSpan().IndexOf("\r\n.\r\n"u8) >= 0 && NextDrop();
                if (drop && SwallowReply)
                {
                    Volatile.Write(ref cutting, true);   // before the data is forwarded: the remote's answer must not get through
                }

                await u.WriteAsync(buffer.AsMemory(0, n), _cts.Token);
                await u.FlushAsync(_cts.Token);
                if (drop)
                {
                    if (SwallowReply)
                    {
                        await Task.WhenAny(replySeen.Task, Task.Delay(TimeSpan.FromSeconds(10)));   // the remote has accepted (or refused) the message
                    }
                    else
                    {
                        await Task.Delay(30);   // let the remote finish and accept the message
                    }

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
            return _random.NextDouble() < DropProbability;
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
public abstract class ChaosPipelineTests : IAsyncLifetime
{
    private static readonly Guid TenantId = Guid.Parse("a0000000-0000-7000-8000-000000000001");

    protected readonly string Dir = Directory.CreateTempSubdirectory("eggmail-chaos-").FullName;
    protected bool Unavailable;
    private readonly CancellationTokenSource _stop = new();
    private ChaosInternet _internet = null!;
    private readonly RecordingLog _log = new();
    private SmtpServer _remote = null!;
    private FlakyProxy _proxy = null!;
    private EggMailRuntime _runtime = null!;
    private Task _engine = Task.CompletedTask;
    private int _submissionPort;
    private int _seed;

    /// <summary>The backend under test.</summary>
    protected abstract StorageOptions StorageOptionsFor();

    protected abstract IStorage CreateStorage(StorageOptions options);

    protected virtual Task PrepareAsync() => Task.CompletedTask;

    protected virtual Task CleanupAsync() => Task.CompletedTask;

    public async Task InitializeAsync()
    {
        await PrepareAsync();
        if (Unavailable)
        {
            return;
        }

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
            Storage = StorageOptionsFor(),
            Smtp = new SmtpSection { Listeners = new Dictionary<string, ListenerSection> { ["submission"] = new() { Port = 0, BindAddress = "127.0.0.1", Mode = ListenerMode.StartTls, AuthRequired = true } } },
            Delivery = new DeliverySection
            {
                BounceDomain = "bounces.egg.test", RemotePort = remotePort, AllowPrivateMxAddresses = true, PollInterval = TimeSpan.FromMilliseconds(20),
                RetryDelays = [TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(200)], Workers = 32,
                Throttle = new ThrottleSection { MaxConnections = 16, InitialConnections = 16, MaxMessagesPerMinute = 600_000, InitialMessagesPerMinute = 600_000, MaxMessagesPerConnection = 1000 },
            },
        };
        var storage = CreateStorage(config.Storage);
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
        if (Unavailable)
        {
            return;
        }

        await _stop.CancelAsync();
        try { await _engine; } catch (OperationCanceledException) { }
        await _runtime.SmtpServer.StopAsync(TimeSpan.FromSeconds(2));
        await _proxy.DisposeAsync();
        await _remote.DisposeAsync();
        await _runtime.DisposeAsync();
        await _runtime.Storage.DisposeAsync();
        await CleanupAsync();
        Directory.Delete(Dir, recursive: true);
    }

    [Fact]
    public async Task Every_recipient_reaches_exactly_one_final_state_and_nothing_is_lost_or_duplicated()
    {
        if (Unavailable)
        {
            return;   // no PostgreSQL on this machine (CI provides one)
        }

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
        try
        {
            await Task.WhenAll(senders);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"submission failed (seed {_seed}): {ex.Message}\n" + string.Join('\n', _log.Lines.Where(l => l.Contains(" Error ") || l.Contains(" Warning ")).Take(20)), ex);
        }

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

        await ChaosInvariants.AssertAsync(_runtime.Storage, TenantId, plan, _internet, $" (seed {_seed})");
    }
}

public sealed class ChaosPipelineOnSqlite : ChaosPipelineTests
{
    protected override StorageOptions StorageOptionsFor() => new() { Sqlite = new SqliteOptions { DataDirectory = Dir } };

    protected override IStorage CreateStorage(StorageOptions options) => SqliteStorage.Create(options);
}

public sealed class ChaosPipelineOnPostgres : ChaosPipelineTests
{
    private Mta.Storage.Postgres.Tests.TestDatabase? _database;

    protected override async Task PrepareAsync()
    {
        if (!PostgresPromise.Available())
        {
            Unavailable = true;
            return;
        }

        _database = await Mta.Storage.Postgres.Tests.PostgresTestServer.Instance.CreateDatabaseAsync();
    }

    protected override async Task CleanupAsync()
    {
        if (_database is not null)
        {
            await _database.DisposeAsync();
        }
    }

    protected override StorageOptions StorageOptionsFor() => new()
    {
        Backend = StorageBackend.Postgres,
        Postgres = new PostgresOptions { OwnerConnectionString = _database!.ConnectionString, RuntimeConnectionString = _database.ConnectionString },
    };

    protected override IStorage CreateStorage(StorageOptions options) => Mta.Storage.Postgres.PostgresStorage.Create(options);
}
