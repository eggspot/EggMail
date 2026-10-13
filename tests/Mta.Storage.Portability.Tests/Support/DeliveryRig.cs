using System.Net;
using Mta.Core;
using Mta.Delivery;
using Mta.Dns;
using Mta.Dsn;
using Mta.Policy;
using Mta.Smtp.Client;
using Mta.Smtp.Protocol;
using Mta.Smtp.Server;
using Mta.Tls;

namespace Mta.Storage.Portability.Tests;

/// <summary>A receiving MTA on loopback whose behavior the tests control: it can hold the reply to the end of data.</summary>
public sealed class RemoteMta : ISmtpServerHandler, IAsyncDisposable
{
    private readonly SmtpServer _server;
    private readonly object _lock = new();
    private readonly List<(string Recipient, string Subject)> _received = [];

    public RemoteMta()
    {
        _server = new SmtpServer(new SmtpServerOptions
        {
            Hostname = "mx.dest.example",
            Listeners = [new SmtpListenerOptions { Name = "mx", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.Plain, AuthRequired = false, Role = ListenerRole.Bounce }],
        }, this);
        _server.Start();
        Port = _server.LocalEndPoints["mx"].Port;
    }

    public int Port { get; }

    /// <summary>When set, the message is recorded as accepted but the reply to the end of data waits for it (the client may time out or be aborted).</summary>
    public TaskCompletionSource? HoldReply { get; set; }

    /// <summary>When set, a recipient command waits for it (the delivery is aborted before the end of data).</summary>
    public TaskCompletionSource? HoldRecipient { get; set; }

    /// <summary>Limits <see cref="HoldReply"/> and <see cref="HoldRecipient"/> to messages for recipients that match (all when null).</summary>
    public Func<string, bool>? HoldWhen { get; set; }

    public int InFlight;

    public IReadOnlyList<(string Recipient, string Subject)> Received
    {
        get
        {
            lock (_lock)
            {
                return _received.ToList();
            }
        }
    }

    public int CountFor(string recipient)
    {
        lock (_lock)
        {
            return _received.Count(r => string.Equals(r.Recipient, recipient, StringComparison.OrdinalIgnoreCase));
        }
    }

    public ValueTask<SmtpReply?> OnConnectedAsync(SmtpSessionContext session, CancellationToken ct) => ValueTask.FromResult<SmtpReply?>(null);

    public ValueTask<SmtpAuthResult> AuthenticateAsync(SmtpSessionContext session, string authorizationId, string userName, string password, CancellationToken ct) => ValueTask.FromResult(SmtpAuthResult.Failed);

    public ValueTask<SmtpReply> OnMailFromAsync(SmtpSessionContext session, MailFromInfo mail, CancellationToken ct) => ValueTask.FromResult(SmtpReplies.SenderOk);

    public async ValueTask<SmtpReply> OnRcptToAsync(SmtpSessionContext session, MailFromInfo mail, EmailAddress recipient, RcptParameters parameters, CancellationToken ct)
    {
        if (HoldRecipient is { } hold && (HoldWhen?.Invoke(recipient.ToString()) ?? true))
        {
            Interlocked.Increment(ref InFlight);
            await hold.Task.WaitAsync(ct).ConfigureAwait(false);
        }

        return SmtpReplies.RecipientOk;
    }

    public async ValueTask<SmtpReply> OnMessageAsync(SmtpMessage message, CancellationToken ct)
    {
        string subject = System.Text.Encoding.ASCII.GetString(message.ToArray()).Split("\r\n").FirstOrDefault(l => l.StartsWith("Subject:", StringComparison.Ordinal)) ?? "";
        lock (_lock)
        {
            foreach (EmailAddress r in message.Recipients)
            {
                _received.Add((r.ToString(), subject));
            }
        }

        if (HoldReply is { } hold && (HoldWhen is null || message.Recipients.Any(r => HoldWhen(r.ToString()))))
        {
            Interlocked.Increment(ref InFlight);
            await hold.Task.ConfigureAwait(false);
        }

        return SmtpReply.Create(250, "2.0.0", "Accepted");
    }

    public void OnDisconnected(SmtpSessionContext session)
    {
    }

    public async ValueTask DisposeAsync() => await _server.DisposeAsync();
}

/// <summary>The real delivery engine over a storage, pointed at a <see cref="RemoteMta"/>.</summary>
public sealed class DeliveryRig : IAsyncDisposable
{
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _run;
    private readonly DeliveryServices _services;

    public DeliveryRig(IStorage storage, RemoteMta remote, string owner = "rig")
    {
        var clock = SystemClock.Instance;
        var dns = new StaticDnsResolver();
        foreach (string domain in new[] { "example.org", "example.net" })
        {
            dns.AddMx(domain, 10, "mx.dest.example").AddA("mx.dest.example", "127.0.0.1");
        }

        var options = new DeliveryOptions { Owner = owner, Hostname = "egg.test", RemotePort = remote.Port, IdlePoll = TimeSpan.FromMilliseconds(30), ExpirySweepInterval = TimeSpan.FromMilliseconds(100), BounceDomain = null };
        _services = new DeliveryServices
        {
            Storage = storage,
            Clock = clock,
            Mx = new MxResolver(dns, new MxResolverOptions { ExcludeSpecialAddresses = false }),
            Tls = new OutboundTlsPolicyResolver(null, null),
            TlsPolicies = new TlsPolicyTable(OutboundTlsConfiguration.Default),
            Pool = new SmtpConnectionPool(new SmtpClientOptions { HeloName = "egg.test", ConnectTimeout = TimeSpan.FromSeconds(5) }, clock),
            Routes = new RoutePlanner(new RouteHealth(clock)),
            Throttle = new DestinationThrottle(clock),
            Limits = new SendingLimits(clock, null, null),
            Retry = new RetrySchedule(),
        };
        Engine = new DeliveryEngine(new DeliveryProcessor(_services, options, new DsnService(storage, clock, options)), _services, options);
        _run = Task.Run(() => Engine.RunAsync(_stop.Token));
    }

    public DeliveryEngine Engine { get; }

    public static async Task WaitAsync(Func<bool> condition, int timeoutMs = 15_000)
    {
        DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline)
            {
                throw new TimeoutException("condition not met in time");
            }

            await Task.Delay(20);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        try
        {
            await _run;
        }
        catch (OperationCanceledException)
        {
        }

        await _services.Pool.DisposeAsync();
    }
}

/// <summary>The host control of a process that runs a real <see cref="DeliveryEngine"/>: the in-process source of a switch.</summary>
public sealed class RigHostControl(DeliveryRig rig) : ISwitchHostControl
{
    public bool Accepting { get; private set; } = true;

    public ValueTask StopAcceptingAsync(CancellationToken cancellationToken)
    {
        Accepting = false;
        return default;
    }

    public ValueTask ResumeAcceptingAsync(CancellationToken cancellationToken)
    {
        Accepting = true;
        return default;
    }

    public ValueTask PauseDispatchAsync(CancellationToken cancellationToken)
    {
        rig.Engine.Pause();
        return default;
    }

    public ValueTask ResumeDispatchAsync(CancellationToken cancellationToken)
    {
        rig.Engine.Resume();
        return default;
    }

    public async ValueTask QuiesceDeliveriesAsync(TimeSpan timeout, CancellationToken cancellationToken) => await rig.Engine.QuiesceAsync(timeout, cancellationToken);
}
