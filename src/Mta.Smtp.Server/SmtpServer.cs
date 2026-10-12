using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Mta.Core;

namespace Mta.Smtp.Server;

/// <summary>
/// The SMTP server: owns the listeners, connection limits and the accepting/quiescing switch. Protocol decisions live in
/// <see cref="SmtpSession"/>, policy and storage in <see cref="ISmtpServerHandler"/>.
/// </summary>
public sealed class SmtpServer : IAsyncDisposable
{
    private readonly List<ListenerRuntime> _listeners = [];
    private readonly ConcurrentDictionary<Task, byte> _sessions = new();
    private readonly CancellationTokenSource _stoppingCts = new();
    private readonly ConnectionLimiter _limiter;
    private volatile bool _acceptingMail = true;
    private bool _started;

    public SmtpServer(SmtpServerOptions options, ISmtpServerHandler handler, IClock? clock = null, IMtaLog? log = null)
    {
        Options = options;
        Handler = handler;
        Clock = clock ?? SystemClock.Instance;
        Log = log ?? NullMtaLog.Instance;
        Budget = new InFlightBudget(options.MaxInFlightBytes);
        _limiter = new ConnectionLimiter(options.MaxConnections, options.MaxConnectionsPerIp);
    }

    internal SmtpServerOptions Options { get; }
    internal ISmtpServerHandler Handler { get; }
    internal IClock Clock { get; }
    internal IMtaLog Log { get; }
    internal InFlightBudget Budget { get; }

    /// <summary>
    /// When false (quiesce / drain, decision I), new connections get <c>421</c> and sessions refuse new transactions;
    /// a message already being received is completed.
    /// </summary>
    public bool AcceptingMail
    {
        get => _acceptingMail;
        set => _acceptingMail = value;
    }

    public int ActiveConnections => _limiter.Total;

    /// <summary>Bound end points by listener name (useful when ports were 0).</summary>
    public IReadOnlyDictionary<string, IPEndPoint> LocalEndPoints => _listeners.ToDictionary(l => l.Options.Name, l => (IPEndPoint)l.Socket.LocalEndPoint!);

    public void Start()
    {
        if (_started)
        {
            throw new InvalidOperationException("Already started.");
        }

        _started = true;
        foreach (var lo in Options.Listeners.Where(l => l.Enabled))
        {
            if (lo.Mode != ListenerMode.Plain && Options.Certificates is null)
            {
                throw new InvalidOperationException($"Listener '{lo.Name}' needs TLS but no certificate provider is configured.");
            }

            var socket = new Socket(lo.BindAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            if (lo.BindAddress.AddressFamily == AddressFamily.InterNetworkV6)
            {
                socket.DualMode = true;
            }

            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            socket.Bind(new IPEndPoint(lo.BindAddress, lo.Port));
            socket.Listen(512);
            var rt = new ListenerRuntime(lo, socket);
            _listeners.Add(rt);
            rt.AcceptTask = AcceptLoopAsync(rt);
        }
    }

    private async Task AcceptLoopAsync(ListenerRuntime listener)
    {
        var ct = _stoppingCts.Token;
        while (!ct.IsCancellationRequested)
        {
            Socket client;
            try
            {
                client = await listener.Socket.AcceptAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.OperationAborted || ct.IsCancellationRequested)
            {
                return;   // the listener was closed on purpose
            }
            catch (SocketException ex)
            {
                Log.Write(MtaLogLevel.Warning, "smtp.server", $"accept failed on {listener.Options.Name}: {ex.SocketErrorCode}");
                await Task.Delay(50, CancellationToken.None).ConfigureAwait(false);
                continue;
            }

            var task = HandleClientAsync(client, listener.Options);
            _sessions[task] = 0;
            _ = task.ContinueWith(static (t, state) => ((ConcurrentDictionary<Task, byte>)state!).TryRemove(t, out _), _sessions, TaskScheduler.Default);
        }
    }

    private async Task HandleClientAsync(Socket client, SmtpListenerOptions listener)
    {
        IPAddress remote = ((IPEndPoint)client.RemoteEndPoint!).Address;
        client.NoDelay = true;
        if (!_limiter.TryAcquire(remote))
        {
            SmtpMetrics.RefusedConnections.Add(1);
            try
            {
                client.Send("421 4.7.0 Too many connections\r\n"u8);
            }
            catch (SocketException)
            {
            }

            client.Dispose();
            return;
        }

        try
        {
            var session = new SmtpSession(this, client, listener, _stoppingCts.Token);
            await session.RunAsync().ConfigureAwait(false);
        }
        finally
        {
            _limiter.Release(remote);
        }
    }

    /// <summary>TLS options for a handshake: picks the certificate by SNI and caches the chain context per certificate.</summary>
    internal ValueTask<SslServerAuthenticationOptions> ServerOptionsCallback(SslStream stream, SslClientHelloInfo hello, object? state, CancellationToken ct)
    {
        var context = Options.Certificates?.GetContext(hello.ServerName);
        if (context is null)
        {
            throw new AuthenticationException("No server certificate available.");
        }

        return ValueTask.FromResult(new SslServerAuthenticationOptions
        {
            ServerCertificateContext = context,
            EnabledSslProtocols = Options.TlsProtocols,
            ClientCertificateRequired = false,
            AllowRenegotiation = false,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
        });
    }

    /// <summary>Stops accepting connections and gives sessions <paramref name="grace"/> to finish before cancelling them.</summary>
    public async Task StopAsync(TimeSpan grace)
    {
        AcceptingMail = false;
        foreach (var l in _listeners)
        {
            l.Socket.Close();
        }

        var grAll = Task.WhenAll(_sessions.Keys);
        if (await Task.WhenAny(grAll, Task.Delay(grace)).ConfigureAwait(false) != grAll)
        {
            await _stoppingCts.CancelAsync().ConfigureAwait(false);
            await Task.WhenAny(grAll, Task.Delay(TimeSpan.FromSeconds(5))).ConfigureAwait(false);
        }
        else
        {
            await _stoppingCts.CancelAsync().ConfigureAwait(false);
        }

        foreach (var l in _listeners)
        {
            await l.AcceptTask.ConfigureAwait(false);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_started && !_stoppingCts.IsCancellationRequested)
        {
            await StopAsync(TimeSpan.FromSeconds(1)).ConfigureAwait(false);
        }

        _stoppingCts.Dispose();
        foreach (var l in _listeners)
        {
            l.Socket.Dispose();
        }
    }

    private sealed class ListenerRuntime(SmtpListenerOptions options, Socket socket)
    {
        public SmtpListenerOptions Options { get; } = options;
        public Socket Socket { get; } = socket;
        public Task AcceptTask { get; set; } = Task.CompletedTask;
    }
}
