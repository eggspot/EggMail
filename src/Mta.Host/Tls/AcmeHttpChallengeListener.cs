using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Mta.Core;

namespace Mta.Host.Tls;

/// <summary>
/// The built-in HTTP-01 responder (decision 87): a deliberately tiny HTTP/1.1 server on its own socket, separate from Kestrel and the dashboard. It answers
/// <c>GET</c> and <c>HEAD</c> of exactly <c>/.well-known/acme-challenge/&lt;token&gt;</c> with the key authorization of a token an order is waiting for, and
/// refuses everything else (404, 405 or 400, no body, the connection closed): no other path, no query string, no redirect, no static files, no request body is read.
/// Requests are bounded (8 KiB head within 2 seconds, 5 seconds in all, 128 connections and 8 per client address) because the port is open to the internet.
/// <para>
/// It runs on every replica whenever HTTP-01 is in use, not only on the one that holds the renewal lease: the CA connects to whichever replica the
/// load balancer picks, and the token is read from the shared store (<see cref="Http01Challenges"/>).
/// </para>
/// </summary>
public sealed class AcmeHttpChallengeListener : IAsyncDisposable
{
    public const string PathPrefix = "/.well-known/acme-challenge/";

    private const int MaxHeadBytes = 8 * 1024;
    private static readonly TimeSpan DefaultRequestTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan DefaultHeadTimeout = TimeSpan.FromSeconds(2);

    private readonly IHttpChallengeResponder _responder;
    private readonly Http01Challenges? _status;
    private readonly string _bindAddress;
    private readonly int _requestedPort;
    private readonly IMtaLog _log;
    private readonly TimeSpan _retryInterval;
    private readonly int _maxConnections;
    private readonly int _maxConnectionsPerAddress;
    private readonly TimeSpan _requestTimeout;
    private readonly TimeSpan _headTimeout;
    private readonly ConcurrentDictionary<IPAddress, int> _perAddress = new();
    private long _lastAcceptWarning;
    private readonly object _gate = new();
    private Socket? _socket;
    private int _active;
    private volatile bool _disposed;

    /// <param name="responder">Finds the answer for a token.</param>
    /// <param name="bindAddress">The address to listen on: <c>::</c> (every IPv4 and IPv6 address), <c>0.0.0.0</c>, or one address.</param>
    /// <param name="port">The port; 0 picks a free one (tests; <see cref="Port"/> says which).</param>
    /// <param name="status">Told why the listener cannot bind (so no order asks the CA to connect to a closed port) and told again when it can.</param>
    /// <param name="retryInterval">How long to wait before trying to bind again (default one minute).</param>
    /// <param name="maxConnections">Connections served at once; more are closed at once.</param>
    /// <param name="maxConnectionsPerAddress">Connections served at once for one client address (IPv4-mapped addresses count as IPv4); more are closed at once. A CA validates from a few addresses, each with one request.</param>
    /// <param name="headTimeout">How long a client has to send its request head (default 2 seconds); a slower one is dropped.</param>
    /// <param name="requestTimeout">How long a connection may live in all (default 5 seconds).</param>
    public AcmeHttpChallengeListener(IHttpChallengeResponder responder, string bindAddress, int port, Http01Challenges? status = null, IMtaLog? log = null,
        TimeSpan? retryInterval = null, int maxConnections = 128, int maxConnectionsPerAddress = 8, TimeSpan? headTimeout = null, TimeSpan? requestTimeout = null)
    {
        _maxConnectionsPerAddress = maxConnectionsPerAddress;
        _headTimeout = headTimeout ?? DefaultHeadTimeout;
        _requestTimeout = requestTimeout ?? DefaultRequestTimeout;
        _responder = responder;
        _bindAddress = bindAddress;
        _requestedPort = port;
        _status = status;
        _log = log ?? NullMtaLog.Instance;
        _retryInterval = retryInterval ?? TimeSpan.FromMinutes(1);
        _maxConnections = maxConnections;
    }

    /// <summary>The port in use once bound (the requested one, or the one the system picked for 0); 0 before.</summary>
    public int Port => (_socket?.LocalEndPoint as IPEndPoint)?.Port ?? 0;

    public bool IsListening => _socket is not null;

    /// <summary>
    /// Binds the port. Returns null when it is bound, otherwise a message that says what is wrong and what to do; the reason is also recorded
    /// as the status of the challenge store, which makes orders wait instead of failing at the CA.
    /// </summary>
    public string? TryBind()
    {
        lock (_gate)
        {
            if (_socket is not null)
            {
                return null;
            }

            Socket? socket = null;
            try
            {
                if (!IPAddress.TryParse(_bindAddress, out IPAddress? address))
                {
                    throw new FormatException($"Acme:Http01BindAddress '{_bindAddress}' is not an IP address.");
                }

                if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && !Socket.OSSupportsIPv6)
                {
                    address = IPAddress.Equals(address, IPAddress.IPv6Any) ? IPAddress.Any : throw new FormatException($"Acme:Http01BindAddress '{_bindAddress}' is an IPv6 address and this host has no IPv6.");
                }

                socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    socket.DualMode = IPAddress.Equals(address, IPAddress.IPv6Any);
                }

                socket.Bind(new IPEndPoint(address, _requestedPort));
                socket.Listen(128);
                _socket = socket;
                _status?.ListenerBound();

                _log.Write(MtaLogLevel.Information, "acme", $"answering ACME HTTP-01 challenges on {socket.LocalEndPoint} (GET {PathPrefix}<token> only)");
                return null;
            }
            catch (Exception ex) when (ex is SocketException or FormatException or ObjectDisposedException)
            {
                socket?.Dispose();
                string message = Describe(ex);
                _status?.ListenerFailed(message);

                return message;
            }
        }
    }

    private string Describe(Exception ex)
    {
        string where = $"{_bindAddress} port {_requestedPort}";
        return ex switch
        {
            SocketException { SocketErrorCode: SocketError.AddressAlreadyInUse } =>
                $"ACME HTTP-01: {where} is already in use (a web server or proxy on this host?). Stop what uses it, or set Acme:Http01ListenPort to a free port and forward port 80 to that port, or use DNS-01 (Acme:CloudflareApiToken).",
            SocketException { SocketErrorCode: SocketError.AccessDenied } =>
                $"ACME HTTP-01: this process is not allowed to listen on {where}. Ports below 1024 need root or the capability CAP_NET_BIND_SERVICE; in a container set the sysctl net.ipv4.ip_unprivileged_port_start=0 or set Acme:Http01ListenPort to a high port (for example 8081) and publish it as port 80 (docker run -p 80:8081), or use DNS-01 (Acme:CloudflareApiToken).",
            SocketException se =>
                $"ACME HTTP-01: cannot listen on {where}: {se.Message}. Set Acme:Http01BindAddress / Acme:Http01ListenPort to something this host can bind, or use DNS-01 (Acme:CloudflareApiToken).",
            _ => $"ACME HTTP-01: cannot listen on {where}: {ex.Message}",
        };
    }

    /// <summary>Binds (retrying until it works, with a log line per changed problem) and serves until cancelled. Nothing that goes wrong here stops the host.</summary>
    public async Task RunAsync(CancellationToken ct)
    {
        string? lastProblem = null;
        try
        {
            while (!ct.IsCancellationRequested && !_disposed)
            {
                try
                {
                    string? problem = TryBind();
                    if (problem is null)
                    {
                        lastProblem = null;
                        await ServeAsync(ct).ConfigureAwait(false);
                    }
                    else if (problem != lastProblem)
                    {
                        _log.Write(MtaLogLevel.Error, "acme", problem);
                        lastProblem = problem;
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    // Unforeseen: say so, mark the listener unavailable (no order asks the CA to connect to it) and try again later.
                    string message = $"ACME HTTP-01: the listener failed unexpectedly ({ex.GetType().Name}: {ex.Message}); binding again.";
                    _status?.ListenerFailed(message);
                    Close();
                    if (message != lastProblem)
                    {
                        _log.Write(MtaLogLevel.Error, "acme", message, ex);
                        lastProblem = message;
                    }
                }

                // Not bound, or the socket failed under us: try again later, never in a tight loop.
                if (!ct.IsCancellationRequested && !_disposed)
                {
                    await Task.Delay(_retryInterval, ct).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    /// <summary>
    /// Accepts connections on the bound socket until cancelled or the socket is unusable (then it is closed, the challenge store is told the listener is
    /// unavailable, and <see cref="RunAsync"/> binds again). A failed accept of one connection (aborted, no free descriptor) is not the end of the listener.
    /// </summary>
    public async Task ServeAsync(CancellationToken ct)
    {
        Socket socket = _socket ?? throw new InvalidOperationException("Not bound.");
        string? failure = null;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                Socket client;
                try
                {
                    client = await socket.AcceptAsync(ct).ConfigureAwait(false);
                }
                catch (SocketException ex) when (!_disposed && !ct.IsCancellationRequested && !IsFatal(ex))
                {
                    WarnAboutAccept(ex);
                    await Task.Delay(TimeSpan.FromMilliseconds(200), ct).ConfigureAwait(false);
                    continue;
                }

                if (!TryEnter(client, out IPAddress? address))
                {
                    client.Dispose();
                    continue;
                }

                _ = HandleAsync(client, address, ct);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
        {
            if (!_disposed && !ct.IsCancellationRequested)
            {
                failure = $"ACME HTTP-01: the listener on {_bindAddress} port {_requestedPort} stopped ({ex.Message}); binding again.";
                _log.Write(MtaLogLevel.Warning, "acme", failure, ex);
            }
        }
        finally
        {
            Close();
            if (failure is not null)
            {
                _status?.ListenerFailed(failure);   // orders wait instead of asking the CA to connect to a closed port, until the bind succeeds again
            }
        }
    }

    /// <summary>An error that means the listening socket itself is gone (closed, shut down), as opposed to one connection failing to be accepted.</summary>
    private static bool IsFatal(SocketException ex) =>
        ex.SocketErrorCode is SocketError.OperationAborted or SocketError.Shutdown or SocketError.NotSocket or SocketError.InvalidArgument or SocketError.Interrupted;

    private void WarnAboutAccept(SocketException ex)
    {
        long now = Environment.TickCount64;
        long last = Interlocked.Read(ref _lastAcceptWarning);
        if ((last == 0 || now - last >= 60_000) && Interlocked.CompareExchange(ref _lastAcceptWarning, now, last) == last)
        {
            _log.Write(MtaLogLevel.Warning, "acme", $"the ACME HTTP-01 listener could not accept a connection ({ex.SocketErrorCode}); continuing (logged once a minute)", ex);
        }
    }

    /// <summary>Counts the connection against the global and the per-address limits; false (nothing counted) when either is reached or the peer is already gone.</summary>
    private bool TryEnter(Socket client, out IPAddress address)
    {
        address = IPAddress.None;
        try
        {
            if (client.RemoteEndPoint is not IPEndPoint remote)
            {
                return false;
            }

            address = remote.Address.IsIPv4MappedToIPv6 ? remote.Address.MapToIPv4() : remote.Address;
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
        {
            return false;
        }

        if (Interlocked.Increment(ref _active) > _maxConnections)
        {
            Interlocked.Decrement(ref _active);
            return false;
        }

        int count = _perAddress.AddOrUpdate(address, 1, static (_, n) => n + 1);
        if (count > _maxConnectionsPerAddress)
        {
            Leave(address);
            return false;
        }

        return true;
    }

    private void Leave(IPAddress address)
    {
        Interlocked.Decrement(ref _active);
        // The entry goes with its last connection, so the table never outgrows the connections in flight.
        while (_perAddress.TryGetValue(address, out int n))
        {
            if (n <= 1 ? _perAddress.TryRemove(new KeyValuePair<IPAddress, int>(address, n)) : _perAddress.TryUpdate(address, n - 1, n))
            {
                break;
            }
        }
    }

    private async Task HandleAsync(Socket client, IPAddress address, CancellationToken ct)
    {
        try
        {
            using (client)
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(_requestTimeout);
                client.NoDelay = true;
                int status;
                string? body;
                bool headOnly;
                using (var headCts = CancellationTokenSource.CreateLinkedTokenSource(cts.Token))
                {
                    headCts.CancelAfter(_headTimeout);   // a client that does not send its request line and headers promptly is dropped
                    (status, body, headOnly) = await ReadAndDecideAsync(client, address, headCts.Token, cts.Token).ConfigureAwait(false);
                }

                await SendAsync(client, status, body, headOnly, cts.Token).ConfigureAwait(false);
                try
                {
                    client.Shutdown(SocketShutdown.Send);
                    // Read what the peer still sends (a bounded amount, until it closes) before closing: closing a socket with unread data resets the
                    // connection, and the reset can destroy the answer the peer has not read yet.
                    byte[] scratch = new byte[4096];
                    for (int drained = 0; drained < 256 * 1024;)
                    {
                        int read = await client.ReceiveAsync(scratch, SocketFlags.None, cts.Token).ConfigureAwait(false);
                        if (read == 0)
                        {
                            break;
                        }

                        drained += read;
                    }
                }
                catch (SocketException)
                {
                }
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException or IOException)
        {
            // A slow, resetting or vanishing peer: nothing to answer.
        }
        finally
        {
            Leave(address);
        }
    }

    private async Task<(int Status, string? Body, bool HeadOnly)> ReadAndDecideAsync(Socket client, IPAddress address, CancellationToken headToken, CancellationToken ct)
    {
        byte[] buffer = new byte[MaxHeadBytes];
        int filled = 0;
        int end;
        while ((end = FindHeadEnd(buffer, filled)) < 0)
        {
            if (filled == buffer.Length)
            {
                return (431, null, false);
            }

            int read = await client.ReceiveAsync(buffer.AsMemory(filled), SocketFlags.None, headToken).ConfigureAwait(false);
            if (read == 0)
            {
                return (400, null, false);
            }

            filled += read;
        }

        // Request line: METHOD SP TARGET SP HTTP/1.x, ASCII, nothing else is looked at (headers and any body are ignored).
        int lineEnd = Array.IndexOf(buffer, (byte)'\r', 0, end);
        string line = Encoding.ASCII.GetString(buffer, 0, lineEnd < 0 ? end : lineEnd);
        string[] parts = line.Split(' ');
        if (parts.Length != 3 || !(parts[2] is "HTTP/1.1" or "HTTP/1.0"))
        {
            return (400, null, false);
        }

        bool head = parts[0] == "HEAD";
        if (parts[0] != "GET" && !head)
        {
            return (405, null, false);
        }

        string target = parts[1];
        if (!target.StartsWith(PathPrefix, StringComparison.Ordinal) || !Http01Challenges.IsPlausibleToken(target.AsSpan(PathPrefix.Length)))
        {
            if (_log.IsEnabled(MtaLogLevel.Debug))
            {
                _log.Write(MtaLogLevel.Debug, "acme", $"HTTP-01 listener refused a request for {Printable(target)}");
            }

            return (404, null, head);
        }

        string token = target[PathPrefix.Length..];
        string? keyAuthorization;
        try
        {
            keyAuthorization = await _responder.FindKeyAuthorizationAsync(token, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The answer could not be looked up (a bug, a store that failed in an unforeseen way): 503 tells the CA to try again; the listener lives on.
            _log.Write(MtaLogLevel.Warning, "acme", $"HTTP-01 listener: looking up token {token[..8]}... failed ({ex.GetType().Name}: {ex.Message})");
            return (503, null, head);
        }

        if (keyAuthorization is null)
        {
            _log.Write(MtaLogLevel.Debug, "acme", $"HTTP-01 listener: no order waits for token {token[..8]}...");
            return (404, null, head);
        }

        _log.Write(MtaLogLevel.Information, "acme", $"answered the ACME HTTP-01 challenge for token {token[..8]}... ({address})");
        return (200, keyAuthorization, head);
    }

    /// <summary>A request target for a log line: printable ASCII only (nothing a client sent can forge a log line), at most 80 characters.</summary>
    internal static string Printable(string text)
    {
        var builder = new StringBuilder(Math.Min(text.Length, 83));
        foreach (char c in text.Length > 80 ? text[..80] : text)
        {
            builder.Append(c is >= ' ' and <= '~' ? c : '?');
        }

        return text.Length > 80 ? builder.Append("...").ToString() : builder.ToString();
    }

    /// <summary>The index of the first byte after the blank line ending the request head, or -1.</summary>
    private static int FindHeadEnd(byte[] buffer, int length)
    {
        ReadOnlySpan<byte> span = buffer.AsSpan(0, length);
        int index = span.IndexOf("\r\n\r\n"u8);
        return index < 0 ? -1 : index + 4;
    }

    private static async Task SendAsync(Socket client, int status, string? body, bool headOnly, CancellationToken ct)
    {
        string reason = status switch
        {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            405 => "Method Not Allowed",
            503 => "Service Unavailable",
            431 => "Request Header Fields Too Large",
            _ => "Error",
        };
        byte[] content = body is null ? [] : Encoding.ASCII.GetBytes(body);
        string head = $"HTTP/1.1 {status} {reason}\r\nContent-Length: {content.Length}\r\n"
            + (status == 200 ? "Content-Type: application/octet-stream\r\n" : "")
            + (status == 405 ? "Allow: GET, HEAD\r\n" : "")
            + "Cache-Control: no-store\r\nConnection: close\r\n\r\n";
        byte[] headBytes = Encoding.ASCII.GetBytes(head);
        await client.SendAsync(headBytes, SocketFlags.None, ct).ConfigureAwait(false);
        if (!headOnly && content.Length > 0)
        {
            await client.SendAsync(content, SocketFlags.None, ct).ConfigureAwait(false);
        }
    }

    internal void Close()
    {
        lock (_gate)
        {
            _socket?.Dispose();
            _socket = null;
        }
    }

    public ValueTask DisposeAsync()
    {
        _disposed = true;
        Close();
        return default;
    }

    /// <summary>Has <see cref="DisposeAsync"/> run? (The accept loop of a disposed listener ends instead of binding again.)</summary>
    public bool IsDisposed => _disposed;
}
