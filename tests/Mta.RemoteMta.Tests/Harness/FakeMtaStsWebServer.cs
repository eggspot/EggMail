using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Mta.RemoteMta.Tests.Harness;

/// <summary>What the fake <c>mta-sts.&lt;domain&gt;</c> web server answers.</summary>
public sealed record WebAnswer(int Status, string ContentType, string Body, string? Location = null, bool Silent = false)
{
    public static WebAnswer Policy(string mode, string[] mx, int maxAge = 86_400) =>
        new(200, "text/plain", "version: STSv1\r\nmode: " + mode + "\r\n" + string.Concat(mx.Select(m => "mx: " + m + "\r\n")) + "max_age: " + maxAge + "\r\n");

    public static WebAnswer Raw(string body, string contentType = "text/plain") => new(200, contentType, body);

    public static WebAnswer NotFound { get; } = new(404, "text/plain", "not found");

    public static WebAnswer RedirectTo(string url) => new(301, "text/plain", string.Empty, url);

    /// <summary>Accepts the request and never answers.</summary>
    public static WebAnswer Hang { get; } = new(0, string.Empty, string.Empty, Silent: true);
}

/// <summary>
/// The HTTPS side of MTA-STS: a loopback TLS web server that answers <c>GET /.well-known/mta-sts.txt</c> for any <c>mta-sts.*</c> host from a script,
/// plus the <see cref="HttpMessageHandler"/> that lets the real <c>MtaStsPolicyFetcher</c> reach it (every host name is connected to this server, and the
/// certificate is validated with the platform's chain and name checks against a private root, so a wrong-name, expired or untrusted certificate fails like it would on the Internet).
/// </summary>
public sealed class FakeMtaStsWebServer : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _loop;
    private readonly ConcurrentQueue<string> _hosts = new();
    public FakeMtaStsWebServer(Func<string?, X509Certificate2> certificateFor)
    {
        CertificateFor = certificateFor;
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _loop = Task.Run(AcceptLoopAsync);
    }

    public int Port { get; }

    /// <summary>The script: host name from the request (for example <c>mta-sts.dest.example</c>) to the answer. Default: 404.</summary>
    public Func<string, WebAnswer> Respond { get; set; } = _ => WebAnswer.NotFound;

    /// <summary>The certificate presented for a requested server name (SNI); replaceable to model a rotated, expired, wrong-name or untrusted certificate.</summary>
    public Func<string?, X509Certificate2> CertificateFor { get; set; }

    /// <summary>The <c>Host</c> of every request received, in order.</summary>
    public IReadOnlyList<string> RequestedHosts => _hosts.ToArray();

    public int Requests => _hosts.Count;

    /// <summary>TCP connections accepted, including those whose TLS handshake the client rejected (these never become a request).</summary>
    public int Connections => Volatile.Read(ref _connections);

    private int _connections;

    /// <summary>A handler for <c>MtaStsPolicyFetcher</c> that connects every host name to this server and validates the certificate against <paramref name="trustedRoot"/>.</summary>
    public HttpMessageHandler CreateHandler(X509Certificate2 trustedRoot)
    {
        var policy = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust, RevocationMode = X509RevocationMode.NoCheck };
        policy.CustomTrustStore.Add(trustedRoot);
        return new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            ConnectCallback = async (_, ct) =>
            {
                var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try
                {
                    await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, Port), ct).ConfigureAwait(false);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            },
            SslOptions = new SslClientAuthenticationOptions { CertificateChainPolicy = policy },
        };
    }

    private async Task AcceptLoopAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            Socket socket;
            try
            {
                socket = await _listener.AcceptSocketAsync(_stop.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }

            Interlocked.Increment(ref _connections);
            _ = Task.Run(() => ServeAsync(socket));
        }
    }

    private async Task ServeAsync(Socket socket)
    {
        try
        {
            using (socket)
            await using (var network = new NetworkStream(socket, ownsSocket: false))
            await using (var ssl = new SslStream(network))
            {
                await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificateSelectionCallback = (_, sni) => CertificateFor(sni) }, _stop.Token).ConfigureAwait(false);
                var head = new StringBuilder();
                var one = new byte[1];
                while (!head.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal))
                {
                    if (await ssl.ReadAsync(one, _stop.Token).ConfigureAwait(false) == 0)
                    {
                        return;
                    }

                    head.Append((char)one[0]);
                    if (head.Length > 16_384)
                    {
                        return;
                    }
                }

                string host = head.ToString().Split("\r\n").Select(l => l.Split(':', 2)).Where(p => p.Length == 2 && p[0].Equals("Host", StringComparison.OrdinalIgnoreCase)).Select(p => p[1].Trim()).FirstOrDefault() ?? string.Empty;
                _hosts.Enqueue(host);
                var answer = Respond(host);
                if (answer.Silent)
                {
                    await Task.Delay(Timeout.Infinite, _stop.Token).ConfigureAwait(false);
                    return;
                }

                byte[] body = Encoding.UTF8.GetBytes(answer.Body);
                var response = new StringBuilder();
                response.Append("HTTP/1.1 ").Append(answer.Status).Append(' ').Append(answer.Status == 200 ? "OK" : "Status").Append("\r\n");
                response.Append("Content-Type: ").Append(answer.ContentType).Append("\r\n");
                if (answer.Location is not null)
                {
                    response.Append("Location: ").Append(answer.Location).Append("\r\n");
                }

                response.Append("Content-Length: ").Append(body.Length).Append("\r\nConnection: close\r\n\r\n");
                await ssl.WriteAsync(Encoding.ASCII.GetBytes(response.ToString()), _stop.Token).ConfigureAwait(false);
                await ssl.WriteAsync(body, _stop.Token).ConfigureAwait(false);
                await ssl.FlushAsync(_stop.Token).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException or OperationCanceledException or System.Security.Authentication.AuthenticationException)
        {
            // a client that rejected the certificate or gave up
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync().ConfigureAwait(false);
        _listener.Stop();
        try
        {
            await _loop.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }

        _stop.Dispose();
    }
}
