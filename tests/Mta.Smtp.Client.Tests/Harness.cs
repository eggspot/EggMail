using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Mta.Core;
using Mta.Smtp.Protocol;
using Mta.Smtp.Server;

namespace Mta.Smtp.Client.Tests;

internal sealed class TestCerts : IServerCertificateProvider
{
    public static readonly TestCerts Instance = new();
    private readonly X509Certificate2 _cert;

    private TestCerts()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        req.CertificateExtensions.Add(san.Build());
        using var temp = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        _cert = X509CertificateLoader.LoadPkcs12(temp.Export(X509ContentType.Pfx, "x"), "x", X509KeyStorageFlags.Exportable);
    }

    public X509Certificate2? GetCertificate(string? serverName) => _cert;
}

internal sealed class CapturingHandler : ISmtpServerHandler
{
    public List<(EmailAddress From, string[] To, byte[] Body, MailParameters Parameters)> Messages { get; } = [];
    public int Connections;
    public Func<EmailAddress, SmtpReply?>? RcptPolicy { get; set; }
    public Func<SmtpReply>? MessageReply { get; set; }

    public ValueTask<SmtpReply?> OnConnectedAsync(SmtpSessionContext session, CancellationToken ct)
    {
        Interlocked.Increment(ref Connections);
        return ValueTask.FromResult<SmtpReply?>(null);
    }

    public ValueTask<SmtpAuthResult> AuthenticateAsync(SmtpSessionContext session, string authorizationId, string userName, string password, CancellationToken ct) =>
        ValueTask.FromResult(userName == "relay" && password == "secret" ? SmtpAuthResult.Succeeded(userName) : SmtpAuthResult.Failed);

    public ValueTask<SmtpReply> OnMailFromAsync(SmtpSessionContext session, MailFromInfo mail, CancellationToken ct) => ValueTask.FromResult(SmtpReplies.SenderOk);

    public ValueTask<SmtpReply> OnRcptToAsync(SmtpSessionContext session, MailFromInfo mail, EmailAddress recipient, RcptParameters p, CancellationToken ct) =>
        ValueTask.FromResult(RcptPolicy?.Invoke(recipient) ?? SmtpReplies.RecipientOk);

    public ValueTask<SmtpReply> OnMessageAsync(SmtpMessage message, CancellationToken ct)
    {
        lock (Messages)
        {
            Messages.Add((message.Sender, message.Recipients.Select(r => r.ToString()).ToArray(), message.Body.ToArray(), message.Parameters));
        }

        return ValueTask.FromResult(MessageReply?.Invoke() ?? SmtpReply.Create(250, "2.0.0", "Queued"));
    }

    public void OnDisconnected(SmtpSessionContext session)
    {
    }
}

internal sealed class RealServer : IAsyncDisposable
{
    public SmtpServer Server { get; }
    public CapturingHandler Handler { get; }
    public int PlainPort { get; }
    public int ImplicitPort { get; }

    public RealServer(Func<SmtpServerOptions, SmtpServerOptions>? tweak = null)
    {
        Handler = new CapturingHandler();
        var options = new SmtpServerOptions
        {
            Hostname = "mx.remote.test",
            Certificates = TestCerts.Instance,
            AuthFailureDelay = TimeSpan.Zero,
            Listeners =
            [
                new SmtpListenerOptions { Name = "mx", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.StartTls, AuthRequired = false, Role = ListenerRole.Bounce },
                new SmtpListenerOptions { Name = "smtps", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.Implicit, AuthRequired = true },
            ],
        };
        if (tweak is not null) { options = tweak(options); }
        Server = new SmtpServer(options, Handler);
        Server.Start();
        PlainPort = Server.LocalEndPoints["mx"].Port;
        ImplicitPort = Server.LocalEndPoints["smtps"].Port;
    }

    public SmtpRemoteTarget Target(SmtpTlsPolicy? tls = null, SmtpCredentials? cred = null, bool implicitTls = false) => new()
    {
        Host = "localhost",
        Address = IPAddress.Loopback,
        Port = implicitTls ? ImplicitPort : PlainPort,
        Tls = tls ?? SmtpTlsPolicy.Opportunistic,
        Credentials = cred,
    };

    public ValueTask DisposeAsync() => Server.DisposeAsync();
}

/// <summary>A scripted one-connection-at-a-time SMTP peer for edge cases the real server never produces.</summary>
internal sealed class ScriptedServer : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public ScriptedServer(Func<ScriptedConnection, Task> script)
    {
        _listener.Start();
        _loop = Task.Run(async () =>
        {
            while (!_cts.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await _listener.AcceptTcpClientAsync(_cts.Token); }
                catch (OperationCanceledException) { return; }
                _ = Task.Run(async () =>
                {
                    using (client)
                    {
                        try { await script(new ScriptedConnection(client)); }
                        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException or OperationCanceledException) { }
                    }
                });
            }
        });
    }

    public SmtpRemoteTarget Target(SmtpTlsPolicy? tls = null) => new() { Host = "scripted.test", Address = IPAddress.Loopback, Port = Port, Tls = tls ?? SmtpTlsPolicy.Opportunistic };

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        _listener.Stop();
        await _loop;
    }
}

internal sealed class ScriptedConnection(TcpClient client)
{
    private readonly NetworkStream _s = client.GetStream();
    private readonly List<byte> _buf = [];

    public Task SendAsync(string text) => _s.WriteAsync(Encoding.UTF8.GetBytes(text)).AsTask();

    public async Task<string> ReadLineAsync()
    {
        byte[] one = new byte[1];
        while (true)
        {
            int idx = _buf.IndexOf((byte)'\n');
            if (idx >= 0)
            {
                string line = Encoding.UTF8.GetString(_buf.GetRange(0, idx).ToArray()).TrimEnd('\r');
                _buf.RemoveRange(0, idx + 1);
                return line;
            }

            byte[] chunk = new byte[1024];
            int n = await _s.ReadAsync(chunk);
            if (n == 0) { throw new IOException("eof"); }
            _buf.AddRange(chunk.AsSpan(0, n).ToArray());
            _ = one;
        }
    }

    /// <summary>Reads data lines until the lone dot; returns them.</summary>
    public async Task<List<string>> ReadDataAsync()
    {
        var lines = new List<string>();
        while (true)
        {
            string l = await ReadLineAsync();
            if (l == ".") { return lines; }
            lines.Add(l);
        }
    }

    /// <summary>Reads exactly <paramref name="count"/> bytes (a BDAT chunk), including any already buffered.</summary>
    public async Task ReadBytesAsync(int count)
    {
        while (_buf.Count < count)
        {
            byte[] chunk = new byte[4096];
            int n = await _s.ReadAsync(chunk);
            if (n == 0) { throw new IOException("eof"); }
            _buf.AddRange(chunk.AsSpan(0, n).ToArray());
        }

        _buf.RemoveRange(0, count);
    }

    public void Abort() => client.Client.Close(0);

    public async Task HoldOpenAsync(int ms) => await Task.Delay(ms);
}
