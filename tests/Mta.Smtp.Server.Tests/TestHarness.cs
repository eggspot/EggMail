using System.Buffers;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Mta.Core;
using Mta.Smtp.Protocol;
using Mta.Smtp.Server;

namespace Mta.Smtp.Server.Tests;

internal sealed class TestCertificates : IServerCertificateProvider
{
    public static readonly TestCertificates Instance = new();

    private readonly X509Certificate2 _cert;

    private TestCertificates()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        san.AddIpAddress(IPAddress.Loopback);
        req.CertificateExtensions.Add(san.Build());
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        using var temp = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        // Re-import so the private key is persisted in a form SslStream accepts on every platform.
        _cert = X509CertificateLoader.LoadPkcs12(temp.Export(X509ContentType.Pfx, "x"), "x", X509KeyStorageFlags.Exportable);
    }

    public X509Certificate2? GetCertificate(string? serverName) => _cert;
}

internal sealed class RecordingHandler : ISmtpServerHandler
{
    public List<ReceivedMessage> Messages { get; } = [];
    public List<string> RejectedRecipients { get; } = [];
    public Func<SmtpMessage, SmtpReply>? OnMessage { get; set; }
    public bool AuthSucceeds { get; set; } = true;
    public string ValidUser { get; set; } = "user";
    public string ValidPassword { get; set; } = "pass";
    public SmtpReply? ConnectRefusal { get; set; }
    public int Disconnects;

    public record ReceivedMessage(EmailAddress Sender, string[] Recipients, byte[] Body, byte[] Received, string? User, bool Tls, MailParameters Parameters);

    public ValueTask<SmtpReply?> OnConnectedAsync(SmtpSessionContext session, CancellationToken ct) => ValueTask.FromResult(ConnectRefusal);

    public ValueTask<SmtpAuthResult> AuthenticateAsync(SmtpSessionContext session, string authorizationId, string userName, string password, CancellationToken ct) =>
        ValueTask.FromResult(userName == ValidUser && password == ValidPassword && AuthSucceeds ? SmtpAuthResult.Succeeded(userName) : SmtpAuthResult.Failed);

    public ValueTask<SmtpReply> OnMailFromAsync(SmtpSessionContext session, MailFromInfo mail, CancellationToken ct) => ValueTask.FromResult(SmtpReplies.SenderOk);

    public ValueTask<SmtpReply> OnRcptToAsync(SmtpSessionContext session, MailFromInfo mail, EmailAddress recipient, RcptParameters p, CancellationToken ct)
    {
        if (recipient.LocalPart == "reject")
        {
            RejectedRecipients.Add(recipient.ToString());
            return ValueTask.FromResult(SmtpReply.Create(550, "5.1.1", "No such user"));
        }

        return ValueTask.FromResult(SmtpReplies.RecipientOk);
    }

    public ValueTask<SmtpReply> OnMessageAsync(SmtpMessage message, CancellationToken ct)
    {
        if (OnMessage is not null)
        {
            return ValueTask.FromResult(OnMessage(message));
        }

        lock (Messages)
        {
            Messages.Add(new ReceivedMessage(message.Sender, message.Recipients.Select(r => r.ToString()).ToArray(), message.Body.ToArray(),
                message.ReceivedHeader.ToArray(), message.Session.AuthenticatedUser, message.Session.TlsActive, message.Parameters));
        }

        return ValueTask.FromResult(SmtpReply.Create(250, "2.0.0", "Queued as TEST"));
    }

    public void OnDisconnected(SmtpSessionContext session) => Interlocked.Increment(ref Disconnects);
}

internal sealed class ServerFixture : IAsyncDisposable
{
    public SmtpServer Server { get; }
    public RecordingHandler Handler { get; }
    public int PlainPort { get; }
    public int ImplicitPort { get; }
    public int OpenPort { get; }

    public ServerFixture(Func<SmtpServerOptions, SmtpServerOptions>? tweak = null, RecordingHandler? handler = null)
    {
        Handler = handler ?? new RecordingHandler();
        var options = new SmtpServerOptions
        {
            Hostname = "mx.test",
            Certificates = TestCertificates.Instance,
            AuthFailureDelay = TimeSpan.Zero,
            Listeners =
            [
                new SmtpListenerOptions { Name = "submission", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.StartTls, AuthRequired = true },
                new SmtpListenerOptions { Name = "smtps", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.Implicit, AuthRequired = true },
                new SmtpListenerOptions { Name = "open", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.Plain, AuthRequired = false, Role = ListenerRole.Bounce },
            ],
        };
        if (tweak is not null)
        {
            options = tweak(options);
        }

        Server = new SmtpServer(options, Handler);
        Server.Start();
        PlainPort = Server.LocalEndPoints["submission"].Port;
        ImplicitPort = Server.LocalEndPoints["smtps"].Port;
        OpenPort = Server.LocalEndPoints["open"].Port;
    }

    public ValueTask DisposeAsync() => Server.DisposeAsync();
}

/// <summary>A tiny raw SMTP client for protocol-level tests (sends exactly the bytes we tell it to).</summary>
internal sealed class RawClient : IDisposable
{
    private readonly TcpClient _tcp = new();
    private Stream _stream = null!;
    private readonly List<byte> _pending = [];

    public static async Task<RawClient> ConnectAsync(int port)
    {
        var c = new RawClient();
        await c._tcp.ConnectAsync(IPAddress.Loopback, port);
        c._stream = c._tcp.GetStream();
        return c;
    }

    public async Task StartTlsHandshakeAsync()
    {
        var ssl = new SslStream(_tcp.GetStream(), false, (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync("localhost");
        _stream = ssl;
        _pending.Clear();
    }

    public SslStream? Ssl => _stream as SslStream;

    public Task SendAsync(string text) => SendBytesAsync(Encoding.UTF8.GetBytes(text));

    public async Task SendBytesAsync(byte[] data)
    {
        await _stream.WriteAsync(data);
        await _stream.FlushAsync();
    }

    public Task SendLineAsync(string line) => SendAsync(line + "\r\n");

    /// <summary>Reads one complete reply (possibly multi-line). Returns null if the connection closed first.</summary>
    public async Task<SmtpReply?> ReadReplyAsync(int timeoutMs = 30_000)
    {
        using var cts = new CancellationTokenSource(timeoutMs);
        byte[] buf = new byte[4096];
        while (true)
        {
            var seq = new ReadOnlySequence<byte>(_pending.ToArray());
            var st = SmtpReplyParser.TryParse(seq, out var reply, out var consumed);
            if (st == ReplyParseStatus.Ok)
            {
                _pending.RemoveRange(0, (int)seq.Slice(0, consumed).Length);
                return reply;
            }

            if (st == ReplyParseStatus.Invalid)
            {
                throw new InvalidOperationException("Server sent invalid reply: " + Encoding.UTF8.GetString(_pending.ToArray()));
            }

            int n;
            try
            {
                n = await _stream.ReadAsync(buf, cts.Token);
            }
            catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
            {
                return null;
            }

            if (n == 0)
            {
                return null;
            }

            _pending.AddRange(buf.AsSpan(0, n).ToArray());
        }
    }

    public async Task<SmtpReply> ExpectAsync(int code)
    {
        var r = await ReadReplyAsync();
        Assert.NotNull(r);
        Assert.Equal(code, r!.Code);
        return r;
    }

    public async Task<SmtpReply> CommandAsync(string line, int expectCode)
    {
        await SendLineAsync(line);
        return await ExpectAsync(expectCode);
    }

    /// <summary>True when the server closed the connection (EOF) within the timeout.</summary>
    public async Task<bool> WaitForCloseAsync(int timeoutMs = 30_000)
    {
        using var cts = new CancellationTokenSource(timeoutMs);
        byte[] buf = new byte[256];
        try
        {
            while (true)
            {
                int n = await _stream.ReadAsync(buf, cts.Token);
                if (n == 0) { return true; }
            }
        }
        catch (OperationCanceledException)
        {
            return false;
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
        {
            return true;
        }
    }

    public void Dispose() => _tcp.Dispose();
}
