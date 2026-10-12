using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Mta.Core;
using Mta.Smtp.Protocol;
using Mta.Smtp.Server;

namespace Mta.Tools;

internal static class SinkCommand
{
    public static async Task<int> RunAsync(ArgParser args, CancellationToken ct)
    {
        int port = args.GetInt("port", 2525);
        var bind = IPAddress.Parse(args.Get("bind") ?? "127.0.0.1");
        int delayMs = args.GetInt("delay-ms", 0);
        long maxSize = args.GetInt("max-size-mb", 25) * 1024L * 1024;
        bool tls = args.Flag("tls");

        var handler = new SinkHandler(TimeSpan.FromMilliseconds(delayMs));
        var options = new SmtpServerOptions
        {
            Hostname = "sink.local",
            MaxMessageSize = maxSize,
            MaxConnections = 100_000,
            MaxConnectionsPerIp = 100_000,
            MaxMessagesPerSession = int.MaxValue,
            Certificates = tls ? new SelfSignedCertificates() : null,
            Listeners = [new SmtpListenerOptions { Name = "sink", BindAddress = bind, Port = port, Mode = tls ? ListenerMode.StartTls : ListenerMode.Plain, AuthRequired = false, Role = ListenerRole.Bounce }],
        };
        await using var server = new SmtpServer(options, handler);
        server.Start();
        Console.WriteLine($"sink listening on {bind}:{server.LocalEndPoints["sink"].Port} (delay {delayMs} ms, tls={tls})");

        long last = 0;
        var lastTime = Environment.TickCount64;
        while (!ct.IsCancellationRequested)
        {
            try { await Task.Delay(2000, ct); } catch (OperationCanceledException) { break; }
            long now = Interlocked.Read(ref handler.Count);
            long t = Environment.TickCount64;
            Console.WriteLine($"{DateTime.UtcNow:HH:mm:ss} total={now} rate={(now - last) * 1000.0 / Math.Max(1, t - lastTime):F0} msg/s");
            last = now;
            lastTime = t;
        }

        return 0;
    }

    private sealed class SinkHandler(TimeSpan delay) : ISmtpServerHandler
    {
        public long Count;

        public ValueTask<SmtpReply?> OnConnectedAsync(SmtpSessionContext session, CancellationToken ct) => ValueTask.FromResult<SmtpReply?>(null);

        public ValueTask<SmtpAuthResult> AuthenticateAsync(SmtpSessionContext session, string authorizationId, string userName, string password, CancellationToken ct) =>
            ValueTask.FromResult(SmtpAuthResult.Failed);

        public ValueTask<SmtpReply> OnMailFromAsync(SmtpSessionContext session, MailFromInfo mail, CancellationToken ct) => ValueTask.FromResult(SmtpReplies.SenderOk);

        public ValueTask<SmtpReply> OnRcptToAsync(SmtpSessionContext session, MailFromInfo mail, EmailAddress recipient, RcptParameters p, CancellationToken ct) =>
            ValueTask.FromResult(SmtpReplies.RecipientOk);

        public async ValueTask<SmtpReply> OnMessageAsync(SmtpMessage message, CancellationToken ct)
        {
            if (delay > TimeSpan.Zero)
            {
                await Task.Delay(delay, ct).ConfigureAwait(false);
            }

            Interlocked.Increment(ref Count);
            return SmtpReply.Create(250, "2.0.0", "OK");
        }

        public void OnDisconnected(SmtpSessionContext session)
        {
        }
    }

    private sealed class SelfSignedCertificates : IServerCertificateProvider
    {
        private readonly X509Certificate2 _cert;

        public SelfSignedCertificates()
        {
            using var rsa = RSA.Create(2048);
            var req = new CertificateRequest("CN=sink.local", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var tmp = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
            _cert = X509CertificateLoader.LoadPkcs12(tmp.Export(X509ContentType.Pfx, "x"), "x");
        }

        public X509Certificate2? GetCertificate(string? serverName) => _cert;
    }
}
