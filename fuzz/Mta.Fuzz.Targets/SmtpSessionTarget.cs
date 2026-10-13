using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Mta.Core;
using Mta.Smtp.Protocol;
using Mta.Smtp.Server;

namespace Mta.Fuzz;

/// <summary>
/// Server session input: a real <see cref="SmtpServer"/> on loopback, fed the fuzzed bytes over a TCP connection (first byte picks the
/// listener: the open bounce listener or the STARTTLS submission listener), then half-closed. The server must finish the session,
/// close the connection, and every reply it sent must be a well-formed SMTP reply.
/// </summary>
internal static class SmtpSessionTarget
{
    private static readonly Lazy<Fixture> Shared = new(() => new Fixture());

    public static FuzzTarget Create() => new("smtp-session", "SMTP server session over loopback (state machine, DATA/BDAT, AUTH, STARTTLS, limits)", Run, Seeds())
    {
        Tokens = Tokens(),
        MutationIterations = 10000,
        MeasureAllocation = false,
        MaxInputLength = 64 * 1024,
    };

    private static void Run(ReadOnlySpan<byte> input) => CheckReplies(Exchange(input));

    /// <summary>Runs one session and returns everything the server sent.</summary>
    internal static byte[] Exchange(ReadOnlySpan<byte> input)
    {
        var fixture = Shared.Value;
        int port = input.Length > 0 && (input[0] & 1) == 1 ? fixture.SubmissionPort : fixture.OpenPort;
        byte[] payload = input.Length > 1 ? input[1..].ToArray() : [];

        using var tcp = Connect(port);
        var stream = tcp.GetStream();
        var output = new MemoryStream();
        var reader = Task.Run(() =>
        {
            byte[] buffer = new byte[8192];
            try
            {
                int n;
                while ((n = stream.Read(buffer)) > 0)
                {
                    output.Write(buffer, 0, n);
                    if (output.Length > 8 * 1024 * 1024)
                    {
                        throw new FuzzFindingException("the server sent more than 8 MiB in reply to a small input");
                    }
                }
            }
            catch (IOException)
            {
                // reset by the server: it closed the connection, which is fine
            }
        });

        try
        {
            stream.Write(payload);
            tcp.Client.Shutdown(SocketShutdown.Send);
        }
        catch (IOException)
        {
            // the server closed first (a violation answered with 5xx and a hang-up)
        }

        if (!reader.Wait(TimeSpan.FromSeconds(60)))
        {
            throw new FuzzFindingException("the server did not close the connection after the client half-closed it");
        }

        reader.GetAwaiter().GetResult();
        return output.ToArray();
    }

    /// <summary>
    /// Connects, backing off while the machine is out of ephemeral loopback ports (sockets in TIME_WAIT from earlier sessions free up on their own).
    /// This is a limit of the test environment, not of the server, so it is waited out instead of being reported as a finding.
    /// </summary>
    private static TcpClient Connect(int port)
    {
        for (int attempt = 0; ; attempt++)
        {
            // Linger 0: the client resets the connection after the server has closed it, which keeps the number of sockets in TIME_WAIT down.
            var tcp = new TcpClient { NoDelay = true, ReceiveTimeout = 30_000, SendTimeout = 30_000, LingerState = new LingerOption(true, 0) };
            try
            {
                tcp.Connect(IPAddress.Loopback, port);
                return tcp;
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AddressNotAvailable && attempt < 600)
            {
                tcp.Dispose();
                Thread.Sleep(100);
            }
        }
    }

    private static void CheckReplies(byte[] bytes)
    {
        var remaining = new System.Buffers.ReadOnlySequence<byte>(bytes);
        while (!remaining.IsEmpty)
        {
            var status = SmtpReplyParser.TryParse(remaining, out var reply, out var consumed);
            if (status == ReplyParseStatus.NeedMoreData)
            {
                return;
            }

            if (status == ReplyParseStatus.Invalid)
            {
                throw new FuzzFindingException("the server sent something that is not a valid SMTP reply: " + Convert.ToHexString(bytes[..Math.Min(bytes.Length, 120)]));
            }

            // After "Ready to start TLS" the stream is a TLS handshake and no longer SMTP.
            if (reply!.Code == 220 && reply.Lines.Any(l => l.Contains("TLS", StringComparison.OrdinalIgnoreCase)))
            {
                return;
            }

            remaining = remaining.Slice(consumed);
        }
    }

    private static IReadOnlyList<byte[]> Seeds() =>
        new[]
        {
            "\0EHLO fuzz.example\r\nMAIL FROM:<a@example.com> SIZE=100\r\nRCPT TO:<b@example.net>\r\nDATA\r\nSubject: t\r\n\r\nbody\r\n.\r\nQUIT\r\n",
            "\0HELO x\r\nMAIL FROM:<>\r\nRCPT TO:<b+token@bounce.example.com>\r\nDATA\r\nFrom: MAILER-DAEMON@x\r\n\r\n.hidden\r\n..dot\r\n.\r\n",
            "\0EHLO x\r\nMAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nBDAT 5\r\nhelloBDAT 3 LAST\r\nabc",
            "\u0001EHLO x\r\nSTARTTLS\r\nEHLO injected\r\n",
            "\u0001EHLO x\r\nAUTH PLAIN AHVzZXIAcGFzcw==\r\nAUTH LOGIN\r\ndXNlcg==\r\ncGFzcw==\r\nAUTH CRAM-MD5\r\n",
            "\0EHLO x\r\nMAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nDATA\r\nline\nbare lf\r\n.\r\nMAIL FROM:<smuggled@x>\r\n",
            "\0EHLO x\r\nMAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nDATA\r\nx\r\n.\n\r\nRSET\r\n",
            "\0\r\r\n\n\n\0\0NOOP\r\nVRFY a\r\nEXPN b\r\nHELP\r\nRSET\r\nQUIT\r\n",
        }.Select(s => Encoding.Latin1.GetBytes(s)).ToList();

    private static IReadOnlyList<byte[]> Tokens() =>
        new[]
        {
            "EHLO ", "HELO ", "MAIL FROM:<", "RCPT TO:<", "DATA\r\n", "BDAT ", " LAST", "RSET\r\n", "QUIT\r\n", "STARTTLS\r\n", "AUTH PLAIN ", "AUTH LOGIN\r\n", "\r\n.\r\n", "\n.\n", "\r\n.\n", "\n.\r\n",
            " SIZE=", " BODY=8BITMIME", " SMTPUTF8", " NOTIFY=", ">", "\r\n", "\r", "\n", "\0", "..", "=",
        }.Select(s => Encoding.Latin1.GetBytes(s)).ToList();

    private sealed class Fixture
    {
        public Fixture()
        {
            var options = new SmtpServerOptions
            {
                Hostname = "mx.fuzz.test",
                Certificates = new Certificates(),
                AuthFailureDelay = TimeSpan.Zero,
                GreetingTimeout = TimeSpan.FromSeconds(3),
                CommandTimeout = TimeSpan.FromSeconds(3),
                DataTimeout = TimeSpan.FromSeconds(3),
                TlsHandshakeTimeout = TimeSpan.FromSeconds(3),
                MaxMessageSize = 64 * 1024,
                MaxConnectionsPerIp = 10_000,
                MaxConnections = 10_000,
                Listeners =
                [
                    new SmtpListenerOptions { Name = "submission", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.StartTls, AuthRequired = true },
                    new SmtpListenerOptions { Name = "open", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.Plain, AuthRequired = false, Role = ListenerRole.Bounce },
                ],
            };
            Server = new SmtpServer(options, new AcceptingHandler());
            Server.Start();
            SubmissionPort = Server.LocalEndPoints["submission"].Port;
            OpenPort = Server.LocalEndPoints["open"].Port;
        }

        public SmtpServer Server { get; }

        public int SubmissionPort { get; }

        public int OpenPort { get; }
    }

    private sealed class Certificates : IServerCertificateProvider
    {
        private readonly X509Certificate2 _cert;

        public Certificates()
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var temp = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
            _cert = X509CertificateLoader.LoadPkcs12(temp.Export(X509ContentType.Pfx, "x"), "x", X509KeyStorageFlags.Exportable);
        }

        public X509Certificate2? GetCertificate(string? serverName) => _cert;
    }

    private sealed class AcceptingHandler : ISmtpServerHandler
    {
        public ValueTask<SmtpReply?> OnConnectedAsync(SmtpSessionContext session, CancellationToken cancellationToken) => ValueTask.FromResult<SmtpReply?>(null);

        public ValueTask<SmtpAuthResult> AuthenticateAsync(SmtpSessionContext session, string authorizationId, string userName, string password, CancellationToken cancellationToken) =>
            ValueTask.FromResult(userName == "user" && password == "pass" ? SmtpAuthResult.Succeeded(userName) : SmtpAuthResult.Failed);

        public ValueTask<SmtpReply> OnMailFromAsync(SmtpSessionContext session, MailFromInfo mail, CancellationToken cancellationToken) => ValueTask.FromResult(SmtpReplies.SenderOk);

        public ValueTask<SmtpReply> OnRcptToAsync(SmtpSessionContext session, MailFromInfo mail, EmailAddress recipient, RcptParameters parameters, CancellationToken cancellationToken) =>
            ValueTask.FromResult(SmtpReplies.RecipientOk);

        public ValueTask<SmtpReply> OnMessageAsync(SmtpMessage message, CancellationToken cancellationToken) =>
            ValueTask.FromResult(SmtpReply.Create(250, "2.0.0", "Queued"));

        public void OnDisconnected(SmtpSessionContext session)
        {
        }
    }
}
