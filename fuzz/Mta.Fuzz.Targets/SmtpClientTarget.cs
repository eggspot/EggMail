using System.Net;
using System.Net.Sockets;
using System.Text;
using Mta.Core;
using Mta.Smtp.Client;

namespace Mta.Fuzz;

/// <summary>
/// The outbound SMTP client against a hostile receiving server: a loopback listener answers with the fuzzed bytes (all of them at once,
/// then a half-close) while the real <see cref="SmtpClientConnection"/> connects, negotiates (banner, EHLO, capabilities, STARTTLS when
/// offered), sends one message to two recipients and quits. The first byte picks the client options (pipelining, chunking, TLS mode, the
/// SMTPUTF8 and 8BITMIME flags of the envelope); the rest is what the server says.
/// <para>Invariants: the only exceptions are the client's documented ones (<see cref="SmtpClientException"/> and its subclasses), never a
/// timeout of the harness; a send result is consistent (no more recipient results than recipients, delivered only after a positive final
/// reply with at least one accepted recipient).</para>
/// </summary>
internal static class SmtpClientTarget
{
    private static readonly Lazy<Fixture> Shared = new(() => new Fixture());
    private static readonly byte[] Message = Encoding.ASCII.GetBytes("From: a@example.com\r\nTo: b@example.net\r\nSubject: fuzz\r\n\r\nline one\r\n.leading dot\r\n");

    public static FuzzTarget Create() => new("smtp-client", "SMTP client against a hostile server (reply parsing, capabilities, pipelining, DATA/BDAT, STARTTLS)", Run, Seeds())
    {
        Tokens = Tokens(),
        MutationIterations = 4000,
        MeasureAllocation = false,
        MaxInputLength = 32 * 1024,
    };

    private static void Run(ReadOnlySpan<byte> input) => Exchange(input);

    /// <summary>Runs one exchange and returns how the client ended (<c>delivered</c>, <c>not delivered</c> or the exception type) and what it sent.</summary>
    internal static (string Outcome, byte[] ClientBytes) Exchange(ReadOnlySpan<byte> input)
    {
        byte flags = input.Length > 0 ? input[0] : (byte)0;
        byte[] script = input.Length > 1 ? input[1..].ToArray() : [];
        var fixture = Shared.Value;
        var server = fixture.Serve(script);

        var options = new SmtpClientOptions
        {
            HeloName = "client.example.com",
            Pipelining = (flags & 1) == 0,
            PreferChunking = (flags & 2) != 0,
            BdatChunkSize = 16,
            ConnectTimeout = TimeSpan.FromSeconds(30),
            BannerTimeout = TimeSpan.FromSeconds(30),
            CommandTimeout = TimeSpan.FromSeconds(30),
            DataInitiationTimeout = TimeSpan.FromSeconds(30),
            DataBlockTimeout = TimeSpan.FromSeconds(30),
            EndOfDataTimeout = TimeSpan.FromSeconds(30),
            TlsHandshakeTimeout = TimeSpan.FromSeconds(30),
        };
        var target = new SmtpRemoteTarget
        {
            Host = "mx.example.net",
            Address = IPAddress.Loopback,
            Port = fixture.Port,
            Tls = (flags & 4) != 0 ? new SmtpTlsPolicy { Mode = SmtpTlsMode.StartTls, Require = (flags & 8) != 0 } : SmtpTlsPolicy.Disabled,
        };
        var envelope = new SmtpEnvelope(
            EmailAddress.Parse("a@example.com"),
            [EmailAddress.Parse("b@example.net"), EmailAddress.Parse("c@example.net")],
            SmtpUtf8: (flags & 16) != 0,
            EightBit: (flags & 32) != 0);

        // A connect that fails never reached the server (out of ephemeral loopback ports after a long run, as the session target sees):
        // an environment limit, waited out like there, with the same server task still waiting for the connection.
        for (int attempt = 0; ; attempt++)
        {
            var (outcome, connected) = RunClient(target, options, envelope);
            if (connected)
            {
                if (!server.Wait(TimeSpan.FromSeconds(30)))
                {
                    throw new FuzzFindingException("the client kept the connection open after it finished");
                }

                return (outcome, server.Result);
            }

            if (attempt >= 600)
            {
                throw new FuzzFindingException("the client could not connect to the loopback server for a minute: " + outcome);
            }

            Thread.Sleep(100);
        }
    }

    private static (string Outcome, bool Connected) RunClient(SmtpRemoteTarget target, SmtpClientOptions options, SmtpEnvelope envelope)
    {
        var client = Task.Run(async () =>
        {
            try
            {
                await using var connection = await SmtpClientConnection.ConnectAsync(target, options);
                var result = await connection.SendAsync(envelope, Message);
                Check(result, envelope);
                if (connection.IsReusable)
                {
                    await connection.ResetAsync();
                    await connection.QuitAsync();
                }

                return (result.Delivered ? "delivered" : "not delivered", true);
            }
            catch (SmtpConnectionException ex) when (ex.Stage == SmtpStage.Connect)
            {
                return (ex.Message, false);
            }
            catch (SmtpClientException ex)
            {
                // The documented way for the client to give up on a server.
                return (ex.GetType().Name, true);
            }
        });

        if (!client.Wait(TimeSpan.FromSeconds(120)))
        {
            throw new FuzzFindingException("the client did not finish although the server had closed its side");
        }

        return client.GetAwaiter().GetResult();
    }

    private static void Check(SmtpSendResult result, SmtpEnvelope envelope)
    {
        Guard.Check(Enum.IsDefined(result.LocalFailure), "undefined local failure");
        Guard.Check(Enum.IsDefined(result.Stage), "undefined stage");
        Guard.Check(result.Recipients.Count <= envelope.Recipients.Count, "more recipient results than recipients");
        if (result.Delivered)
        {
            Guard.Check(result.LocalFailure == LocalFailure.None, "delivered with a local failure");
            Guard.Check(result.Recipients.Any(r => r.Accepted), "delivered without an accepted recipient");
            Guard.Check(result.EndOfDataSent, "delivered without sending the end of the data");
        }

        foreach (var reply in new[] { result.SenderRejection, result.DataRejection, result.FinalReply }.Concat(result.Recipients.Select(r => r.Reply)))
        {
            if (reply is not null)
            {
                Guard.Check(reply.Code is >= 200 and <= 599, $"reply code {reply.Code} outside 200..599");
                Guard.Check(reply.Lines.All(l => !l.Contains('\r') && !l.Contains('\n')), "a reply line with CR or LF in it");
            }
        }
    }

    private static IReadOnlyList<byte[]> Seeds() =>
        new[]
        {
            "\u0000220 mx.example.net ESMTP\r\n250-mx.example.net\r\n250-PIPELINING\r\n250-SIZE 1000000\r\n250-8BITMIME\r\n250 ENHANCEDSTATUSCODES\r\n250 2.1.0 OK\r\n250 2.1.5 OK\r\n550 5.1.1 No such user\r\n354 Go ahead\r\n250 2.0.0 Queued as 1\r\n250 2.0.0 Reset\r\n221 2.0.0 Bye\r\n",
            "\u0001220 mx.example.net\r\n250 mx.example.net\r\n250 OK\r\n250 OK\r\n250 OK\r\n354 Go\r\n250 OK\r\n",
            "\u0002220 mx ESMTP\r\n250-mx\r\n250-CHUNKING\r\n250 PIPELINING\r\n250 OK\r\n250 OK\r\n250 OK\r\n250 2.0.0 chunk\r\n250 2.0.0 chunk\r\n250 2.0.0 chunk\r\n250 2.0.0 chunk\r\n250 2.0.0 done\r\n",
            "\u0004220 mx ESMTP\r\n250-mx\r\n250 STARTTLS\r\n220 2.0.0 Ready to start TLS\r\n\u0016\u0003\u0001\u0000\u0005hello",
            "\u000c220 mx ESMTP\r\n250 mx\r\n",
            "\u0000554 5.7.1 Go away\r\n",
            "\u0000220-first\r\n220-second\r\n220 third\r\n250-mx\r\n250-SIZE 10\r\n250 OK\r\n",
            "\u0000220 mx\r\n250-mx\r\n250 PIPELINING\r\n421 4.3.2 Shutting down\r\n",
            "\u0010220 mx\r\n250-mx\r\n250 SMTPUTF8\r\n",
            "\u0000220 mx\r\n250 mx\r\n250 OK\r\n250 OK\r\n250 OK\r\n354 Go\r\n",
            "\u0000220 mx\n250 mx\n2501 OK\r\n25\r\n999 x\r\n250-\r\n250\r\n",
            "\u0000",
        }.Select(s => Encoding.Latin1.GetBytes(s)).ToList();

    private static IReadOnlyList<byte[]> Tokens() =>
        new[]
        {
            "220 ", "220-", "250 ", "250-", "354 ", "421 ", "451 ", "550 ", "221 ", "\r\n", "\n", "PIPELINING", "CHUNKING", "STARTTLS", "SIZE ", "SIZE 0", "8BITMIME", "SMTPUTF8",
            "ENHANCEDSTATUSCODES", "AUTH PLAIN LOGIN", "2.0.0 ", "5.1.1 ", "\u0016\u0003\u0001", "\0", " ",
        }.Select(s => Encoding.Latin1.GetBytes(s)).ToList();

    /// <summary>One loopback listener for the whole process; each run accepts one connection and plays its script on it.</summary>
    private sealed class Fixture
    {
        private readonly TcpListener _listener;

        public Fixture()
        {
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start(16);
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        }

        public int Port { get; }

        /// <summary>Plays <paramref name="script"/> on the next connection and returns what the client sent.</summary>
        public Task<byte[]> Serve(byte[] script) => Task.Run(() =>
        {
            var received = new MemoryStream();
            using var socket = _listener.AcceptSocket();
            socket.NoDelay = true;
            socket.LingerState = new LingerOption(true, 0);
            socket.ReceiveTimeout = 30_000;
            socket.SendTimeout = 30_000;
            try
            {
                socket.Send(script);
                socket.Shutdown(SocketShutdown.Send);

                // Read (and drop) what the client sends until it closes, so it is not reset in the middle of a command.
                byte[] buffer = new byte[8192];
                int n;
                while ((n = socket.Receive(buffer)) > 0)
                {
                    received.Write(buffer, 0, n);
                }
            }
            catch (SocketException)
            {
                // the client went away first
            }

            return received.ToArray();
        });
    }
}
