using System.Net;
using System.Net.Sockets;
using System.Text;
using Mta.Smtp.Protocol;

namespace Mta.Smtp.Server.Tests;

public class FuzzTests
{
    [Fact]
    public async Task Garbage_connections_never_break_the_server()
    {
        await using var f = new ServerFixture(o => new SmtpServerOptions
        {
            Hostname = o.Hostname, Certificates = o.Certificates, Listeners = o.Listeners,
            CommandTimeout = TimeSpan.FromSeconds(2), GreetingTimeout = TimeSpan.FromSeconds(2), DataTimeout = TimeSpan.FromSeconds(2), AuthFailureDelay = TimeSpan.Zero,
        });
        var rng = new Random(2026);
        string[] fragments = ["EHLO a\r\n", "MAIL FROM:<a@b.c>\r\n", "RCPT TO:<d@e.f>\r\n", "DATA\r\n", "\r\n.\r\n", "BDAT 5\r\n", "\n", "\r", "\0", "STARTTLS\r\n", "AUTH PLAIN\r\n", "QUIT\r\n"];
        for (int i = 0; i < 150; i++)
        {
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(IPAddress.Loopback, i % 2 == 0 ? f.OpenPort : f.PlainPort);
            var s = tcp.GetStream();
            var payload = new StringBuilder();
            int parts = rng.Next(1, 12);
            for (int p = 0; p < parts; p++)
            {
                if (rng.Next(4) == 0)
                {
                    byte[] junk = new byte[rng.Next(1, 64)];
                    rng.NextBytes(junk);
                    payload.Append(Encoding.Latin1.GetString(junk));
                }
                else
                {
                    payload.Append(fragments[rng.Next(fragments.Length)]);
                }
            }

            try
            {
                await s.WriteAsync(Encoding.Latin1.GetBytes(payload.ToString()));
                if (rng.Next(2) == 0)
                {
                    tcp.Client.Shutdown(SocketShutdown.Send);
                }

                var buf = new byte[1024];
                using var cts = new CancellationTokenSource(300);
                try { _ = await s.ReadAsync(buf, cts.Token); } catch (OperationCanceledException) { }
            }
            catch (Exception ex) when (ex is IOException or SocketException)
            {
            }
        }

        // The server must still serve a normal transaction afterwards.
        using var c = await RawClient.ConnectAsync(f.OpenPort);
        await c.ExpectAsync(220);
        await c.CommandAsync("EHLO ok.test", 250);
        await c.CommandAsync("MAIL FROM:<a@b.example>", 250);
        await c.CommandAsync("RCPT TO:<c@d.example>", 250);
        await c.CommandAsync("DATA", 354);
        await c.SendAsync("S: x\r\n\r\nfine\r\n.\r\n");
        await c.ExpectAsync(250);
    }
}
