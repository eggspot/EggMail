using System.Net;
using System.Text;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using Mta.Smtp.Protocol;
using SmtpCapabilities = Mta.Smtp.Protocol.SmtpCapabilities;

namespace Mta.Smtp.Server.Tests;

public class TlsAndAuthTests
{
    [Fact]
    public async Task Starttls_upgrade_then_authenticated_submission()
    {
        await using var f = new ServerFixture();
        using var c = await RawClient.ConnectAsync(f.PlainPort);
        await c.ExpectAsync(220);
        var caps = SmtpCapabilities.Parse((await c.CommandAsync("EHLO x.test", 250)).Lines.Skip(1));
        Assert.True(caps.StartTls);
        Assert.Empty(caps.AuthMechanisms); // AUTH only after TLS
        await c.CommandAsync("AUTH PLAIN AHVzZXIAcGFzcw==", 538);
        await c.CommandAsync("MAIL FROM:<a@b.example>", 530); // TLS required before auth, auth required before mail
        await c.CommandAsync("STARTTLS", 220);
        await c.StartTlsHandshakeAsync();
        await c.CommandAsync("MAIL FROM:<a@b.example>", 503); // must EHLO again after TLS
        var caps2 = SmtpCapabilities.Parse((await c.CommandAsync("EHLO x.test", 250)).Lines.Skip(1));
        Assert.False(caps2.StartTls);
        Assert.Contains("PLAIN", caps2.AuthMechanisms);
        Assert.Contains("LOGIN", caps2.AuthMechanisms);
        await c.CommandAsync("MAIL FROM:<a@b.example>", 530); // auth still required
        await c.CommandAsync("AUTH PLAIN " + Convert.ToBase64String("\0user\0pass"u8.ToArray()), 235);
        await c.CommandAsync("MAIL FROM:<a@b.example>", 250);
        await c.CommandAsync("RCPT TO:<c@d.example>", 250);
        await c.CommandAsync("DATA", 354);
        await c.SendAsync("S: x\r\n\r\nsecure body\r\n.\r\n");
        await c.ExpectAsync(250);
        var m = Assert.Single(f.Handler.Messages);
        Assert.Equal("user", m.User);
        Assert.True(m.Tls);
        string rec = Encoding.UTF8.GetString(m.Received);
        Assert.Contains("with ESMTPSA", rec);
        Assert.Contains("TLS", rec, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Starttls_command_injection_is_refused()
    {
        // RFC 3207 §4.2 / CVE-2011-0411 family: plaintext sent right behind STARTTLS must never be processed.
        await using var f = new ServerFixture();
        using var c = await RawClient.ConnectAsync(f.PlainPort);
        await c.ExpectAsync(220);
        await c.CommandAsync("EHLO x.test", 250);
        await c.SendAsync("STARTTLS\r\nMAIL FROM:<evil@example.org>\r\n");
        // The server may answer 220 or just close; either way it must not carry out the injected command.
        await c.ReadReplyAsync();
        Assert.True(await c.WaitForCloseAsync());
        Assert.Empty(f.Handler.Messages);
    }

    [Fact]
    public async Task Implicit_tls_listener()
    {
        await using var f = new ServerFixture();
        using var c = await RawClient.ConnectAsync(f.ImplicitPort);
        await c.StartTlsHandshakeAsync();
        await c.ExpectAsync(220);
        var caps = SmtpCapabilities.Parse((await c.CommandAsync("EHLO x.test", 250)).Lines.Skip(1));
        Assert.False(caps.StartTls);
        Assert.Contains("PLAIN", caps.AuthMechanisms);
        Assert.NotNull(c.Ssl);
        Assert.True(c.Ssl!.SslProtocol is System.Security.Authentication.SslProtocols.Tls12 or System.Security.Authentication.SslProtocols.Tls13);
    }

    [Fact]
    public async Task Auth_login_and_failure_handling()
    {
        await using var f = new ServerFixture();
        using var c = await RawClient.ConnectAsync(f.ImplicitPort);
        await c.StartTlsHandshakeAsync();
        await c.ExpectAsync(220);
        await c.CommandAsync("EHLO x.test", 250);
        var ch1 = await c.CommandAsync("AUTH LOGIN", 334);
        Assert.Equal("Username:", Encoding.ASCII.GetString(Convert.FromBase64String(ch1.Lines[0])));
        var ch2 = await c.CommandAsync(Convert.ToBase64String("user"u8.ToArray()), 334);
        Assert.Equal("Password:", Encoding.ASCII.GetString(Convert.FromBase64String(ch2.Lines[0])));
        await c.CommandAsync(Convert.ToBase64String("wrong"u8.ToArray()), 535);
        await c.CommandAsync("AUTH PLAIN notbase64!", 501);
        await c.CommandAsync("AUTH PLAIN", 334);
        await c.CommandAsync("*", 501);
        await c.CommandAsync("AUTH LOGIN " + Convert.ToBase64String("user"u8.ToArray()), 334);
        await c.CommandAsync(Convert.ToBase64String("pass"u8.ToArray()), 235);
        await c.CommandAsync("AUTH PLAIN AHVzZXIAcGFzcw==", 503); // already authenticated
    }

    [Fact]
    public async Task Auth_failures_are_counted_toward_error_limit()
    {
        await using var f = new ServerFixture(o => new SmtpServerOptions
        {
            Hostname = o.Hostname, Certificates = o.Certificates, Listeners = o.Listeners, MaxErrorsPerSession = 3, AuthFailureDelay = TimeSpan.Zero,
        });
        using var c = await RawClient.ConnectAsync(f.ImplicitPort);
        await c.StartTlsHandshakeAsync();
        await c.ExpectAsync(220);
        await c.CommandAsync("EHLO x.test", 250);
        string bad = Convert.ToBase64String("\0user\0bad"u8.ToArray());
        await c.CommandAsync("AUTH PLAIN " + bad, 535);
        await c.CommandAsync("AUTH PLAIN " + bad, 535);
        await c.SendLineAsync("AUTH PLAIN " + bad);
        await c.ExpectAsync(535);
        Assert.Equal(421, (await c.ReadReplyAsync())!.Code);
    }

    [Fact]
    public async Task Mailkit_can_submit_over_starttls_and_implicit_tls()
    {
        await using var f = new ServerFixture();
        foreach (var (port, option) in new[] { (f.PlainPort, SecureSocketOptions.StartTls), (f.ImplicitPort, SecureSocketOptions.SslOnConnect) })
        {
            using var client = new SmtpClient { CheckCertificateRevocation = false, ServerCertificateValidationCallback = (_, _, _, _) => true };
            await client.ConnectAsync("localhost", port, option);
            await client.AuthenticateAsync("user", "pass");
            var message = new MimeMessage();
            message.From.Add(MailboxAddress.Parse("sender@example.org"));
            message.To.Add(MailboxAddress.Parse("rcpt@example.com"));
            message.Subject = "Hello from MailKit ü";
            message.Body = new BodyBuilder { TextBody = "Line 1\r\n.dotted line\r\nLine 3\r\n", HtmlBody = "<p>hi</p>" }.ToMessageBody();
            await client.SendAsync(message);
            await client.DisconnectAsync(true);
        }

        Assert.Equal(2, f.Handler.Messages.Count);
        foreach (var m in f.Handler.Messages)
        {
            using var ms = new MemoryStream(m.Body);
            var parsed = MimeMessage.Load(ms);
            Assert.Equal("Hello from MailKit ü", parsed.Subject);
            Assert.Contains(".dotted line", parsed.TextBody ?? "");
            Assert.Equal("user", m.User);
        }
    }

    [Fact]
    public async Task Mailkit_unauthenticated_submission_is_refused()
    {
        await using var f = new ServerFixture();
        using var client = new SmtpClient { CheckCertificateRevocation = false, ServerCertificateValidationCallback = (_, _, _, _) => true };
        await client.ConnectAsync("localhost", f.ImplicitPort, SecureSocketOptions.SslOnConnect);
        var message = new MimeMessage();
        message.From.Add(MailboxAddress.Parse("sender@example.org"));
        message.To.Add(MailboxAddress.Parse("rcpt@example.com"));
        message.Subject = "x";
        message.Body = new TextPart("plain") { Text = "x" };
        await Assert.ThrowsAnyAsync<Exception>(() => client.SendAsync(message));
        Assert.Empty(f.Handler.Messages);
    }

    [Fact]
    public async Task Large_message_through_tls_with_mailkit()
    {
        await using var f = new ServerFixture();
        using var client = new SmtpClient { CheckCertificateRevocation = false, ServerCertificateValidationCallback = (_, _, _, _) => true };
        await client.ConnectAsync("localhost", f.ImplicitPort, SecureSocketOptions.SslOnConnect);
        await client.AuthenticateAsync("user", "pass");
        var message = new MimeMessage();
        message.From.Add(MailboxAddress.Parse("sender@example.org"));
        message.To.Add(MailboxAddress.Parse("rcpt@example.com"));
        message.Subject = "big";
        var attachment = new byte[3 * 1024 * 1024];
        new Random(1).NextBytes(attachment);
        var builder = new BodyBuilder { TextBody = "see attachment" };
        builder.Attachments.Add("data.bin", attachment);
        message.Body = builder.ToMessageBody();
        await client.SendAsync(message);
        var m = Assert.Single(f.Handler.Messages);
        using var ms = new MemoryStream(m.Body);
        var parsed = MimeMessage.Load(ms);
        var part = parsed.Attachments.OfType<MimePart>().Single();
        using var content = new MemoryStream();
        part.Content!.DecodeTo(content);
        Assert.Equal(attachment, content.ToArray());
    }
}

public class StarttlsRaceTests
{
    /// <summary>A real TLS ClientHello recorded once (the handshake itself is never completed with it).</summary>
    private static async Task<byte[]> RecordClientHelloAsync()
    {
        using var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var accept = Task.Run(async () =>
        {
            using var peer = await listener.AcceptTcpClientAsync();
            byte[] buffer = new byte[4096];
            int n = await peer.GetStream().ReadAsync(buffer);
            return buffer.AsSpan(0, n).ToArray();
        });
        using var client = new System.Net.Sockets.TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
        using var ssl = new System.Net.Security.SslStream(client.GetStream(), false, (_, _, _, _) => true);
        _ = Task.Run(async () => { try { await ssl.AuthenticateAsClientAsync("localhost"); } catch { } });
        return await accept;
    }

    [Fact]
    public async Task A_ClientHello_written_in_the_same_instant_as_220_is_read_gets_a_ServerHello_not_a_closed_connection()
    {
        // A native TLS client (OpenSSL, Python) sends its ClientHello within microseconds of seeing 220. The server must not have a plaintext
        // reader running at that moment. The first TLS record back must be the ServerHello (content type 0x16), never EOF.
        byte[] hello = await RecordClientHelloAsync();
        await using var f = new ServerFixture();
        for (int i = 0; i < 40; i++)
        {
            using var tcp = new System.Net.Sockets.TcpClient();
            await tcp.ConnectAsync(IPAddress.Loopback, f.PlainPort);
            var stream = tcp.GetStream();
            byte[] buffer = new byte[4096];
            await ReadUntilAsync(stream, buffer, "220");                          // greeting
            await stream.WriteAsync("EHLO x.test\r\n"u8.ToArray());
            await ReadUntilAsync(stream, buffer, "250 STARTTLS");
            await stream.WriteAsync("STARTTLS\r\n"u8.ToArray());
            await ReadUntilAsync(stream, buffer, "220");
            await stream.WriteAsync(hello);
            using var cts = new CancellationTokenSource(5000);
            int n = await stream.ReadAsync(buffer, cts.Token);
            Assert.True(n > 0 && buffer[0] == 0x16, $"iteration {i}: expected a TLS record, got {(n == 0 ? "EOF" : "0x" + buffer[0].ToString("x2"))}");
        }
    }

    private static async Task ReadUntilAsync(System.Net.Sockets.NetworkStream stream, byte[] buffer, string marker)
    {
        var text = new StringBuilder();
        while (!text.ToString().Contains(marker))
        {
            int n = await stream.ReadAsync(buffer);
            Assert.True(n > 0, "connection closed while waiting for " + marker);
            text.Append(Encoding.ASCII.GetString(buffer, 0, n));
        }
    }

    [Fact]
    public async Task A_client_that_starts_the_handshake_the_instant_it_sees_220_is_never_mistaken_for_an_injection()
    {
        // The ClientHello can arrive while the server is still switching from plaintext to TLS; it must wait for the handshake, not be
        // read as pipelined plaintext. Many fast, concurrent upgrades make the window visible.
        await using var f = new ServerFixture();
        int failures = 0;
        var gate = new SemaphoreSlim(32);
        var tasks = Enumerable.Range(0, 600).Select(async _ =>
        {
            await gate.WaitAsync();
            try
            {
                using var c = await RawClient.ConnectAsync(f.PlainPort);
                await c.ExpectAsync(220);
                await c.CommandAsync("EHLO x.test", 250);
                await c.CommandAsync("STARTTLS", 220);
                await c.StartTlsHandshakeAsync();
                await c.CommandAsync("EHLO x.test", 250);
            }
            catch (Exception)
            {
                Interlocked.Increment(ref failures);
            }
            finally
            {
                gate.Release();
            }
        }).ToArray();
        await Task.WhenAll(tasks);
        Assert.Equal(0, failures);
    }
}
