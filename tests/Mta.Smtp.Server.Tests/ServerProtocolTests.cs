using System.Text;
using Mta.Smtp.Protocol;

namespace Mta.Smtp.Server.Tests;

public class ServerProtocolTests
{
    private static async Task<RawClient> OpenAsync(ServerFixture f, bool greet = true)
    {
        var c = await RawClient.ConnectAsync(f.OpenPort);
        if (greet)
        {
            var g = await c.ExpectAsync(220);
            Assert.Contains("mx.test", g.Lines[0]);
        }

        return c;
    }

    [Fact]
    public async Task Greeting_and_ehlo_capabilities()
    {
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        var r = await c.CommandAsync("EHLO client.test", 250);
        var caps = SmtpCapabilities.Parse(r.Lines.Skip(1));
        Assert.True(caps.Pipelining && caps.EightBitMime && caps.SmtpUtf8 && caps.Chunking && caps.EnhancedStatusCodes);
        Assert.Equal(25L * 1024 * 1024, caps.Size);
        Assert.False(caps.StartTls); // plain listener has no STARTTLS... actually Mode.Plain
        Assert.Empty(caps.AuthMechanisms); // bounce role offers no AUTH
        await c.CommandAsync("QUIT", 221);
        Assert.True(await c.WaitForCloseAsync());
    }

    [Fact]
    public async Task Complete_transaction_delivers_unstuffed_body_and_received_header()
    {
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        await c.CommandAsync("EHLO client.test", 250);
        await c.CommandAsync("MAIL FROM:<sender@example.org> SIZE=100 BODY=8BITMIME", 250);
        await c.CommandAsync("RCPT TO:<rcpt@example.com>", 250);
        await c.CommandAsync("DATA", 354);
        await c.SendAsync("Subject: hi\r\n\r\n..leading dot\r\nline two\r\n.\r\n");
        var done = await c.ExpectAsync(250);
        Assert.Contains("Queued as TEST", done.Lines[0]);
        var m = Assert.Single(f.Handler.Messages);
        Assert.Equal("sender@example.org", m.Sender.ToString());
        Assert.Equal(["rcpt@example.com"], m.Recipients);
        Assert.Equal("Subject: hi\r\n\r\n.leading dot\r\nline two\r\n", Encoding.UTF8.GetString(m.Body));
        string received = Encoding.UTF8.GetString(m.Received);
        Assert.StartsWith("Received: from client.test ([127.0.0.1])", received);
        Assert.Contains("by mx.test with ESMTP id ", received);
        Assert.Contains("for <rcpt@example.com>;", received);
        Assert.EndsWith("\r\n", received);
        Assert.Equal(SmtpBodyType.EightBitMime, m.Parameters.BodyType);
    }

    [Fact]
    public async Task Pipelined_commands_in_one_write()
    {
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        await c.SendAsync("EHLO p.test\r\nMAIL FROM:<a@b.example>\r\nRCPT TO:<c@d.example>\r\nRCPT TO:<e@f.example>\r\nDATA\r\n");
        await c.ExpectAsync(250);
        await c.ExpectAsync(250);
        await c.ExpectAsync(250);
        await c.ExpectAsync(250);
        await c.ExpectAsync(354);
        await c.SendAsync("X: y\r\n\r\nbody\r\n.\r\nQUIT\r\n");
        await c.ExpectAsync(250);
        await c.ExpectAsync(221);
        Assert.Equal(2, f.Handler.Messages.Single().Recipients.Length);
    }

    [Fact]
    public async Task Sequence_errors()
    {
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        await c.CommandAsync("MAIL FROM:<a@b.example>", 503);   // before EHLO
        await c.CommandAsync("EHLO x.test", 250);
        await c.CommandAsync("RCPT TO:<a@b.example>", 503);     // before MAIL
        await c.CommandAsync("DATA", 503);
        await c.CommandAsync("MAIL FROM:<a@b.example>", 250);
        await c.CommandAsync("MAIL FROM:<a@b.example>", 503);   // nested
        await c.CommandAsync("DATA", 554);                      // no recipients
        await c.CommandAsync("RSET", 250);
        await c.CommandAsync("NOOP", 250);
        await c.CommandAsync("FROB", 500);
        await c.CommandAsync("MAIL FROM:<>", 250);
        await c.CommandAsync("RCPT TO:<reject@d.example>", 550);
        Assert.Single(f.Handler.RejectedRecipients);
    }

    [Fact]
    public async Task Bdat_chunks()
    {
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        await c.CommandAsync("EHLO x.test", 250);
        await c.CommandAsync("MAIL FROM:<a@b.example>", 250);
        await c.CommandAsync("RCPT TO:<c@d.example>", 250);
        string part1 = "Subject: bdat\r\n\r\n";
        string part2 = ".starts with dot\r\nQUIT\r\n.\r\n";  // content that looks like commands must stay inert
        await c.SendAsync($"BDAT {part1.Length}\r\n{part1}");
        await c.ExpectAsync(250);
        await c.SendAsync($"BDAT {part2.Length} LAST\r\n{part2}");
        await c.ExpectAsync(250);
        var m = Assert.Single(f.Handler.Messages);
        Assert.Equal(part1 + part2, Encoding.UTF8.GetString(m.Body));
        await c.CommandAsync("NOOP", 250);
    }

    [Fact]
    public async Task Bdat_then_data_is_a_sequence_error()
    {
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        await c.CommandAsync("EHLO x.test", 250);
        await c.CommandAsync("MAIL FROM:<a@b.example>", 250);
        await c.CommandAsync("RCPT TO:<c@d.example>", 250);
        await c.SendAsync("BDAT 3\r\nabc");
        await c.ExpectAsync(250);
        await c.CommandAsync("DATA", 503);
        Assert.Empty(f.Handler.Messages);
    }

    [Theory]
    [InlineData("Subject: x\r\n\r\nbody\n.\r\nMAIL FROM:<evil@example.org>\r\n")]       // LF.CRLF
    [InlineData("Subject: x\r\n\r\nbody\r\n.\nMAIL FROM:<evil@example.org>\r\n")]       // CRLF.LF
    [InlineData("Subject: x\r\n\r\nbody\r.\r\nMAIL FROM:<evil@example.org>\r\n")]       // CR.CRLF
    [InlineData("Subject: x\r\n\r\nbody\r\n.\r\r\nMAIL FROM:<evil@example.org>\r\n")]   // CRLF.CRCRLF
    public async Task Smuggling_attempts_are_refused_and_connection_closed(string payload)
    {
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        await c.CommandAsync("EHLO x.test", 250);
        await c.CommandAsync("MAIL FROM:<a@b.example>", 250);
        await c.CommandAsync("RCPT TO:<c@d.example>", 250);
        await c.CommandAsync("DATA", 354);
        await c.SendAsync(payload);
        var r = await c.ReadReplyAsync();
        Assert.NotNull(r);
        Assert.Equal(500, r!.Code);
        Assert.True(await c.WaitForCloseAsync());
        Assert.Empty(f.Handler.Messages); // nothing smuggled in as a second message
    }

    [Fact]
    public async Task Bare_lf_in_command_closes_connection()
    {
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        await c.SendAsync("NOOP\n");
        var r = await c.ReadReplyAsync();
        Assert.Equal(500, r!.Code);
        Assert.True(await c.WaitForCloseAsync());
    }

    [Fact]
    public async Task Overlong_line_closes_connection()
    {
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        await c.SendAsync("NOOP " + new string('a', 5000) + "\r\n");
        var r = await c.ReadReplyAsync();
        Assert.Equal(500, r!.Code);
        Assert.True(await c.WaitForCloseAsync());
    }

    [Fact]
    public async Task Too_many_errors_closes_with_421()
    {
        await using var f = new ServerFixture(o => new SmtpServerOptions
        {
            Hostname = o.Hostname, Certificates = o.Certificates, Listeners = o.Listeners, MaxErrorsPerSession = 3, AuthFailureDelay = TimeSpan.Zero,
        });
        using var c = await OpenAsync(f);
        await c.CommandAsync("FROB", 500);
        await c.CommandAsync("FROB", 500);
        await c.SendLineAsync("FROB");
        await c.ExpectAsync(500);
        var last = await c.ReadReplyAsync();
        Assert.Equal(421, last!.Code);
        Assert.True(await c.WaitForCloseAsync());
    }

    [Fact]
    public async Task Message_too_large_is_refused_with_552_and_session_continues()
    {
        await using var f = new ServerFixture(o => new SmtpServerOptions
        {
            Hostname = o.Hostname, Certificates = o.Certificates, Listeners = o.Listeners, MaxMessageSize = 1000, AuthFailureDelay = TimeSpan.Zero,
        });
        using var c = await OpenAsync(f);
        await c.CommandAsync("EHLO x.test", 250);
        await c.CommandAsync("MAIL FROM:<a@b.example> SIZE=5000", 552);
        await c.CommandAsync("MAIL FROM:<a@b.example>", 250);
        await c.CommandAsync("RCPT TO:<c@d.example>", 250);
        await c.CommandAsync("DATA", 354);
        await c.SendAsync(string.Concat(Enumerable.Repeat(new string('x', 98) + "\r\n", 30)) + ".\r\n");
        await c.ExpectAsync(552);
        Assert.Empty(f.Handler.Messages);
        await c.CommandAsync("NOOP", 250);
    }

    [Fact]
    public async Task Too_many_recipients()
    {
        await using var f = new ServerFixture(o => new SmtpServerOptions
        {
            Hostname = o.Hostname, Certificates = o.Certificates, Listeners = o.Listeners, MaxRecipients = 2, AuthFailureDelay = TimeSpan.Zero,
        });
        using var c = await OpenAsync(f);
        await c.CommandAsync("EHLO x.test", 250);
        await c.CommandAsync("MAIL FROM:<a@b.example>", 250);
        await c.CommandAsync("RCPT TO:<c1@d.example>", 250);
        await c.CommandAsync("RCPT TO:<c2@d.example>", 250);
        await c.CommandAsync("RCPT TO:<c3@d.example>", 452);
    }

    [Fact]
    public async Task Handler_can_defer_and_reject_message()
    {
        var h = new RecordingHandler { OnMessage = m => SmtpReply.Create(451, "4.3.0", "try later") };
        await using var f = new ServerFixture(handler: h);
        using var c = await OpenAsync(f);
        await c.CommandAsync("EHLO x.test", 250);
        await c.CommandAsync("MAIL FROM:<a@b.example>", 250);
        await c.CommandAsync("RCPT TO:<c@d.example>", 250);
        await c.CommandAsync("DATA", 354);
        await c.SendAsync("S: x\r\n\r\nb\r\n.\r\n");
        await c.ExpectAsync(451);
        await c.CommandAsync("MAIL FROM:<a@b.example>", 250); // transaction was reset
    }

    [Fact]
    public async Task Handler_exception_yields_451()
    {
        var h = new RecordingHandler { OnMessage = m => throw new InvalidOperationException("boom") };
        await using var f = new ServerFixture(handler: h);
        using var c = await OpenAsync(f);
        await c.CommandAsync("EHLO x.test", 250);
        await c.CommandAsync("MAIL FROM:<a@b.example>", 250);
        await c.CommandAsync("RCPT TO:<c@d.example>", 250);
        await c.CommandAsync("DATA", 354);
        await c.SendAsync("S: x\r\n\r\nb\r\n.\r\n");
        await c.ExpectAsync(451);
    }

    [Fact]
    public async Task Connection_refusal_by_handler()
    {
        var h = new RecordingHandler { ConnectRefusal = SmtpReply.Create(554, "5.7.1", "blocked") };
        await using var f = new ServerFixture(handler: h);
        using var c = await OpenAsync(f, greet: false);
        var r = await c.ReadReplyAsync();
        Assert.Equal(554, r!.Code);
        Assert.True(await c.WaitForCloseAsync());
    }

    [Fact]
    public async Task Per_ip_connection_limit()
    {
        await using var f = new ServerFixture(o => new SmtpServerOptions
        {
            Hostname = o.Hostname, Certificates = o.Certificates, Listeners = o.Listeners, MaxConnectionsPerIp = 2, AuthFailureDelay = TimeSpan.Zero,
        });
        using var c1 = await OpenAsync(f);
        using var c2 = await OpenAsync(f);
        using var c3 = await OpenAsync(f, greet: false);
        var r = await c3.ReadReplyAsync();
        Assert.Equal(421, r!.Code);
    }

    [Fact]
    public async Task Quiesce_refuses_new_connections_and_new_transactions()
    {
        await using var f = new ServerFixture();
        using var c1 = await OpenAsync(f);
        await c1.CommandAsync("EHLO x.test", 250);
        f.Server.AcceptingMail = false;
        await c1.CommandAsync("NOOP", 250);
        var r = await c1.CommandAsync("MAIL FROM:<a@b.example>", 421);
        Assert.NotNull(r);
        using var c2 = await OpenAsync(f, greet: false);
        Assert.Equal(421, (await c2.ReadReplyAsync())!.Code);
    }

    [Fact]
    public async Task Command_timeout_sends_421()
    {
        await using var f = new ServerFixture(o => new SmtpServerOptions
        {
            Hostname = o.Hostname, Certificates = o.Certificates, Listeners = o.Listeners, CommandTimeout = TimeSpan.FromMilliseconds(300),
            GreetingTimeout = TimeSpan.FromMilliseconds(300), AuthFailureDelay = TimeSpan.Zero,
        });
        using var c = await OpenAsync(f);
        var r = await c.ReadReplyAsync();
        Assert.Equal(421, r!.Code);
        Assert.True(await c.WaitForCloseAsync());
    }

    [Fact]
    public async Task Data_timeout_sends_421()
    {
        await using var f = new ServerFixture(o => new SmtpServerOptions
        {
            Hostname = o.Hostname, Certificates = o.Certificates, Listeners = o.Listeners, DataTimeout = TimeSpan.FromMilliseconds(300), AuthFailureDelay = TimeSpan.Zero,
        });
        using var c = await OpenAsync(f);
        await c.CommandAsync("EHLO x.test", 250);
        await c.CommandAsync("MAIL FROM:<a@b.example>", 250);
        await c.CommandAsync("RCPT TO:<c@d.example>", 250);
        await c.CommandAsync("DATA", 354);
        await c.SendAsync("Subject: partial\r\n");
        Assert.Equal(421, (await c.ReadReplyAsync())!.Code);
    }

    [Fact]
    public async Task Concurrent_sessions_all_succeed()
    {
        await using var f = new ServerFixture();
        var tasks = Enumerable.Range(0, 50).Select(async i =>
        {
            using var c = await OpenAsync(f);
            await c.CommandAsync("EHLO x.test", 250);
            await c.CommandAsync($"MAIL FROM:<s{i}@b.example>", 250);
            await c.CommandAsync("RCPT TO:<c@d.example>", 250);
            await c.CommandAsync("DATA", 354);
            await c.SendAsync($"Subject: {i}\r\n\r\nbody {i}\r\n.\r\n");
            await c.ExpectAsync(250);
            await c.CommandAsync("QUIT", 221);
        });
        await Task.WhenAll(tasks);
        Assert.Equal(50, f.Handler.Messages.Count);
    }
}
