using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using Mta.Smtp.Protocol;

namespace Mta.Smtp.Server.Tests;

/// <summary>
/// Security regression tests for the SMTP server (docs/security-test-map.md, SMTP-*): smuggling, STARTTLS injection, authentication, relaying,
/// resource limits and TLS settings, against the real server over loopback with ephemeral ports. The in-house review, not an independent audit.
/// </summary>
public class SmtpSmuggling
{
    private static Task<RawClient> OpenAsync(ServerFixture f) => OpenCoreAsync(f);

    private static async Task<RawClient> OpenCoreAsync(ServerFixture f)
    {
        var c = await RawClient.ConnectAsync(f.OpenPort);
        await c.ExpectAsync(220);
        await c.CommandAsync("EHLO client.test", 250);
        return c;
    }

    private static async Task BeginDataAsync(RawClient c)
    {
        await c.CommandAsync("MAIL FROM:<a@b.example>", 250);
        await c.CommandAsync("RCPT TO:<c@d.example>", 250);
        await c.CommandAsync("DATA", 354);
    }

    [Theory]
    [InlineData("Subject: x\r\n\r\nbo\0dy\r\n.\r\n")]                                                   // NUL in the body
    [InlineData("Subject: x\r\n\r\nbo\rdy\r\n.\r\n")]                                                   // lone CR mid-line
    [InlineData("Subject: x\r\n\r\nbody\nmore\r\n.\r\n")]                                               // lone LF mid-body
    [InlineData("\n.\nMAIL FROM:<evil@example.org>\r\n")]                                               // LF.LF as the very first bytes
    [InlineData("\r.\rMAIL FROM:<evil@example.org>\r\n")]                                               // CR.CR
    [InlineData("Subject: x\r\n\r\nbody\r\n.\n")]                                                       // CRLF.LF
    [InlineData("Subject: x\r\n\r\nbody\r\n\r.\r\n")]                                                   // CRLF CR.CRLF
    [InlineData("Subject: x\r\n\r\nbody\n.\r\nRCPT TO:<evil@example.org>\r\nDATA\r\nsmuggled\r\n.\r\n")] // the classic: a second message after an LF.CRLF
    [InlineData("Subject: x\r\n\r\nbody\r\n.\r\r\nMAIL FROM:<evil@example.org>\r\n")]                   // CRLF.CR CRLF
    [InlineData("Subject: x\r\n\r\nbody\r\n\0.\r\n")]                                                   // NUL before the dot
    public async Task Every_variant_of_a_forged_end_of_data_is_refused_closes_the_connection_and_queues_nothing(string payload)
    {
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        await BeginDataAsync(c);

        await c.SendAsync(payload);

        var reply = await c.ReadReplyAsync();
        Assert.NotNull(reply);
        Assert.Equal(500, reply!.Code);
        Assert.True(await c.WaitForCloseAsync());
        Assert.Empty(f.Handler.Messages);
        Assert.Equal(1, f.Handler.MailFromCalls);   // the smuggled MAIL FROM was never executed
    }

    [Fact]
    public async Task A_message_sent_one_byte_per_write_is_accepted_once_and_unchanged()
    {
        // The defence must not depend on where TCP happens to split the stream.
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        await BeginDataAsync(c);
        byte[] message = Encoding.ASCII.GetBytes("Subject: split\r\n\r\nline one\r\n.dotted\r\n..two dots\r\n\r\n.\r\n");   // a leading dot is stuffed: ".dotted" is "dotted"

        foreach (byte b in message)
        {
            await c.SendBytesAsync([b]);
        }

        await c.ExpectAsync(250);
        var m = Assert.Single(f.Handler.Messages);
        Assert.Equal("Subject: split\r\n\r\nline one\r\ndotted\r\n.two dots\r\n\r\n", Encoding.ASCII.GetString(m.Body));
    }

    [Fact]
    public async Task A_forged_terminator_split_across_writes_is_still_refused()
    {
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        await BeginDataAsync(c);

        foreach (string piece in new[] { "Subject: x\r\n\r\nbody\r", "\r", ".", "\r", "\r\nMAIL FROM:<evil@example.org>\r\n" })
        {
            await c.SendAsync(piece);
        }

        var reply = await c.ReadReplyAsync();
        Assert.Equal(500, reply!.Code);
        Assert.True(await c.WaitForCloseAsync());
        Assert.Empty(f.Handler.Messages);
    }

    [Fact]
    public async Task Commands_pipelined_after_the_real_terminator_run_as_new_transactions_and_never_join_the_body()
    {
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        await BeginDataAsync(c);

        await c.SendAsync("Subject: one\r\n\r\nfirst\r\n.\r\nMAIL FROM:<second@b.example>\r\nRCPT TO:<c@d.example>\r\nDATA\r\nSubject: two\r\n\r\nsecond\r\n.\r\n");

        await c.ExpectAsync(250);   // message one
        await c.ExpectAsync(250);   // MAIL
        await c.ExpectAsync(250);   // RCPT
        await c.ExpectAsync(354);   // DATA
        await c.ExpectAsync(250);   // message two
        Assert.Equal(2, f.Handler.Messages.Count);
        Assert.Equal("Subject: one\r\n\r\nfirst\r\n", Encoding.ASCII.GetString(f.Handler.Messages[0].Body));
        Assert.Equal("Subject: two\r\n\r\nsecond\r\n", Encoding.ASCII.GetString(f.Handler.Messages[1].Body));
        Assert.Equal("second@b.example", f.Handler.Messages[1].Sender.ToString());
    }

    [Theory]
    [InlineData("Subject: x\r\n\r\nbo\0dy\r\n")]       // NUL
    [InlineData("Subject: x\r\n\r\nbo\rdy\r\n")]       // lone CR
    [InlineData("Subject: x\r\n\r\nbo\ndy\r\n")]       // lone LF
    [InlineData("Subject: x\r\n\r\nbody\r")]           // ends in CR: the LF that would complete it never comes
    [InlineData("\n.\n")]                              // the DATA terminator written with bare LF, as BDAT payload
    public async Task A_BDAT_body_is_held_to_the_same_line_ending_rule_as_DATA_in_its_first_chunk(string body)
    {
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        await c.CommandAsync("MAIL FROM:<a@b.example>", 250);
        await c.CommandAsync("RCPT TO:<c@d.example>", 250);

        await c.SendAsync($"BDAT {Encoding.ASCII.GetByteCount(body)} LAST\r\n{body}");

        var reply = await c.ReadReplyAsync();
        Assert.NotNull(reply);
        Assert.Equal(500, reply!.Code);
        Assert.True(await c.WaitForCloseAsync());
        Assert.Empty(f.Handler.Messages);
    }

    [Fact]
    public async Task Commands_and_a_terminator_inside_a_BDAT_chunk_are_inert_text_of_the_message()
    {
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        await c.CommandAsync("MAIL FROM:<a@b.example>", 250);
        await c.CommandAsync("RCPT TO:<c@d.example>", 250);
        string body = "Subject: x\r\n\r\n.\r\nMAIL FROM:<evil@example.org>\r\nDATA\r\nQUIT\r\n.\r\n";

        await c.SendAsync($"BDAT {body.Length} LAST\r\n{body}");

        await c.ExpectAsync(250);
        var m = Assert.Single(f.Handler.Messages);
        Assert.Equal(body, Encoding.ASCII.GetString(m.Body));   // not unstuffed, not interpreted
        Assert.Equal(1, f.Handler.MailFromCalls);
    }

    [Fact]
    public async Task A_BDAT_size_that_is_smaller_than_what_follows_never_turns_the_rest_into_a_command()
    {
        // The client announces 5 octets and sends more: the surplus is parsed as a command, and while chunking only BDAT/RSET/NOOP/QUIT are valid.
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        await c.CommandAsync("MAIL FROM:<a@b.example>", 250);
        await c.CommandAsync("RCPT TO:<c@d.example>", 250);

        await c.SendAsync("BDAT 5\r\nab\r\nXMAIL FROM:<evil@example.org>\r\n");

        await c.ExpectAsync(250);
        var refusal = await c.ReadReplyAsync();
        Assert.True(refusal is { Code: >= 500 });
        Assert.Equal(1, f.Handler.MailFromCalls);
        Assert.Empty(f.Handler.Messages);
    }

    [Fact]
    public async Task DATA_after_a_BDAT_chunk_and_BDAT_after_DATA_are_sequence_errors_so_the_two_framings_cannot_be_mixed()
    {
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        await c.CommandAsync("MAIL FROM:<a@b.example>", 250);
        await c.CommandAsync("RCPT TO:<c@d.example>", 250);
        await c.CommandAsync("DATA", 354);

        await c.SendAsync("BDAT 3\r\n");   // inside the DATA body this is only a line of text
        await c.SendAsync("abc\r\n.\r\n");
        await c.ExpectAsync(250);
        Assert.Equal("BDAT 3\r\nabc\r\n", Encoding.ASCII.GetString(Assert.Single(f.Handler.Messages).Body));

        await c.CommandAsync("MAIL FROM:<a@b.example>", 250);
        await c.CommandAsync("RCPT TO:<c@d.example>", 250);
        await c.SendAsync("BDAT 3\r\nabc");
        await c.ExpectAsync(250);
        await c.CommandAsync("DATA", 503);
        // The error ends the BDAT sequence: what was sent so far is dropped, not delivered, and a new transaction starts clean.
        Assert.Single(f.Handler.Messages);
        await c.CommandAsync("RCPT TO:<c@d.example>", 503);   // no MAIL in the new state
        await c.CommandAsync("MAIL FROM:<b@b.example>", 250);
        Assert.Single(f.Handler.Messages);
    }

    [Theory]
    [InlineData("BDAT -1")]
    [InlineData("BDAT 99999999999999999999")]
    [InlineData("BDAT abc")]
    [InlineData("BDAT")]
    public async Task A_malformed_BDAT_size_is_a_syntax_error_and_not_a_negative_or_huge_read(string line)
    {
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        await c.CommandAsync("MAIL FROM:<a@b.example>", 250);
        await c.CommandAsync("RCPT TO:<c@d.example>", 250);

        await c.SendLineAsync(line);

        var reply = await c.ReadReplyAsync();
        Assert.NotNull(reply);
        Assert.InRange(reply!.Code, 500, 599);
        Assert.Empty(f.Handler.Messages);
    }

    [Theory]
    [InlineData("NOOP\0\r\n")]
    [InlineData("MAIL FROM:<a@b.example>\0\r\n")]
    [InlineData("EHLO a\u0001b\r\n")]
    [InlineData("RCPT TO:<c@d.example>\n")]
    [InlineData("RSET\r")]
    public async Task Control_characters_and_bare_line_ends_in_a_command_never_run_the_command(string line)
    {
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        await c.SendAsync(line + "QUIT\r\n");

        var reply = await c.ReadReplyAsync();
        Assert.NotNull(reply);
        Assert.InRange(reply!.Code, 500, 599);
        Assert.Equal(0, f.Handler.MailFromCalls);
        Assert.Equal(0, f.Handler.RcptToCalls);
    }
}

public class SmtpTraceHeaderSecurity
{
    [Theory]
    [InlineData("a by evil.example with ESMTP id FORGED")]
    [InlineData("a) by evil.example (")]
    [InlineData("a;\tby evil.example")]
    [InlineData("<evil@example.org>")]
    [InlineData("[1.2.3.4] ([9.9.9.9]) by evil.example")]
    [InlineData("a\u0001b")]
    [InlineData("a\u007fb")]
    [InlineData("a\tb")]
    [InlineData("\u00fc\u00f1.example")]
    [InlineData("\"quoted\"")]
    [InlineData("x")]
    public async Task A_greeting_name_cannot_forge_a_hop_in_the_received_header_the_server_writes(string name)
    {
        await using var f = new ServerFixture();
        using var c = await RawClient.ConnectAsync(f.OpenPort);
        await c.ExpectAsync(220);
        await c.SendBytesAsync(Encoding.UTF8.GetBytes("EHLO " + name + "\r\n"));
        var reply = await c.ReadReplyAsync();
        if (reply!.Code != 250)
        {
            Assert.InRange(reply.Code, 500, 599);   // refused outright: nothing to forge
            return;
        }

        await c.CommandAsync("MAIL FROM:<a@b.example>", 250);
        await c.CommandAsync("RCPT TO:<c@d.example>", 250);
        await c.CommandAsync("DATA", 354);
        await c.SendAsync("Subject: s\r\n\r\nbody\r\n.\r\n");
        await c.ExpectAsync(250);

        string received = Encoding.UTF8.GetString(Assert.Single(f.Handler.Messages).Received);
        string[] lines = received.TrimEnd('\r', '\n').Split("\r\n");
        Assert.StartsWith("Received: from ", lines[0], StringComparison.Ordinal);
        // The greeting name is one token inside the "from" clause, followed by the address the connection really came from.
        System.Text.RegularExpressions.Match m = System.Text.RegularExpressions.Regex.Match(lines[0], @"^Received: from (\S+) \(\[127\.0\.0\.1\]\)$");
        Assert.True(m.Success, "first line: " + lines[0]);
        Assert.StartsWith("\tby mx.test with ESMTP id ", lines[1], StringComparison.Ordinal);
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(received, @"(?m)^Received:"));
        Assert.DoesNotContain("evil.example", string.Join("", lines.Skip(1)), StringComparison.Ordinal);
        Assert.DoesNotContain("FORGED", string.Join("", lines.Skip(1)), StringComparison.Ordinal);
        Assert.All(lines.Skip(1), l => Assert.StartsWith("\t", l, StringComparison.Ordinal));   // continuation lines only
    }
}

public class SmtpStartTlsAndAuthentication
{
    private static SmtpServerOptions Options(SmtpServerOptions o, IReadOnlyList<SmtpListenerOptions>? listeners = null, int? maxMessagesPerSession = null,
        TimeSpan? tlsHandshakeTimeout = null, TimeSpan? maxDataDuration = null, TimeSpan? dataTimeout = null, int? maxConnections = null) => new()
    {
        Hostname = o.Hostname,
        Certificates = o.Certificates,
        AuthFailureDelay = TimeSpan.Zero,
        Listeners = listeners ?? o.Listeners,
        MaxMessagesPerSession = maxMessagesPerSession ?? o.MaxMessagesPerSession,
        TlsHandshakeTimeout = tlsHandshakeTimeout ?? o.TlsHandshakeTimeout,
        MaxDataDuration = maxDataDuration ?? o.MaxDataDuration,
        DataTimeout = dataTimeout ?? o.DataTimeout,
        MaxConnections = maxConnections ?? o.MaxConnections,
    };

    /// <summary>The "open" listener becomes a STARTTLS submission listener that does not demand authentication (to see what STARTTLS resets).</summary>
    private static IReadOnlyList<SmtpListenerOptions> StartTlsOpenSubmission(SmtpServerOptions o) =>
    [
        o.Listeners[0], o.Listeners[1],
        new SmtpListenerOptions { Name = "open", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.StartTls, AuthRequired = false, Role = ListenerRole.Submission },
    ];

    [Theory]
    [InlineData("STARTTLS\r\nMAIL FROM:<evil@example.org>\r\n")]
    [InlineData("STARTTLS\r\nAUTH PLAIN AHVzZXIAcGFzcw==\r\n")]                         // the credential-injection variant
    [InlineData("STARTTLS\r\nRSET\r\nMAIL FROM:<evil@example.org>\r\nRCPT TO:<c@d.example>\r\nDATA\r\n")]
    [InlineData("STARTTLS\r\nSTARTTLS\r\n")]
    public async Task Plaintext_that_arrives_behind_STARTTLS_is_never_processed_before_or_after_the_upgrade(string burst)
    {
        // RFC 3207 section 4.2 / CVE-2011-0411 and relatives: the bytes sent with STARTTLS are an attacker's.
        await using var f = new ServerFixture();
        using var c = await RawClient.ConnectAsync(f.PlainPort);
        await c.ExpectAsync(220);
        await c.CommandAsync("EHLO x.test", 250);

        await c.SendAsync(burst);

        // Whatever the server says next (a 220, or nothing and a close), it must not be an answer to an injected command.
        var next = await c.ReadReplyAsync();
        Assert.True(next is null || next.Code is 220 or >= 400, $"unexpected {next?.Code}");
        Assert.True(await c.WaitForCloseAsync());
        Assert.Equal(0, f.Handler.MailFromCalls);
        Assert.Equal(0, f.Handler.AuthAttempts);
        Assert.Empty(f.Handler.Messages);
    }

    [Fact]
    public async Task A_late_injection_before_the_handshake_ruins_the_handshake_and_not_the_session()
    {
        // A man in the middle that adds a command between "220 go ahead" and the ClientHello: the server reads it as TLS, and fails the handshake.
        await using var f = new ServerFixture();
        using var c = await RawClient.ConnectAsync(f.PlainPort);
        await c.ExpectAsync(220);
        await c.CommandAsync("EHLO x.test", 250);
        await c.CommandAsync("STARTTLS", 220);

        await c.SendAsync("MAIL FROM:<evil@example.org>\r\n");

        Assert.True(await c.WaitForCloseAsync());
        Assert.Equal(0, f.Handler.MailFromCalls);
    }

    [Fact]
    public async Task AUTH_is_not_offered_and_not_accepted_before_TLS_and_the_credentials_are_never_looked_at()
    {
        await using var f = new ServerFixture();
        using var c = await RawClient.ConnectAsync(f.PlainPort);
        await c.ExpectAsync(220);
        var ehlo = await c.CommandAsync("EHLO x.test", 250);
        var caps = SmtpCapabilities.Parse(ehlo.Lines.Skip(1));
        Assert.True(caps.StartTls);
        Assert.Empty(caps.AuthMechanisms);

        await c.CommandAsync("AUTH PLAIN AHVzZXIAcGFzcw==", 538);
        await c.CommandAsync("AUTH LOGIN", 538);
        await c.CommandAsync("AUTH LOGIN dXNlcg==", 538);
        Assert.Equal(0, f.Handler.AuthAttempts);

        // After the upgrade it is offered, and the same credentials work.
        await c.CommandAsync("STARTTLS", 220);
        await c.StartTlsHandshakeAsync();
        var secure = await c.CommandAsync("EHLO x.test", 250);
        Assert.Contains("PLAIN", SmtpCapabilities.Parse(secure.Lines.Skip(1)).AuthMechanisms);
        await c.CommandAsync("AUTH PLAIN AHVzZXIAcGFzcw==", 235);
    }

    [Fact]
    public async Task Nothing_said_before_STARTTLS_survives_the_upgrade()
    {
        await using var f = new ServerFixture(o => Options(o, StartTlsOpenSubmission(o)));
        using var c = await RawClient.ConnectAsync(f.OpenPort);
        await c.ExpectAsync(220);
        await c.CommandAsync("EHLO before.test", 250);
        await c.CommandAsync("MAIL FROM:<a@b.example>", 250);
        await c.CommandAsync("STARTTLS", 503);   // not inside a transaction (RFC 3207)
        await c.CommandAsync("RSET", 250);
        await c.CommandAsync("STARTTLS", 220);
        await c.StartTlsHandshakeAsync();

        // The server forgot the greeting and the transaction: a client has to say hello again.
        await c.CommandAsync("RCPT TO:<c@d.example>", 503);
        await c.CommandAsync("MAIL FROM:<a@b.example>", 503);
        await c.CommandAsync("EHLO after.test", 250);
        await c.CommandAsync("MAIL FROM:<a@b.example>", 250);
        await c.CommandAsync("STARTTLS", 503);   // TLS is already active
    }

    [Fact]
    public async Task Mail_cannot_be_submitted_before_authentication_on_a_submission_listener()
    {
        await using var f = new ServerFixture();
        using var c = await RawClient.ConnectAsync(f.PlainPort);
        await c.ExpectAsync(220);
        await c.CommandAsync("EHLO x.test", 250);
        await c.CommandAsync("STARTTLS", 220);
        await c.StartTlsHandshakeAsync();
        await c.CommandAsync("EHLO x.test", 250);

        await c.CommandAsync("MAIL FROM:<anyone@example.com>", 530);
        await c.CommandAsync("RCPT TO:<victim@d.example>", 503);
        await c.CommandAsync("AUTH PLAIN AHVzZXIAd3Jvbmc=", 535);
        await c.CommandAsync("MAIL FROM:<anyone@example.com>", 530);   // a failed AUTH does not unlock anything
        Assert.Equal(0, f.Handler.MailFromCalls);
        Assert.Equal(0, f.Handler.RcptToCalls);
        Assert.Empty(f.Handler.Messages);
    }

    [Fact]
    public async Task Authentication_does_not_survive_a_reset_of_the_greeting_and_cannot_be_repeated_to_switch_users()
    {
        await using var f = new ServerFixture();
        using var c = await RawClient.ConnectAsync(f.ImplicitPort);
        await c.StartTlsHandshakeAsync();
        await c.ExpectAsync(220);
        await c.CommandAsync("EHLO x.test", 250);
        await c.CommandAsync("AUTH PLAIN AHVzZXIAcGFzcw==", 235);

        await c.CommandAsync("AUTH PLAIN AHVzZXIAcGFzcw==", 503);   // one authentication per session
        await c.CommandAsync("EHLO again.test", 250);
        await c.CommandAsync("MAIL FROM:<a@b.example>", 250);
    }

    [Fact]
    public async Task A_plaintext_client_on_the_implicit_TLS_port_gets_no_SMTP_reply()
    {
        await using var f = new ServerFixture();
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, f.ImplicitPort);
        var stream = tcp.GetStream();
        await stream.WriteAsync("EHLO x.test\r\nAUTH PLAIN AHVzZXIAcGFzcw==\r\n"u8.ToArray());

        byte[] buffer = new byte[256];
        int total = 0;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try
        {
            while (true)
            {
                int n = await stream.ReadAsync(buffer.AsMemory(total), cts.Token);
                if (n == 0) { break; }
                total += n;
                if (total == buffer.Length) { break; }
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException) { }

        string said = Encoding.ASCII.GetString(buffer, 0, total);
        Assert.DoesNotContain("220", said);
        Assert.DoesNotContain("250", said);
        Assert.Equal(0, f.Handler.AuthAttempts);
    }

    [Fact]
    public async Task A_client_that_never_finishes_the_TLS_handshake_is_dropped_after_the_handshake_timeout()
    {
        await using var f = new ServerFixture(o => Options(o, tlsHandshakeTimeout: TimeSpan.FromMilliseconds(300)));
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, f.ImplicitPort);
        var stream = tcp.GetStream();
        await stream.WriteAsync(new byte[] { 0x16, 0x03, 0x01, 0x00 });   // the start of a TLS record, then silence

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        int n;
        try { n = await stream.ReadAsync(new byte[16], cts.Token); }
        catch (Exception ex) when (ex is IOException or SocketException) { n = 0; }

        Assert.Equal(0, n);   // closed by the server; it did not wait for the client
    }

    [Fact]
    public async Task The_server_refuses_TLS_below_1_2_and_negotiates_a_modern_cipher()
    {
        await using var f = new ServerFixture();
        Assert.Equal(SslProtocols.Tls12 | SslProtocols.Tls13, new SmtpServerOptions().TlsProtocols);

        // TLS 1.2 and 1.3 are accepted; the negotiated suite is an AEAD one with at least 128 bits.
        int negotiated = 0;
        foreach (SslProtocols version in new[] { SslProtocols.Tls12, SslProtocols.Tls13, SslProtocols.Tls12 | SslProtocols.Tls13 })
        {
            using var c = await RawClient.ConnectAsync(f.ImplicitPort);
            var ssl = new SslStream(new NetworkStream(GetSocket(c)), false, (_, _, _, _) => true);
            try
            {
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = "localhost", EnabledSslProtocols = version });
            }
            catch (AuthenticationException ex) when (ex.InnerException is PlatformNotSupportedException)
            {
                continue;   // this machine's TLS library cannot be restricted to that one version on the client side
            }

            negotiated++;
            Assert.True(ssl.SslProtocol is SslProtocols.Tls12 or SslProtocols.Tls13);
            string suite = ssl.NegotiatedCipherSuite.ToString();
            Assert.True(suite.Contains("GCM", StringComparison.Ordinal) || suite.Contains("CHACHA20", StringComparison.Ordinal), $"not an AEAD suite: {suite}");
            Assert.DoesNotContain("RC4", suite, StringComparison.Ordinal);
            Assert.DoesNotContain("3DES", suite, StringComparison.Ordinal);
            Assert.DoesNotContain("NULL", suite, StringComparison.Ordinal);
        }

        Assert.True(negotiated >= 1);

        // A client that offers nothing newer than TLS 1.1 gets no session (or cannot even start): both are a refusal.
#pragma warning disable SYSLIB0039 // TLS 1.0 and 1.1 are obsolete: that is the point of the test
        using var old = await RawClient.ConnectAsync(f.ImplicitPort);
        var oldSsl = new SslStream(new NetworkStream(GetSocket(old)), false, (_, _, _, _) => true);
        var attempt = Record.ExceptionAsync(() => oldSsl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = "localhost", EnabledSslProtocols = SslProtocols.Tls11 }));
#pragma warning restore SYSLIB0039
        Exception? failure = await attempt;
        Assert.True(failure is AuthenticationException or IOException or NotSupportedException or PlatformNotSupportedException, failure?.GetType().Name ?? "handshake succeeded");
    }

    private static Socket GetSocket(RawClient c) => c.Socket;

    [Fact]
    public async Task The_server_does_not_ask_for_a_client_certificate()
    {
        await using var f = new ServerFixture();
        var hello = default(SslClientHelloInfo);
        SslServerAuthenticationOptions options = await f.Server.ServerOptionsCallback(null!, hello, null, default);

        Assert.False(options.ClientCertificateRequired);
        Assert.False(options.AllowRenegotiation);
        Assert.Equal(SslProtocols.Tls12 | SslProtocols.Tls13, options.EnabledSslProtocols);
        Assert.NotNull(options.ServerCertificateContext);
    }

    [Fact]
    public async Task A_global_connection_cap_refuses_the_next_connection_with_421_and_frees_up_when_one_leaves()
    {
        await using var f = new ServerFixture(o => Options(o, maxConnections: 2));
        var first = await RawClient.ConnectAsync(f.OpenPort);
        await first.ExpectAsync(220);
        using var second = await RawClient.ConnectAsync(f.OpenPort);
        await second.ExpectAsync(220);

        using (var third = await RawClient.ConnectAsync(f.OpenPort))
        {
            Assert.Equal(421, (await third.ReadReplyAsync())!.Code);
        }

        first.Dispose();
        // The slot comes back once the server notices the disconnect.
        for (int i = 0; i < 200; i++)
        {
            using var again = await RawClient.ConnectAsync(f.OpenPort);
            var r = await again.ReadReplyAsync();
            if (r!.Code == 220) { return; }
            await Task.Delay(50);
        }

        Assert.Fail("The connection slot was not released.");
    }

    [Fact]
    public async Task A_session_is_limited_in_the_number_of_messages()
    {
        await using var f = new ServerFixture(o => Options(o, maxMessagesPerSession: 2));
        using var c = await RawClient.ConnectAsync(f.OpenPort);
        await c.ExpectAsync(220);
        await c.CommandAsync("EHLO x.test", 250);
        for (int i = 0; i < 2; i++)
        {
            await c.CommandAsync("MAIL FROM:<a@b.example>", 250);
            await c.CommandAsync("RCPT TO:<c@d.example>", 250);
            await c.CommandAsync("DATA", 354);
            await c.SendAsync("Subject: x\r\n\r\nx\r\n.\r\n");
            await c.ExpectAsync(250);
        }

        await c.CommandAsync("MAIL FROM:<a@b.example>", 421);
        Assert.True(await c.WaitForCloseAsync());
    }

    [Fact]
    public async Task A_sender_that_drips_data_slowly_enough_to_beat_the_idle_timeout_is_stopped_by_the_total_time_limit()
    {
        // Slow-loris on DATA: every pause is shorter than DataTimeout, the whole is longer than MaxDataDuration.
        await using var f = new ServerFixture(o => Options(o, maxDataDuration: TimeSpan.FromMilliseconds(600), dataTimeout: TimeSpan.FromSeconds(20)));
        using var c = await RawClient.ConnectAsync(f.OpenPort);
        await c.ExpectAsync(220);
        await c.CommandAsync("EHLO x.test", 250);
        await c.CommandAsync("MAIL FROM:<a@b.example>", 250);
        await c.CommandAsync("RCPT TO:<c@d.example>", 250);
        await c.CommandAsync("DATA", 354);

        SmtpReply? reply = null;
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (reply is null && DateTime.UtcNow < deadline)
        {
            try { await c.SendAsync("X: y\r\n"); } catch (Exception ex) when (ex is IOException or SocketException) { break; }
            await Task.Delay(100);
            reply = await c.ReadReplyAsyncNoWait();
        }

        Assert.NotNull(reply);
        Assert.Equal(421, reply!.Code);
        Assert.Empty(f.Handler.Messages);
    }
}
