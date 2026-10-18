using System.Text;
using Mta.Host.Configuration;
using Mta.Host.Tests.Api;
using Mta.Host.Tests.Inbound;
using Mta.Smtp.Server;
using Mta.Storage;

namespace Mta.Host.Tests.InboundE2E;

/// <summary>
/// The SMTP-level defences of the port-25 listener through a real runtime: end-of-data smuggling (DATA and BDAT), STARTTLS (offered, command injection, plaintext buffered behind it), declared and
/// actual size, and what a refused or abandoned message leaves behind in the stores. The byte-level cases are also in <c>Smtp.Server.Tests</c> and <c>Inbound/InboundSecurityTests</c>; here they run
/// against the listener as the host configures it, with the stores that keep the mail.
/// </summary>
public abstract class InboundProtocolTests(LabBackend backend)
{
    private const string Victim = "postmaster@example.net";   // a recipient of another tenant: a command smuggled into the stream would put a message here

    private static string Smuggled() => $"MAIL FROM:<evil@sender.test>\r\nRCPT TO:<{Victim}>\r\nDATA\r\nSubject: smuggled\r\n\r\nsmuggled body\r\n.\r\n";

    public static IEnumerable<object[]> SmugglingPayloads()
    {
        // The body stops in the middle of a line, so each of these is a forged terminator: none of them is CRLF "." CRLF.
        string header = "Subject: x\r\n\r\nbody";
        foreach (string terminator in new[] { "\n.\r\n", "\r\n.\n", "\n.\n", "\r.\r", "\r\n.\r", "\r.\r\n", "\r\n.\r\r\n", "\r\n.\0\r\n", "\r\n\0.\r\n", "\r\n.\n\r", "\r\n .\r\n" })
        {
            yield return [terminator.Replace("\r", "<CR>", StringComparison.Ordinal).Replace("\n", "<LF>", StringComparison.Ordinal).Replace("\0", "<NUL>", StringComparison.Ordinal), header + terminator + Smuggled()];
        }

        yield return ["bare LF in a header", "Subject: x\nX-Injected: 1\r\n\r\nbody\r\n.\r\n" + Smuggled()];
        yield return ["bare CR in the body", "Subject: x\r\n\r\nbo\rdy\r\n.\r\n" + Smuggled()];
        yield return ["NUL in the body", "Subject: x\r\n\r\nbo\0dy\r\n.\r\n" + Smuggled()];
    }

    [Theory]
    [MemberData(nameof(SmugglingPayloads))]
    public async Task A_smuggled_end_of_data_never_runs_a_command_and_never_stores_the_second_message(string name, string payload)
    {
        _ = name;
        await using InboundLab? lab = await InboundLab.StartAsync(backend);
        if (lab is null)
        {
            return;
        }

        await using FakeMta mta = await lab.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);
        Assert.Equal(354, (await mta.CommandAsync("DATA")).Code);
        await mta.SendRawAsync(payload);
        await DrainAsync(mta);

        // Whatever the server made of the bytes (a refusal of the whole message, or one message in which the bytes after a line that merely looks like a terminator are body text), the part after
        // the forged terminator was not a command: nothing was sent from the smuggled sender, and nothing reached the other tenant.
        Assert.Empty(await lab.MessagesAsync(InboundLab.Globex));
        foreach (InboundMessage m in await lab.MessagesAsync(InboundLab.Acme))
        {
            Assert.Equal("bob@sender.test", m.EnvelopeFrom);
            Assert.Equal("support@example.org", m.EnvelopeTo);
        }

        await lab.AssertNothingWasSentAsync();
    }

    [Fact]
    public async Task A_message_that_is_sent_one_byte_at_a_time_is_stored_once_and_unchanged_and_a_terminator_split_across_writes_is_still_refused()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend);
        if (lab is null)
        {
            return;
        }

        string message = InboundLab.Message(subject: "slow", body: "a\r\n.b\r\n..c\r\n");
        await using (FakeMta mta = await lab.ConnectedAsync())
        {
            Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
            Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);
            Assert.Equal(354, (await mta.CommandAsync("DATA")).Code);
            foreach (char c in message.Replace("\r\n.b", "\r\n..b", StringComparison.Ordinal).Replace("\r\n..c", "\r\n...c", StringComparison.Ordinal) + ".\r\n")
            {
                await mta.SendRawAsync(c.ToString());
            }

            Assert.Equal(250, (await mta.ReadReplyAsync()).Code);
        }

        Assert.EndsWith(message, await lab.RawAsync(Assert.Single(await lab.MessagesAsync(InboundLab.Acme))), StringComparison.Ordinal);

        await using (FakeMta forged = await lab.ConnectedAsync())
        {
            Assert.Equal(250, (await forged.MailFromAsync("bob@sender.test")).Code);
            Assert.Equal(250, (await forged.RcptAsync("support@example.org")).Code);
            Assert.Equal(354, (await forged.CommandAsync("DATA")).Code);
            foreach (string piece in new[] { "Subject: x\r\n\r\nbody", "\n", ".", "\r", "\n", Smuggled() })
            {
                await forged.SendRawAsync(piece);
            }

            await DrainAsync(forged);
        }

        Assert.Single(await lab.MessagesAsync(InboundLab.Acme));
        Assert.Empty(await lab.MessagesAsync(InboundLab.Globex));
    }

    [Fact]
    public async Task Commands_pipelined_after_the_real_terminator_run_as_new_transactions_and_never_join_the_body()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend);
        if (lab is null)
        {
            return;
        }

        await using FakeMta mta = await lab.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);
        Assert.Equal(354, (await mta.CommandAsync("DATA")).Code);
        string first = InboundLab.Message(subject: "first");
        string second = InboundLab.Message(subject: "second", to: Victim);
        await mta.SendRawAsync(first + ".\r\nMAIL FROM:<carol@sender.test>\r\nRCPT TO:<" + Victim + ">\r\nDATA\r\n");
        Assert.Equal(250, (await mta.ReadReplyAsync()).Code);
        Assert.Equal(250, (await mta.ReadReplyAsync()).Code);
        Assert.Equal(250, (await mta.ReadReplyAsync()).Code);
        Assert.Equal(354, (await mta.ReadReplyAsync()).Code);
        await mta.SendRawAsync(second + ".\r\n");
        Assert.Equal(250, (await mta.ReadReplyAsync()).Code);

        Assert.Equal("first", Assert.Single(await lab.MessagesAsync(InboundLab.Acme)).Subject);
        InboundMessage victim = Assert.Single(await lab.MessagesAsync(InboundLab.Globex));
        Assert.Equal(("carol@sender.test", "second"), (victim.EnvelopeFrom, victim.Subject));
        Assert.DoesNotContain("second", await lab.RawAsync(Assert.Single(await lab.MessagesAsync(InboundLab.Acme))), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Subject: x\r\n\r\nline\nbare\r\n", false)]
    [InlineData("Subject: x\r\n\r\nline\rbare\r\n", false)]
    [InlineData("Subject: x\r\n\r\nnul\0here\r\n", false)]
    [InlineData("Subject: x\r\n\r\nbody\r\n.\r\n", true)]
    [InlineData("Subject: x\r\n\r\nbody\n.\r\n", false)]
    public async Task A_bdat_chunk_with_a_bare_line_ending_or_a_nul_is_refused_and_a_dot_line_inside_a_chunk_is_text_not_a_terminator(string start, bool stored)
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend);
        if (lab is null)
        {
            return;
        }

        await using FakeMta mta = await lab.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);
        string body = start + Smuggled();   // the commands are inside the chunk: BDAT's length frames them, so they are body text, whatever they look like
        await mta.SendRawAsync($"BDAT {Encoding.Latin1.GetByteCount(body)} LAST\r\n{body}");
        await DrainAsync(mta);

        Assert.Empty(await lab.MessagesAsync(InboundLab.Globex));
        IReadOnlyList<InboundMessage> acme = await lab.MessagesAsync(InboundLab.Acme);
        if (stored)
        {
            Assert.EndsWith(body, await lab.RawAsync(Assert.Single(acme)), StringComparison.Ordinal);   // the text, whole and inert
        }
        else
        {
            Assert.Empty(acme);
        }
    }

    private static async Task DrainAsync(FakeMta mta)
    {
        // Read whatever the server says until it closes the connection or stops talking (it answers the junk after a refusal with errors, or closes).
        try
        {
            await mta.SendRawAsync("QUIT\r\n");
            while (true)
            {
                FakeMta.Reply reply = await mta.ReadReplyAsync();
                if (reply.Code is 221 or 421)
                {
                    return;
                }
            }
        }
        catch (Exception ex) when (ex is EndOfStreamException or IOException or System.Net.Sockets.SocketException)
        {
        }
    }

    [Theory]
    [InlineData("SIZE=abc", 501)]
    [InlineData("SIZE=-1", 501)]
    [InlineData("SIZE=", 501)]
    [InlineData("SIZE=99999999999999999999999", 501)]   // a number that does not fit is a syntax error, not "too big"
    [InlineData("SIZE=1 SIZE=2", 501)]
    [InlineData("BODY=BINARYMIME", 501)]
    [InlineData("BODY=9BIT", 501)]
    [InlineData("SMTPUTF8=1", 501)]
    [InlineData("RET=FULL", 250)]                      // the DSN parameters are tolerated and ignored (the server never sends a notification for received mail)
    [InlineData("ENVID=x", 250)]
    [InlineData("AUTH=<>", 250)]
    [InlineData("X-UNKNOWN=1", 501)]
    [InlineData("SIZE=100 BODY=8BITMIME SMTPUTF8", 250)]
    public async Task A_mail_parameter_is_accepted_or_refused_with_a_syntax_error_and_the_session_goes_on(string parameters, int expected)
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend);
        if (lab is null)
        {
            return;
        }

        await using FakeMta mta = await lab.ConnectedAsync();
        FakeMta.Reply reply = await mta.MailFromAsync("bob@sender.test", parameters);

        Assert.True(reply.Code == expected || (expected == 501 && reply.Code is 500 or 501 or 504 or 555), $"{parameters}: {reply}");
        // Whatever it said, the session is intact: a new transaction works.
        await mta.CommandAsync("RSET");
        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message())).Code);
        Assert.Single(await lab.MessagesAsync(InboundLab.Acme));
    }

    [Theory]
    [InlineData("")]                                    // no byte at all between DATA and the dot
    [InlineData("\r\n")]                                // only the empty line that ends a header block
    [InlineData("\r\n\r\n\r\n")]
    [InlineData("X")]                                   // one byte that is not a header
    [InlineData("Subject: only a subject\r\n")]        // no empty line, no body, no From
    public async Task A_message_with_next_to_nothing_in_it_is_stored_or_refused_cleanly_and_can_be_read_back(string body)
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend, new LabOptions { WithApi = true });
        if (lab is null)
        {
            return;
        }

        await using FakeMta mta = await lab.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);
        Assert.Equal(354, (await mta.CommandAsync("DATA")).Code);
        await mta.SendRawAsync(body + (body.EndsWith('\n') || body.Length == 0 ? "" : "\r\n") + ".\r\n");
        FakeMta.Reply reply = await mta.ReadReplyAsync();

        Assert.True(reply.Code is 250 or 554, reply.ToString());
        if (reply.Code != 250)
        {
            Assert.Empty(await lab.MessagesAsync(InboundLab.Acme));
            return;
        }

        InboundMessage stored = Assert.Single(await lab.MessagesAsync(InboundLab.Acme));
        string raw = await lab.RawAsync(stored);
        Assert.StartsWith("Received: ", raw, StringComparison.Ordinal);
        Assert.Equal(InboundVerdict.PermError, stored.Auth.Dmarc);   // no usable From
        ApiClient alice = await lab.Api!.SignedInAsync("alice");
        Assert.Equal(System.Net.HttpStatusCode.OK, (await alice.GetAsync("/api/v1/inbound/messages/" + Mta.Host.Api.ApiJson.Id(stored.Id))).Status);
        lab.AssertNoErrorsLogged();
    }

    // ------------------------------------------------------------------ STARTTLS

    [Fact]
    public async Task Starttls_is_offered_with_the_real_certificate_never_required_and_never_comes_with_auth()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend, new LabOptions { Mode = ListenerMode.StartTls });
        if (lab is null)
        {
            return;
        }

        await using (FakeMta tls = await lab.ConnectAsync())
        {
            FakeMta.Reply ehlo = await tls.EhloAsync("mail.sender.test");
            Assert.Contains(ehlo.Lines, l => l.EndsWith("STARTTLS", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(ehlo.Lines, l => l.Contains("AUTH", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(ehlo.Lines, l => l.Contains("SIZE ", StringComparison.OrdinalIgnoreCase));
            Assert.True(await tls.StartTlsAsync());
            ehlo = await tls.EhloAsync("mail.sender.test");
            Assert.DoesNotContain(ehlo.Lines, l => l.Contains("STARTTLS", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(ehlo.Lines, l => l.Contains("AUTH", StringComparison.OrdinalIgnoreCase));   // inbound sessions have no AUTH, not even over TLS
            Assert.Equal(502, (await tls.CommandAsync("AUTH PLAIN AGJvYgBwYXNz")).Code);
            Assert.Equal(250, (await tls.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message(subject: "encrypted"))).Code);
        }

        // Plaintext is accepted as well: a public MX that refuses it loses mail.
        await using (FakeMta plain = await lab.ConnectedAsync())
        {
            Assert.Equal(250, (await plain.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message(subject: "clear"))).Code);
        }

        IReadOnlyList<InboundMessage> stored = await lab.MessagesAsync(InboundLab.Acme);
        Assert.True(stored.Single(m => m.Subject == "encrypted").TlsUsed);
        Assert.False(stored.Single(m => m.Subject == "clear").TlsUsed);
        string raw = await lab.RawAsync(stored.Single(m => m.Subject == "encrypted"));
        Assert.Contains("with ESMTPS", raw[..raw.IndexOf("\r\nAuthentication-Results", StringComparison.Ordinal)], StringComparison.Ordinal);
        Assert.Contains("TLS", raw[..raw.IndexOf("\r\nAuthentication-Results", StringComparison.Ordinal)], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Plaintext_sent_in_the_same_packet_as_starttls_is_never_executed_before_or_after_the_handshake()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend, new LabOptions { Mode = ListenerMode.StartTls });
        if (lab is null)
        {
            return;
        }

        await using FakeMta mta = await lab.ConnectedAsync();
        // CVE-2011-0411 family: commands behind STARTTLS in the same TCP segment. The server must not run them in plaintext, and must not run them after the upgrade either.
        await mta.SendRawAsync($"STARTTLS\r\nMAIL FROM:<evil@sender.test>\r\nRCPT TO:<{Victim}>\r\nDATA\r\nSubject: injected\r\n\r\ninjected\r\n.\r\n");
        bool upgraded;
        try
        {
            FakeMta.Reply reply = await mta.ReadReplyAsync();
            upgraded = reply.Code == 220;
            if (upgraded)
            {
                // The server wrote 220 and nothing else in plaintext; start the handshake.
                var ssl = new System.Net.Security.SslStream(mta.UnderlyingStream, leaveInnerStreamOpen: false, (_, _, _, _) => true);
                await ssl.AuthenticateAsClientAsync("localhost");
                await ssl.WriteAsync(Encoding.ASCII.GetBytes("RSET\r\nQUIT\r\n"));
                var buffer = new byte[2048];
                int n = await ssl.ReadAsync(buffer);
                string text = Encoding.ASCII.GetString(buffer, 0, n);
                Assert.DoesNotContain("354", text, StringComparison.Ordinal);   // no DATA was started on behalf of the injected bytes
            }
        }
        catch (Exception ex) when (ex is IOException or EndOfStreamException or System.Security.Authentication.AuthenticationException)
        {
            // Closing the connection is also a correct answer to an injection attempt.
        }

        Assert.Empty(await lab.MessagesAsync(InboundLab.Globex));
        Assert.Empty(await lab.MessagesAsync(InboundLab.Acme));
        await lab.AssertNothingWasSentAsync();
    }

    // ------------------------------------------------------------------ size

    private static InboundSection WithMaxMessage(long bytes) => new() { Enabled = true, CheckSpfForInternalClients = true, MaxMessageSize = bytes, MaxInFlightBytes = Math.Max(bytes * 8, 1L << 20) };

    [Fact]
    public async Task A_declared_size_over_the_ceiling_is_refused_at_mail_over_a_domains_limit_at_rcpt_and_a_larger_body_than_declared_at_the_end_of_data()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend, new LabOptions { Inbound = WithMaxMessage(40_000) });
        if (lab is null)
        {
            return;
        }

        await lab.SetSettingsAsync(lab.ExampleOrg, InboundLab.Acme, s => s with { MaxMessageBytes = 10_000 });   // example.net keeps the ceiling

        // MAIL FROM ... SIZE= over the ceiling of the listener: the sender is told before it sends anything.
        await using (FakeMta mta = await lab.ConnectedAsync())
        {
            FakeMta.Reply big = await mta.MailFromAsync("bob@sender.test", "SIZE=50000");
            Assert.Equal((552, "5.3.4"), (big.Code, big.Enhanced));

            // Within the ceiling but over this domain's limit: refused for that recipient (at RCPT), accepted for the domain without a limit of its own.
            Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test", "SIZE=20000")).Code);
            FakeMta.Reply rcpt = await mta.RcptAsync("support@example.org");
            Assert.Equal((552, "5.3.4"), (rcpt.Code, rcpt.Enhanced));
            Assert.Equal(250, (await mta.RcptAsync("anyone@example.net")).Code);
            Assert.Equal(250, (await mta.DataAsync(InboundLab.Message(to: "anyone@example.net", body: new string('x', 19_000) + "\r\n"))).Code);
        }

        // No SIZE at all and a body over the domain's limit: refused at the end of DATA, the connection stays usable.
        await using (FakeMta mta = await lab.ConnectedAsync())
        {
            Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
            Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);
            FakeMta.Reply refused = await mta.DataAsync(InboundLab.Message(body: new string('y', 12_000) + "\r\n"));
            Assert.Equal((552, "5.3.4"), (refused.Code, refused.Enhanced));
            Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message(subject: "small after big"))).Code);
        }

        // A client that declares less than it sends is held to the real size, too.
        await using (FakeMta liar = await lab.ConnectedAsync())
        {
            Assert.Equal(250, (await liar.MailFromAsync("bob@sender.test", "SIZE=500")).Code);
            Assert.Equal(250, (await liar.RcptAsync("support@example.org")).Code);
            Assert.Equal(552, (await liar.DataAsync(InboundLab.Message(body: new string('z', 11_000) + "\r\n"))).Code);
        }

        Assert.Equal(["small after big"], (await lab.MessagesAsync(InboundLab.Acme)).Select(m => m.Subject!).ToArray());
        Assert.Single(await lab.MessagesAsync(InboundLab.Globex));
        await lab.AssertNothingWasSentAsync();
    }

    [Fact]
    public async Task A_message_of_exactly_the_limit_is_stored_and_one_byte_more_is_refused_and_bdat_obeys_the_same_limit()
    {
        const int Limit = 8_192;
        await using InboundLab? lab = await InboundLab.StartAsync(backend, new LabOptions { Inbound = WithMaxMessage(Limit) });
        if (lab is null)
        {
            return;
        }

        string Sized(int total, string subject)
        {
            string head = InboundLab.Message(subject: subject, body: "");
            return head + new string('a', total - head.Length - 2) + "\r\n";
        }

        string exact = Sized(Limit, "exact");
        string over = Sized(Limit + 1, "over");
        Assert.Equal(Limit, Encoding.ASCII.GetByteCount(exact));

        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", exact)).Code);
        Assert.Equal(552, (await lab.SendAsync("bob@sender.test", "support@example.org", over)).Code);

        await using FakeMta chunked = await lab.ConnectedAsync();
        Assert.Equal(250, (await chunked.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(250, (await chunked.RcptAsync("support@example.org")).Code);
        await chunked.SendRawAsync($"BDAT {over.Length} LAST\r\n{over}");
        Assert.Equal(552, (await chunked.ReadReplyAsync()).Code);
        Assert.Equal(["exact"], (await lab.MessagesAsync(InboundLab.Acme)).Select(m => m.Subject!).ToArray());
    }
}

public sealed class SqliteInboundProtocolTests() : InboundProtocolTests(LabBackend.Sqlite);

public sealed class PostgresInboundProtocolTests() : InboundProtocolTests(LabBackend.Postgres);
