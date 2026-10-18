using System.Text;
using Mta.Host.Tests.Inbound;
using Mta.Smtp.Client;
using Mta.Smtp.Server;
using Mta.Storage;
using MimeKit.Cryptography;

namespace Mta.Host.Tests.InboundE2E;

/// <summary>
/// The receive path end to end through a real runtime on SQLite and on PostgreSQL: a real sending client (the project's SMTP client, the way an MTA connects), the real listener, the real store.
/// Written once; <see cref="SqliteInboundFlowTests"/> and <see cref="PostgresInboundFlowTests"/> run it. The PostgreSQL scenarios return at once when no server is there (and none is promised).
/// </summary>
public abstract class InboundFlowTests(LabBackend backend)
{
    [Fact]
    public async Task A_real_mta_delivers_over_starttls_and_the_stored_copy_is_the_message_with_our_headers_on_top()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend, new LabOptions { Mode = ListenerMode.StartTls });
        if (lab is null)
        {
            return;
        }

        lab.PublishSpf("sender.test");
        lab.PublishDmarc("sender.test", "none");
        string message = InboundFixture.Message(subject: "Quarterly numbers", body: "Line one\r\n.a dotted line\r\n..two dots\r\nlast\r\n");

        var (result, tls) = await RealMta.SendAsync(lab.Port, "bob@sender.test", ["support@example.org"], message, startTls: true);

        Assert.True(result.Delivered);
        Assert.True(tls.Used);
        InboundMessage stored = Assert.Single(await lab.MessagesAsync(InboundLab.Acme));
        Assert.True(stored.TlsUsed);
        Assert.Equal("client.sender.test", stored.Helo);
        Assert.Equal("127.0.0.1", stored.RemoteAddress);
        Assert.Equal(("bob@sender.test", "support@example.org", "Quarterly numbers"), (stored.EnvelopeFrom, stored.EnvelopeTo, stored.Subject));
        Assert.Equal((InboundVerdict.Pass, InboundVerdict.None, InboundActionKind.Store, InboundActionState.Done), (stored.Auth.Spf, stored.Auth.SpfHelo, stored.ActionKind, stored.ActionState));
        Assert.Equal(lab.SupportRoute, stored.RouteId);

        // Our headers on top, in this order; the sender's bytes follow exactly as sent (the dot-stuffing is undone, the body is not altered).
        string raw = await lab.RawAsync(stored);
        Assert.StartsWith("Received: from client.sender.test (", raw);
        int authentication = raw.IndexOf("\r\nAuthentication-Results: mx.egg.test;", StringComparison.Ordinal);
        Assert.True(authentication > 0);
        Assert.True(raw.EndsWith(message, StringComparison.Ordinal), "the received message is a suffix of the stored copy, byte for byte");
        Assert.Equal(stored.Size, Encoding.UTF8.GetByteCount(raw));
        Assert.Contains("with ESMTPS", raw[..authentication], StringComparison.Ordinal);

        // An independent reader (MimeKit) agrees with what the verdicts say.
        int start = authentication + 2;
        string header = raw[start..raw.IndexOf("\r\nFrom:", start, StringComparison.Ordinal)].Replace("\r\n", " ", StringComparison.Ordinal);
        Assert.True(AuthenticationResults.TryParse(Encoding.ASCII.GetBytes(header["Authentication-Results:".Length..]), out AuthenticationResults? parsed));
        Assert.Equal("mx.egg.test", parsed!.AuthenticationServiceIdentifier);
        Assert.Equal(["pass", "none"], parsed.Results.Where(r => r.Method == "spf").Select(r => r.Result).ToArray());   // the MAIL FROM domain, then the HELO name (no record for it)
        Assert.Contains(parsed.Results.First(r => r.Method == "spf").Properties, p => p.PropertyType == "smtp" && p.Property == "mailfrom" && p.Value == "bob@sender.test");
        Assert.Equal("none", parsed.Results.Single(r => r.Method == "dkim").Result);
        Assert.Equal("pass", parsed.Results.Single(r => r.Method == "dmarc").Result);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task A_message_comes_through_data_and_bdat_as_the_same_stored_bytes(bool chunking)
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend);
        if (lab is null)
        {
            return;
        }

        string message = InboundFixture.Message(subject: "Same bytes", body: new string('x', 70_000) + "\r\n.\r\nafter a lone dot\r\n");

        var (result, _) = await RealMta.SendAsync(lab.Port, "bob@sender.test", ["support@example.org"], message, chunking: chunking);

        Assert.True(result.Delivered);
        string raw = await lab.RawAsync(Assert.Single(await lab.MessagesAsync(InboundLab.Acme)));
        Assert.EndsWith(message, raw, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Each_kind_of_recipient_gets_the_documented_reply_and_only_the_routed_ones_are_stored()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend);
        if (lab is null)
        {
            return;
        }

        // One transaction with every kind of recipient: the server answers each one and accepts the message for the accepted ones only.
        await using SmtpClientConnection connection = await SmtpClientConnection.ConnectAsync(RealMta.Target(lab.Port), RealMta.Options());
        string[] recipients =
        [
            "support@example.org", "SUPPORT@EXAMPLE.ORG", "billing-7@example.org", "old@example.org", "nobody@example.org", "postmaster@example.org",
            "anyone@example.net", "someone@gmail.test", "user@registered.elsewhere.test",
        ];
        SmtpSendResult result = await connection.SendAsync(RealMta.Envelope("bob@sender.test", recipients), Encoding.UTF8.GetBytes(InboundLab.Message(to: "many@example.org")));

        Assert.True(result.Delivered);
        string[] expected = ["250", "250", "250", "250", "550 5.1.1", "250", "250", "550 5.7.1", "550 5.7.1"];
        Assert.Equal(expected, result.Recipients.Select(r => r.Reply.Code == 250 ? "250" : $"{r.Reply.Code} {r.Reply.EnhancedCode}").ToArray());

        IReadOnlyList<InboundMessage> acme = await lab.MessagesAsync(InboundLab.Acme);
        Assert.Equal(
            ["billing-7@example.org", "old@example.org", "postmaster@example.org", "support@example.org"],
            acme.Select(m => m.EnvelopeTo).Distinct().Order(StringComparer.Ordinal).ToArray());
        Assert.Equal(4, acme.Count);   // the mailbox named twice (in two cases) is two RCPT commands and one delivery
        InboundMessage globex = Assert.Single(await lab.MessagesAsync(InboundLab.Globex));
        Assert.Equal("anyone@example.net", globex.EnvelopeTo);
    }

    [Fact]
    public async Task A_refused_recipient_stores_nothing_and_creates_no_message_of_any_kind()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend);
        if (lab is null)
        {
            return;
        }

        foreach ((string rcpt, int code, string enhanced) in new[]
        {
            ("nobody@example.org", 550, "5.1.1"), ("x@unknown.test", 550, "5.7.1"), ("x@gmail.test", 550, "5.7.1"), ("x@bounces.egg.test", 550, "5.1.1"), ("x@sub.example.org", 550, "5.7.1"),
        })
        {
            await using FakeMta mta = await lab.ConnectedAsync();
            FakeMta.Reply reply = await mta.SendAsync("bob@sender.test", rcpt, InboundLab.Message());
            Assert.Equal((code, enhanced), (reply.Code, reply.Enhanced));
        }

        Assert.Empty(await lab.MessagesAsync(InboundLab.Acme));
        Assert.Empty(await lab.MessagesAsync(InboundLab.Globex));
        await lab.AssertNothingWasSentAsync();
    }
}

public sealed class SqliteInboundFlowTests() : InboundFlowTests(LabBackend.Sqlite);

public sealed class PostgresInboundFlowTests() : InboundFlowTests(LabBackend.Postgres);
