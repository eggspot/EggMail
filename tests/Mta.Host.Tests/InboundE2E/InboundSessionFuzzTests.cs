using System.Text;
using Mta.Host.Tests.Inbound;
using Mta.Storage;

namespace Mta.Host.Tests.InboundE2E;

/// <summary>
/// A seeded random walk over the dialog of the port-25 listener against the real runtime and stores: sessions made of valid and invalid commands in any order, addresses of every class (a route, a
/// bounce token, an SRS address, an external domain, hostile spellings), bodies of every shape. The properties that must hold whatever the sequence: the server answers every command with a well-formed
/// reply and survives, a stored message exists only for an address a route or the postmaster rule accepts, and nothing at all is queued for sending. The seeds are fixed, so a failure is reproducible.
/// </summary>
public abstract class InboundSessionFuzzTests(LabBackend backend)
{
    private static readonly string[] Recipients =
    [
        "support@example.org", "SUPPORT@example.org", "billing-1@example.org", "old@example.org", "postmaster@example.org", "nobody@example.org", "anyone@example.net", "x@example.net",
        "victim@gmail.test", "support@example.org@gmail.test", "@example.org:victim@gmail.test", "victim%gmail.test@example.org", "\"support\"@example.org", "<support@example.org>", "support@[127.0.0.1]",
        "postmaster@bounces.egg.test", "abuse@bounces.egg.test", "b+invalid@bounces.egg.test", "SRS0=aaaa=bb=cc=dd@example.org", "SRS1=aaaa=bb==cc=dd@example.org", "", "a", "@", "<>",
        "support@example.org ", " support@example.org", "support@example.org\t", "support@EXAMPLE.ORG", new string('a', 70) + "@example.org", "support@" + new string('d', 260),
    ];

    private static readonly string[] Senders = ["bob@sender.test", "", "ceo@example.org", "postmaster@example.org", "\"a b\"@sender.test", "SRS0=zz=yy=x=y@example.org", "x@y", "bob@sender.test> <evil@x.test", new string('s', 80) + "@sender.test"];

    private static readonly string[] Verbs = ["NOOP", "RSET", "VRFY support@example.org", "EXPN list", "HELP", "AUTH PLAIN AAAA", "STARTTLS", "XYZZY", "MAIL", "RCPT", "DATA", "BDAT x", "BDAT -1", "BDAT 0 LAST", "EHLO", "HELO x", "QUIT"];

    private static string Body(Random random)
    {
        string head = $"From: bob@sender.test\r\nTo: support@example.org\r\nSubject: fuzz {random.Next()}\r\nMessage-ID: <{Guid.NewGuid():N}@sender.test>\r\n";
        return random.Next(8) switch
        {
            0 => head + "\r\n",
            1 => head + "\r\n" + new string('x', random.Next(1, 5_000)) + "\r\n",
            2 => "\r\n.\r\nMAIL FROM:<evil@x.test>\r\nRCPT TO:<victim@gmail.test>\r\nDATA\r\nx\r\n.\r\n",
            3 => head + "X-EggMail-Hops: 99; deadbeefdeadbeef\r\nAuthentication-Results: mx.egg.test; dmarc=pass\r\n\r\nbody\r\n",
            4 => "bad start\r\n\r\nbody\r\n",
            5 => " starts with space\r\n\r\nbody\r\n",
            6 => string.Concat(Enumerable.Range(0, random.Next(1, 40)).Select(i => $"Received: from h{i}.test by x.test; Fri, 16 Oct 2026 12:00:00 +0000\r\n")) + head + "\r\nb\r\n",
            _ => head + "\r\nbody\r\n",
        };
    }

    [Theory]
    [InlineData(11)]
    [InlineData(2026)]
    [InlineData(987654321)]
    [InlineData(31337)]
    [InlineData(7)]
    public async Task No_sequence_of_commands_makes_the_server_relay_crash_or_store_mail_no_route_accepts(int seed)
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend, new LabOptions
        {
            Inbound = new Mta.Host.Configuration.InboundSection { Enabled = true, CheckSpfForInternalClients = true, MaxMessagesPerMinute = 1_000_000, MaxMessagesPerMinutePerRemote = 1_000_000, MaxRecipients = 5 },
        });
        if (lab is null)
        {
            return;
        }

        var random = new Random(seed);
        int sessions = 60;
        for (int s = 0; s < sessions; s++)
        {
            await using FakeMta mta = await lab.ConnectAsync();
            var transcript = new List<string>();
            bool open = true;
            int steps = random.Next(3, 25);
            for (int i = 0; i < steps && open; i++)
            {
                string line;
                switch (random.Next(10))
                {
                    case 0 or 1:
                        line = $"MAIL FROM:<{Senders[random.Next(Senders.Length)]}>{(random.Next(6) == 0 ? " SIZE=" + random.Next(0, 100_000) : "")}{(random.Next(12) == 0 ? " BODY=8BITMIME" : "")}{(random.Next(20) == 0 ? " AUTH=<>" : "")}";
                        break;
                    case 2 or 3 or 4:
                        line = $"RCPT TO:<{Recipients[random.Next(Recipients.Length)]}>{(random.Next(15) == 0 ? " NOTIFY=SUCCESS" : "")}";
                        break;
                    case 5 or 6:
                        line = "DATA";
                        break;
                    case 7:
                        line = "EHLO " + (random.Next(3) == 0 ? "bad name" : "mail.sender.test");
                        break;
                    default:
                        line = Verbs[random.Next(Verbs.Length)];
                        break;
                }

                transcript.Add(line);
                try
                {
                    FakeMta.Reply reply = await mta.CommandAsync(line);
                    Assert.InRange(reply.Code, 200, 599);
                    if (reply.Code == 354)
                    {
                        string body = Body(random);
                        await mta.SendRawAsync(body.Replace("\r\n.", "\r\n..", StringComparison.Ordinal) + ".\r\n");
                        FakeMta.Reply done = await mta.ReadReplyAsync();
                        Assert.InRange(done.Code, 200, 599);
                    }

                    if (reply.Code == 421 || (line == "QUIT" && reply.Code == 221))
                    {
                        open = false;
                    }
                }
                catch (Exception ex) when (ex is EndOfStreamException or IOException or System.Net.Sockets.SocketException)
                {
                    open = false;   // a closed connection is a legal answer to nonsense
                }
                catch (OperationCanceledException)
                {
                    throw new Xunit.Sdk.XunitException($"seed {seed}, session {s}: no answer after: " + string.Join(" | ", transcript));
                }
            }
        }

        // The server is up and serves a normal message after all that.
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message(subject: "after the fuzz"))).Code);

        // Properties.
        var routesOf = new Dictionary<Guid, IReadOnlyList<InboundRouteRecord>>
        {
            [lab.ExampleOrg] = await lab.Storage.Inbound.GetRoutesAsync(lab.ExampleOrg, default),
            [lab.ExampleNet] = await lab.Storage.Inbound.GetRoutesAsync(lab.ExampleNet, default),
        };
        foreach ((Guid tenant, Guid domain, string name) in new[] { (InboundLab.Acme, lab.ExampleOrg, "example.org"), (InboundLab.Globex, lab.ExampleNet, "example.net") })
        {
            foreach (InboundMessage m in await lab.MessagesAsync(tenant, new InboundMessageQuery(tenant, Limit: 200)))
            {
                int at = m.EnvelopeTo.LastIndexOf('@');
                Assert.Equal(name, m.EnvelopeTo[(at + 1)..]);   // only ever for a domain of the tenant
                Assert.Equal(domain, m.DomainId);
                string local = m.EnvelopeTo[..at];
                bool handled = Mta.Storage.Logic.InboundRules.MatchRoute(routesOf[domain], local) is not null || Mta.Storage.Logic.InboundRules.IsPostmaster(local);
                Assert.True(handled, $"{m.EnvelopeTo} was stored and no route or rule accepts it");
                Assert.Equal(m.EnvelopeTo, m.EnvelopeTo.ToLowerInvariant());
                Assert.True(m.HasRaw == (m.ActionKind != InboundActionKind.Discard));
            }
        }

        await lab.AssertNothingWasSentAsync();
        Assert.False(await lab.Storage.Config.IsSuppressedAsync(InboundLab.Acme, "evil@x.test", default));
        lab.AssertNoErrorsLogged();   // nothing the sequences did made the receive path fail on its own
    }
}

public sealed class SqliteInboundSessionFuzzTests() : InboundSessionFuzzTests(LabBackend.Sqlite);

public sealed class PostgresInboundSessionFuzzTests() : InboundSessionFuzzTests(LabBackend.Postgres);
