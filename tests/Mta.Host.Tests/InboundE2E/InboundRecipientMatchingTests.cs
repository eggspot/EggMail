using Mta.Host.Api;
using Mta.Host.Tests.Api;
using Mta.Host.Tests.Inbound;
using Mta.Smtp.Server;
using Mta.Storage;

namespace Mta.Host.Tests.InboundE2E;

public abstract class InboundRecipientMatchingTests(LabBackend backend)
{
    [Fact]
    public async Task The_route_test_of_the_api_gives_the_reply_the_receive_path_gives_for_every_way_of_writing_an_address()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend, new LabOptions { WithApi = true, Mode = ListenerMode.Plain });
        if (lab is null)
        {
            return;
        }

        await lab.AddRouteAsync(lab.ExampleOrg, InboundLab.Acme, 40, InboundMatchKind.Address, "sales", InboundActionKind.Store, plus: true);
        await lab.AddRouteAsync(lab.ExampleOrg, InboundLab.Acme, 50, InboundMatchKind.Wildcard, "*-team", InboundActionKind.Store);
        await lab.AddRouteAsync(lab.ExampleOrg, InboundLab.Acme, 60, InboundMatchKind.Address, "closed", InboundActionKind.Store, enabled: false);
        await lab.AddRouteAsync(lab.ExampleOrg, InboundLab.Acme, 70, InboundMatchKind.Wildcard, "a*b*c", InboundActionKind.Store);
        Guid idn = await lab.AddDomainAsync(InboundLab.Globex, "xn--bcher-kva.example");
        await lab.AddRouteAsync(idn, InboundLab.Globex, 10, InboundMatchKind.CatchAll, null, InboundActionKind.Store);
        await lab.RefreshAsync();

        (string Address, string Domain)[] cases =
        [
            ("support@example.org", "example.org"), ("SUPPORT@EXAMPLE.ORG", "example.org"), ("Support@Example.Org", "example.org"),
            ("support+tag@example.org", "example.org"),
            ("sales@example.org", "example.org"), ("sales+q4@example.org", "example.org"), ("sales+@example.org", "example.org"), ("+sales@example.org", "example.org"),
            ("billing-1@example.org", "example.org"), ("billing-@example.org", "example.org"), ("billing@example.org", "example.org"), ("BILLING-X@example.org", "example.org"),
            ("dev-team@example.org", "example.org"), ("-team@example.org", "example.org"), ("team@example.org", "example.org"), ("dev-teams@example.org", "example.org"),
            ("abc@example.org", "example.org"), ("aXbYc@example.org", "example.org"), ("ab@example.org", "example.org"), ("acb@example.org", "example.org"),
            ("closed@example.org", "example.org"), ("old@example.org", "example.org"), ("nobody@example.org", "example.org"),
            ("postmaster@example.org", "example.org"), ("POSTMASTER@example.org", "example.org"), ("postmaster+x@example.org", "example.org"), ("abuse@example.org", "example.org"),
            ("\"support\"@example.org", "example.org"), ("sup.port@example.org", "example.org"),
            ("anyone@bücher.example", "bücher.example"), ("anyone@xn--bcher-kva.example", "bücher.example"), ("anyone@BÜCHER.example", "bücher.example"),
        ];

        ApiClient api = await lab.Api!.SignedInAsync("alice");
        ApiClient globexApi = await lab.Api.SignedInAsync("bob");
        foreach ((string address, string domainName) in cases)
        {
            bool globex = domainName != "example.org";
            Guid domainId = globex ? idn : lab.ExampleOrg;
            Reply match = await (globex ? globexApi : api).GetAsync($"/api/v1/domains/{ApiJson.Id(domainId)}/inbound/routes/match?address={Uri.EscapeDataString(address)}");
            await using FakeMta mta = await lab.ConnectedAsync();
            Assert.Equal(250, (await mta.CommandAsync($"MAIL FROM:<bob@sender.test>{(address.Any(c => c > 127) ? " SMTPUTF8" : "")}")).Code);
            FakeMta.Reply wire = await mta.CommandAsync($"RCPT TO:<{address}>", utf8: address.Any(c => c > 127));
            string wireText = wire.Code == 250 ? "250" : $"{wire.Code} {wire.Enhanced}";

            if (match.Status != System.Net.HttpStatusCode.OK)
            {
                Assert.True(wire.Code != 250 || address.Contains('"', StringComparison.Ordinal) || address.EndsWith('.') || address.Contains('Ü', StringComparison.Ordinal) || address.Contains("xn--", StringComparison.Ordinal),
                    $"{address}: the API refused the probe ({match.Status}) and the receive path answered {wireText}");
                continue;
            }

            string apiText = match.Str("reply");
            Assert.True(apiText == wireText, $"{address}: the API says '{apiText}', the receive path answers '{wireText}'");
        }
    }

    [Fact]
    public async Task A_fully_qualified_name_with_a_trailing_dot_and_an_international_name_in_either_form_reach_the_same_route_and_a_look_alike_does_not()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend);
        if (lab is null)
        {
            return;
        }

        Guid idn = await lab.AddDomainAsync(InboundLab.Globex, "xn--bcher-kva.example");
        await lab.AddRouteAsync(idn, InboundLab.Globex, 10, InboundMatchKind.CatchAll, null, InboundActionKind.Store);
        await lab.RefreshAsync();

        async Task<FakeMta.Reply> TryAsync(string recipient, bool utf8 = false)
        {
            await using FakeMta mta = await lab.ConnectedAsync();
            await mta.CommandAsync($"MAIL FROM:<bob@sender.test>{(utf8 ? " SMTPUTF8" : "")}");
            return await mta.CommandAsync($"RCPT TO:<{recipient}>", utf8);
        }

        Assert.Equal(250, (await TryAsync("x@xn--bcher-kva.example")).Code);
        foreach (string dotted in new[] { "support@example.org.", "support@EXAMPLE.ORG.", "x@xn--bcher-kva.example." })
        {
            FakeMta.Reply reply = await TryAsync(dotted);
            Assert.True(reply.Code is 250 or (>= 500 and < 600), $"{dotted}: {reply}");
            if (reply.Code == 250)
            {
                Assert.Equal(250, (await lab.SendAsync("bob@sender.test", dotted, InboundLab.Message(subject: "dotted " + dotted))).Code);
            }
        }

        Assert.All(await lab.MessagesAsync(InboundLab.Acme), m => Assert.Equal("support@example.org", m.EnvelopeTo));
        Assert.All(await lab.MessagesAsync(InboundLab.Globex), m => Assert.Equal("x@xn--bcher-kva.example", m.EnvelopeTo));
        await lab.Storage.Inbound.DeleteMatchingAsync(new InboundMessageQuery(InboundLab.Acme, Recipient: "support@example.org"), default);
        await lab.Storage.Inbound.DeleteMatchingAsync(new InboundMessageQuery(InboundLab.Globex, Recipient: "x@xn--bcher-kva.example"), default);

        Assert.Equal(250, (await TryAsync("x@bücher.example", utf8: true)).Code);
        Assert.Equal(250, (await TryAsync("x@BÜCHER.example", utf8: true)).Code);

        foreach (string refused in new[] { "support@еxample.org", "x@bücher.example.evil.test", "x@sub.bücher.example", "support@example.org..", "support@.example.org", "support@example.org.evil.test" })
        {
            FakeMta.Reply reply = await TryAsync(refused, utf8: true);
            Assert.True(reply.Code is >= 500 and < 600, $"{refused}: {reply}");
        }

        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "x@xn--bcher-kva.example", InboundLab.Message(subject: "a-label"))).Code);
        InboundMessage stored = Assert.Single(await lab.MessagesAsync(InboundLab.Globex));
        Assert.Equal("x@xn--bcher-kva.example", stored.EnvelopeTo);
        Assert.Empty(await lab.MessagesAsync(InboundLab.Acme));
    }
}

public sealed class SqliteInboundRecipientMatchingTests() : InboundRecipientMatchingTests(LabBackend.Sqlite);

public sealed class PostgresInboundRecipientMatchingTests() : InboundRecipientMatchingTests(LabBackend.Postgres);
