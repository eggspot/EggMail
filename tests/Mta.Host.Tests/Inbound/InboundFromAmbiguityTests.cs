using System.Text;
using Mta.Host.Ingest;
using Mta.Storage;

namespace Mta.Host.Tests.Inbound;

public class InboundFromAmbiguityTests
{
    private static InboundHeaderAnalysis Analyze(string fromValue) =>
        InboundHeaderAnalysis.Analyze(Encoding.UTF8.GetBytes("From: " + fromValue + "\r\nSubject: x\r\n\r\nbody\r\n"), ["mx.egg.test"], null);

    [Theory]
    [InlineData("ceo@victim.test <x@evil.test>")]
    [InlineData("ceo@victim.test <x@evil.test")]
    [InlineData("ceo@victim.test\t<x@evil.test>")]
    [InlineData("ceo@victim.test<x@evil.test>")]
    [InlineData("'ceo@victim.test' <x@evil.test>")]
    [InlineData("a@b.example <d@e.example>")]
    [InlineData("x@evil.test <ceo@victim.test>")]
    [InlineData("x@evil.test<ceo@victim.test>")]
    [InlineData("<ceo@victim.test> <x@evil.test>")]
    [InlineData("<ceo@victim.test><x@evil.test>")]
    [InlineData("Bob <ceo@victim.test>x@evil.test")]
    [InlineData("x <ceo@victim.test> <y@z.example>")]
    [InlineData("=?utf-8?q?Bob_<x@evil.test>?= <ceo@victim.test>")]
    [InlineData("x@evil.test@victim.test")]
    [InlineData("ceo@victim.test@evil.test")]
    [InlineData("ceo@@victim.test")]
    [InlineData("<ceo@victim.test>,x@evil.test<ceo@victim.test>")]
    [InlineData("Bob <x@evil.test>@victim.test")]
    [InlineData(":<x@evil.test>,ceo@victim.test<")]
    [InlineData("\"Bob <ceo@victim.test>")]
    [InlineData("Bob\" <ceo@victim.test>")]
    [InlineData("x@evil.test\":,@ceo@victim.test")]
    [InlineData("ceo@victim.test (comment")]
    [InlineData("@evil.test:ceo@victim.test")]
    [InlineData("ceo\\@victim.test <x@evil.test>")]
    [InlineData("ceo\\@victim.test<x@evil.test>")]
    [InlineData("Bob ceo\\@victim.test <x@evil.test>")]
    [InlineData("x\\@evil.test <ceo@victim.test>")]
    [InlineData("<ceo\\@victim.test x@evil.test>")]
    [InlineData("a\\@b@victim.test")]
    [InlineData("<@evil.test,ceo@victim.test:x@evil.test>")]
    [InlineData("Bob <@evil.test,ceo@victim.test:x@evil.test>")]
    [InlineData("<@evil.test ceo@victim.test:x@evil.test>")]
    [InlineData("<@evil.test,@ceo@victim.test:x@evil.test>")]
    [InlineData("<@evil.test,(c)ceo@victim.test:x@evil.test>")]
    public void A_from_field_that_another_parser_reads_as_a_different_identity_is_unusable(string value)
    {
        Assert.True(Analyze(value).FromUnusable, value);
    }

    [Theory]
    [InlineData("ceo@victim.test", "victim.test")]
    [InlineData("Bob <ceo@victim.test>", "victim.test")]
    [InlineData("\"ceo@victim.test\" <x@evil.test>", "evil.test")]
    [InlineData("\"ceo@victim.test\"<x@evil.test>", "evil.test")]
    [InlineData("Bob (ceo@victim.test) <x@evil.test>", "evil.test")]
    [InlineData("x@evil.test (ceo@victim.test)", "evil.test")]
    [InlineData("Bob <ceo@victim.test> (x@evil.test)", "victim.test")]
    [InlineData("Bob \"<x@evil.test>\" <ceo@victim.test>", "victim.test")]
    [InlineData("=?utf-8?q?ceo=40victim.test?= <x@evil.test>", "evil.test")]
    [InlineData("=?utf-8?q?Bob?= <ceo@victim.test>", "victim.test")]
    [InlineData("=?utf-8?b?Qm9iIDx4QGV2aWwudGVzdD4=?= <ceo@victim.test>", "victim.test")]
    [InlineData("Doe, John <ceo@victim.test>", "victim.test")]
    [InlineData("\"Doe, John\" <ceo@victim.test>", "victim.test")]
    [InlineData("Group: ceo@victim.test, x@evil.test;", "victim.test,evil.test")]
    [InlineData("ceo@victim.test, x@evil.test", "victim.test,evil.test")]
    [InlineData("<@evil.test,@evil2.test:ceo@victim.test>", "victim.test")]
    [InlineData("< @evil.test , (c) @evil2.test : ceo@victim.test>", "victim.test")]
    [InlineData("<@[192.0.2.1]:ceo@victim.test>", "victim.test")]
    [InlineData("<@[IPv6:2001:db8::1]:ceo@victim.test>", "victim.test")]
    [InlineData("\"a@b\"@victim.test", "victim.test")]
    [InlineData("\"a\\@b\"@victim.test", "victim.test")]
    [InlineData("Bob (x\\@evil.test) <ceo@victim.test>", "victim.test")]
    [InlineData("ceo(comment)@victim.test", "victim.test")]
    [InlineData("ceo@(comment)victim.test", "victim.test")]
    [InlineData("ceo @ victim.test", "victim.test")]
    [InlineData("ceo@VICTIM.test.", "victim.test")]
    [InlineData("ceo@bücher.example", "xn--bcher-kva.example")]
    public void A_from_field_every_parser_reads_the_same_way_names_the_domains_that_are_evaluated(string value, string domains)
    {
        InboundHeaderAnalysis analysis = Analyze(value);

        Assert.False(analysis.FromUnusable, value);
        Assert.Equal(domains.Split(','), analysis.FromDomains);
    }

    [Theory]
    [InlineData("john@example.test <john@example.test>")]
    [InlineData("john@example.test <john@EXAMPLE.test>")]
    [InlineData("john@example.test <john@example.test.>")]
    [InlineData("jo..hn@example.test")]
    [InlineData("john.@example.test")]
    [InlineData("a@example.test@example.test")]
    [InlineData("<a@example.test@example.test>")]
    public void The_same_domain_written_more_than_once_is_one_identity_and_not_unusable(string value)
    {
        InboundHeaderAnalysis analysis = Analyze(value);

        Assert.False(analysis.FromUnusable, value);
        Assert.Equal(["example.test"], analysis.FromDomains);
    }

    [Fact]
    public async Task A_from_with_a_hidden_second_domain_cannot_get_the_verdict_of_a_domain_the_attacker_controls_and_the_mail_is_refused_under_reject()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync();
        await f.EnableAsync(f.ExampleOrg, InboundFixture.Acme, InboundDmarcAction.Reject);
        await f.RefreshConfigAsync();
        f.PublishSpf("evil.test");
        f.PublishDmarc("evil.test", "none");
        f.PublishDmarc("victim.test", "reject");

        foreach (string from in new[]
                 {
                     "ceo@victim.test <x@evil.test", "ceo@victim.test <x@evil.test>", "=?utf-8?q?Bob_<x@evil.test>?= <ceo@victim.test>", "x@evil.test <ceo@victim.test>",
                     "ceo\\@victim.test <x@evil.test>", "<@evil.test,ceo@victim.test:x@evil.test>",
                 })
        {
            string message = f.DkimSign(InboundFixture.Message(from: from), "evil.test");
            await using FakeMta mta = await f.ConnectedAsync();
            var reply = await mta.SendAsync("x@evil.test", "support@example.org", message);

            Assert.Equal((554, "5.6.0"), (reply.Code, reply.Enhanced));
            Assert.Contains("No usable From address", reply.Text, StringComparison.Ordinal);
        }

        Assert.Empty(await f.StoredAsync(InboundFixture.Acme));
    }

    [Fact]
    public async Task Under_record_only_the_ambiguous_from_is_stored_with_a_permerror_and_never_with_the_pass_of_the_attackers_domain()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync();
        f.PublishSpf("evil.test");
        f.PublishDmarc("evil.test", "none");
        string message = f.DkimSign(InboundFixture.Message(from: "ceo@victim.test <x@evil.test"), "evil.test");

        await using FakeMta mta = await f.ConnectedAsync();
        Assert.Equal(250, (await mta.SendAsync("x@evil.test", "support@example.org", message)).Code);

        InboundMessage stored = Assert.Single(await f.StoredAsync(InboundFixture.Acme));
        Assert.Equal((InboundVerdict.Pass, InboundVerdict.Pass, InboundVerdict.PermError), (stored.Auth.Spf, stored.Auth.Dkim, stored.Auth.Dmarc));
        string headers = (await f.RawAsync(stored)).Split("\r\n\r\n")[0];
        Assert.Contains("dmarc=permerror", headers, StringComparison.Ordinal);
        Assert.DoesNotContain("dmarc=pass", headers, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_sender_that_writes_its_own_address_as_the_display_name_is_still_evaluated_for_that_domain()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync();
        await f.EnableAsync(f.ExampleOrg, InboundFixture.Acme, InboundDmarcAction.Reject);
        await f.RefreshConfigAsync();
        f.PublishSpf("sender.test");
        f.PublishDmarc("sender.test", "reject");

        await using FakeMta mta = await f.ConnectedAsync();
        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", InboundFixture.Message(from: "bob@sender.test <bob@sender.test>"))).Code);

        InboundMessage stored = Assert.Single(await f.StoredAsync(InboundFixture.Acme));
        Assert.Equal(InboundVerdict.Pass, stored.Auth.Dmarc);
    }
}
