using System.Text;
using Mta.Host.Ingest;
using Mta.Storage;

namespace Mta.Host.Tests.Inbound;

/// <summary>
/// The identity DMARC is evaluated for is the domain of the From address, and every consumer of the stored message (a webhook receiver, a mail client, a script) reads that header with a parser of its
/// own. A From field that two parsers read differently is a way to have the verdict computed for the attacker's domain while the consumer reads the victim's. These tests are the parser-differential
/// regressions: the cases were found by running a corpus of 1,460 hostile values through this parser and through Python's <c>email.policy.default</c> (and its legacy <c>getaddresses</c>) and listing every
/// value where Python names a domain that was not evaluated here. A field in which a domain stands after an unquoted "@" that was not taken as the identity is unusable; the same domain written twice is not.
/// </summary>
public class InboundFromAmbiguityTests
{
    private static InboundHeaderAnalysis Analyze(string fromValue) =>
        InboundHeaderAnalysis.Analyze(Encoding.UTF8.GetBytes("From: " + fromValue + "\r\nSubject: x\r\n\r\nbody\r\n"), ["mx.egg.test"], null);

    [Theory]
    // An address as the display name, another one in the angle brackets (the two are different identities); Python reads victim.test, this parser used to read evil.test.
    [InlineData("ceo@victim.test <x@evil.test>")]
    [InlineData("ceo@victim.test <x@evil.test")]                          // the angle bracket never closes (the case the reviewers named)
    [InlineData("ceo@victim.test\t<x@evil.test>")]
    [InlineData("ceo@victim.test<x@evil.test>")]
    [InlineData("'ceo@victim.test' <x@evil.test>")]
    [InlineData("a@b.example <d@e.example>")]
    // The same the other way round: Python reads the unbracketed address first.
    [InlineData("x@evil.test <ceo@victim.test>")]
    [InlineData("x@evil.test<ceo@victim.test>")]
    // A second address after the first one, in or out of angle brackets.
    [InlineData("<ceo@victim.test> <x@evil.test>")]
    [InlineData("<ceo@victim.test><x@evil.test>")]
    [InlineData("Bob <ceo@victim.test>x@evil.test")]
    [InlineData("x <ceo@victim.test> <y@z.example>")]
    // A Q-encoded word with a literal "@" in its text: a parser that reads the structure before it decodes words sees an address there. (A base64 word has no "@" in its text and decodes to display text only.)
    [InlineData("=?utf-8?q?Bob_<x@evil.test>?= <ceo@victim.test>")]
    // Several at signs that lead to different domains.
    [InlineData("x@evil.test@victim.test")]
    [InlineData("ceo@victim.test@evil.test")]
    [InlineData("ceo@@victim.test")]
    [InlineData("<ceo@victim.test>,x@evil.test<ceo@victim.test>")]
    [InlineData("Bob <x@evil.test>@victim.test")]
    // A mailbox that is only a piece of a display name but names a domain.
    [InlineData(":<x@evil.test>,ceo@victim.test<")]
    // Quotes and comments that never end swallow the rest of the field for one reader and not for another.
    [InlineData("\"Bob <ceo@victim.test>")]
    [InlineData("Bob\" <ceo@victim.test>")]
    [InlineData("x@evil.test\":,@ceo@victim.test")]
    [InlineData("ceo@victim.test (comment")]
    // An obsolete route outside the angle brackets is an address to a parser that does not know it.
    [InlineData("@evil.test:ceo@victim.test")]
    // A backslash outside quotes and comments is text, not a quoted pair: Python reads the "@" after it as the start of the domain (ceo\@victim.test), this parser used to skip that "@".
    [InlineData("ceo\\@victim.test <x@evil.test>")]
    [InlineData("ceo\\@victim.test<x@evil.test>")]
    [InlineData("Bob ceo\\@victim.test <x@evil.test>")]
    [InlineData("x\\@evil.test <ceo@victim.test>")]
    [InlineData("<ceo\\@victim.test x@evil.test>")]
    [InlineData("a\\@b@victim.test")]                                   // Python reads no address at all here
    // Text after "<@" that is not a route (an "@" in it that does not follow the "<" or a ","): Python reads ceo@victim.test in it, this parser used to skip it up to the colon.
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
    [InlineData("\"ceo@victim.test\" <x@evil.test>", "evil.test")]                // quoted: the display name, not an address (Python agrees)
    [InlineData("\"ceo@victim.test\"<x@evil.test>", "evil.test")]
    [InlineData("Bob (ceo@victim.test) <x@evil.test>", "evil.test")]               // a comment is not an address
    [InlineData("x@evil.test (ceo@victim.test)", "evil.test")]
    [InlineData("Bob <ceo@victim.test> (x@evil.test)", "victim.test")]
    [InlineData("Bob \"<x@evil.test>\" <ceo@victim.test>", "victim.test")]
    [InlineData("=?utf-8?q?ceo=40victim.test?= <x@evil.test>", "evil.test")]       // an encoded "@" is a character of the name
    [InlineData("=?utf-8?q?Bob?= <ceo@victim.test>", "victim.test")]
    [InlineData("=?utf-8?b?Qm9iIDx4QGV2aWwudGVzdD4=?= <ceo@victim.test>", "victim.test")]  // base64 of "Bob <x@evil.test>": display text once decoded, no "@" before (Python agrees)
    [InlineData("Doe, John <ceo@victim.test>", "victim.test")]                     // Outlook's unquoted comma
    [InlineData("\"Doe, John\" <ceo@victim.test>", "victim.test")]
    [InlineData("Group: ceo@victim.test, x@evil.test;", "victim.test,evil.test")]  // each mailbox is its own identity and is evaluated
    [InlineData("ceo@victim.test, x@evil.test", "victim.test,evil.test")]
    [InlineData("<@evil.test,@evil2.test:ceo@victim.test>", "victim.test")]         // the route of an angle address is not an address
    [InlineData("< @evil.test , (c) @evil2.test : ceo@victim.test>", "victim.test")]  // white space and comments inside the route
    [InlineData("<@[192.0.2.1]:ceo@victim.test>", "victim.test")]
    [InlineData("<@[IPv6:2001:db8::1]:ceo@victim.test>", "victim.test")]           // a domain literal in the route holds colons
    [InlineData("\"a@b\"@victim.test", "victim.test")]                             // a quoted local part
    [InlineData("\"a\\@b\"@victim.test", "victim.test")]                           // a quoted pair inside the quotes
    [InlineData("Bob (x\\@evil.test) <ceo@victim.test>", "victim.test")]          // and inside a comment
    [InlineData("ceo(comment)@victim.test", "victim.test")]
    [InlineData("ceo@(comment)victim.test", "victim.test")]                        // white space and comments around the "@" are legal
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
    [InlineData("john@example.test <john@example.test>")]            // the display name is the address, a habit of some mail systems
    [InlineData("john@example.test <john@EXAMPLE.test>")]
    [InlineData("john@example.test <john@example.test.>")]
    [InlineData("jo..hn@example.test")]                              // refused by the strict parser, one domain
    [InlineData("john.@example.test")]
    [InlineData("a@example.test@example.test")]                      // several at signs, all leading to one domain: nothing to disagree about
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
        // evil.test is the attacker's: its SPF authorizes the client, its DKIM key is published and signs the message, its DMARC is p=none. victim.test publishes p=reject and signs nothing.
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
        Assert.Equal((InboundVerdict.Pass, InboundVerdict.Pass, InboundVerdict.PermError), (stored.Auth.Spf, stored.Auth.Dkim, stored.Auth.Dmarc));   // the mechanisms are true; the identity they would vouch for is not clear
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
