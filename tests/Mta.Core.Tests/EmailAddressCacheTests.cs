using Mta.Core;

namespace Mta.Core.Tests;

/// <summary>The allocation savings in address parsing (shared domain names, a per-session memo, parsing only the domain) must not change any result.</summary>
public class EmailAddressCacheTests
{
    private static readonly string[] Mailboxes =
    [
        "user@example.com", "User.Name@Example.COM", "first.last+tag@sub.example.co.uk", "\"quoted local\"@example.org", "user@[192.0.2.1]",
        "user@[IPv6:2001:db8::1]", "user@example.com.", "user@EXAMPLE.com.", "jürgen@example.com", "user@bücher.example", "üser@bücher.example",
        "a_b@host_name.example", "a@b", "UPPER@LOWER.test",
        // invalid ones
        "", "nodomain", "@example.com", "user@", "a..b@example.com", ".a@example.com", "user@-bad.com", "user@exa mple.com", "user@..", "user@.",
        "user@a..b", "user@[999.1.1.1]", "user@" + "a" + new string('b', 70) + ".com", new string('a', 70) + "@example.com",
    ];

    [Fact]
    public void Domains_are_lower_case_and_shared_between_addresses()
    {
        var a = EmailAddress.Parse("one@Shared-Domain.EXAMPLE");
        var b = EmailAddress.Parse("two@shared-domain.example");
        var c = EmailAddress.Parse("three@shared-domain.example.");
        Assert.Equal("shared-domain.example", a.Domain);
        Assert.Same(a.Domain, b.Domain);
        Assert.Same(a.Domain, c.Domain);
    }

    [Fact]
    public void A_flood_of_distinct_domains_still_parses_correctly_after_the_table_is_full()
    {
        for (int i = 0; i < 6000; i++)
        {
            string domain = $"flood-{i}.example";
            Assert.True(EmailAddress.TryParse($"x@{domain.ToUpperInvariant()}", false, out var address));
            Assert.Equal(domain, address.Domain);
        }

        Assert.Equal("example.com", EmailAddress.Parse("late@EXAMPLE.com").Domain);
    }

    [Fact]
    public void The_memo_gives_the_result_of_a_plain_parse_for_every_input_every_time()
    {
        var cache = new EmailAddressCache();
        for (int round = 0; round < 3; round++)
        {
            foreach (string mailbox in Mailboxes)
            {
                foreach (bool allowUtf8 in new[] { true, false })
                {
                    bool expectedOk = EmailAddress.TryParse(mailbox, allowUtf8, out var expected);
                    bool ok = cache.TryParse(mailbox, allowUtf8, out var actual);
                    Assert.Equal(expectedOk, ok);
                    if (ok)
                    {
                        Assert.Equal(expected, actual);
                        Assert.Equal(expected.IsInternational, actual.IsInternational);
                    }
                }
            }
        }
    }

    [Fact]
    public void The_memo_returns_the_stored_strings_for_an_address_seen_again_and_forgets_the_oldest_after_four()
    {
        var cache = new EmailAddressCache();
        Assert.True(cache.TryParse("a@example.com", true, out var first));
        Assert.True(cache.TryParse("a@example.com", true, out var again));
        Assert.Same(first.LocalPart, again.LocalPart);
        Assert.Same(first.Domain, again.Domain);

        // A different allowUtf8 setting is a different question (an internationalized address is refused without it).
        Assert.True(cache.TryParse("jürgen@example.com", true, out _));
        Assert.False(cache.TryParse("jürgen@example.com", false, out _));

        foreach (string other in new[] { "b@example.com", "c@example.com", "d@example.com", "e@example.com" })
        {
            Assert.True(cache.TryParse(other, true, out _));
        }

        Assert.True(cache.TryParse("a@example.com", true, out var reparsed));
        Assert.Equal(first, reparsed);
        Assert.NotSame(first.LocalPart, reparsed.LocalPart);   // it had been replaced: parsed afresh, equal in value
    }

    [Fact]
    public void Parsing_only_the_domain_agrees_with_the_full_parse()
    {
        foreach (string mailbox in Mailboxes)
        {
            foreach (bool allowUtf8 in new[] { true, false })
            {
                bool full = EmailAddress.TryParse(mailbox, allowUtf8, out var address);
                bool domainOnly = EmailAddress.TryParseDomain(mailbox, allowUtf8, out string? domain);
                Assert.Equal(full, domainOnly);
                if (full)
                {
                    Assert.Equal(address.Domain, domain);
                }
            }
        }
    }
}
