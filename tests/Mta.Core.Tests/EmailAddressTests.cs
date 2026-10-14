using Mta.Core;

namespace Mta.Core.Tests;

public class EmailAddressTests
{
    [Theory]
    [InlineData("user@example.com", "user", "example.com")]
    [InlineData("first.last+tag@Example.COM", "first.last+tag", "example.com")]
    [InlineData("\"quoted local\"@example.org", "\"quoted local\"", "example.org")]
    [InlineData("user@[192.0.2.1]", "user", "[192.0.2.1]")]
    [InlineData("user@[IPv6:2001:db8::1]", "user", "[IPv6:2001:db8::1]")]
    public void Parses_valid_addresses(string input, string local, string domain)
    {
        Assert.True(EmailAddress.TryParse(input, false, out var a));
        Assert.Equal(local, a.LocalPart);
        Assert.Equal(domain, a.Domain);
    }

    [Theory]
    [InlineData("")]
    [InlineData("nodomain")]
    [InlineData("@example.com")]
    [InlineData("user@")]
    [InlineData("a..b@example.com")]
    [InlineData(".a@example.com")]
    [InlineData("a.@example.com")]
    [InlineData("us er@example.com")]
    [InlineData("user@exa mple.com")]
    [InlineData("user@-bad.com")]
    [InlineData("user@[999.1.1.1]")]
    [InlineData("user@[1.2.3]")]
    public void Rejects_invalid_addresses(string input)
    {
        Assert.False(EmailAddress.TryParse(input, false, out _));
    }

    [Fact]
    public void Rejects_overlong_local_part()
    {
        string local = new('a', 65);
        Assert.False(EmailAddress.TryParse($"{local}@example.com", false, out _));
        Assert.True(EmailAddress.TryParse($"{new string('a', 64)}@example.com", false, out _));
    }

    [Fact]
    public void Non_ascii_requires_utf8_and_domain_is_punycoded()
    {
        Assert.False(EmailAddress.TryParse("üser@example.com", false, out _));
        Assert.True(EmailAddress.TryParse("üser@bücher.example", true, out var a));
        Assert.True(a.IsInternational);
        Assert.Equal("xn--bcher-kva.example", a.Domain);
    }

    [Theory]
    [InlineData("user@example.org", false, false)]
    [InlineData("user@bücher.example", true, false)]     // the domain is held as an A-label: plain ASCII on the wire
    [InlineData("üser@example.org", true, true)]
    [InlineData("üser@bücher.example", true, true)]
    public void Only_a_non_ascii_local_part_requires_smtputf8(string mailbox, bool international, bool requiresSmtpUtf8)
    {
        var a = EmailAddress.Parse(mailbox);
        Assert.Equal(international, a.IsInternational);
        Assert.Equal(requiresSmtpUtf8, a.RequiresSmtpUtf8);
        if (!requiresSmtpUtf8)
        {
            Assert.True(System.Text.Ascii.IsValid(a.ToString()));
        }

        Assert.False(EmailAddress.Null.RequiresSmtpUtf8);
    }

    [Fact]
    public void Uuid7_ids_are_ordered_and_carry_time()
    {
        var t = new DateTimeOffset(2026, 10, 12, 8, 0, 0, TimeSpan.Zero);
        var id = Ids.New(t);
        Assert.Equal(t, Ids.GetTimestamp(id));
        Assert.Equal(new DateOnly(2026, 10, 12), Ids.GetDay(id));
    }

    [Fact]
    public void Null_path_formats_as_empty_brackets()
    {
        Assert.True(EmailAddress.Null.IsNull);
        Assert.Equal("<>", EmailAddress.Null.ToPath());
    }
}
