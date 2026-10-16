using Mta.Core;

namespace Mta.Core.Tests;

/// <summary>
/// Security regression tests (docs/security-test-map.md, INJ-5): an address reaches SMTP commands (<c>MAIL FROM</c>, <c>RCPT TO</c>), headers and
/// storage, so it can never carry a line break, a NUL, a second address or a command. The in-house review, not an independent audit.
/// </summary>
public class EmailAddressSecurityTests
{
    public static TheoryData<string> Hostile() => new()
    {
        "a@b.test\r\nRCPT TO:<evil@x.test>",
        "a@b.test\nRCPT TO:<evil@x.test>",
        "a@b.test\rRCPT TO:<evil@x.test>",
        "a\r\n@b.test",
        "\"a\r\nRCPT TO:<evil@x.test>\"@b.test",
        "\"a\nb\"@b.test",
        "\"a\rb\"@b.test",
        "\"a\\\r\n\"@b.test",
        "\"a\0b\"@b.test",
        "a\0@b.test",
        "a@b\0.test",
        "a@b.test\0",
        "a@b.test>",
        "<a@b.test>",
        "a@b.test, c@d.test",
        "a@b.test c@d.test",
        "a@b.test;c@d.test",
        "a b@c.test",
        "a@b.test\t",
        "a@b .test",
        "\ta@b.test",
        "a@b.test\u0085",
        "a@b.test\u2028RCPT TO:<evil@x.test>",
        "a@b.test\u2029",
        "a@b.test\u007f",
        "a@b.test\u0001",
        "a@b.test\u001b[31m",
        "a@[127.0.0.1\r\n]",
        "a@[IPv6:::1\r\n]",
        "a@b.test%0d%0aRCPT TO:<evil@x.test>",
        "a@@b.test",
        "@",
        "a@b@c.test",
        "\"\"@b.test@c.test",
        "a@b.test\u202e",
        "a\u202e@b.test",                  // bidirectional override in the local part
        "\"a\u2028b\"@b.test",             // line separator inside quotes
        "a\u2066b@b.test",                 // bidirectional isolate
        "a@b\uff0etest\r\n",
    };

    [Theory]
    [MemberData(nameof(Hostile))]
    public void An_address_that_could_carry_a_command_or_a_second_address_is_not_an_address(string text)
    {
        Assert.False(EmailAddress.TryParse(text, false, out _), "ascii: " + Escape(text));
        Assert.False(EmailAddress.TryParse(text, true, out _), "utf8: " + Escape(text));
        Assert.False(EmailAddress.TryParseDomain(text, true, out _));
    }

    [Fact]
    public void Whatever_parses_contains_no_control_character_and_no_whitespace_outside_quotes_so_it_is_safe_on_one_command_line()
    {
        var rng = new Random(20261016);
        string alphabet = "ab.@\"\\<>\r\n\0 \t;,:[]!#%&'*+-/=?^_`{|}~é\u2028\u0085";
        for (int i = 0; i < 20_000; i++)
        {
            var chars = new char[rng.Next(1, 24)];
            for (int c = 0; c < chars.Length; c++) { chars[c] = alphabet[rng.Next(alphabet.Length)]; }
            string text = new(chars);
            if (!EmailAddress.TryParse(text, true, out EmailAddress address)) { continue; }

            string written = address.LocalPart + "@" + address.Domain;
            Assert.False(written.Any(c => c is '\r' or '\n' or '\0' or '\u2028' or '\u2029' or '\u0085' || char.IsControl(c)), "parsed: " + Escape(text));
            Assert.False(address.Domain.Any(c => c is ' ' or '<' or '>' or '"' or ',' or ';' or '@'), "domain of: " + Escape(text));
            if (!address.LocalPart.StartsWith('"'))
            {
                Assert.False(address.LocalPart.Any(c => c is ' ' or '<' or '>' or ',' or ';' or '@' or ':' or '"' or '\\'), "local part of: " + Escape(text));
            }
        }
    }

    [Fact]
    public void A_quoted_local_part_keeps_special_characters_inside_its_quotes_only()
    {
        Assert.True(EmailAddress.TryParse("\"a>b c\"@example.org", false, out var a));
        Assert.Equal("\"a>b c\"", a.LocalPart);
        Assert.Equal("example.org", a.Domain);
        // Without the quotes the same characters are not an address.
        Assert.False(EmailAddress.TryParse("a>b c@example.org", false, out _));
        // A quote that is not closed, or text after the closing quote, is not a local part.
        Assert.False(EmailAddress.TryParse("\"abc@example.org", false, out _));
        Assert.False(EmailAddress.TryParse("\"abc\"def@example.org", false, out _));
    }

    private static string Escape(string text) => text.Replace("\r", "\\r", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal).Replace("\0", "\\0", StringComparison.Ordinal);
}
