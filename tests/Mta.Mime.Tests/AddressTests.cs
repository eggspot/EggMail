namespace Mta.Mime.Tests;

public class AddressTests
{
    private static List<Mailbox> Boxes(string value) => AddressList.Parse(value).Mailboxes.ToList();

    [Fact]
    public void Plain_address()
    {
        var m = Assert.Single(Boxes("alice@example.com"));
        Assert.True(m.IsValid);
        Assert.Null(m.DisplayName);
        Assert.Equal("alice@example.com", m.Address.ToString());
        Assert.Equal("example.com", m.Domain);
    }

    [Theory]
    [InlineData("Alice Smith <alice@example.com>", "Alice Smith")]
    [InlineData("\"Smith, Alice\" <alice@example.com>", "Smith, Alice")]
    [InlineData("alice@example.com (Alice Smith)", "Alice Smith")]
    [InlineData("\"Alice \\\"Al\\\" Smith\" <alice@example.com>", "Alice \"Al\" Smith")]
    [InlineData("Alice (comment) Smith <alice@example.com>", "Alice Smith")]
    [InlineData("=?utf-8?Q?Alice_Sm=C3=AFth?= <alice@example.com>", "Alice Smïth")]
    [InlineData("\"=?utf-8?B?QWxpY2U=?=\" <alice@example.com>", "Alice")]
    [InlineData("=?utf-8?Q?Al?= =?utf-8?Q?ice?= <alice@example.com>", "Alice")]
    [InlineData("Alice S. Smith <alice@example.com>", "Alice S. Smith")]
    [InlineData("<alice@example.com> (Alice)", "Alice")]
    public void Display_names(string value, string expectedName)
    {
        var m = Assert.Single(Boxes(value));
        Assert.True(m.IsValid, value);
        Assert.Equal(expectedName, m.DisplayName);
        Assert.Equal("alice@example.com", m.Address.ToString());
    }

    [Fact]
    public void List_of_mailboxes_with_commas_in_quotes_and_comments()
    {
        var boxes = Boxes("\"Doe, John\" <john@example.com>, jane@example.org (Jane, the second), <bob@example.net>");
        Assert.Equal(3, boxes.Count);
        Assert.Equal("Doe, John", boxes[0].DisplayName);
        Assert.Equal("Jane, the second", boxes[1].DisplayName);
        Assert.Null(boxes[2].DisplayName);
        Assert.Equal("bob@example.net", boxes[2].Address.ToString());
    }

    [Fact]
    public void Groups()
    {
        var list = AddressList.Parse("Team: a@example.com, \"B\" <b@example.org>;, c@example.net, undisclosed-recipients:;");
        Assert.Equal(3, list.Count);
        var group = Assert.IsType<MailboxGroup>(list[0]);
        Assert.Equal("Team", group.Name);
        Assert.Equal(2, group.Members.Count);
        Assert.Equal("B", group.Members[1].DisplayName);
        Assert.IsType<Mailbox>(list[1]);
        var empty = Assert.IsType<MailboxGroup>(list[2]);
        Assert.Equal("undisclosed-recipients", empty.Name);
        Assert.Empty(empty.Members);
        Assert.Equal(3, list.MailboxCount);
        Assert.Equal(3, list.Mailboxes.Count());
    }

    [Fact]
    public void Obsolete_route_is_ignored()
    {
        var m = Assert.Single(Boxes("Route <@relay1.example,@relay2.example:user@example.com>"));
        Assert.Equal("user@example.com", m.Address.ToString());
        Assert.Equal("Route", m.DisplayName);
    }

    [Fact]
    public void Obsolete_whitespace_around_dots_and_at()
    {
        var m = Assert.Single(Boxes("john . doe @ example . com"));
        Assert.True(m.IsValid);
        Assert.Equal("john.doe@example.com", m.Address.ToString());
    }

    [Fact]
    public void Quoted_local_part_is_preserved()
    {
        var m = Assert.Single(Boxes("\"john smith\"@example.com"));
        Assert.True(m.IsValid);
        Assert.Equal("\"john smith\"", m.Address.LocalPart);
    }

    [Fact]
    public void Name_without_angle_brackets_recovers_the_address()
    {
        var list = AddressList.Parse("Alice Smith alice@example.com");
        var m = Assert.Single(list.Mailboxes);
        Assert.True(m.IsValid);
        Assert.Equal("alice@example.com", m.Address.ToString());
        Assert.Equal("Alice Smith", m.DisplayName);
    }

    [Fact]
    public void Missing_closing_angle_is_reported()
    {
        var list = AddressList.Parse("Alice <alice@example.com");
        var m = Assert.Single(list.Mailboxes);
        Assert.True(m.IsValid);
        Assert.True(list.Anomalies.HasAny(MimeAnomaly.InvalidAddress));
    }

    [Theory]
    [InlineData("not an address")]
    [InlineData("@example.com")]
    [InlineData("user@")]
    [InlineData("user@@example.com")]
    [InlineData("<>")]
    public void Invalid_addresses_are_kept_as_invalid_mailboxes(string value)
    {
        var list = AddressList.Parse(value);
        Assert.True(list.Anomalies.HasAny(MimeAnomaly.InvalidAddress), value);
        Assert.All(list.Mailboxes, m => Assert.False(m.IsValid));
    }

    [Fact]
    public void Internationalized_addresses()
    {
        var m = Assert.Single(Boxes("用户 <用户@bücher.example>"));
        Assert.True(m.IsValid);
        Assert.True(m.Address.IsInternational);
        Assert.Equal("xn--bcher-kva.example", m.Domain);
        Assert.Equal("用户", m.DisplayName);
    }

    [Fact]
    public void Address_count_is_limited()
    {
        string value = string.Join(", ", Enumerable.Range(0, 5000).Select(i => $"u{i}@example.com"));
        var list = AddressList.Parse(value, new MimeLimits { MaxAddresses = 100 });
        Assert.Equal(100, list.Count);
        Assert.True(list.Anomalies.HasAny(MimeAnomaly.TooManyAddresses));
    }

    [Fact]
    public void Pathological_inputs_terminate_quickly()
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        AddressList.Parse(new string('(', 200_000));
        AddressList.Parse(new string('"', 200_000));
        AddressList.Parse(new string('<', 200_000));
        AddressList.Parse(new string(':', 200_000));
        AddressList.Parse(string.Concat(Enumerable.Repeat("a:", 100_000)));
        AddressList.Parse(string.Concat(Enumerable.Repeat("a b ", 100_000)));
        AddressList.Parse(string.Concat(Enumerable.Repeat("<a@b>,", 100_000)), new MimeLimits { MaxAddresses = 50 });
        AddressList.Parse(string.Concat(Enumerable.Repeat("\"a", 100_000)));
        sw.Stop();
        Assert.True(sw.ElapsedMilliseconds < 5000, $"took {sw.ElapsedMilliseconds} ms");
    }

    [Fact]
    public void Parses_from_a_header()
    {
        var headers = HeaderList.Parse(T.Crlf("From: Alice\n <alice@example.com>,\n bob@example.net\n\n"));
        var list = AddressList.Parse(headers[0]);
        Assert.Equal(2, list.MailboxCount);
        Assert.Equal("Alice", list.Mailboxes.First().DisplayName);
    }

    [Fact]
    public void Empty_values()
    {
        Assert.Empty(AddressList.Parse(null));
        Assert.Empty(AddressList.Parse("   "));
        Assert.Empty(AddressList.Parse(",,;;"));
    }

    // ---- formatting

    [Theory]
    [InlineData("Alice", "Alice <alice@example.com>")]
    [InlineData("Alice Smith", "Alice Smith <alice@example.com>")]
    [InlineData("Smith, Alice", "\"Smith, Alice\" <alice@example.com>")]
    [InlineData("Say \"hi\"", "\"Say \\\"hi\\\"\" <alice@example.com>")]
    [InlineData(null, "alice@example.com")]
    public void Formats_display_names(string? name, string expected)
    {
        var m = Mailbox.Create(name, "alice@example.com");
        Assert.Equal(expected, m.ToHeaderValue());
    }

    [Fact]
    public void Non_ascii_display_name_is_encoded_unless_utf8_allowed()
    {
        var m = Mailbox.Create("Renée Müller", "renee@example.com");
        string encoded = m.ToHeaderValue();
        Assert.True(System.Text.Ascii.IsValid(encoded));
        Assert.Equal("Renée Müller", Assert.Single(Boxes(encoded)).DisplayName);
        Assert.Equal("Renée Müller <renee@example.com>", m.ToHeaderValue(allowUtf8: true));
    }

    [Fact]
    public void Format_then_parse_round_trips()
    {
        foreach (string name in new[] { "Plain", "With, comma", "Quote \" and \\", "Résumé", "世界", "=?fake?Q?x?=", "semi;colon", "angle <x>", "(paren)" })
        {
            var m = Mailbox.Create(name, "user@example.com");
            foreach (bool utf8 in new[] { false, true })
            {
                var parsed = Assert.Single(Boxes(m.ToHeaderValue(utf8)));
                Assert.Equal(name, parsed.DisplayName);
                Assert.Equal("user@example.com", parsed.Address.ToString());
            }
        }
    }

    [Theory]
    [InlineData("evil\r\nBcc: x@example.com")]
    [InlineData("evil\nname")]
    [InlineData("nul\0name")]
    public void Display_name_injection_is_rejected(string name)
    {
        var m = Mailbox.Create(name, "alice@example.com");
        Assert.Throws<HeaderInjectionException>(() => m.ToHeaderValue());
    }

    [Fact]
    public void International_local_part_needs_utf8()
    {
        var m = Mailbox.Parse("用户@example.com");
        Assert.Throws<MessageBuildException>(() => m.ToHeaderValue());
        Assert.Equal("用户@example.com", m.ToHeaderValue(allowUtf8: true));
    }

    [Fact]
    public void Mailbox_parse_helpers()
    {
        Assert.True(Mailbox.TryParse("A <a@example.com>", out var m));
        Assert.Equal("A", m.DisplayName);
        Assert.False(Mailbox.TryParse("a@example.com, b@example.com", out _));
        Assert.False(Mailbox.TryParse("garbage", out _));
        Assert.Throws<FormatException>(() => Mailbox.Parse("garbage"));
        Assert.Throws<FormatException>(() => Mailbox.Create("x", "garbage"));
    }
}
