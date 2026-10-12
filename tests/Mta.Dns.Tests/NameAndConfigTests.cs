using System.Net;

namespace Mta.Dns.Tests;

public class DnsNameTests
{
    [Theory]
    [InlineData("Example.COM", "example.com")]
    [InlineData("example.com.", "example.com")]
    [InlineData("EXAMPLE.com.", "example.com")]
    [InlineData("_dmarc.Example.com", "_dmarc.example.com")]
    [InlineData("", "")]
    [InlineData(".", "")]
    [InlineData("bücher.example", "xn--bcher-kva.example")]
    [InlineData("BÜCHER.Example.", "xn--bcher-kva.example")]
    [InlineData("xn--bcher-kva.example", "xn--bcher-kva.example")]
    [InlineData("日本語.jp", "xn--wgv71a119e.jp")]
    public void Normalizes(string input, string expected)
    {
        Assert.True(DnsName.TryNormalize(input, out var n));
        Assert.Equal(expected, n);
        Assert.Equal(expected, DnsName.Normalize(input));
    }

    [Fact]
    public void An_already_normal_name_is_returned_without_copying()
    {
        string s = "mail.example.com";
        Assert.Same(s, DnsName.Normalize(s));
    }

    [Theory]
    [InlineData("a..b")]
    [InlineData("..")]
    [InlineData(".a")]
    [InlineData("a b")]
    [InlineData("a\tb")]
    [InlineData("a\\.b")]
    [InlineData("example.com..")]
    [InlineData("bad\u0000name")]
    public void Rejects_invalid_names(string input)
    {
        Assert.False(DnsName.TryNormalize(input, out _));
        Assert.False(DnsName.IsValid(input));
        Assert.Throws<ArgumentException>(() => DnsName.Normalize(input));
    }

    [Fact]
    public void Rejects_null_and_overlong_input()
    {
        Assert.False(DnsName.TryNormalize(null, out _));
        Assert.Throws<ArgumentNullException>(() => DnsName.Normalize(null!));
        Assert.False(DnsName.IsValid(new string('a', 64) + ".example"));
        Assert.True(DnsName.IsValid(new string('a', 63) + ".example"));
        Assert.False(DnsName.IsValid(new string('a', 100_000)));
        Assert.False(DnsName.IsValid(string.Join('.', Enumerable.Repeat("abcdefghi", 26))));   // 259 chars
    }

    [Fact]
    public void Rejects_unpaired_surrogates_and_labels_that_become_too_long_through_idna()
    {
        Assert.False(DnsName.IsValid("\ud800.example"));
        Assert.False(DnsName.IsValid(new string('ü', 60) + ".example"));
    }

    [Theory]
    [InlineData("example.com", "example.com", true)]
    [InlineData("mail.example.com", "example.com", true)]
    [InlineData("MAIL.Example.com.", "EXAMPLE.COM", true)]
    [InlineData("a.b.example.com", "b.example.com", true)]
    [InlineData("badexample.com", "example.com", false)]
    [InlineData("example.com", "mail.example.com", false)]
    [InlineData("example.com", "", true)]
    [InlineData("example.com", ".", true)]
    [InlineData("example.org", "example.com", false)]
    [InlineData("a b", "example.com", false)]
    public void IsSubdomainOf_respects_label_boundaries(string name, string ancestor, bool expected)
    {
        Assert.Equal(expected, DnsName.IsSubdomainOf(name, ancestor));
    }

    [Fact]
    public void GetParent_strips_one_label()
    {
        Assert.Equal("example.com", DnsName.GetParent("mail.Example.com"));
        Assert.Equal(string.Empty, DnsName.GetParent("com"));
        Assert.Null(DnsName.GetParent(""));
        Assert.Null(DnsName.GetParent("bad name"));
    }

    [Fact]
    public void Builds_ipv4_reverse_names()
    {
        Assert.Equal("4.3.2.1.in-addr.arpa", DnsName.ReverseArpaName(IPAddress.Parse("1.2.3.4")));
        Assert.Equal("4.3.2.1.zen.example.org", DnsName.ReverseName(IPAddress.Parse("1.2.3.4"), "Zen.Example.org."));
        Assert.Equal("4.3.2.1", DnsName.ReverseName(IPAddress.Parse("1.2.3.4"), ""));
    }

    [Fact]
    public void Builds_ipv6_reverse_names_from_nibbles()
    {
        // RFC 3596 §2.5 example
        var address = IPAddress.Parse("4321:0:1:2:3:4:567:89ab");
        Assert.Equal("b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.ip6.arpa", DnsName.ReverseArpaName(address));
        Assert.Equal("1." + string.Join('.', Enumerable.Repeat("0", 31)) + ".ip6.arpa", DnsName.ReverseArpaName(IPAddress.IPv6Loopback));
        Assert.Equal(32 * 2 - 1 + ".ip6.arpa".Length, DnsName.ReverseArpaName(address).Length);
        Assert.EndsWith(".dnsbl.example", DnsName.ReverseName(address, "dnsbl.example"));
        Assert.Equal(32 * 2 - 1, DnsName.ReverseName(address, "").Length);
    }

    [Fact]
    public void Ipv4_mapped_ipv6_addresses_reverse_as_ipv4()
    {
        Assert.Equal("4.3.2.1.in-addr.arpa", DnsName.ReverseArpaName(IPAddress.Parse("::ffff:1.2.3.4")));
    }

    [Fact]
    public void Builds_tlsa_names()
    {
        Assert.Equal("_25._tcp.mail.example.com", DnsName.TlsaName("Mail.Example.com.", 25));
        Assert.Equal("_443._tcp.example.com", DnsName.TlsaName("example.com", 443, "TCP"));
        Assert.Throws<ArgumentOutOfRangeException>(() => DnsName.TlsaName("example.com", 70000));
    }
}

public class ResolvConfTests
{
    [Fact]
    public void Parses_nameservers_and_options()
    {
        var c = SystemDnsConfiguration.ParseResolvConf("""
            # Generated by NetworkManager
            search corp.example example.com
            nameserver 192.0.2.53
            nameserver 2001:db8::53   # inline comment
            ; another comment
            nameserver 192.0.2.53
            options ndots:2 timeout:3 attempts:4 rotate
            """);
        Assert.Equal([new IPEndPoint(IPAddress.Parse("192.0.2.53"), 53), new IPEndPoint(IPAddress.Parse("2001:db8::53"), 53)], c.Servers);
        Assert.Equal(TimeSpan.FromSeconds(3), c.Timeout);
        Assert.Equal(4, c.Attempts);
    }

    [Fact]
    public void Ignores_garbage_search_domain_and_invalid_addresses_and_clamps_options()
    {
        var c = SystemDnsConfiguration.ParseResolvConf("nameserver not-an-ip\nnameserver 0.0.0.0\nnameserver\nbogus line here\r\nnameserver 10.0.0.1\r\noptions timeout:99 attempts:0\n");
        Assert.Equal([new IPEndPoint(IPAddress.Parse("10.0.0.1"), 53)], c.Servers);
        Assert.Equal(TimeSpan.FromSeconds(30), c.Timeout);
        Assert.Equal(1, c.Attempts);
    }

    [Fact]
    public void Empty_file_gives_no_servers_and_no_options()
    {
        var c = SystemDnsConfiguration.ParseResolvConf(string.Empty);
        Assert.Empty(c.Servers);
        Assert.Null(c.Timeout);
        Assert.Null(c.Attempts);
    }

    [Fact]
    public void Parses_systemd_stub_and_link_local_scoped_addresses()
    {
        var c = SystemDnsConfiguration.ParseResolvConf("nameserver 127.0.0.53\nnameserver fe80::1%1\n");
        Assert.Equal(2, c.Servers.Count);
        Assert.Equal(IPAddress.Parse("127.0.0.53"), c.Servers[0].Address);
    }

    private static string TempFile(string content)
    {
        string path = Path.Combine(Path.GetTempPath(), "eggmail-resolv-" + Guid.NewGuid().ToString("N"));
        File.WriteAllText(path, content);
        return path;
    }

    [Fact]
    public void Discover_prefers_the_file()
    {
        string path = TempFile("nameserver 192.0.2.1\n");
        try
        {
            var c = SystemDnsConfiguration.Discover(false, path, useNetworkInterfaces: false);
            Assert.Equal([new IPEndPoint(IPAddress.Parse("192.0.2.1"), 53)], c.Servers);
            Assert.Equal(path, c.Source);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Discover_falls_back_to_loopback_only_by_default()
    {
        string path = TempFile("# nothing here\n");
        try
        {
            var c = SystemDnsConfiguration.Discover(false, path, useNetworkInterfaces: false);
            Assert.Equal([new IPEndPoint(IPAddress.Loopback, 53)], c.Servers);
            Assert.Equal("fallback", c.Source);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Public_fallback_is_opt_in_and_comes_after_loopback()
    {
        var c = SystemDnsConfiguration.Discover(true, "/nonexistent/resolv.conf", useNetworkInterfaces: false);
        Assert.Equal(
            [new IPEndPoint(IPAddress.Loopback, 53), new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53), new IPEndPoint(IPAddress.Parse("8.8.8.8"), 53)],
            c.Servers);
    }

    [Fact]
    public void Missing_file_is_not_an_error()
    {
        Assert.Null(SystemDnsConfiguration.ReadResolvConf("/nonexistent/resolv.conf"));
        Assert.NotEmpty(SystemDnsConfiguration.Discover().Servers);
    }

    [Fact]
    public void Options_from_system_configuration_always_have_a_server()
    {
        var o = DnsResolverOptions.FromSystemConfiguration();
        Assert.NotEmpty(o.Servers);
        o.Validate();
    }
}

public class DnsResolverOptionsTests
{
    [Fact]
    public void Defaults_are_valid_and_conservative()
    {
        var o = new DnsResolverOptions();
        o.Validate();
        Assert.Equal((ushort)1232, o.EdnsUdpPayloadSize);
        Assert.False(o.TrustAuthenticatedData);
        Assert.False(o.RequestDnssecOk);
        Assert.False(o.AllowPublicResolverFallback);
        Assert.Equal(8, o.MaxCnameDepth);
    }

    [Fact]
    public void Out_of_range_values_are_rejected()
    {
        Assert.Throws<ArgumentException>(() => (new DnsResolverOptions { Attempts = 0 }).Validate());
        Assert.Throws<ArgumentException>(() => (new DnsResolverOptions { AttemptTimeout = TimeSpan.Zero }).Validate());
        Assert.Throws<ArgumentException>(() => (new DnsResolverOptions { EdnsUdpPayloadSize = 100 }).Validate());
        Assert.Throws<ArgumentException>(() => (new DnsResolverOptions { MinCacheTtl = TimeSpan.FromDays(2) }).Validate());
        Assert.Throws<ArgumentException>(() => (new DnsResolverOptions { MaxCnameDepth = -1 }).Validate());
        Assert.Throws<ArgumentException>(() => new UdpTcpDnsTransport(new DnsResolverOptions()));   // no servers
    }
}
