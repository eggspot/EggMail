using System.Net;

namespace Mta.Core.Tests;

/// <summary>
/// The one classification behind every SSRF guard (webhooks, MTA-STS and TLS-RPT fetchers) and the MX exclusion. Security regression tests
/// (docs/security-test-map.md, SSRF-1 and SSRF-2): the forms an attacker uses to hide an internal address behind a public-looking one.
/// </summary>
public class NetworkAddressesTests
{
    [Theory]
    // public
    [InlineData("8.8.8.8", true)]
    [InlineData("1.1.1.1", true)]
    [InlineData("93.184.216.34", true)]
    [InlineData("172.32.0.1", true)]
    [InlineData("172.15.255.255", true)]
    [InlineData("100.63.255.255", true)]
    [InlineData("100.128.0.1", true)]
    [InlineData("169.253.1.1", true)]
    [InlineData("2606:4700:4700::1111", true)]
    [InlineData("2a00:1450:4001:81b::200e", true)]
    [InlineData("::ffff:8.8.8.8", true)]
    [InlineData("64:ff9b::808:808", true)]              // NAT64 of 8.8.8.8
    [InlineData("2002:0808:0808::1", true)]             // 6to4 of 8.8.8.8
    // IPv4 internal and reserved
    [InlineData("0.0.0.0", false)]
    [InlineData("0.1.2.3", false)]
    [InlineData("10.0.0.1", false)]
    [InlineData("10.255.255.255", false)]
    [InlineData("127.0.0.1", false)]
    [InlineData("127.255.255.254", false)]
    [InlineData("100.64.0.1", false)]
    [InlineData("100.127.255.255", false)]
    [InlineData("169.254.0.1", false)]
    [InlineData("169.254.169.254", false)]               // cloud metadata
    [InlineData("172.16.0.1", false)]
    [InlineData("172.31.255.255", false)]
    [InlineData("192.0.0.1", false)]
    [InlineData("192.0.2.1", false)]
    [InlineData("192.88.99.1", false)]
    [InlineData("192.168.0.1", false)]
    [InlineData("198.18.0.1", false)]
    [InlineData("198.19.255.255", false)]
    [InlineData("198.51.100.7", false)]
    [InlineData("203.0.113.9", false)]
    [InlineData("224.0.0.1", false)]
    [InlineData("239.255.255.255", false)]
    [InlineData("240.0.0.1", false)]
    [InlineData("255.255.255.255", false)]
    // IPv6 internal and reserved
    [InlineData("::", false)]
    [InlineData("::1", false)]
    [InlineData("fc00::1", false)]
    [InlineData("fd00:ec2::254", false)]                 // AWS IMDS over IPv6
    [InlineData("fe80::1", false)]
    [InlineData("fe80::a9fe:a9fe", false)]
    [InlineData("fec0::1", false)]                       // site-local, deprecated
    [InlineData("febf::1", false)]
    [InlineData("ff02::1", false)]
    [InlineData("2001:db8::1", false)]
    [InlineData("3fff::1", false)]
    [InlineData("100::1", false)]
    [InlineData("2001::1", false)]                       // Teredo
    // IPv4 hidden inside an IPv6 address
    [InlineData("::ffff:127.0.0.1", false)]
    [InlineData("::ffff:7f00:1", false)]
    [InlineData("0:0:0:0:0:ffff:7f00:1", false)]
    [InlineData("::ffff:169.254.169.254", false)]
    [InlineData("::ffff:a9fe:a9fe", false)]
    [InlineData("::ffff:10.1.2.3", false)]
    [InlineData("::127.0.0.1", false)]                   // IPv4-compatible
    [InlineData("::10.0.0.1", false)]
    [InlineData("::8.8.8.8", false)]                     // IPv4-compatible is deprecated and never a destination
    [InlineData("::ffff:0:127.0.0.1", false)]            // IPv4-translated (SIIT)
    [InlineData("::ffff:0:a9fe:a9fe", false)]
    [InlineData("64:ff9b::7f00:1", false)]               // NAT64 of 127.0.0.1
    [InlineData("64:ff9b::a9fe:a9fe", false)]            // NAT64 of 169.254.169.254
    [InlineData("64:ff9b::a00:1", false)]
    [InlineData("64:ff9b:1::1", false)]                  // local-use NAT64 prefix
    [InlineData("64:ff9b:1:2:3:4:7f00:1", false)]
    [InlineData("2002:7f00:1::", false)]                 // 6to4 of 127.0.0.1
    [InlineData("2002:a9fe:a9fe::1", false)]             // 6to4 of 169.254.169.254
    [InlineData("2002:0a00:0001::", false)]
    [InlineData("2002:c0a8:0101::1", false)]             // 6to4 of 192.168.1.1
    public void Classifies(string address, bool publiclyRoutable) =>
        Assert.Equal(publiclyRoutable, NetworkAddresses.IsPubliclyRoutable(IPAddress.Parse(address)));

    [Theory]
    [InlineData("10.1.2.3", true)]
    [InlineData("172.20.0.1", true)]
    [InlineData("192.168.5.5", true)]
    [InlineData("169.254.169.254", true)]
    [InlineData("100.100.100.200", true)]                // CGNAT, and the Alibaba Cloud metadata address
    [InlineData("127.0.0.1", true)]
    [InlineData("::1", true)]
    [InlineData("fd12::1", true)]
    [InlineData("fe80::1", true)]
    [InlineData("::ffff:192.168.1.1", true)]
    [InlineData("64:ff9b::c0a8:101", true)]
    [InlineData("2002:0a00:0001::", true)]
    [InlineData("93.184.216.34", false)]
    [InlineData("192.0.2.1", false)]                     // documentation space is not a network of the operator's
    [InlineData("2001:db8::1", false)]
    [InlineData("224.0.0.1", false)]
    [InlineData("2606:4700:4700::1111", false)]
    public void Internal_networks_are_the_addresses_an_MX_may_not_name(string address, bool internalNetwork) =>
        Assert.Equal(internalNetwork, NetworkAddresses.IsInternalNetwork(IPAddress.Parse(address)));

    [Fact]
    public void Every_ipv4_address_of_every_internal_block_is_refused_at_its_edges()
    {
        (string First, string Last)[] blocks =
        [
            ("10.0.0.0", "10.255.255.255"), ("172.16.0.0", "172.31.255.255"), ("192.168.0.0", "192.168.255.255"), ("127.0.0.0", "127.255.255.255"),
            ("169.254.0.0", "169.254.255.255"), ("100.64.0.0", "100.127.255.255"), ("0.0.0.0", "0.255.255.255"),
        ];
        foreach (var (first, last) in blocks)
        {
            Assert.False(NetworkAddresses.IsPubliclyRoutable(IPAddress.Parse(first)), first);
            Assert.False(NetworkAddresses.IsPubliclyRoutable(IPAddress.Parse(last)), last);
            // The same address behind an IPv6 prefix that embeds it.
            foreach (string prefix in new[] { "::ffff:", "64:ff9b::" })
            {
                Assert.False(NetworkAddresses.IsPubliclyRoutable(IPAddress.Parse(prefix + ToHexGroups(first))), prefix + first);
                Assert.False(NetworkAddresses.IsPubliclyRoutable(IPAddress.Parse(prefix + ToHexGroups(last))), prefix + last);
            }

            Assert.False(NetworkAddresses.IsPubliclyRoutable(IPAddress.Parse("2002:" + ToHexGroups(first) + "::")), "6to4 " + first);
        }
    }

    private static string ToHexGroups(string v4)
    {
        byte[] b = IPAddress.Parse(v4).GetAddressBytes();
        return $"{b[0]:x2}{b[1]:x2}:{b[2]:x2}{b[3]:x2}";
    }
}
