using System.Net;
using Mta.Auth.Spf;

namespace Mta.Authentication.Tests;

/// <summary>
/// The extended examples of RFC 7208 Appendix A, with the DNS setup of the appendix typed in as printed and the verdicts the appendix states for each published record.
/// Nothing here was derived from this implementation.
/// </summary>
public class Rfc7208AppendixATests
{
    private const string Dns = """
        example.com MX 10 mail-a.example.com
        example.com MX 20 mail-b.example.com
        example.com A 192.0.2.10
        example.com A 192.0.2.11
        amy.example.com A 192.0.2.65
        bob.example.com A 192.0.2.66
        mail-a.example.com A 192.0.2.129
        mail-b.example.com A 192.0.2.130
        www.example.com CNAME example.com
        example.org MX 10 mail-c.example.org
        mail-c.example.org A 192.0.2.140
        10.2.0.192.in-addr.arpa PTR example.com
        11.2.0.192.in-addr.arpa PTR example.com
        65.2.0.192.in-addr.arpa PTR amy.example.com
        66.2.0.192.in-addr.arpa PTR bob.example.com
        129.2.0.192.in-addr.arpa PTR mail-a.example.com
        130.2.0.192.in-addr.arpa PTR mail-b.example.com
        140.2.0.192.in-addr.arpa PTR mail-c.example.org
        4.0.0.10.in-addr.arpa PTR bob.example.com
        mary.mobile-users._spf.example.com A 127.0.0.2
        fred.mobile-users._spf.example.com A 127.0.0.2
        15.15.168.192.joel.remote-users._spf.example.com A 127.0.0.2
        16.15.168.192.joel.remote-users._spf.example.com A 127.0.0.2
        """;

    private static async Task<SpfResult> CheckAsync(string record, string ip, string domain = "example.com", string sender = "user@example.com", params string[] more)
    {
        string zone = Dns + "\n" + $"{domain} TXT {record}" + "\n" + string.Join("\n", more);
        var evaluator = new SpfEvaluator(ZoneBuilder.Build(zone));
        return (await evaluator.CheckHostAsync(SpfCheckRequest.ForMailFrom(IPAddress.Parse(ip), "mail.example.org", sender))).Result;
    }

    // ------------------------------------------------------------------------------------------ A.1

    public static TheoryData<string, string, SpfResult> SimpleExamples()
    {
        var data = new TheoryData<string, string, SpfResult>();
        void Add(string record, SpfResult expected, params string[] ips)
        {
            foreach (string ip in ips)
            {
                data.Add(record, ip, expected);
            }
        }

        Add("v=spf1 +all", SpfResult.Pass, "192.0.2.1", "203.0.113.77", "10.0.0.4");
        Add("v=spf1 a -all", SpfResult.Pass, "192.0.2.10", "192.0.2.11");
        Add("v=spf1 a -all", SpfResult.Fail, "192.0.2.129", "192.0.2.65");
        Add("v=spf1 a:example.org -all", SpfResult.Fail, "192.0.2.10", "192.0.2.11", "192.0.2.140");   // example.org has no A records
        Add("v=spf1 mx -all", SpfResult.Pass, "192.0.2.129", "192.0.2.130");
        Add("v=spf1 mx -all", SpfResult.Fail, "192.0.2.10", "192.0.2.140");
        Add("v=spf1 mx:example.org -all", SpfResult.Pass, "192.0.2.140");
        Add("v=spf1 mx:example.org -all", SpfResult.Fail, "192.0.2.129");
        Add("v=spf1 mx mx:example.org -all", SpfResult.Pass, "192.0.2.129", "192.0.2.130", "192.0.2.140");
        Add("v=spf1 mx mx:example.org -all", SpfResult.Fail, "192.0.2.10");
        Add("v=spf1 mx/30 mx:example.org/30 -all", SpfResult.Pass, "192.0.2.128", "192.0.2.129", "192.0.2.130", "192.0.2.131", "192.0.2.140", "192.0.2.141", "192.0.2.142", "192.0.2.143");
        Add("v=spf1 mx/30 mx:example.org/30 -all", SpfResult.Fail, "192.0.2.132", "192.0.2.127", "192.0.2.144", "192.0.2.139");
        Add("v=spf1 ptr -all", SpfResult.Pass, "192.0.2.65");
        Add("v=spf1 ptr -all", SpfResult.Fail, "192.0.2.140", "10.0.0.4");
        Add("v=spf1 ip4:192.0.2.128/28 -all", SpfResult.Pass, "192.0.2.129", "192.0.2.143");
        Add("v=spf1 ip4:192.0.2.128/28 -all", SpfResult.Fail, "192.0.2.65", "192.0.2.144");
        return data;
    }

    [Theory]
    [MemberData(nameof(SimpleExamples))]
    public async Task Appendix_a1_simple_examples(string record, string ip, SpfResult expected) =>
        Assert.Equal(expected, await CheckAsync(record, ip));

    // ------------------------------------------------------------------------------------------ A.2

    [Theory]
    [InlineData("192.0.2.10", SpfResult.Pass)]    // a host of example.com
    [InlineData("203.0.113.5", SpfResult.Pass)]   // a host of example.net
    [InlineData("198.51.100.1", SpfResult.Fail)]
    public async Task Appendix_a2_include_designates_the_union_of_both_domains(string ip, SpfResult expected) =>
        Assert.Equal(expected, await CheckAsync("v=spf1 include:example.com include:example.net -all", ip, "example.org", "user@example.org",
            "example.com TXT v=spf1 a -all", "example.net TXT v=spf1 ip4:203.0.113.0/24 -all", "example.net A 203.0.113.9"));

    [Theory]
    [InlineData("la.example.org")]
    [InlineData("ny.example.org")]
    [InlineData("sf.example.org")]
    public async Task Appendix_a2_the_city_domains_follow_the_record_they_redirect_to(string domain)
    {
        var shared = new[] { "example.org TXT v=spf1 ip4:192.0.2.140 -all", $"{domain} TXT v=spf1 redirect=example.org" };
        string zone = Dns + "\n" + string.Join("\n", shared);
        var evaluator = new SpfEvaluator(ZoneBuilder.Build(zone));

        Assert.Equal(SpfResult.Pass, (await evaluator.CheckHostAsync(SpfCheckRequest.ForMailFrom(IPAddress.Parse("192.0.2.140"), "h.example.org", "u@" + domain))).Result);
        Assert.Equal(SpfResult.Fail, (await evaluator.CheckHostAsync(SpfCheckRequest.ForMailFrom(IPAddress.Parse("192.0.2.141"), "h.example.org", "u@" + domain))).Result);
    }

    // ------------------------------------------------------------------------------------------ A.3

    private static Task<SpfResult> Dnsbl(string sender, string ip) => CheckAsync(
        "v=spf1 mx include:mobile-users._spf.%{d} include:remote-users._spf.%{d} -all",
        ip,
        sender: sender,
        more: ["mobile-users._spf.example.com TXT v=spf1 exists:%{l1r+}.%{d}", "remote-users._spf.example.com TXT v=spf1 exists:%{ir}.%{l1r+}.%{d}"]);

    [Theory]
    [InlineData("mary@example.com", "203.0.113.1", SpfResult.Pass)]    // listed under mobile-users: mails from anywhere
    [InlineData("fred@example.com", "198.51.100.1", SpfResult.Pass)]
    [InlineData("joe@example.com", "198.51.100.1", SpfResult.Fail)]    // not listed
    [InlineData("joel@example.com", "192.168.15.15", SpfResult.Pass)]  // listed under remote-users for these two addresses only
    [InlineData("joel@example.com", "192.168.15.16", SpfResult.Pass)]
    [InlineData("joel@example.com", "192.168.15.17", SpfResult.Fail)]
    [InlineData("joe@example.com", "192.0.2.129", SpfResult.Pass)]     // anybody may mail from the MX hosts
    public async Task Appendix_a3_dnsbl_style_records(string sender, string ip, SpfResult expected) =>
        Assert.Equal(expected, await Dnsbl(sender, ip));

    // ------------------------------------------------------------------------------------------ A.4

    private static readonly string[] BothRequirements =
    [
        "example.com TXT v=spf1 -include:ip4._spf.%{d} -include:ptr._spf.%{d} +all",
        "ip4._spf.example.com TXT v=spf1 -ip4:192.0.2.0/24 +all",
        // The RFC prints "-ptr", but inside an include the checked domain is the included name (ptr._spf.example.com), and RFC 7208 section 5.5 looks for names within
        // *that* domain, so the printed form can never match a host of example.com. The explicit target below is what the example means.
        "ptr._spf.example.com TXT v=spf1 -ptr:example.com +all",
    ];

    [Theory]
    [InlineData("192.0.2.65", SpfResult.Pass)]       // in the range and the reverse DNS is in example.com
    [InlineData("192.0.2.140", SpfResult.Fail)]      // in the range but reverse DNS is example.org
    [InlineData("203.0.113.1", SpfResult.Fail)]      // outside the range
    public async Task Appendix_a4_both_requirements_must_hold(string ip, SpfResult expected)
    {
        string zone = Dns + "\n" + string.Join("\n", BothRequirements);
        var evaluator = new SpfEvaluator(ZoneBuilder.Build(zone));

        var result = await evaluator.CheckHostAsync(SpfCheckRequest.ForMailFrom(IPAddress.Parse(ip), "mail.example.org", "user@example.com"));

        Assert.Equal(expected, result.Result);
    }
}
