using Mta.Auth.Spf;
using static Mta.Auth.Tests.TestZone;

namespace Mta.Auth.Tests.Spf;

/// <summary>Data-driven check_host() cases in the style of the openspf.org / RFC 7208 test suite.</summary>
public static class SpfCases
{
    private const string DefaultIp = "192.0.2.3";

    public static IEnumerable<object?[]> All()
    {
        var c = new CaseList();
        Selection(c);
        Qualifiers(c);
        Ip4(c);
        Ip6(c);
        A(c);
        Mx(c);
        Ptr(c);
        Exists(c);
        Include(c);
        Redirect(c);
        Explanation(c);
        Modifiers(c);
        MacrosInEvaluation(c);
        Limits(c);
        return c.Rows;
    }

    private sealed class CaseList
    {
        public List<object?[]> Rows { get; } = [];

        public void Add(
            string id,
            string zone,
            SpfResult expected,
            string? matched = null,
            string ip = DefaultIp,
            string domain = "example.com",
            string sender = "user@example.com",
            string? explanation = null) =>
            Rows.Add([id, zone, ip, domain, sender, expected, matched, explanation]);
    }

    private static string Spf(string terms) => $"example.com TXT v=spf1 {terms}";

    private static void Selection(CaseList c)
    {
        c.Add("selection/no-txt-nxdomain", Z(), SpfResult.None);
        c.Add("selection/domain-without-txt", Z("example.com A 192.0.2.1"), SpfResult.None);
        c.Add("selection/non-spf-txt", Z("example.com TXT google-site-verification=abc"), SpfResult.None);
        c.Add("selection/empty-record-is-neutral", Z("example.com TXT v=spf1"), SpfResult.Neutral);
        c.Add("selection/uppercase-version", Z("example.com TXT V=SPF1 -all"), SpfResult.Fail, "all");
        c.Add("selection/version-spf10-is-not-spf1", Z("example.com TXT v=spf10 -all"), SpfResult.None);
        c.Add("selection/version-needs-space", Z("example.com TXT v=spf1-all"), SpfResult.None);
        c.Add("selection/trailing-space", Z("example.com TXT v=spf1 "), SpfResult.Neutral);
        c.Add("selection/tab-after-version", Z("example.com TXT v=spf1\t-all"), SpfResult.None);
        c.Add("selection/two-spf-records", Z(Spf("-all"), Spf("+all")), SpfResult.PermError);
        c.Add("selection/two-identical-spf-records", Z(Spf("-all"), Spf("-all")), SpfResult.PermError);
        c.Add("selection/other-txt-ignored", Z("example.com TXT hello", Spf("-all"), "example.com TXT v=DMARC1; p=none"), SpfResult.Fail, "all");
        c.Add("selection/txt-servfail", Z("example.com SERVFAIL TXT"), SpfResult.TempError);
        c.Add("selection/txt-refused", Z("example.com REFUSED TXT"), SpfResult.TempError);
        c.Add("selection/invalid-domain-empty-label", Z(Spf("-all")), SpfResult.None, domain: "bad..example.com");
        c.Add("selection/ip-literal-domain", Z(Spf("-all")), SpfResult.None, domain: "[192.0.2.1]");
        c.Add("selection/numeric-domain", Z(Spf("-all")), SpfResult.None, domain: "192.0.2.1");
        c.Add("selection/empty-domain", Z(Spf("-all")), SpfResult.None, domain: "");
        c.Add("selection/trailing-dot-domain", Z(Spf("-all")), SpfResult.Fail, "all", domain: "example.com.");
        c.Add("selection/uppercase-domain", Z(Spf("-all")), SpfResult.Fail, "all", domain: "EXAMPLE.COM");
        c.Add("selection/long-label-domain", Z(Spf("-all")), SpfResult.None, domain: new string('a', 64) + ".example.com");
        c.Add("selection/record-too-long", Z("example.com TXT v=spf1 " + string.Concat(Enumerable.Repeat("ip4:10.0.0.1 ", 400)) + "-all"), SpfResult.PermError);
        c.Add("selection/multiple-spaces", Z("example.com TXT v=spf1   ip4:192.0.2.3    -all"), SpfResult.Pass, "ip4:192.0.2.3");
        c.Add("selection/cname-to-record", Z("example.com CNAME real.example.org", "real.example.org TXT v=spf1 -all"), SpfResult.Fail, "all");
        c.Add("selection/unknown-mechanism", Z(Spf("foo -all")), SpfResult.PermError);
        c.Add("selection/syntax-error-after-match", Z(Spf("ip4:192.0.2.3 foo")), SpfResult.PermError);
        c.Add("selection/syntax-error-after-all", Z(Spf("-all bogus:x")), SpfResult.PermError);
    }

    private static void Qualifiers(CaseList c)
    {
        c.Add("qualifier/minus-all", Z(Spf("-all")), SpfResult.Fail, "all");
        c.Add("qualifier/tilde-all", Z(Spf("~all")), SpfResult.SoftFail, "all");
        c.Add("qualifier/question-all", Z(Spf("?all")), SpfResult.Neutral, "all");
        c.Add("qualifier/plus-all", Z(Spf("+all")), SpfResult.Pass, "all");
        c.Add("qualifier/default-all", Z(Spf("all")), SpfResult.Pass, "all");
        c.Add("qualifier/all-with-argument", Z(Spf("all:foo")), SpfResult.PermError);
        c.Add("qualifier/terms-after-all-ignored", Z(Spf("-all ip4:192.0.2.3")), SpfResult.Fail, "all");
        c.Add("qualifier/mechanism-names-case-insensitive", Z(Spf("IP4:192.0.2.3 -ALL")), SpfResult.Pass, "IP4:192.0.2.3");
        c.Add("qualifier/minus-ip4", Z(Spf("-ip4:192.0.2.3 +all")), SpfResult.Fail, "ip4:192.0.2.3");
        c.Add("qualifier/tilde-ip4", Z(Spf("~ip4:192.0.2.3")), SpfResult.SoftFail, "ip4:192.0.2.3");
        c.Add("qualifier/question-ip4", Z(Spf("?ip4:192.0.2.3")), SpfResult.Neutral, "ip4:192.0.2.3");
        c.Add("qualifier/plus-ip4", Z(Spf("+ip4:192.0.2.3")), SpfResult.Pass, "ip4:192.0.2.3");
        c.Add("qualifier/no-match-is-neutral", Z(Spf("ip4:10.0.0.0/8")), SpfResult.Neutral);
        c.Add("qualifier/first-match-wins", Z(Spf("~ip4:192.0.2.0/24 -ip4:192.0.2.3 +all")), SpfResult.SoftFail, "ip4:192.0.2.0/24");
    }

    private static void Ip4(CaseList c)
    {
        c.Add("ip4/exact", Z(Spf("ip4:192.0.2.3 -all")), SpfResult.Pass, "ip4:192.0.2.3");
        c.Add("ip4/slash-32", Z(Spf("ip4:192.0.2.3/32 -all")), SpfResult.Pass, "ip4:192.0.2.3/32");
        c.Add("ip4/cidr-24-match", Z(Spf("ip4:192.0.2.0/24 -all")), SpfResult.Pass, "ip4:192.0.2.0/24");
        c.Add("ip4/cidr-24-no-match", Z(Spf("ip4:192.0.2.0/24 -all")), SpfResult.Fail, "all", ip: "192.0.3.3");
        c.Add("ip4/cidr-26-boundary-in", Z(Spf("ip4:192.0.2.64/26 -all")), SpfResult.Pass, "ip4:192.0.2.64/26", ip: "192.0.2.127");
        c.Add("ip4/cidr-26-boundary-out", Z(Spf("ip4:192.0.2.64/26 -all")), SpfResult.Fail, "all", ip: "192.0.2.128");
        c.Add("ip4/cidr-31", Z(Spf("ip4:192.0.2.2/31 -all")), SpfResult.Pass, "ip4:192.0.2.2/31");
        c.Add("ip4/cidr-0-matches-all", Z(Spf("ip4:0.0.0.0/0 -all")), SpfResult.Pass, "ip4:0.0.0.0/0", ip: "203.0.113.9");
        c.Add("ip4/cidr-33-is-error", Z(Spf("ip4:192.0.2.0/33")), SpfResult.PermError);
        c.Add("ip4/cidr-leading-zero-is-error", Z(Spf("ip4:192.0.2.0/024")), SpfResult.PermError);
        c.Add("ip4/cidr-empty-is-error", Z(Spf("ip4:192.0.2.0/")), SpfResult.PermError);
        c.Add("ip4/cidr-double-is-error", Z(Spf("ip4:192.0.2.0/24/24")), SpfResult.PermError);
        c.Add("ip4/octet-256-is-error", Z(Spf("ip4:192.0.2.256")), SpfResult.PermError);
        c.Add("ip4/three-octets-is-error", Z(Spf("ip4:192.0.2")), SpfResult.PermError);
        c.Add("ip4/leading-zero-octet-is-error", Z(Spf("ip4:192.0.02.1")), SpfResult.PermError);
        c.Add("ip4/missing-argument-is-error", Z(Spf("ip4")), SpfResult.PermError);
        c.Add("ip4/empty-argument-is-error", Z(Spf("ip4:")), SpfResult.PermError);
        c.Add("ip4/hostname-is-error", Z(Spf("ip4:mail.example.com")), SpfResult.PermError);
        c.Add("ip4/ignores-ipv6-client", Z(Spf("ip4:0.0.0.0/0 -all")), SpfResult.Fail, "all", ip: "2001:db8::3");
        c.Add("ip4/ipv4-mapped-ipv6-client-is-ipv4", Z(Spf("ip4:192.0.2.0/24 -all")), SpfResult.Pass, "ip4:192.0.2.0/24", ip: "::ffff:192.0.2.3");
        c.Add("ip4/multiple-networks", Z(Spf("ip4:10.0.0.0/8 ip4:198.51.100.0/24 ip4:192.0.2.0/24 -all")), SpfResult.Pass, "ip4:192.0.2.0/24");
    }

    private static void Ip6(CaseList c)
    {
        c.Add("ip6/prefix-match", Z(Spf("ip6:2001:db8::/32 -all")), SpfResult.Pass, "ip6:2001:db8::/32", ip: "2001:db8::1");
        c.Add("ip6/exact", Z(Spf("ip6:2001:db8::1 -all")), SpfResult.Pass, "ip6:2001:db8::1", ip: "2001:db8::1");
        c.Add("ip6/exact-no-match", Z(Spf("ip6:2001:db8::1 -all")), SpfResult.Fail, "all", ip: "2001:db8::2");
        c.Add("ip6/prefix-64-no-match", Z(Spf("ip6:2001:db8::/64 -all")), SpfResult.Fail, "all", ip: "2001:db8:0:1::5");
        c.Add("ip6/prefix-127-mid-byte", Z(Spf("ip6:2001:db8::1/127 -all")), SpfResult.Pass, "ip6:2001:db8::1/127", ip: "2001:db8::");
        c.Add("ip6/prefix-0", Z(Spf("ip6:::/0 -all")), SpfResult.Pass, "ip6:::/0", ip: "2001:db8::77");
        c.Add("ip6/prefix-129-is-error", Z(Spf("ip6:2001:db8::/129")), SpfResult.PermError);
        c.Add("ip6/garbage-is-error", Z(Spf("ip6:zzz")), SpfResult.PermError);
        c.Add("ip6/ipv4-text-is-error", Z(Spf("ip6:192.0.2.1")), SpfResult.PermError);
        c.Add("ip6/bracketed-is-error", Z(Spf("ip6:[2001:db8::1]")), SpfResult.PermError);
        c.Add("ip6/scope-id-is-error", Z(Spf("ip6:fe80::1%eth0")), SpfResult.PermError);
        c.Add("ip6/ignores-ipv4-client", Z(Spf("ip6:::/0 -all")), SpfResult.Fail, "all");
        c.Add("ip6/uppercase-hex", Z(Spf("ip6:2001:DB8::/32 -all")), SpfResult.Pass, "ip6:2001:DB8::/32", ip: "2001:db8::9");
        c.Add("ip6/missing-argument-is-error", Z(Spf("ip6")), SpfResult.PermError);
    }

    private static void A(CaseList c)
    {
        c.Add("a/current-domain", Z(Spf("a -all"), "example.com A 192.0.2.3"), SpfResult.Pass, "a");
        c.Add("a/other-domain", Z(Spf("a:mail.example.org -all"), "mail.example.org A 192.0.2.3"), SpfResult.Pass, "a:mail.example.org");
        c.Add("a/cidr-24", Z(Spf("a/24 -all"), "example.com A 192.0.2.99"), SpfResult.Pass, "a/24");
        c.Add("a/cidr-24-no-match", Z(Spf("a/24 -all"), "example.com A 198.51.100.1"), SpfResult.Fail, "all");
        c.Add("a/other-domain-and-cidr", Z(Spf("a:mail.example.org/24 -all"), "mail.example.org A 192.0.2.200"), SpfResult.Pass, "a:mail.example.org/24");
        c.Add("a/ipv6-client-uses-aaaa", Z(Spf("a -all"), "example.com AAAA 2001:db8::1"), SpfResult.Pass, "a", ip: "2001:db8::1");
        c.Add("a/ipv6-client-ignores-a-records", Z(Spf("a -all"), "example.com A 192.0.2.3"), SpfResult.Fail, "all", ip: "2001:db8::1");
        c.Add("a/ipv6-cidr-64", Z(Spf("a//64 -all"), "example.com AAAA 2001:db8::1"), SpfResult.Pass, "a//64", ip: "2001:db8::ffff");
        c.Add("a/ipv6-cidr-64-no-match", Z(Spf("a//64 -all"), "example.com AAAA 2001:db8::1"), SpfResult.Fail, "all", ip: "2001:db8:0:1::1");
        c.Add("a/dual-cidr-ipv4-client", Z(Spf("a/24//64 -all"), "example.com A 192.0.2.50"), SpfResult.Pass, "a/24//64");
        c.Add("a/dual-cidr-ipv6-client", Z(Spf("a/24//64 -all"), "example.com AAAA 2001:db8::1"), SpfResult.Pass, "a/24//64", ip: "2001:db8::abcd");
        c.Add("a/ipv6-cidr-only-keeps-ipv4-exact", Z(Spf("a//64 -all"), "example.com A 192.0.2.50"), SpfResult.Fail, "all");
        c.Add("a/domain-and-dual-cidr", Z(Spf("a:mail.example.org/24//64 -all"), "mail.example.org A 192.0.2.50"), SpfResult.Pass, "a:mail.example.org/24//64");
        c.Add("a/cidr-33-is-error", Z(Spf("a/33")), SpfResult.PermError);
        c.Add("a/cidr6-129-is-error", Z(Spf("a//129")), SpfResult.PermError);
        c.Add("a/empty-domain-is-error", Z(Spf("a:")), SpfResult.PermError);
        c.Add("a/empty-cidr-is-error", Z(Spf("a:mail.example.org/")), SpfResult.PermError);
        c.Add("a/bare-slash-is-error", Z(Spf("a/")), SpfResult.PermError);
        c.Add("a/double-slash-only-is-error", Z(Spf("a//")), SpfResult.PermError);
        c.Add("a/triple-slash-is-error", Z(Spf("a///64")), SpfResult.PermError);
        c.Add("a/domain-without-top-label-is-error", Z(Spf("a:foo")), SpfResult.PermError);
        c.Add("a/numeric-top-label-is-error", Z(Spf("a:example.123")), SpfResult.PermError);
        c.Add("a/no-address-records-is-void", Z(Spf("a -all")), SpfResult.Fail, "all");
        c.Add("a/two-void-lookups-allowed", Z(Spf("a:v1.example.org a:v2.example.org -all")), SpfResult.Fail, "all");
        c.Add("a/three-void-lookups-is-permerror", Z(Spf("a:v1.example.org a:v2.example.org a:v3.example.org -all")), SpfResult.PermError);
        c.Add("a/servfail-is-temperror", Z(Spf("a -all"), "example.com SERVFAIL A"), SpfResult.TempError);
        c.Add("a/follows-cname", Z(Spf("a:mail.example.org -all"), "mail.example.org CNAME real.example.org", "real.example.org A 192.0.2.3"), SpfResult.Pass, "a:mail.example.org");
        c.Add("a/overlong-label-never-matches", Z(Spf($"a:{new string('x', 64)}.example.org -all")), SpfResult.Fail, "all");
        c.Add("a/negative-qualifier", Z(Spf("-a +all"), "example.com A 192.0.2.3"), SpfResult.Fail, "a");
        c.Add("a/multiple-addresses", Z(Spf("a -all"), "example.com A 198.51.100.1", "example.com A 192.0.2.3"), SpfResult.Pass, "a");
    }

    private static void Mx(CaseList c)
    {
        string basic = Z("example.com MX 10 mail.example.com", "mail.example.com A 192.0.2.3");
        c.Add("mx/current-domain", Z(Spf("mx -all"), basic), SpfResult.Pass, "mx");
        c.Add("mx/other-domain", Z(Spf("mx:example.org -all"), "example.org MX 10 mail.example.org", "mail.example.org A 192.0.2.3"), SpfResult.Pass, "mx:example.org");
        c.Add("mx/cidr-24", Z(Spf("mx/24 -all"), "example.com MX 10 mail.example.com", "mail.example.com A 192.0.2.99"), SpfResult.Pass, "mx/24");
        c.Add("mx/second-exchange", Z(Spf("mx -all"), "example.com MX 10 a.example.com", "example.com MX 20 b.example.com", "a.example.com A 198.51.100.1", "b.example.com A 192.0.2.3"), SpfResult.Pass, "mx");
        c.Add("mx/ipv6", Z(Spf("mx -all"), "example.com MX 10 mail.example.com", "mail.example.com AAAA 2001:db8::25"), SpfResult.Pass, "mx", ip: "2001:db8::25");
        c.Add("mx/ipv6-cidr", Z(Spf("mx//64 -all"), "example.com MX 10 mail.example.com", "mail.example.com AAAA 2001:db8::25"), SpfResult.Pass, "mx//64", ip: "2001:db8::99");
        c.Add("mx/no-match", Z(Spf("mx -all"), "example.com MX 10 mail.example.com", "mail.example.com A 198.51.100.1"), SpfResult.Fail, "all");
        c.Add("mx/no-mx-records-is-void-and-no-implicit-mx", Z(Spf("mx -all"), "example.com A 192.0.2.3"), SpfResult.Fail, "all");
        c.Add("mx/ten-exchanges-last-matches", Z(Spf("mx -all"), MxFarm(10, "mail9.example.com A 192.0.2.3")), SpfResult.Pass, "mx");
        c.Add("mx/eleven-exchanges-is-permerror", Z(Spf("mx -all"), MxFarm(11, "mail10.example.com A 192.0.2.3")), SpfResult.PermError);
        c.Add("mx/null-mx-is-skipped", Z(Spf("mx -all"), "example.com MX 0 ."), SpfResult.Fail, "all");
        c.Add("mx/servfail-on-mx-query", Z(Spf("mx -all"), "example.com SERVFAIL MX"), SpfResult.TempError);
        c.Add("mx/servfail-on-exchange-address", Z(Spf("mx -all"), "example.com MX 10 mail.example.com", "mail.example.com SERVFAIL A"), SpfResult.TempError);
        c.Add("mx/two-void-exchanges-then-match", Z(Spf("mx -all"), "example.com MX 10 n1.example.com", "example.com MX 20 n2.example.com", "example.com MX 30 mail.example.com", "mail.example.com A 192.0.2.3"), SpfResult.Pass, "mx");
        c.Add("mx/three-void-exchanges-is-permerror", Z(Spf("mx -all"), "example.com MX 10 n1.example.com", "example.com MX 20 n2.example.com", "example.com MX 30 n3.example.com", "example.com MX 40 mail.example.com", "mail.example.com A 192.0.2.3"), SpfResult.PermError);
        c.Add("mx/cidr-33-is-error", Z(Spf("mx/33")), SpfResult.PermError);
        c.Add("mx/empty-domain-is-error", Z(Spf("mx:")), SpfResult.PermError);
        c.Add("mx/preference-order-does-not-change-result", Z(Spf("mx -all"), "example.com MX 50 z.example.com", "example.com MX 5 a.example.com", "a.example.com A 192.0.2.3"), SpfResult.Pass, "mx");
    }

    private static string MxFarm(int count, string lastHostRecord)
    {
        var lines = new List<string>();
        for (int i = 0; i < count; i++)
        {
            lines.Add($"example.com MX {10 + i} mail{i}.example.com");
            if (i < count - 1)
            {
                lines.Add($"mail{i}.example.com A 198.51.100.{i + 1}");
            }
        }

        lines.Add(lastHostRecord);
        return Z(lines.ToArray());
    }

    private static void Ptr(CaseList c)
    {
        string good = Z("3.2.0.192.in-addr.arpa PTR mail.example.com", "mail.example.com A 192.0.2.3");
        c.Add("ptr/validated", Z(Spf("ptr -all"), good), SpfResult.Pass, "ptr");
        c.Add("ptr/explicit-domain", Z(Spf("ptr:example.com -all"), good), SpfResult.Pass, "ptr:example.com");
        c.Add("ptr/domain-differs", Z(Spf("ptr:example.org -all"), good), SpfResult.Fail, "all");
        c.Add("ptr/forward-does-not-match", Z(Spf("ptr -all"), "3.2.0.192.in-addr.arpa PTR mail.example.com", "mail.example.com A 192.0.2.99"), SpfResult.Fail, "all");
        c.Add("ptr/different-domain", Z(Spf("ptr -all"), "3.2.0.192.in-addr.arpa PTR mail.other.org", "mail.other.org A 192.0.2.3"), SpfResult.Fail, "all");
        c.Add("ptr/suffix-without-dot-boundary", Z(Spf("ptr -all"), "3.2.0.192.in-addr.arpa PTR evilexample.com", "evilexample.com A 192.0.2.3"), SpfResult.Fail, "all");
        c.Add("ptr/name-equals-domain", Z(Spf("ptr -all"), "3.2.0.192.in-addr.arpa PTR example.com", "example.com A 192.0.2.3"), SpfResult.Pass, "ptr");
        c.Add("ptr/no-ptr-record", Z(Spf("ptr -all")), SpfResult.Fail, "all");
        c.Add("ptr/ptr-servfail-is-no-match", Z(Spf("ptr -all"), "3.2.0.192.in-addr.arpa SERVFAIL PTR"), SpfResult.Fail, "all");
        c.Add("ptr/forward-servfail-skips-name", Z(Spf("ptr -all"), "3.2.0.192.in-addr.arpa PTR bad.example.com", "3.2.0.192.in-addr.arpa PTR mail.example.com", "bad.example.com SERVFAIL A", "mail.example.com A 192.0.2.3"), SpfResult.Pass, "ptr");
        c.Add("ptr/ipv6", Z(Spf("ptr -all"), "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa PTR mail.example.com", "mail.example.com AAAA 2001:db8::1"), SpfResult.Pass, "ptr", ip: "2001:db8::1");
        c.Add("ptr/tenth-name-is-examined", Z(Spf("ptr -all"), PtrFarm(10, 9)), SpfResult.Pass, "ptr");
        c.Add("ptr/eleventh-name-is-ignored", Z(Spf("ptr -all"), PtrFarm(11, 10)), SpfResult.Fail, "all");
        c.Add("ptr/does-not-count-void", Z(Spf("ptr a:x1.example.org a:x2.example.org -all")), SpfResult.Fail, "all");
        c.Add("ptr/negative-qualifier", Z(Spf("-ptr +all"), good), SpfResult.Fail, "ptr");
        c.Add("ptr/with-cidr-is-error", Z(Spf("ptr/24")), SpfResult.PermError);
    }

    private static string PtrFarm(int count, int validIndex)
    {
        var lines = new List<string>();
        for (int i = 0; i < count; i++)
        {
            lines.Add($"3.2.0.192.in-addr.arpa PTR h{i}.example.com");
            lines.Add(i == validIndex ? $"h{i}.example.com A 192.0.2.3" : $"h{i}.example.com A 198.51.100.{i + 1}");
        }

        return Z(lines.ToArray());
    }

    private static void Exists(CaseList c)
    {
        c.Add("exists/ip-macro", Z(Spf("exists:%{ir}.rbl.example.org -all"), "3.2.0.192.rbl.example.org A 127.0.0.2"), SpfResult.Pass, "exists:%{ir}.rbl.example.org");
        c.Add("exists/no-record", Z(Spf("exists:%{ir}.rbl.example.org -all")), SpfResult.Fail, "all");
        c.Add("exists/servfail", Z(Spf("exists:%{ir}.rbl.example.org -all"), "3.2.0.192.rbl.example.org SERVFAIL A"), SpfResult.TempError);
        c.Add("exists/local-part-macro", Z(Spf("exists:%{l}.example.org -all"), "user.example.org A 127.0.0.2"), SpfResult.Pass, "exists:%{l}.example.org");
        c.Add("exists/ipv6-nibbles", Z(Spf("exists:%{ir}.rbl.example.org -all"), "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.rbl.example.org A 127.0.0.2"), SpfResult.Pass, "exists:%{ir}.rbl.example.org", ip: "2001:db8::1");
        c.Add("exists/missing-argument-is-error", Z(Spf("exists")), SpfResult.PermError);
        c.Add("exists/empty-argument-is-error", Z(Spf("exists:")), SpfResult.PermError);
        c.Add("exists/aaaa-only-is-no-match", Z(Spf("exists:x.example.org -all"), "x.example.org AAAA 2001:db8::1"), SpfResult.Fail, "all");
        c.Add("exists/uppercase-macro-url-escapes", Z(Spf("exists:%{L}.example.org -all"), "us%2fer.example.org A 127.0.0.2"), SpfResult.Pass, "exists:%{L}.example.org", sender: "us/er@example.com");
        c.Add("exists/two-void-lookups-allowed", Z(Spf("exists:a.example.org exists:b.example.org -all")), SpfResult.Fail, "all");
        c.Add("exists/three-void-lookups-is-permerror", Z(Spf("exists:a.example.org exists:b.example.org exists:c.example.org -all")), SpfResult.PermError);
        c.Add("exists/negative-qualifier-blocklist", Z(Spf("-exists:%{ir}.bl.example.org +all"), "3.2.0.192.bl.example.org A 127.0.0.2"), SpfResult.Fail, "exists:%{ir}.bl.example.org");
    }

    private static void Include(CaseList c)
    {
        string inner(string terms) => $"_spf.example.org TXT v=spf1 {terms}";
        c.Add("include/pass", Z(Spf("include:_spf.example.org -all"), inner("ip4:192.0.2.0/24 -all")), SpfResult.Pass, "include:_spf.example.org");
        c.Add("include/fail-is-no-match-continues", Z(Spf("include:_spf.example.org ip4:192.0.2.3 -all"), inner("-all")), SpfResult.Pass, "ip4:192.0.2.3");
        c.Add("include/softfail-is-no-match", Z(Spf("include:_spf.example.org -all"), inner("~all")), SpfResult.Fail, "all");
        c.Add("include/neutral-is-no-match", Z(Spf("include:_spf.example.org -all"), inner("?all")), SpfResult.Fail, "all");
        c.Add("include/inner-no-match-is-no-match", Z(Spf("include:_spf.example.org -all"), inner("ip4:10.0.0.0/8")), SpfResult.Fail, "all");
        c.Add("include/target-without-record-is-permerror", Z(Spf("include:_spf.example.org -all")), SpfResult.PermError);
        c.Add("include/target-without-spf-txt-is-permerror", Z(Spf("include:_spf.example.org -all"), "_spf.example.org TXT hello"), SpfResult.PermError);
        c.Add("include/inner-permerror-propagates", Z(Spf("include:_spf.example.org -all"), inner("foo")), SpfResult.PermError);
        c.Add("include/inner-temperror-propagates", Z(Spf("include:_spf.example.org -all"), "_spf.example.org SERVFAIL TXT"), SpfResult.TempError);
        c.Add("include/nested-pass", Z(Spf("include:b.example.org -all"), "b.example.org TXT v=spf1 include:c.example.org -all", "c.example.org TXT v=spf1 ip4:192.0.2.3 -all"), SpfResult.Pass, "include:b.example.org");
        c.Add("include/negative-qualifier", Z(Spf("-include:_spf.example.org +all"), inner("+all")), SpfResult.Fail, "include:_spf.example.org");
        c.Add("include/softfail-qualifier", Z(Spf("~include:_spf.example.org"), inner("+all")), SpfResult.SoftFail, "include:_spf.example.org");
        c.Add("include/missing-argument-is-error", Z(Spf("include")), SpfResult.PermError);
        c.Add("include/empty-argument-is-error", Z(Spf("include:")), SpfResult.PermError);
        c.Add("include/loop-hits-lookup-limit", Z(Spf("include:example.com -all")), SpfResult.PermError);
        c.Add("include/mutual-loop-hits-lookup-limit", Z(Spf("include:b.example.org"), "b.example.org TXT v=spf1 include:example.com"), SpfResult.PermError);
        c.Add("include/ten-lookups-allowed", Z(Spf(IncludeTerms(10) + " -all"), IncludeTargets(10)), SpfResult.Fail, "all");
        c.Add("include/eleven-lookups-is-permerror", Z(Spf(IncludeTerms(11) + " -all"), IncludeTargets(11)), SpfResult.PermError);
        c.Add("include/inner-exp-is-ignored", Z(Spf("include:_spf.example.org -all"), inner("-all exp=why.example.org"), "why.example.org TXT inner explanation"), SpfResult.Fail, "all", explanation: "domain of example.com does not designate 192.0.2.3 as permitted sender");
        c.Add("include/inner-redirect-works", Z(Spf("include:_spf.example.org -all"), inner("redirect=r.example.org"), "r.example.org TXT v=spf1 ip4:192.0.2.3 -all"), SpfResult.Pass, "include:_spf.example.org");
        c.Add("include/uses-macros", Z(Spf("include:%{d}.spf.example.org -all"), "example.com.spf.example.org TXT v=spf1 +all"), SpfResult.Pass, "include:%{d}.spf.example.org");
        c.Add("include/domain-macro-refers-to-included-domain", Z(Spf("include:_spf.example.org -all"), inner("exists:%{d}.x.example.org -all"), "_spf.example.org.x.example.org A 127.0.0.2"), SpfResult.Pass, "include:_spf.example.org");
        c.Add("include/overlong-label-is-permerror", Z(Spf($"include:{new string('x', 64)}.example.org")), SpfResult.PermError);
    }

    private static string IncludeTerms(int count) => string.Join(' ', Enumerable.Range(0, count).Select(i => $"include:i{i}.example.org"));

    private static string IncludeTargets(int count) => Z(Enumerable.Range(0, count).Select(i => $"i{i}.example.org TXT v=spf1 -all").ToArray());

    private static void Redirect(CaseList c)
    {
        c.Add("redirect/basic", Z(Spf("redirect=other.example.org"), "other.example.org TXT v=spf1 ip4:192.0.2.3 -all"), SpfResult.Pass, "ip4:192.0.2.3");
        c.Add("redirect/ignored-when-all-present", Z(Spf("-all redirect=other.example.org"), "other.example.org TXT v=spf1 +all"), SpfResult.Fail, "all");
        c.Add("redirect/not-evaluated-after-match", Z(Spf("ip4:192.0.2.3 redirect=missing.example.org")), SpfResult.Pass, "ip4:192.0.2.3");
        c.Add("redirect/evaluated-after-mechanisms-regardless-of-position", Z(Spf("redirect=other.example.org ip4:192.0.2.3"), "other.example.org TXT v=spf1 -all"), SpfResult.Pass, "ip4:192.0.2.3");
        c.Add("redirect/no-match-then-redirect", Z(Spf("ip4:10.0.0.0/8 redirect=other.example.org"), "other.example.org TXT v=spf1 ~all"), SpfResult.SoftFail, "all");
        c.Add("redirect/target-without-record-is-permerror", Z(Spf("redirect=other.example.org")), SpfResult.PermError);
        c.Add("redirect/chain", Z(Spf("redirect=b.example.org"), "b.example.org TXT v=spf1 redirect=c.example.org", "c.example.org TXT v=spf1 -all"), SpfResult.Fail, "all");
        c.Add("redirect/target-neutral", Z(Spf("redirect=b.example.org"), "b.example.org TXT v=spf1 ?all"), SpfResult.Neutral, "all");
        c.Add("redirect/target-empty-record-is-neutral", Z(Spf("redirect=b.example.org"), "b.example.org TXT v=spf1"), SpfResult.Neutral);
        c.Add("redirect/duplicate-is-permerror", Z(Spf("redirect=a.example.org redirect=b.example.org")), SpfResult.PermError);
        c.Add("redirect/empty-is-permerror", Z(Spf("redirect=")), SpfResult.PermError);
        c.Add("redirect/macro", Z(Spf("redirect=_spf.%{d}"), "_spf.example.com TXT v=spf1 +all"), SpfResult.Pass, "all");
        c.Add("redirect/servfail-is-temperror", Z(Spf("redirect=b.example.org"), "b.example.org SERVFAIL TXT"), SpfResult.TempError);
        c.Add("redirect/loop-is-permerror", Z(Spf("redirect=example.com")), SpfResult.PermError);
        c.Add("redirect/target-permerror", Z(Spf("redirect=b.example.org"), "b.example.org TXT v=spf1 bogus"), SpfResult.PermError);
        c.Add("redirect/target-exp-is-used", Z(Spf("redirect=b.example.org"), "b.example.org TXT v=spf1 -all exp=why.example.org", "why.example.org TXT Go away %{i}"), SpfResult.Fail, "all", explanation: "Go away 192.0.2.3");
        c.Add("redirect/domain-macro-is-redirect-target", Z(Spf("redirect=b.example.org"), "b.example.org TXT v=spf1 exists:%{d}.x.example.org -all", "b.example.org.x.example.org A 127.0.0.2"), SpfResult.Pass, "exists:%{d}.x.example.org");
        c.Add("redirect/counts-as-lookup", Z(Spf(IncludeTerms(10) + " redirect=b.example.org"), IncludeTargets(10), "b.example.org TXT v=spf1 -all"), SpfResult.PermError);
        c.Add("redirect/uppercase-modifier-name", Z(Spf("REDIRECT=b.example.org"), "b.example.org TXT v=spf1 -all"), SpfResult.Fail, "all");
    }

    private static void Explanation(CaseList c)
    {
        string why(string text) => $"why.example.org TXT {text}";
        string recordWithExp = Spf("-all exp=why.example.org");
        const string DefaultText = "domain of example.com does not designate 192.0.2.3 as permitted sender";
        c.Add("exp/basic", Z(recordWithExp, why("See http://example.com/why")), SpfResult.Fail, "all", explanation: "See http://example.com/why");
        c.Add("exp/macros-expanded", Z(recordWithExp, why("%{i} is not allowed to send for %{d}")), SpfResult.Fail, "all", explanation: "192.0.2.3 is not allowed to send for example.com");
        c.Add("exp/escapes", Z(recordWithExp, why("a%_b%-c%%d")), SpfResult.Fail, "all", explanation: "a b%20c%d");
        c.Add("exp/ipv6-client-macro", Z(recordWithExp, why("%{c}")), SpfResult.Fail, "all", ip: "2001:db8::1", explanation: "2001:db8::1");
        c.Add("exp/sender-macros", Z(recordWithExp, why("%{s} %{l} %{o}")), SpfResult.Fail, "all", explanation: "user@example.com user example.com");
        c.Add("exp/spaces-allowed-in-text", Z(recordWithExp, why("no   way")), SpfResult.Fail, "all", explanation: "no   way");
        c.Add("exp/only-for-fail-softfail", Z(Spf("~all exp=why.example.org"), why("nope")), SpfResult.SoftFail, "all");
        c.Add("exp/only-for-fail-neutral", Z(Spf("?all exp=why.example.org"), why("nope")), SpfResult.Neutral, "all");
        c.Add("exp/missing-record-uses-default", Z(recordWithExp), SpfResult.Fail, "all", explanation: DefaultText);
        c.Add("exp/multiple-txt-uses-default", Z(recordWithExp, why("one"), why("two")), SpfResult.Fail, "all", explanation: DefaultText);
        c.Add("exp/servfail-uses-default", Z(recordWithExp, "why.example.org SERVFAIL TXT"), SpfResult.Fail, "all", explanation: DefaultText);
        c.Add("exp/non-ascii-uses-default", Z(recordWithExp, why("café")), SpfResult.Fail, "all", explanation: DefaultText);
        c.Add("exp/bad-macro-uses-default", Z(recordWithExp, why("%{q}")), SpfResult.Fail, "all", explanation: DefaultText);
        c.Add("exp/too-long-uses-default", Z(recordWithExp, why(new string('x', 600))), SpfResult.Fail, "all", explanation: DefaultText);
        c.Add("exp/invalid-domain-spec-is-permerror", Z(Spf("-all exp=nodot")), SpfResult.PermError);
        c.Add("exp/duplicate-is-permerror", Z(Spf("-all exp=a.example.org exp=b.example.org")), SpfResult.PermError);
        c.Add("exp/empty-is-permerror", Z(Spf("-all exp=")), SpfResult.PermError);
        c.Add("exp/default-explanation-without-exp", Z(Spf("-all")), SpfResult.Fail, "all", explanation: DefaultText);
        c.Add("exp/fail-from-mechanism", Z(Spf("-ip4:192.0.2.3 exp=why.example.org"), why("blocked %{i}")), SpfResult.Fail, "ip4:192.0.2.3", explanation: "blocked 192.0.2.3");
        c.Add("exp/validated-domain-unknown", Z(recordWithExp, why("%{p}")), SpfResult.Fail, "all", explanation: "unknown");
        c.Add("exp/url-escaped-uppercase", Z(recordWithExp, why("%{S}")), SpfResult.Fail, "all", sender: "us er@example.com", explanation: "us%20er%40example.com");
        c.Add("exp/exp-not-counted-as-lookup", Z(Spf(IncludeTerms(10) + " -all exp=why.example.org"), IncludeTargets(10), why("ok")), SpfResult.Fail, "all", explanation: "ok");
    }

    private static void Modifiers(CaseList c)
    {
        c.Add("modifier/unknown-ignored", Z(Spf("foo=bar ip4:192.0.2.3 -all")), SpfResult.Pass, "ip4:192.0.2.3");
        c.Add("modifier/unknown-with-macro", Z(Spf("foo=%{d} -all")), SpfResult.Fail, "all");
        c.Add("modifier/unknown-with-bad-macro-is-error", Z(Spf("foo=%{ -all")), SpfResult.PermError);
        c.Add("modifier/unknown-with-dangling-percent-is-error", Z(Spf("foo=100% -all")), SpfResult.PermError);
        c.Add("modifier/name-with-punctuation", Z(Spf("foo.bar_baz-1=x -all")), SpfResult.Fail, "all");
        c.Add("modifier/name-starting-with-digit-is-mechanism", Z(Spf("1foo=bar -all")), SpfResult.PermError);
        c.Add("modifier/unknown-empty-value", Z(Spf("foo= -all")), SpfResult.Fail, "all");
        c.Add("modifier/many-unknown", Z(Spf("a1=x b2=y c3=z -all")), SpfResult.Fail, "all");
    }

    private static void MacrosInEvaluation(CaseList c)
    {
        c.Add("macro/helo", Z(Spf("exists:%{h}.hosts.example.org -all"), "helo.example.net.hosts.example.org A 127.0.0.2"), SpfResult.Pass, "exists:%{h}.hosts.example.org");
        c.Add("macro/version-ipv4", Z(Spf("exists:%{v}.example.org -all"), "in-addr.example.org A 127.0.0.2"), SpfResult.Pass, "exists:%{v}.example.org");
        c.Add("macro/version-ipv6", Z(Spf("exists:%{v}.example.org -all"), "ip6.example.org A 127.0.0.2"), SpfResult.Pass, "exists:%{v}.example.org", ip: "2001:db8::1");
        c.Add("macro/validated-domain", Z(Spf("exists:%{p}.example.org -all"), "3.2.0.192.in-addr.arpa PTR mail.example.com", "mail.example.com A 192.0.2.3", "mail.example.com.example.org A 127.0.0.2"), SpfResult.Pass, "exists:%{p}.example.org");
        c.Add("macro/validated-domain-unknown", Z(Spf("exists:%{p}.example.org -all"), "unknown.example.org A 127.0.0.2"), SpfResult.Pass, "exists:%{p}.example.org");
        c.Add("macro/sender-without-at-uses-postmaster", Z(Spf("exists:%{l}.example.org -all"), "postmaster.example.org A 127.0.0.2"), SpfResult.Pass, "exists:%{l}.example.org", sender: "example.com");
        c.Add("macro/sender-domain-differs-from-current", Z(Spf("exists:%{o}.example.org -all"), "sender.example.net.example.org A 127.0.0.2"), SpfResult.Pass, "exists:%{o}.example.org", sender: "u@sender.example.net");
        c.Add("macro/rfc-example-domain-spec", Z(Spf("exists:%{ir}.%{v}._spf.%{d2} -all"), "3.2.0.192.in-addr._spf.example.com A 127.0.0.2"), SpfResult.Pass, "exists:%{ir}.%{v}._spf.%{d2}");
        c.Add("macro/rfc-example-lp", Z(Spf("exists:%{lr-}.lp._spf.%{d2} -all"), "user.lp._spf.example.com A 127.0.0.2"), SpfResult.Pass, "exists:%{lr-}.lp._spf.%{d2}");
        c.Add("macro/reverse-with-delimiter", Z(Spf("exists:%{lr-}.x.example.org -all"), "bad.strong.x.example.org A 127.0.0.2"), SpfResult.Pass, "exists:%{lr-}.x.example.org", sender: "strong-bad@example.com");
        c.Add("macro/explanation-only-letter-in-domain-spec-is-error", Z(Spf("exists:%{c}.example.org")), SpfResult.PermError);
        c.Add("macro/unknown-letter-is-error", Z(Spf("exists:%{x}.example.org")), SpfResult.PermError);
        c.Add("macro/zero-digits-is-error", Z(Spf("exists:%{d0}.example.org")), SpfResult.PermError);
        c.Add("macro/unterminated-is-error", Z(Spf("exists:%{d.example.org")), SpfResult.PermError);
        c.Add("macro/bad-escape-is-error", Z(Spf("exists:%x.example.org")), SpfResult.PermError);
        c.Add("macro/percent-escape", Z(Spf("exists:a%%b.example.org -all"), "a%b.example.org A 127.0.0.2"), SpfResult.Pass, "exists:a%%b.example.org");
        c.Add("macro/expansion-too-long-is-permerror", Z(Spf("exists:" + string.Concat(Enumerable.Repeat("%{s}", 600)) + ".example.org")), SpfResult.PermError, sender: new string('u', 60) + "@example.com");
        string longTail = string.Join('.', Enumerable.Repeat("abcdefghi", 25)) + ".org";
        c.Add("macro/expansion-over-253-truncates-from-left", Z(Spf($"exists:%{{d}}.{longTail} -all"), $"{longTail} A 127.0.0.2"), SpfResult.Pass, $"exists:%{{d}}.{longTail}");
        c.Add("macro/local-part-in-redirect", Z(Spf("redirect=%{l}.%{d}"), "user.example.com TXT v=spf1 +all"), SpfResult.Pass, "all");
        c.Add("macro/macro-in-a-with-cidr", Z(Spf("a:%{d}/24 -all"), "example.com A 192.0.2.77"), SpfResult.Pass, "a:%{d}/24");
        c.Add("macro/delimiter-slash-in-braces-is-not-cidr", Z(Spf("a:%{d/}.example.org -all"), "example.com.example.org A 192.0.2.3"), SpfResult.Pass, "a:%{d/}.example.org");
    }

    private static void Limits(CaseList c)
    {
        string hosts(int count) => Z(Enumerable.Range(0, count).Select(i => $"h{i}.example.org A 198.51.100.{i + 1}").ToArray());
        string aTerms(int count) => string.Join(' ', Enumerable.Range(0, count).Select(i => $"a:h{i}.example.org"));
        c.Add("limit/ten-a-terms-ok", Z(Spf(aTerms(10) + " -all"), hosts(10)), SpfResult.Fail, "all");
        c.Add("limit/eleven-a-terms-is-permerror", Z(Spf(aTerms(11) + " -all"), hosts(11)), SpfResult.PermError);
        c.Add("limit/ip4-and-all-do-not-count", Z(Spf(string.Join(' ', Enumerable.Range(1, 40).Select(i => $"ip4:10.0.{i}.0/24")) + " -all")), SpfResult.Fail, "all");
        c.Add("limit/match-before-limit-skips-rest", Z(Spf("ip4:192.0.2.3 " + string.Join(' ', Enumerable.Repeat("include:x.example.org", 30)))), SpfResult.Pass, "ip4:192.0.2.3");
        c.Add("limit/shared-across-include-depth", Z(Spf(IncludeTerms(5) + " -all"), Z(Enumerable.Range(0, 5).Select(i => $"i{i}.example.org TXT v=spf1 a:h{i}.example.org -all").ToArray()), hosts(5)), SpfResult.Fail, "all");
        c.Add("limit/shared-across-include-depth-exceeded", Z(Spf(IncludeTerms(6) + " -all"), Z(Enumerable.Range(0, 6).Select(i => $"i{i}.example.org TXT v=spf1 a:h{i}.example.org -all").ToArray()), hosts(6)), SpfResult.PermError);
        c.Add("limit/mx-and-ptr-count", Z(Spf("mx ptr " + aTerms(8) + " -all"), hosts(8), "example.com MX 10 m.example.com", "m.example.com A 198.51.100.200"), SpfResult.Fail, "all");
        c.Add("limit/mx-and-ptr-count-exceeded", Z(Spf("mx ptr " + aTerms(9) + " -all"), hosts(9), "example.com MX 10 m.example.com", "m.example.com A 198.51.100.200"), SpfResult.PermError);
        c.Add("limit/void-lookups-across-include", Z(Spf("include:i.example.org exists:z.example.org -all"), "i.example.org TXT v=spf1 exists:x.example.org exists:y.example.org -all"), SpfResult.PermError);
        c.Add("limit/nodata-counts-as-void", Z(Spf("a:n1.example.org a:n2.example.org a:n3.example.org -all"), "n1.example.org TXT x", "n2.example.org TXT x", "n3.example.org TXT x"), SpfResult.PermError);
    }
}
