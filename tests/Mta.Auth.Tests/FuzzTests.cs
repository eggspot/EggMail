using System.Net;
using System.Text;
using Mta.Auth.AuthenticationResults;
using Mta.Auth.Dmarc;
using Mta.Auth.Domains;
using Mta.Auth.Reports;
using Mta.Auth.Spf;
using Mta.Dns;
using static Mta.Auth.Tests.TestZone;

namespace Mta.Auth.Tests;

/// <summary>Deterministic (seeded) fuzzing of every parser that consumes hostile input: nothing may throw or hang.</summary>
public class FuzzTests
{
    private static readonly string[] SpfFragments =
    [
        "v=spf1", " ", " ", " ", "+", "-", "~", "?", "all", "include:", "a", "mx", "ptr", "ip4:", "ip6:", "exists:", "redirect=", "exp=",
        "192.0.2.0", "/24", "//64", "/33", "/", ":", "=", "example.com", "_spf.example.org", ".", "%{", "%{d}", "%{ir}", "%{l1r-}", "%{S}", "%%", "%_", "%-", "}",
        "2001:db8::", "::1", "1.2.3.4", "foo", "\t", "é", "%", "{", "0", "99999999999", "\"", "\\", ";", ",",
    ];

    private const string DmarcAlphabet = "vDMARC1=; pquarantinerejectnoneskfodiriuaftpsmailto:@.!,mgktx0123456789%-_\t";
    private const string ArAlphabet = "abcdefg012 \t\r\n;=.()\"\\/-@:_,pass dkim spf header smtp";

    private static string Compose(Random random, string[] fragments, int maxParts)
    {
        var sb = new StringBuilder();
        int parts = random.Next(1, maxParts);
        for (int i = 0; i < parts; i++)
        {
            sb.Append(fragments[random.Next(fragments.Length)]);
        }

        return sb.ToString();
    }

    private static string Mutate(Random random, string input, string alphabet)
    {
        var sb = new StringBuilder(input);
        int edits = random.Next(1, 6);
        for (int i = 0; i < edits; i++)
        {
            switch (random.Next(3))
            {
                case 0 when sb.Length > 0:
                    sb.Remove(random.Next(sb.Length), 1);
                    break;
                case 1:
                    sb.Insert(random.Next(sb.Length + 1), alphabet[random.Next(alphabet.Length)]);
                    break;
                default:
                    if (sb.Length > 0)
                    {
                        sb[random.Next(sb.Length)] = alphabet[random.Next(alphabet.Length)];
                    }

                    break;
            }
        }

        return sb.ToString();
    }

    [Fact]
    public void Spf_record_parser_never_throws()
    {
        var random = new Random(7001);
        int parsed = 0;
        for (int i = 0; i < 30_000; i++)
        {
            string text = "v=spf1 " + Compose(random, SpfFragments, 12);
            if (SpfRecord.TryParse(text, 4096, out var record, out string? error))
            {
                parsed++;
                Assert.NotNull(record);
            }
            else
            {
                Assert.False(string.IsNullOrEmpty(error));
            }
        }

        Assert.True(parsed > 100, "fuzz generator should sometimes produce valid records");
    }

    [Fact]
    public void Spf_record_parser_survives_mutations_of_valid_records()
    {
        string[] seeds =
        [
            "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a mx:mail.example.com/24//64 include:_spf.example.org exists:%{ir}.%{v}._spf.%{d2} ptr -all",
            "v=spf1 redirect=_spf.%{d} exp=explain._spf.%{d}",
            "v=spf1 a:%{l1r+-}.%{o}/28 ?all",
        ];
        var random = new Random(7002);
        for (int i = 0; i < 30_000; i++)
        {
            string text = Mutate(random, seeds[i % seeds.Length], " :/=.%{}-+~?0129abcxyzé");
            SpfRecord.TryParse(text, 4096, out _, out _);
        }
    }

    [Fact]
    public void Macro_parser_and_expander_never_throw_and_respect_the_size_limit()
    {
        string[] pieces = ["%{", "}", "s", "l", "o", "d", "i", "p", "v", "h", "c", "r", "t", "S", "D", "0", "1", "2", "9", "r", ".", "-", "+", ",", "/", "_", "=", "%%", "%_", "%-", "%", "x", "example.com", " "];
        var context = new SpfMacroContext("us.er+tag@mail.example.co.uk", "mail.example.co.uk", IPAddress.Parse("2001:db8::1"), "helo.example.net");
        var v4 = new SpfMacroContext("a b@c", "d", IPAddress.Parse("192.0.2.3"), "h");
        var random = new Random(7003);
        int expanded = 0;
        foreach (SpfMacroKind kind in Enum.GetValues<SpfMacroKind>())
        {
            for (int i = 0; i < 20_000; i++)
            {
                string text = Compose(random, pieces, 14);
                if (!SpfMacroString.TryParse(text, kind, out var macro, out _))
                {
                    continue;
                }

                foreach (var ctx in new[] { context, v4 })
                {
                    if (macro.TryExpand(ctx, 200, out string? result))
                    {
                        expanded++;
                        Assert.True(result.Length <= 200);
                    }

                    SpfMacroString.TryParseDomainSpec(text, out _, out _);
                }
            }
        }

        Assert.True(expanded > 1000);
    }

    [Fact]
    public void Domain_normalisation_never_throws()
    {
        var random = new Random(7004);
        const string alphabet = "abc.-_%é \t\u0000XYZ019";
        for (int i = 0; i < 20_000; i++)
        {
            string text = new(Enumerable.Range(0, random.Next(0, 300)).Select(_ => alphabet[random.Next(alphabet.Length)]).ToArray());
            if (SpfDomainName.TryNormalizeExpanded(text, out string? domain))
            {
                Assert.True(domain.Length <= 253);
            }

            SpfDomainName.TryNormalizeCheckDomain(text, out _);
        }
    }

    [Fact]
    public async Task Spf_evaluation_over_random_zones_never_throws_and_respects_limits()
    {
        var random = new Random(7005);
        string[] ips = ["192.0.2.3", "198.51.100.77", "2001:db8::25", "::ffff:192.0.2.3", "0.0.0.0", "255.255.255.255"];
        string[] names = ["example.com", "a.example.com", "b.example.com", "c.example.org", "mail.example.com"];
        string[] terms =
        [
            "a", "mx", "ptr", "-all", "~all", "?all", "+all", "ip4:192.0.2.0/24", "ip6:2001:db8::/32", "a:a.example.com", "a:b.example.com/24//64", "mx:c.example.org",
            "include:a.example.com", "include:b.example.com", "include:c.example.org", "include:example.com", "redirect=a.example.com", "redirect=example.com",
            "exists:%{ir}.a.example.com", "exists:%{l}.%{d}", "exp=mail.example.com", "ptr:example.com", "include:%{d}", "a:%{p}.example.com", "bogus", "ip4:999.0.0.1",
        ];
        int outcomes = 0;
        for (int round = 0; round < 1500; round++)
        {
            var lines = new List<string>();
            foreach (string name in names)
            {
                if (random.Next(5) == 0)
                {
                    continue;
                }

                var record = new StringBuilder("v=spf1");
                int count = random.Next(0, 9);
                for (int t = 0; t < count; t++)
                {
                    record.Append(' ').Append(terms[random.Next(terms.Length)]);
                }

                lines.Add($"{name} TXT {record}");
                if (random.Next(2) == 0)
                {
                    lines.Add($"{name} A 192.0.2.{random.Next(1, 6)}");
                }

                if (random.Next(3) == 0)
                {
                    lines.Add($"{name} MX {random.Next(1, 20)} {names[random.Next(names.Length)]}");
                }

                if (random.Next(10) == 0)
                {
                    lines.Add($"{name} SERVFAIL A");
                }

                if (random.Next(10) == 0)
                {
                    lines.Add($"3.2.0.192.in-addr.arpa PTR {name}");
                }
            }

            var evaluator = new SpfEvaluator(Build(Z(lines.ToArray())));
            string domain = names[random.Next(names.Length)];
            var result = await evaluator.CheckHostAsync(new SpfCheckRequest(IPAddress.Parse(ips[random.Next(ips.Length)]), domain, "user@" + domain, "helo.example.net"));
            Assert.DoesNotContain("internal error", result.Reason ?? string.Empty);
            Assert.True(result.DnsLookupCount <= 11, $"lookups {result.DnsLookupCount}");
            Assert.True(result.VoidLookupCount <= 3, $"void lookups {result.VoidLookupCount}");
            outcomes += (int)result.Result;
        }

        Assert.True(outcomes > 0);
    }

    [Fact]
    public async Task Spf_evaluation_survives_random_txt_content()
    {
        var random = new Random(7006);
        for (int round = 0; round < 3000; round++)
        {
            string text = (random.Next(4) == 0 ? string.Empty : "v=spf1 ") + Compose(random, SpfFragments, 14);
            var resolver = new StaticDnsResolver();
            resolver.AddTxt("example.com", text);
            resolver.AddTxt("a.example.com", text);
            var result = await new SpfEvaluator(resolver).CheckHostAsync(new SpfCheckRequest(IPAddress.Parse("192.0.2.3"), "example.com", "u@example.com", "h.example.net"));
            Assert.DoesNotContain("internal error", result.Reason ?? string.Empty);
        }
    }

    [Fact]
    public void Dmarc_record_parser_never_throws()
    {
        var random = new Random(7007);
        string[] fragments = ["v=DMARC1", ";", " ", "p=reject", "p=none", "p=quarantine", "sp=reject", "pct=", "50", "adkim=s", "aspf=r", "rua=mailto:a@example.com", ",", "!10m", "ruf=", "fo=1:d", "ri=86400", "=", "x=y", "%", "é"];
        int parsed = 0;
        for (int i = 0; i < 30_000; i++)
        {
            string text = random.Next(3) == 0
                ? Mutate(random, "v=DMARC1; p=reject; sp=none; pct=50; rua=mailto:a@example.com!5m,mailto:b@example.net; adkim=s", DmarcAlphabet)
                : (random.Next(2) == 0 ? "v=DMARC1;" : string.Empty) + Compose(random, fragments, 12);
            if (DmarcRecord.TryParse(text, out var record, out _))
            {
                parsed++;
                Assert.InRange(record.Percentage, 0, 100);
                Assert.True(record.AggregateReportUris.Count <= 32);
            }
        }

        Assert.True(parsed > 500);
    }

    [Fact]
    public void Dmarc_report_uri_parser_never_throws()
    {
        var random = new Random(7008);
        string[] fragments = ["mailto:", "MAILTO:", "http://", "a@example.com", "@", "!", "10", "m", "k", "g", "t", "%2C", "%", "%zz", "?subject=x", " ", ",", "é", "example.com", "[", "]"];
        for (int i = 0; i < 30_000; i++)
        {
            DmarcReportUri.TryParse(Compose(random, fragments, 8), out _);
        }
    }

    [Fact]
    public async Task Dmarc_evaluation_survives_random_txt_content()
    {
        var random = new Random(7009);
        string[] fragments = ["v=DMARC1", ";", " ", "p=reject", "p=none", "sp=quarantine", "pct=50", "adkim=s", "rua=mailto:a@example.com", "junk", "=", "%"];
        for (int round = 0; round < 3000; round++)
        {
            var resolver = new StaticDnsResolver();
            int count = random.Next(0, 4);
            for (int i = 0; i < count; i++)
            {
                resolver.AddTxt(random.Next(2) == 0 ? "_dmarc.example.com" : "_dmarc.mail.example.com", Compose(random, fragments, 10));
            }

            var evaluator = new DmarcEvaluator(resolver, new DmarcOptions { Random = new Random(round) });
            var input = new DmarcInput("mail.example.com", new SpfAuthResult(SpfResult.Pass, round % 2 == 0 ? "example.com" : null), [new DkimAuthResult("x.example", round % 3 == 0)]);
            var result = await evaluator.EvaluateAsync(input);
            Assert.True(Enum.IsDefined(result.Result));
        }
    }

    [Fact]
    public void Public_suffix_list_never_throws()
    {
        var random = new Random(7010);
        const string alphabet = "abc.-_éあ xn--0123";
        for (int i = 0; i < 20_000; i++)
        {
            string text = new(Enumerable.Range(0, random.Next(0, 120)).Select(_ => alphabet[random.Next(alphabet.Length)]).ToArray());
            string org = PublicSuffixList.Default.GetOrganizationalDomain(text);
            Assert.NotNull(org);
            PublicSuffixList.Default.GetPublicSuffix(text);
            PublicSuffixList.Default.IsPublicSuffix(text);
        }
    }

    [Fact]
    public void Authentication_results_parser_never_throws_and_parsed_headers_survive_rebuilding()
    {
        var random = new Random(7011);
        string[] seeds =
        [
            "mx.example.org 1; spf=pass (domain of x designates 192.0.2.1 as permitted sender) smtp.mailfrom=x@example.com; dkim=pass header.d=example.com header.s=s1; dmarc=fail (p=REJECT) header.from=example.com",
            "example.com;\r\n\tdkim=pass reason=\"good signature\"\r\n\t  header.i=@mail-router.example.net;\r\n\tdkim=fail header.i=@newyork.example.com",
            "example.org; none",
        ];
        int parsed = 0;
        for (int i = 0; i < 30_000; i++)
        {
            string text = random.Next(4) == 0
                ? new string(Enumerable.Range(0, random.Next(0, 60)).Select(_ => ArAlphabet[random.Next(ArAlphabet.Length)]).ToArray())
                : Mutate(random, seeds[i % seeds.Length], ArAlphabet);
            if (!AuthenticationResultsHeader.TryParse(text, out var header))
            {
                continue;
            }

            parsed++;
            var builder = new AuthenticationResultsBuilder("rebuilt.example") { Version = header.Version };
            foreach (var r in header.Results)
            {
                builder.Add(r.Method, r.Result, r.Properties.Select(p => (p.Ptype, p.Property, p.Value)), r.Reason, r.Comment, r.MethodVersion);
            }

            string body = builder.BuildFieldBody();
            Assert.True(AuthenticationResultsHeader.TryParse(body, out var again), body);
            Assert.Equal(header.Results.Count, again.Results.Count);
            Assert.DoesNotContain("\r\n", body.Replace("\r\n\t", string.Empty));
        }

        Assert.True(parsed > 100);
    }

    [Fact]
    public void Aggregate_report_reader_never_throws_on_mutated_input()
    {
        var random = new Random(7012);
        byte[] xml = Encoding.UTF8.GetBytes(DmarcAggregateReportWriter.ToXmlString(Reports.ReportTestSupport.SampleReport(3)));
        byte[] gz = DmarcAggregateReportWriter.ToGzip(Reports.ReportTestSupport.SampleReport(3));
        for (int i = 0; i < 3000; i++)
        {
            byte[] source = i % 2 == 0 ? xml : gz;
            byte[] data = (byte[])source.Clone();
            int edits = random.Next(1, 8);
            for (int e = 0; e < edits; e++)
            {
                data[random.Next(data.Length)] = (byte)random.Next(256);
            }

            if (random.Next(5) == 0)
            {
                data = data[..random.Next(data.Length)];
            }

            DmarcAggregateReportReader.TryRead(data, out _);
        }
    }

    [Fact]
    public async Task Spf_ip_matching_handles_every_prefix_length()
    {
        var random = new Random(7013);
        for (int i = 0; i < 5000; i++)
        {
            var bytes4 = new byte[4];
            random.NextBytes(bytes4);
            var a = new IPAddress(bytes4);
            int prefix = random.Next(0, 33);
            string record = $"v=spf1 ip4:{a}/{prefix} -all";
            Assert.True(SpfRecord.TryParse(record, 4096, out var parsed, out _), record);
            // The network itself and any address sharing the prefix must match; flipping a prefix bit must not.
            var resolver = new StaticDnsResolver();
            resolver.AddTxt("example.com", record);
            var evaluator = new SpfEvaluator(resolver);
            var same = await evaluator.CheckHostAsync(new SpfCheckRequest(a, "example.com", "u@example.com", "h.example"));
            Assert.Equal(SpfResult.Pass, same.Result);
            if (prefix > 0)
            {
                var flipped = (byte[])bytes4.Clone();
                int bit = random.Next(prefix);
                flipped[bit / 8] ^= (byte)(0x80 >> (bit % 8));
                var other = await evaluator.CheckHostAsync(new SpfCheckRequest(new IPAddress(flipped), "example.com", "u@example.com", "h.example"));
                Assert.Equal(SpfResult.Fail, other.Result);
            }
        }
    }
}
