using System.Text;
using Mta.Dns;
using Mta.Tls.Dane;
using Mta.Tls.MtaSts;
using Mta.Tls.TlsRpt;
using Mta.Tls.Tests.Support;

namespace Mta.Tls.Tests;

/// <summary>
/// Deterministic fuzzing (fixed seeds): parsers of remote data must never throw and must only ever return values that
/// satisfy their documented invariants.
/// </summary>
public class ParserFuzzTests
{
    private const int Iterations = 4000;

    private const string ValidPolicy = "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmx: *.example.net\r\nmax_age: 604800\r\n";
    private const string ValidTxt = "v=STSv1; id=20190429T010101";
    private const string ValidRpt = "v=TLSRPTv1; rua=mailto:reports@example.com,https://reports.example.com/tlsrpt";

    private static string RandomText(Random rng, int maxLength, string alphabet)
    {
        int length = rng.Next(maxLength + 1);
        var sb = new StringBuilder(length);
        for (int i = 0; i < length; i++)
        {
            sb.Append(alphabet[rng.Next(alphabet.Length)]);
        }

        return sb.ToString();
    }

    private static string Mutate(Random rng, string seed)
    {
        var chars = new StringBuilder(seed);
        int edits = rng.Next(1, 6);
        const string Noise = " \t\r\n:;,=*.-_@/\\\"'!0123456789abcxyz\uFEFF\u00FC\0";
        for (int i = 0; i < edits && chars.Length > 0; i++)
        {
            int at = rng.Next(chars.Length);
            switch (rng.Next(4))
            {
                case 0:
                    chars.Remove(at, 1);
                    break;
                case 1:
                    chars.Insert(at, Noise[rng.Next(Noise.Length)]);
                    break;
                case 2:
                    chars[at] = Noise[rng.Next(Noise.Length)];
                    break;
                default:
                    int len = Math.Min(rng.Next(1, 20), chars.Length - at);
                    string piece = chars.ToString(at, len);
                    chars.Insert(rng.Next(chars.Length), piece);
                    break;
            }
        }

        return chars.ToString();
    }

    private static IEnumerable<string> Inputs(int seed, string valid, string alphabet)
    {
        var rng = new Random(seed);
        yield return valid;
        for (int i = 0; i < Iterations; i++)
        {
            yield return (i % 3) switch
            {
                0 => RandomText(rng, 200, alphabet),
                1 => Mutate(rng, valid),
                _ => Mutate(rng, Mutate(rng, valid)),
            };
        }
    }

    private const string PolicyAlphabet = "version:STSv1modeforcetingnx\r\n *.-_a.example.commax_age0123456789";

    [Fact]
    public void Policy_parser_never_throws_and_upholds_its_invariants()
    {
        int accepted = 0;
        foreach (string input in Inputs(1, ValidPolicy, PolicyAlphabet))
        {
            bool ok = MtaStsPolicyParser.TryParse(input, out var policy, out string? error);
            if (!ok)
            {
                Assert.Null(policy);
                Assert.False(string.IsNullOrEmpty(error));
                continue;
            }

            accepted++;
            Assert.NotNull(policy);
            Assert.InRange(policy!.MaxAgeSeconds, 0, MtaStsPolicyParser.MaxAgeCeilingSeconds);
            Assert.True(policy.Mode == MtaStsMode.None || policy.MxPatterns.Count > 0);
            Assert.True(policy.MxPatterns.Count <= MtaStsPolicyParser.MaxMxPatterns);
            foreach (string pattern in policy.MxPatterns)
            {
                Assert.True(MtaStsMxMatcher.TryNormalizePattern(pattern, out string again));
                Assert.Equal(pattern, again);
            }

            // Re-parsing the stored policy lines yields the same policy.
            Assert.True(MtaStsPolicyParser.TryParse(string.Join("\n", policy.PolicyLines), out var second, out _));
            Assert.Equal(policy.Mode, second!.Mode);
            Assert.Equal(policy.MaxAgeSeconds, second.MaxAgeSeconds);
            Assert.Equal(policy.MxPatterns, second.MxPatterns);
        }

        Assert.True(accepted > 5, "the fuzzer should reach the success path");
    }

    [Fact]
    public void Policy_parser_handles_random_bytes()
    {
        var rng = new Random(2);
        for (int i = 0; i < Iterations; i++)
        {
            var bytes = new byte[rng.Next(300)];
            rng.NextBytes(bytes);
            _ = MtaStsPolicyParser.TryParse(bytes, out _, out _);
        }
    }

    [Fact]
    public void Mx_matching_never_throws_for_arbitrary_hosts_and_patterns()
    {
        var rng = new Random(3);
        const string Alphabet = "abc.-*_ \u00FC\t01xn--";
        for (int i = 0; i < Iterations; i++)
        {
            string pattern = RandomText(rng, 30, Alphabet);
            string host = RandomText(rng, 40, Alphabet);
            _ = MtaStsMxMatcher.Matches(pattern, host);
            if (MtaStsMxMatcher.TryNormalizePattern(pattern, out string normalized))
            {
                // A normalised exact pattern always matches itself; a wildcard never matches its own suffix.
                if (normalized.StartsWith("*.", StringComparison.Ordinal))
                {
                    Assert.False(MtaStsMxMatcher.Matches(normalized, normalized[2..]));
                    Assert.True(MtaStsMxMatcher.Matches(normalized, "x" + normalized[1..]));
                    Assert.False(MtaStsMxMatcher.Matches(normalized, "y.x" + normalized[1..]));
                }
                else
                {
                    Assert.True(MtaStsMxMatcher.Matches(normalized, normalized));
                }
            }
        }
    }

    [Fact]
    public void Sts_txt_parser_never_throws_and_ids_are_always_alphanumeric()
    {
        int accepted = 0;
        foreach (string input in Inputs(4, ValidTxt, "v=STSv1; id=abc0123-_ \t"))
        {
            if (MtaStsTxtParser.TryParse(input, out var record))
            {
                accepted++;
                Assert.Matches("^[A-Za-z0-9]{1,32}$", record!.Id);
            }
        }

        Assert.True(accepted > 5);
    }

    [Fact]
    public void Tls_rpt_parser_never_throws_and_endpoints_are_always_safe()
    {
        int accepted = 0;
        foreach (string input in Inputs(5, ValidRpt, "v=TLSRPTv1;rua=mailto:@.example.com,https://abc/?!"))
        {
            if (!TlsRptRecordParser.TryParse(input, out var record))
            {
                Assert.Null(record);
                continue;
            }

            accepted++;
            Assert.NotEmpty(record!.Endpoints);
            Assert.True(record.Endpoints.Count <= TlsRptRecordParser.MaxEndpoints);
            foreach (var endpoint in record.Endpoints)
            {
                if (endpoint.Kind == TlsRptEndpointKind.Https)
                {
                    var uri = new Uri(endpoint.Uri);
                    Assert.Equal("https", uri.Scheme);
                    Assert.Empty(uri.UserInfo);
                    Assert.Contains('.', uri.IdnHost);
                }
                else
                {
                    Assert.NotNull(endpoint.MailtoAddress);
                    Assert.DoesNotContain(endpoint.MailtoAddress, c => c <= ' ');
                    Assert.Single(endpoint.MailtoAddress!, '@');
                }
            }
        }

        Assert.True(accepted > 5);
    }

    [Fact]
    public void Txt_selection_never_throws_on_mixed_rrsets()
    {
        var rng = new Random(6);
        var seeds = new[] { ValidTxt, ValidRpt, "v=spf1 -all", "", "v=STSv1" };
        for (int i = 0; i < 500; i++)
        {
            var records = Enumerable.Range(0, rng.Next(0, 5))
                .Select(_ => new TxtRecord("n", 60, Mutate(rng, seeds[rng.Next(seeds.Length)])))
                .ToArray();
            _ = MtaStsTxtParser.Select(records);
            _ = TlsRptRecordParser.Select(records);
        }
    }

    [Fact]
    public void Tlsa_classification_never_throws_and_usable_means_well_formed()
    {
        var rng = new Random(7);
        for (int i = 0; i < Iterations; i++)
        {
            var data = new byte[rng.Next(0, 70)];
            rng.NextBytes(data);
            var record = new TlsaRecord("_25._tcp.mx.example.com", 60, (byte)rng.Next(0, 6), (byte)rng.Next(0, 4), (byte)rng.Next(0, 4), data);
            bool usable = TlsaRecordClassifier.IsUsable(record, out string? reason);
            Assert.Equal(usable, reason is null);
            if (usable)
            {
                Assert.True(record.Usage is 2 or 3);
                Assert.True(record.Selector <= 1);
                Assert.True(record.MatchingType switch { 1 => data.Length == 32, 2 => data.Length == 64, _ => data.Length > 0 });
            }

            _ = TlsaRecordClassifier.ToPresentation(record);
        }
    }

    [Fact]
    public void Dane_verification_survives_random_record_sets()
    {
        var rng = new Random(8);
        var leaf = TestPki.CreateSelfSignedLeaf(["mx.example.com"]);
        for (int i = 0; i < 300; i++)
        {
            var records = Enumerable.Range(0, rng.Next(0, 5)).Select(_ =>
            {
                var data = new byte[rng.Next(0, 70)];
                rng.NextBytes(data);
                return new TlsaRecord("n", 60, (byte)rng.Next(0, 5), (byte)rng.Next(0, 3), (byte)rng.Next(0, 4), data);
            }).ToArray();

            var result = DaneVerifier.Verify(records, leaf.Public, [leaf.Public], "mx.example.com");
            Assert.False(result.Success);
            Assert.NotNull(result.Failure);
        }
    }

    [Fact]
    public void Host_normalisation_never_throws()
    {
        var rng = new Random(9);
        const string Alphabet = "abcXYZ019.-_ \t:/@\u00FC\u4E2D\uD83D\uDE00\0*";
        for (int i = 0; i < Iterations; i++)
        {
            string input = RandomText(rng, 80, Alphabet);
            if (DnsNames.TryNormalizeHost(input, out string host))
            {
                Assert.True(host.Length <= 253);
                Assert.Equal(host, host.ToLowerInvariant());
                Assert.Matches("^[a-z0-9-]+(\\.[a-z0-9-]+)*$", host);
                Assert.DoesNotContain(".-", host);
                Assert.DoesNotContain("-.", host);
                Assert.True(DnsNames.TryNormalizeHost(host, out string again) && again == host);
            }
        }
    }

    [Fact]
    public void Collector_survives_arbitrary_outcomes()
    {
        var rng = new Random(10);
        var collector = new TlsRptCollector(new TestClock(), new TlsRptCollectorOptions { MaxDomainDays = 50, MaxPoliciesPerDomain = 3, MaxFailureDetailsPerPolicy = 10 });
        var types = Enum.GetValues<TlsResultType>();
        for (int i = 0; i < Iterations; i++)
        {
            var policy = new TlsRptPolicyDescriptor((TlsPolicyType)rng.Next(0, 3), [RandomText(rng, 10, "ab")], []);
            collector.Record(new TlsRptSessionOutcome(
                RandomText(rng, 12, "ab.c-"),
                policy,
                RandomText(rng, 12, "mx.ab"),
                rng.Next(2) == 0,
                types[rng.Next(types.Length)],
                RandomText(rng, 5, "12."),
                null,
                null,
                RandomText(rng, 400, "xyz"),
                null));
        }

        var snapshot = collector.Snapshot();
        Assert.True(snapshot.Count <= 50);
        long total = snapshot.SelectMany(d => d.Policies).Sum(p => p.SuccessCount + p.FailureCount) + collector.DroppedSessionCount;
        Assert.Equal(Iterations, total);
    }

    [Fact]
    public void Result_type_wire_strings_round_trip()
    {
        foreach (var type in Enum.GetValues<TlsResultType>())
        {
            Assert.True(TlsResultTypeExtensions.TryParseWireString(type.ToWireString(), out var parsed));
            Assert.Equal(type, parsed);
        }

        Assert.False(TlsResultTypeExtensions.TryParseWireString("nonsense", out _));
        Assert.False(TlsResultTypeExtensions.TryParseWireString(null, out _));
        Assert.Equal("certificate-host-mismatch", TlsResultType.CertificateHostMismatch.ToWireString());
        Assert.Equal("sts", TlsPolicyType.Sts.ToWireString());
        Assert.Equal("tlsa", TlsPolicyType.Tlsa.ToWireString());
        Assert.Equal("no-policy-found", TlsPolicyType.NoPolicyFound.ToWireString());
    }
}
