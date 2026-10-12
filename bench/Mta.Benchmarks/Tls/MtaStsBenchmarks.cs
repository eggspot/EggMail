using BenchmarkDotNet.Attributes;
using Mta.Tls.MtaSts;

namespace Mta.Benchmarks.Tls;

/// <summary>
/// Hot-path costs of MTA-STS evaluation: parsing a policy body (once per fetch) and matching MX hosts against a policy
/// (once per delivery attempt). Run: <c>dotnet run -c Release --project bench/Mta.Benchmarks -- --filter "*MtaSts*"</c>.
/// </summary>
[MemoryDiagnoser]
public class MtaStsBenchmarks
{
    private const string SmallPolicy = "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmx: *.example.net\r\nmax_age: 604800\r\n";

    private string _largePolicy = string.Empty;
    private byte[] _largePolicyBytes = [];
    private MtaStsPolicy _small = null!;
    private MtaStsPolicy _large = null!;

    [GlobalSetup]
    public void Setup()
    {
        var lines = new List<string> { "version: STSv1", "mode: enforce", "max_age: 86400" };
        lines.AddRange(Enumerable.Range(0, 50).Select(i => $"mx: mx{i}.mail{i % 7}.example.com"));
        lines.Add("mx: *.wildcard.example.org");
        _largePolicy = string.Join("\r\n", lines) + "\r\n";
        _largePolicyBytes = System.Text.Encoding.UTF8.GetBytes(_largePolicy);

        MtaStsPolicyParser.TryParse(SmallPolicy, out var small, out _);
        MtaStsPolicyParser.TryParse(_largePolicy, out var large, out _);
        _small = small!;
        _large = large!;
    }

    [Benchmark]
    public MtaStsPolicy? ParseSmallPolicy()
    {
        MtaStsPolicyParser.TryParse(SmallPolicy, out var policy, out _);
        return policy;
    }

    [Benchmark]
    public MtaStsPolicy? ParseLargePolicy()
    {
        MtaStsPolicyParser.TryParse(_largePolicy, out var policy, out _);
        return policy;
    }

    [Benchmark]
    public MtaStsPolicy? ParseLargePolicyFromUtf8()
    {
        MtaStsPolicyParser.TryParse(_largePolicyBytes, out var policy, out _);
        return policy;
    }

    [Benchmark]
    public bool MatchExactMx() => MtaStsEvaluation.IsMxAllowed(_small, "mail.example.com");

    [Benchmark]
    public bool MatchWildcardMx() => MtaStsEvaluation.IsMxAllowed(_small, "mx1.example.net");

    [Benchmark]
    public bool MatchRejectedMx() => MtaStsEvaluation.IsMxAllowed(_small, "mail.evil.example.org");

    [Benchmark]
    public bool MatchLastOfManyPatterns() => MtaStsEvaluation.IsMxAllowed(_large, "x.wildcard.example.org");

    [Benchmark]
    public bool MatchNoneOfManyPatterns() => MtaStsEvaluation.IsMxAllowed(_large, "mail.nowhere.example.org");
}
