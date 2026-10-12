using System.Net;
using BenchmarkDotNet.Attributes;
using Mta.Auth.Dmarc;
using Mta.Auth.Spf;
using Mta.Dns;

namespace Mta.Benchmarks.Auth;

/// <summary>SPF check_host() cost against an in-memory zone (no network): parse, macro expansion, include chain, CIDR matching.</summary>
[MemoryDiagnoser]
public class SpfBenchmarks
{
    private SpfEvaluator _simple = null!;
    private SpfEvaluator _includeChain = null!;
    private SpfEvaluator _macros = null!;
    private readonly IPAddress _passIp = IPAddress.Parse("192.0.2.3");
    private readonly IPAddress _failIp = IPAddress.Parse("203.0.113.9");
    private readonly SpfCheckRequest _simplePass;
    private readonly SpfCheckRequest _simpleFail;
    private readonly SpfCheckRequest _includePass;
    private readonly SpfCheckRequest _macroPass;

    public SpfBenchmarks()
    {
        _simplePass = new SpfCheckRequest(_passIp, "simple.example", "user@simple.example", "mx.simple.example");
        _simpleFail = new SpfCheckRequest(_failIp, "simple.example", "user@simple.example", "mx.simple.example");
        _includePass = new SpfCheckRequest(_passIp, "chain.example", "user@chain.example", "mx.chain.example");
        _macroPass = new SpfCheckRequest(_passIp, "macro.example", "user@macro.example", "mx.macro.example");
    }

    [GlobalSetup]
    public void Setup()
    {
        var simple = new StaticDnsResolver()
            .AddTxt("simple.example", "v=spf1 ip4:198.51.100.0/24 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all");
        _simple = new SpfEvaluator(simple);

        var chain = new StaticDnsResolver()
            .AddTxt("chain.example", "v=spf1 include:_spf1.chain.example include:_spf2.chain.example include:_spf3.chain.example -all")
            .AddTxt("_spf1.chain.example", "v=spf1 ip4:198.51.100.0/24 a:mail.chain.example -all")
            .AddTxt("_spf2.chain.example", "v=spf1 mx ip4:203.0.113.0/25 -all")
            .AddTxt("_spf3.chain.example", "v=spf1 ip4:192.0.2.0/24 -all")
            .AddA("mail.chain.example", "198.51.100.10")
            .AddMx("_spf2.chain.example", 10, "mx1.chain.example")
            .AddA("mx1.chain.example", "203.0.113.200");
        _includeChain = new SpfEvaluator(chain);

        var macros = new StaticDnsResolver()
            .AddTxt("macro.example", "v=spf1 exists:%{ir}.%{v}._spf.%{d2} exists:%{l}.%{o}._u.example -all")
            .AddA("3.2.0.192.in-addr._spf.macro.example", "127.0.0.2");
        _macros = new SpfEvaluator(macros);
    }

    [Benchmark(Baseline = true)]
    public async Task<SpfResult> SimpleRecordPass() => (await _simple.CheckHostAsync(_simplePass)).Result;

    [Benchmark]
    public async Task<SpfResult> SimpleRecordFail() => (await _simple.CheckHostAsync(_simpleFail)).Result;

    [Benchmark]
    public async Task<SpfResult> ThreeIncludesWithAAndMx() => (await _includeChain.CheckHostAsync(_includePass)).Result;

    [Benchmark]
    public async Task<SpfResult> MacroExpansionExists() => (await _macros.CheckHostAsync(_macroPass)).Result;

    [Benchmark]
    public bool ParseRecord() =>
        SpfRecord.TryParse("v=spf1 ip4:198.51.100.0/24 ip4:192.0.2.0/24 ip6:2001:db8::/32 include:_spf.example.org a mx -all", 4096, out _, out _);
}

/// <summary>DMARC evaluation cost against an in-memory zone: policy discovery with organizational-domain fallback and alignment.</summary>
[MemoryDiagnoser]
public class DmarcBenchmarks
{
    private DmarcEvaluator _evaluator = null!;
    private DmarcInput _directPass = null!;
    private DmarcInput _fallbackFail = null!;
    private DmarcPolicyLookup _cachedLookup = null!;

    [GlobalSetup]
    public void Setup()
    {
        var zone = new StaticDnsResolver()
            .AddTxt("_dmarc.example.com", "v=DMARC1; p=reject; sp=quarantine; adkim=r; aspf=r; rua=mailto:dmarc@example.com")
            .AddTxt("_dmarc.example.co.uk", "v=DMARC1; p=none");
        _evaluator = new DmarcEvaluator(zone);
        _directPass = new DmarcInput("example.com", new SpfAuthResult(SpfResult.Pass, "bounce.example.com"), [new DkimAuthResult("example.com", true, "s1")]);
        _fallbackFail = new DmarcInput("news.eu.example.co.uk", new SpfAuthResult(SpfResult.Fail, "other.net"), [new DkimAuthResult("esp.net", true, "s")]);
        _cachedLookup = _evaluator.LookupPolicyAsync("example.com").AsTask().GetAwaiter().GetResult();
    }

    [Benchmark(Baseline = true)]
    public async Task<DmarcResult> EvaluateDirectRecordPass() => (await _evaluator.EvaluateAsync(_directPass)).Result;

    [Benchmark]
    public async Task<DmarcResult> EvaluateOrganizationalFallbackFail() => (await _evaluator.EvaluateAsync(_fallbackFail)).Result;

    [Benchmark]
    public DmarcResult EvaluateWithCachedLookup() => _evaluator.Evaluate(_directPass, _cachedLookup).Result;

    [Benchmark]
    public bool ParseRecord() =>
        DmarcRecord.TryParse("v=DMARC1; p=reject; sp=quarantine; pct=100; adkim=s; aspf=r; rua=mailto:a@example.com!10m,mailto:b@example.net; fo=1", out _, out _);
}
