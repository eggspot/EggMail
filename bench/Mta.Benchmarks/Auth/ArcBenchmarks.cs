using System.Security.Cryptography;
using System.Text;
using BenchmarkDotNet.Attributes;
using Mta.Auth.Arc;
using Mta.Dkim;
using Mta.Dns;

namespace Mta.Benchmarks.Auth;

/// <summary>ARC sealing and validation of a 2 KB message against an in-memory zone (no network): one RSA signature or three RSA verifications per iteration dominate.</summary>
[MemoryDiagnoser]
public class ArcBenchmarks
{
    private RSA _key = null!;
    private ArcSealer _sealer = null!;
    private ArcValidator _validator = null!;
    private byte[] _plain = null!;
    private byte[] _threeHops = null!;
    private readonly ArcChainResult _none = new(ArcChainStatus.None, "none");

    [GlobalSetup]
    public void Setup()
    {
        _key = RSA.Create(2048);
        var dns = new StaticDnsResolver().AddTxt("arc1._domainkey.hop.example", DkimKeyTools.FormatDnsTxtValue(_key));
        _validator = new ArcValidator(dns);
        _sealer = new ArcSealer(new ArcSealerOptions { Domain = "hop.example", Selector = "arc1" }, _key);

        string body = string.Concat(Enumerable.Repeat("The quick brown fox jumps over the lazy dog.\r\n", 40));
        string message = "From: Alice <alice@origin.example>\r\nTo: Bob <bob@dest.example>\r\nSubject: Benchmark\r\nDate: Mon, 12 Oct 2026 12:00:00 +0000\r\nMessage-ID: <1@origin.example>\r\n\r\n" + body;
        _plain = Encoding.ASCII.GetBytes(message);

        byte[] current = _plain;
        for (int hop = 0; hop < 3; hop++)
        {
            var incoming = _validator.ValidateAsync(current).AsTask().GetAwaiter().GetResult();
            var sealedSet = _sealer.Seal(current, "mx.hop.example; spf=pass smtp.mailfrom=alice@origin.example", incoming);
            current = Encoding.ASCII.GetBytes(sealedSet.Headers).Concat(current).ToArray();
        }

        _threeHops = current;
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _sealer.Dispose();
        _key.Dispose();
    }

    [Benchmark(Baseline = true)]
    public ArcSealResult SealFirstHop() => _sealer.Seal(_plain, "mx.hop.example; spf=pass smtp.mailfrom=alice@origin.example", _none);

    [Benchmark]
    public async Task<ArcChainResult> ValidateNoChain() => await _validator.ValidateAsync(_plain);

    [Benchmark]
    public async Task<ArcChainResult> ValidateThreeHopChain() => await _validator.ValidateAsync(_threeHops);
}
