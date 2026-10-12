using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using BenchmarkDotNet.Attributes;
using Mta.Core;
using Mta.Dkim;
using Mta.Dns;

namespace Mta.Benchmarks.Dkim;

/// <summary>
/// DKIM signing, verification and body canonicalization for 1 KB and 50 KB messages (RSA-2048, relaxed/relaxed).
/// Run: <c>dotnet run -c Release --project bench/Mta.Benchmarks -- --filter "*DkimBenchmarks*"</c>.
/// Signing is dominated by the RSA private key operation; what the allocation column shows is everything else.
/// </summary>
[MemoryDiagnoser]
public class DkimBenchmarks
{
    private RSA _key = null!;
    private DkimSigner _signer = null!;
    private DkimVerifier _verifier = null!;
    private byte[] _message = null!;
    private byte[] _signedMessage = null!;
    private ArrayBufferWriter<byte> _output = null!;

    [Params(1024, 50 * 1024)]
    public int MessageSize { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _key = DkimKeyTools.GenerateRsa2048();
        _signer = new DkimSigner(new DkimSignerOptions { Domain = "example.com", Selector = "bench" }, _key);

        var dns = new StaticDnsResolver();
        dns.AddTxt("bench._domainkey.example.com", DkimKeyTools.FormatDnsTxtValue(_key));
        _verifier = new DkimVerifier(dns, new DkimVerifierOptions { Clock = SystemClock.Instance });

        var body = new StringBuilder();
        int i = 0;
        while (body.Length < MessageSize)
        {
            body.Append("Line ").Append(i++).Append(" of the benchmark body with   some  spacing and words.  \r\n");
        }

        string message =
            "From: Alice <alice@example.com>\r\nTo: Bob <bob@example.net>\r\nSubject: Benchmark\r\n"
            + "Date: Mon, 12 Oct 2026 12:00:00 +0000\r\nMessage-ID: <bench@example.com>\r\nMIME-Version: 1.0\r\n"
            + "Content-Type: text/plain; charset=utf-8\r\n\r\n" + body;
        _message = Encoding.ASCII.GetBytes(message);
        _signedMessage = Encoding.ASCII.GetBytes(_signer.Sign(_message) + message);
        _output = new ArrayBufferWriter<byte>(4096);
    }

    [GlobalCleanup]
    public void Cleanup() => _key.Dispose();

    [Benchmark]
    public int Sign()
    {
        _output.Clear();
        return _signer.Sign(_message, _output);
    }

    [Benchmark]
    public async Task<DkimStatus> Verify()
    {
        var results = await _verifier.VerifyAsync(_signedMessage).ConfigureAwait(false);
        return results[0].Status;
    }

    [Benchmark]
    public long CanonicalizeAndHashRelaxedBody()
    {
        Span<byte> hash = stackalloc byte[32];
        DkimVerifier.HashBody(_message, relaxed: true, limit: long.MaxValue, hash, out long total);
        return total;
    }

    [Benchmark]
    public long CanonicalizeAndHashSimpleBody()
    {
        Span<byte> hash = stackalloc byte[32];
        DkimVerifier.HashBody(_message, relaxed: false, limit: long.MaxValue, hash, out long total);
        return total;
    }
}
