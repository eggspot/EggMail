using System.Text;
using BenchmarkDotNet.Attributes;
using Mta.Dsn;

namespace Mta.Benchmarks.Dsn;

/// <summary>
/// The keyed addresses of the bounce and forward paths: a VERP bounce address issued and decoded, an SRS address issued and verified, a forward hop marker signed and verified,
/// with a ring of three keys (one signing, two retired, as after rotations).
/// Run: <c>dotnet run -c Release --project bench/Mta.Benchmarks -- --filter "*VerpBenchmarks*"</c>.
/// </summary>
[MemoryDiagnoser]
public class VerpBenchmarks
{
    private static readonly DateTimeOffset Now = new(2026, 10, 23, 12, 0, 0, TimeSpan.Zero);
    private static readonly Guid Tenant = Guid.Parse("a0000000-0000-7000-8000-000000000001");
    private static readonly Guid Domain = Guid.Parse("d0000000-0000-7000-8000-000000000001");

    private VerpCodec _verp = null!;
    private SrsCodec _srs = null!;
    private ForwardHopMarker _hops = null!;
    private string _bounceLocalPart = null!;
    private string _srsLocalPart = null!;
    private string _bodyHash = null!;
    private string _marker = null!;

    [GlobalSetup]
    public void Setup()
    {
        _verp = new VerpCodec(new Dictionary<int, byte[]> { [1] = VerpCodec.GenerateKey(), [2] = VerpCodec.GenerateKey(), [3] = VerpCodec.GenerateKey() }, 3);
        _srs = new SrsCodec(_verp);
        _hops = new ForwardHopMarker(_verp);
        _bounceLocalPart = _verp.CreateLocalPart(Tenant, Domain, Now, "example.net");
        _srsLocalPart = _srs.CreateLocalPart("sender.example", "alice", Now);
        _bodyHash = ForwardHopMarker.BodyHash(Encoding.ASCII.GetBytes("Hello\r\n"));
        _marker = _hops.CreateValue(1, _bodyHash);
    }

    [Benchmark]
    public string VerpCreate() => _verp.CreateLocalPart(Tenant, Domain, Now, "example.net");

    [Benchmark]
    public bool VerpDecode() => _verp.TryDecode(_bounceLocalPart, Now, TimeSpan.FromDays(14), out _);

    [Benchmark]
    public string SrsCreate() => _srs.CreateLocalPart("sender.example", "alice", Now);

    [Benchmark]
    public bool SrsVerify() => _srs.TryVerify(_srsLocalPart, Now);

    [Benchmark]
    public bool HopMarkerVerify() => _hops.TryVerify(_marker, _bodyHash, out _);
}
