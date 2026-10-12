using System.Net;
using BenchmarkDotNet.Attributes;
using Mta.Dns;

namespace Mta.Benchmarks.Dns;

/// <summary>DNS packet codec: query building (should be allocation-free) and response parsing.</summary>
/// <remarks>Run with: <c>dotnet run -c Release --project bench/Mta.Benchmarks -- --filter "*DnsCodec*"</c></remarks>
[MemoryDiagnoser]
public class DnsCodecBenchmarks
{
    private byte[] _query = null!;
    private byte[] _mxResponse = null!;
    private byte[] _txtResponse = null!;
    private byte[] _buffer = null!;
    private DnsQueryOptions _options;
    private readonly IPAddress _ipv6 = IPAddress.Parse("2001:db8::1234");

    [GlobalSetup]
    public void Setup()
    {
        _buffer = new byte[DnsMessageWriter.MaxQueryLength];
        _options = new DnsQueryOptions(RecursionDesired: true, EdnsUdpPayloadSize: 1232, DnssecOk: true);
        _query = DnsMessageWriter.BuildQuery(0x1234, "example.com", DnsRecordType.MX, _options);

        // MX response with four compressed exchanges plus A/AAAA glue in the additional section (ignored by the parser).
        _mxResponse = Compose(
            _query,
            answers:
            [
                MxRecord(10, "mx1"),
                MxRecord(20, "mx2"),
                MxRecord(30, "mx3"),
                MxRecord(40, "mx4"),
            ]);

        // SPF-style TXT split over two character-strings.
        var txt = new List<byte> { 0xC0, 0x0C, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C };
        byte[] s1 = System.Text.Encoding.ASCII.GetBytes("v=spf1 include:_spf.example.com ip4:192.0.2.0/24 ");
        byte[] s2 = System.Text.Encoding.ASCII.GetBytes("ip6:2001:db8::/32 -all");
        int rdLength = 2 + s1.Length + s2.Length;
        txt.Add((byte)(rdLength >> 8));
        txt.Add((byte)rdLength);
        txt.Add((byte)s1.Length);
        txt.AddRange(s1);
        txt.Add((byte)s2.Length);
        txt.AddRange(s2);
        _txtResponse = Compose(DnsMessageWriter.BuildQuery(0x1234, "example.com", DnsRecordType.TXT, _options), [txt.ToArray()]);
    }

    private static byte[] MxRecord(ushort preference, string host)
    {
        var rr = new List<byte> { 0xC0, 0x0C, 0x00, 0x0F, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C };
        var name = new List<byte> { (byte)host.Length };
        name.AddRange(System.Text.Encoding.ASCII.GetBytes(host));
        name.AddRange([0xC0, 0x0C]);
        int rdLength = 2 + name.Count;
        rr.Add((byte)(rdLength >> 8));
        rr.Add((byte)rdLength);
        rr.Add((byte)(preference >> 8));
        rr.Add((byte)preference);
        rr.AddRange(name);
        return rr.ToArray();
    }

    private static byte[] Compose(byte[] query, byte[][] answers)
    {
        // Header + the query's question section (without its OPT record) + answers.
        DnsWire.TryGetQuestionLength(query, out int questionLength);
        var message = new List<byte>(query.AsSpan(0, DnsWire.HeaderLength + questionLength).ToArray());
        message[2] = 0x81;
        message[3] = 0x80;
        message[5] = 1;
        message[7] = (byte)answers.Length;
        message[11] = 0;
        foreach (var a in answers)
        {
            message.AddRange(a);
        }

        return message.ToArray();
    }

    [Benchmark]
    public int BuildQuery() => DnsMessageWriter.WriteQuery(_buffer, 0x1234, "mail.example.com", DnsRecordType.MX, in _options);

    [Benchmark]
    public bool MatchResponseToQuery() => DnsWire.IsResponseTo(_query, _mxResponse, caseSensitive: false);

    [Benchmark]
    public int ParseMxResponse() => DnsMessageReader.Parse(_mxResponse).Answers.Count;

    [Benchmark]
    public int ParseTxtResponse() => DnsMessageReader.Parse(_txtResponse).Answers.Count;

    [Benchmark]
    public string ReverseName() => DnsName.ReverseArpaName(_ipv6);

    [Benchmark]
    public string NormalizeAlreadyNormalName() => DnsName.Normalize("mail.example.com");
}
