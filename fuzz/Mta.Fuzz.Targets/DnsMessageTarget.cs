using System.Buffers.Binary;
using System.Text;
using Mta.Dns;

namespace Mta.Fuzz;

/// <summary>The DNS response parser (names with compression pointers, every record type) plus name normalization and the query writer.</summary>
internal static class DnsMessageTarget
{
    public static FuzzTarget Create() => new("dns-message", "DNS message parser, name normalization and query writer", Run, Seeds())
    {
        Tokens =
        [
            [0xC0, 0x0C], [0xC0, 0x00], [0xC0, 0x0B], [0xFF, 0xFF], [0x00, 0x01], [0x00, 0x0F], [0x00, 0x10], [0x00, 0x1C], [0x00, 0x06], [0x00, 0x34],
            [0x3F], [0x40], [0x80], [0x00], Encoding.ASCII.GetBytes("xn--"), Encoding.ASCII.GetBytes("\\"), Encoding.ASCII.GetBytes(".."),
        ],
        MutationIterations = 12000,
        MaxInputLength = 70_000,
    };

    private static void Run(ReadOnlySpan<byte> input)
    {
        try
        {
            var message = DnsMessageReader.Parse(input);
            Guard.Check(message.Answers.Count <= message.Header.AnswerCount, "more answers than the header announces");
            Guard.Check(message.Authority.Count <= message.Header.AuthorityCount, "more authority records than the header announces");
            foreach (var record in message.Answers.Concat(message.Authority))
            {
                Guard.Check(record.Name.Length <= (253 * 4) + 126, "owner name longer than any legal name can expand to");
                _ = record.ToString();
            }

            _ = message.NegativeTtl;
        }
        catch (DnsException ex) when (ex.Reason == DnsFailureReason.MalformedResponse)
        {
            // The documented, only way a hostile packet may be refused.
        }

        // The same bytes as text: names go through normalization and into the query writer.
        string text = Encoding.Latin1.GetString(input);
        if (text.Length > 600)
        {
            text = text[..600];
        }

        if (DnsName.TryNormalize(text, out string? normalized))
        {
            Guard.Check(normalized.Length <= 253, "a normalized name is at most 253 characters");
            Guard.Check(DnsName.TryNormalize(normalized, out string? again) && again == normalized, "normalization must be idempotent");
        }

        try
        {
            byte[] query = DnsMessageWriter.BuildQuery(0x1234, text, DnsRecordType.TXT, DnsQueryOptions.Default);
            Guard.Check(query.Length <= DnsMessageWriter.MaxQueryLength, "query longer than the documented maximum");
            _ = DnsMessageReader.Parse(query);
        }
        catch (DnsException ex) when (ex.Reason is DnsFailureReason.InvalidRequest or DnsFailureReason.MalformedResponse)
        {
        }
    }

    private static IReadOnlyList<byte[]> Seeds() =>
    [
        new Packet(0x1234, rcode: 0).Question("example.com", 15).Mx("example.com", 10, "mx1.example.com").Mx("example.com", 20, "mx2.example.com").A("mx1.example.com", [192, 0, 2, 1]).Build(),
        new Packet(0x4321, rcode: 0).Question("_dmarc.example.com", 16).Txt("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:r@example.com", "second string").Build(),
        new Packet(0x0001, rcode: 3).Question("nx.example.com", 1).Soa("example.com", "ns.example.com", "hostmaster.example.com").Build(),
        new Packet(0x0002, rcode: 0).Question("www.example.com", 1).Cname("www.example.com", "example.com").A("example.com", [198, 51, 100, 7]).Aaaa("example.com").Build(),
        new Packet(0x0003, rcode: 0).Question("_25._tcp.mx.example.com", 52).Tlsa("_25._tcp.mx.example.com").Build(),
        // A compression loop and an out-of-range pointer, the classic hostile shapes.
        new Packet(0x0004, rcode: 0).Question("loop.example.com", 1).RawAnswer([0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 1, 2, 3, 4]).Build(),
        [0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01],
        DnsMessageWriter.BuildQuery(0xBEEF, "Example.COM", DnsRecordType.MX, DnsQueryOptions.Default),
        Encoding.ASCII.GetBytes("mail.example.com"),
        Encoding.ASCII.GetBytes("xn--bcher-kva.example"),
    ];

    /// <summary>A minimal independent DNS message encoder for the seeds.</summary>
    private sealed class Packet
    {
        private readonly List<byte> _body = [];
        private readonly ushort _id;
        private readonly int _rcode;
        private int _questions;
        private int _answers;
        private readonly Dictionary<string, int> _names = new(StringComparer.Ordinal);

        public Packet(ushort id, int rcode)
        {
            _id = id;
            _rcode = rcode;
        }

        public Packet Question(string name, ushort type)
        {
            Name(name);
            U16(type);
            U16(1);
            _questions++;
            return this;
        }

        public Packet A(string owner, byte[] address) => Record(owner, 1, w => w.AddRange(address));

        public Packet Aaaa(string owner) => Record(owner, 28, w => w.AddRange(new byte[] { 0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }));

        public Packet Mx(string owner, ushort preference, string exchange) => Record(owner, 15, _ =>
        {
            U16(preference);
            Name(exchange);
        });

        public Packet Cname(string owner, string target) => Record(owner, 5, _ => Name(target));

        public Packet Txt(string owner, params string[] strings) => Record(owner, 16, _ =>
        {
            foreach (string s in strings)
            {
                _body.Add((byte)s.Length);
                _body.AddRange(Encoding.ASCII.GetBytes(s));
            }
        });

        public Packet Soa(string owner, string mname, string rname) => Record(owner, 6, _ =>
        {
            Name(mname);
            Name(rname);
            for (int i = 0; i < 5; i++)
            {
                _body.AddRange(new byte[] { 0, 0, 0, (byte)(i + 1) });
            }
        });

        public Packet Tlsa(string owner) => Record(owner, 52, w => w.AddRange(new byte[] { 3, 1, 1, 0xAA, 0xBB, 0xCC, 0xDD }));

        public Packet RawAnswer(byte[] bytes)
        {
            _body.AddRange(bytes);
            _answers++;
            return this;
        }

        public byte[] Build()
        {
            var header = new byte[12];
            BinaryPrimitives.WriteUInt16BigEndian(header, _id);
            BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(2), (ushort)(0x8180 | _rcode));
            BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4), (ushort)_questions);
            BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(6), (ushort)_answers);
            return [.. header, .. _body];
        }

        private Packet Record(string owner, ushort type, Action<List<byte>> writeData)
        {
            Name(owner);
            U16(type);
            U16(1);
            _body.AddRange(new byte[] { 0, 0, 0x0E, 0x10 });
            int lengthAt = _body.Count;
            U16(0);
            int start = _body.Count;
            writeData(_body);
            ushort length = (ushort)(_body.Count - start);
            _body[lengthAt] = (byte)(length >> 8);
            _body[lengthAt + 1] = (byte)length;
            _answers++;
            return this;
        }

        private void U16(ushort value)
        {
            _body.Add((byte)(value >> 8));
            _body.Add((byte)value);
        }

        private void Name(string name)
        {
            string rest = name;
            while (rest.Length > 0)
            {
                if (_names.TryGetValue(rest, out int offset))
                {
                    U16((ushort)(0xC000 | offset));
                    return;
                }

                _names[rest] = 12 + _body.Count;
                int dot = rest.IndexOf('.', StringComparison.Ordinal);
                string label = dot < 0 ? rest : rest[..dot];
                _body.Add((byte)label.Length);
                _body.AddRange(Encoding.ASCII.GetBytes(label));
                rest = dot < 0 ? string.Empty : rest[(dot + 1)..];
            }

            _body.Add(0);
        }
    }
}
