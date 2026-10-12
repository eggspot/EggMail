using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace Mta.Dns.Tests;

/// <summary>
/// An independent DNS message encoder for tests (deliberately not sharing code with the production reader), able to
/// emit name compression and arbitrary hostile content.
/// </summary>
internal sealed class PacketBuilder
{
    private enum Section { Answer, Authority, Additional }

    private sealed record Rr(Section Section, string Name, ushort Type, ushort Class, uint Ttl, Action<Writer> WriteData);

    private readonly List<Rr> _records = [];
    private byte[] _rawQuestion = [];
    private int _questionCount;

    public ushort Id { get; set; }

    public ushort Flags { get; set; } = 0x8180; // QR RD RA

    public int Rcode
    {
        get => Flags & 0xF;
        set => Flags = (ushort)((Flags & ~0xF) | value);
    }

    public bool Compress { get; set; } = true;

    public static PacketBuilder Response(ushort id, string qname, DnsRecordType qtype, int rcode = 0)
    {
        var b = new PacketBuilder { Id = id, Rcode = rcode };
        b.SetQuestion(qname, (ushort)qtype);
        return b;
    }

    /// <summary>Builds a reply that copies the ID and the raw question (including its letter case) from <paramref name="query"/>.</summary>
    public static PacketBuilder ReplyTo(ReadOnlySpan<byte> query, int rcode = 0)
    {
        Assert.True(DnsWire.TryGetQuestionLength(query, out int questionLength));
        var b = new PacketBuilder { Id = BinaryPrimitives.ReadUInt16BigEndian(query), Rcode = rcode };
        b._rawQuestion = query.Slice(12, questionLength).ToArray();
        b._questionCount = 1;
        return b;
    }

    public PacketBuilder SetQuestion(string name, ushort type)
    {
        var w = new Writer(false);
        w.Name(name);
        w.U16(type);
        w.U16(1);
        _rawQuestion = w.ToArray();
        _questionCount = 1;
        return this;
    }

    public PacketBuilder NoQuestion()
    {
        _rawQuestion = [];
        _questionCount = 0;
        return this;
    }

    public PacketBuilder Truncated()
    {
        Flags |= 0x0200;
        return this;
    }

    public PacketBuilder AuthenticData()
    {
        Flags |= 0x0020;
        return this;
    }

    public PacketBuilder Add(string name, ushort type, uint ttl, Action<Writer> data, bool authority = false, ushort cls = 1, bool additional = false) =>
        Push(additional ? Section.Additional : authority ? Section.Authority : Section.Answer, name, type, cls, ttl, data);

    public PacketBuilder A(string name, string ip, uint ttl = 300) => Add(name, 1, ttl, w => w.Bytes(IPAddress.Parse(ip).GetAddressBytes()));

    public PacketBuilder Aaaa(string name, string ip, uint ttl = 300) => Add(name, 28, ttl, w => w.Bytes(IPAddress.Parse(ip).GetAddressBytes()));

    public PacketBuilder Cname(string name, string target, uint ttl = 300) => Add(name, 5, ttl, w => w.Name(target));

    public PacketBuilder Ns(string name, string target, uint ttl = 300, bool authority = false) => Add(name, 2, ttl, w => w.Name(target), authority);

    public PacketBuilder Ptr(string name, string target, uint ttl = 300) => Add(name, 12, ttl, w => w.Name(target));

    public PacketBuilder Mx(string name, ushort pref, string exchange, uint ttl = 300) => Add(name, 15, ttl, w =>
    {
        w.U16(pref);
        w.Name(exchange);
    });

    public PacketBuilder Txt(string name, params string[] strings) => Add(name, 16, 300, w =>
    {
        foreach (var s in strings)
        {
            var bytes = Encoding.Latin1.GetBytes(s);
            w.Bytes([(byte)bytes.Length]);
            w.Bytes(bytes);
        }
    });

    public PacketBuilder Soa(string name, uint ttl, uint minimum, string mname = "ns.example", string rname = "hostmaster.example", bool authority = true) =>
        Add(name, 6, ttl, w =>
        {
            w.Name(mname);
            w.Name(rname);
            w.U32(2024010101);
            w.U32(7200);
            w.U32(900);
            w.U32(1209600);
            w.U32(minimum);
        }, authority);

    public PacketBuilder Tlsa(string name, byte usage, byte selector, byte matching, byte[] data, uint ttl = 300) => Add(name, 52, ttl, w =>
    {
        w.Bytes([usage, selector, matching]);
        w.Bytes(data);
    });

    public PacketBuilder Raw(string name, ushort type, byte[] rdata, uint ttl = 300) => Add(name, type, ttl, w => w.Bytes(rdata));

    private PacketBuilder Push(Section section, string name, ushort type, ushort cls, uint ttl, Action<Writer> data)
    {
        _records.Add(new Rr(section, name, type, cls, ttl, data));
        return this;
    }

    public byte[] Build()
    {
        var w = new Writer(Compress);
        w.U16(Id);
        w.U16(Flags);
        w.U16((ushort)_questionCount);
        w.U16((ushort)_records.Count(r => r.Section == Section.Answer));
        w.U16((ushort)_records.Count(r => r.Section == Section.Authority));
        w.U16((ushort)_records.Count(r => r.Section == Section.Additional));
        if (_questionCount > 0)
        {
            w.RegisterQuestion(_rawQuestion);
            w.Bytes(_rawQuestion);
        }

        foreach (var section in new[] { Section.Answer, Section.Authority, Section.Additional })
        {
            foreach (var r in _records.Where(r => r.Section == section))
            {
                w.Name(r.Name);
                w.U16(r.Type);
                w.U16(r.Class);
                w.U32(r.Ttl);
                int lengthAt = w.Position;
                w.U16(0);
                int start = w.Position;
                r.WriteData(w);
                w.PatchU16(lengthAt, (ushort)(w.Position - start));
            }
        }

        return w.ToArray();
    }

    public sealed class Writer(bool compress)
    {
        private readonly List<byte> _buf = [];
        private readonly Dictionary<string, int> _suffixes = new(StringComparer.OrdinalIgnoreCase);

        public int Position => _buf.Count;

        public void Bytes(ReadOnlySpan<byte> b)
        {
            foreach (var x in b)
            {
                _buf.Add(x);
            }
        }

        public void U16(ushort v)
        {
            _buf.Add((byte)(v >> 8));
            _buf.Add((byte)v);
        }

        public void U32(uint v)
        {
            U16((ushort)(v >> 16));
            U16((ushort)v);
        }

        public void PatchU16(int at, ushort v)
        {
            _buf[at] = (byte)(v >> 8);
            _buf[at + 1] = (byte)v;
        }

        /// <summary>Makes the question name available as a compression target (it starts at offset 12).</summary>
        public void RegisterQuestion(byte[] rawQuestion)
        {
            if (!compress)
            {
                return;
            }

            var labels = new List<(string Text, int Offset)>();
            int pos = 0;
            while (rawQuestion[pos] != 0)
            {
                int len = rawQuestion[pos];
                labels.Add((Encoding.Latin1.GetString(rawQuestion, pos + 1, len), 12 + pos));
                pos += len + 1;
            }

            for (int i = 0; i < labels.Count; i++)
            {
                string suffix = string.Join('.', labels.Skip(i).Select(l => l.Text));
                _suffixes.TryAdd(suffix, labels[i].Offset);
            }
        }

        public void Name(string name)
        {
            name = name.TrimEnd('.');
            var labels = name.Length == 0 ? [] : name.Split('.');
            for (int i = 0; i < labels.Length; i++)
            {
                string suffix = string.Join('.', labels.Skip(i));
                if (compress && _suffixes.TryGetValue(suffix, out int offset))
                {
                    U16((ushort)(0xC000 | offset));
                    return;
                }

                if (compress && Position < 0x3FFF)
                {
                    _suffixes[suffix] = Position;
                }

                var bytes = Encoding.Latin1.GetBytes(labels[i]);
                _buf.Add((byte)bytes.Length);
                Bytes(bytes);
            }

            _buf.Add(0);
        }

        public byte[] ToArray() => [.. _buf];
    }
}
