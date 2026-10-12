using System.Buffers.Binary;

namespace Mta.Dns;

/// <summary>The fixed 12-byte DNS message header (RFC 1035 §4.1.1).</summary>
public readonly record struct DnsHeader(
    ushort Id,
    ushort Flags,
    ushort QuestionCount,
    ushort AnswerCount,
    ushort AuthorityCount,
    ushort AdditionalCount)
{
    public bool IsResponse => (Flags & DnsWire.FlagResponse) != 0;

    public byte OpCode => (byte)((Flags >> 11) & 0xF);

    public bool Authoritative => (Flags & DnsWire.FlagAuthoritative) != 0;

    public bool Truncated => (Flags & DnsWire.FlagTruncated) != 0;

    public bool RecursionDesired => (Flags & DnsWire.FlagRecursionDesired) != 0;

    public bool RecursionAvailable => (Flags & DnsWire.FlagRecursionAvailable) != 0;

    public bool AuthenticData => (Flags & DnsWire.FlagAuthenticData) != 0;

    public bool CheckingDisabled => (Flags & DnsWire.FlagCheckingDisabled) != 0;

    /// <summary>The 4-bit RCODE of the header (the EDNS extended bits are not interpreted).</summary>
    public DnsRcode Rcode => (DnsRcode)(Flags & DnsWire.RcodeMask);
}

/// <summary>Low-level wire-format constants and allocation-free helpers shared by the codec and the transport.</summary>
public static class DnsWire
{
    public const int HeaderLength = 12;

    /// <summary>The longest name on the wire, including length bytes and the root label (RFC 1035 §2.3.4).</summary>
    public const int MaxNameWireLength = 255;

    public const int MaxLabelLength = 63;

    /// <summary>The longest name in presentation form without a trailing dot.</summary>
    public const int MaxNamePresentationLength = 253;

    /// <summary>The largest DNS message (the TCP length prefix is 16 bits).</summary>
    public const int MaxMessageLength = ushort.MaxValue;

    public const ushort FlagResponse = 0x8000;
    public const ushort FlagAuthoritative = 0x0400;
    public const ushort FlagTruncated = 0x0200;
    public const ushort FlagRecursionDesired = 0x0100;
    public const ushort FlagRecursionAvailable = 0x0080;
    public const ushort FlagAuthenticData = 0x0020;
    public const ushort FlagCheckingDisabled = 0x0010;
    public const ushort RcodeMask = 0x000F;

    /// <summary>The class IN, the only class this client accepts.</summary>
    public const ushort ClassIn = 1;

    /// <summary>Reads the header; false if the packet is shorter than 12 bytes.</summary>
    public static bool TryReadHeader(ReadOnlySpan<byte> packet, out DnsHeader header)
    {
        if (packet.Length < HeaderLength)
        {
            header = default;
            return false;
        }

        header = new DnsHeader(
            BinaryPrimitives.ReadUInt16BigEndian(packet),
            BinaryPrimitives.ReadUInt16BigEndian(packet[2..]),
            BinaryPrimitives.ReadUInt16BigEndian(packet[4..]),
            BinaryPrimitives.ReadUInt16BigEndian(packet[6..]),
            BinaryPrimitives.ReadUInt16BigEndian(packet[8..]),
            BinaryPrimitives.ReadUInt16BigEndian(packet[10..]));
        return true;
    }

    /// <summary>
    /// Anti-spoofing check: does <paramref name="response"/> look like the answer to exactly this
    /// <paramref name="query"/>? Compares the 16-bit ID, the QR bit, the opcode, the question count and the whole
    /// question section (name, type, class). The name comparison is ASCII-case-insensitive unless
    /// <paramref name="caseSensitive"/> is set (0x20 mode), in which case the echoed case must be identical.
    /// Allocation-free; never throws. Returns false when the query itself is not a well-formed single-question message.
    /// </summary>
    public static bool IsResponseTo(ReadOnlySpan<byte> query, ReadOnlySpan<byte> response, bool caseSensitive)
    {
        if (!TryReadHeader(query, out var q) || !TryReadHeader(response, out var r))
        {
            return false;
        }

        if (q.QuestionCount != 1 || r.QuestionCount != 1 || q.IsResponse || !r.IsResponse || q.Id != r.Id || q.OpCode != r.OpCode)
        {
            return false;
        }

        if (!TryGetQuestionLength(query, out int questionLength) || response.Length < HeaderLength + questionLength)
        {
            return false;
        }

        var qq = query.Slice(HeaderLength, questionLength);
        var rq = response.Slice(HeaderLength, questionLength);
        if (caseSensitive)
        {
            return qq.SequenceEqual(rq);
        }

        for (int i = 0; i < qq.Length; i++)
        {
            byte a = qq[i];
            byte b = rq[i];
            if (a == b)
            {
                continue;
            }

            // Length bytes are <= 63, so they can never be mistaken for letters; folding only affects label text.
            if (!(IsAsciiLetter(a) && (a | 0x20) == (b | 0x20)))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>The length in bytes of the (uncompressed) question section of a query: name, type and class.</summary>
    internal static bool TryGetQuestionLength(ReadOnlySpan<byte> query, out int length)
    {
        int pos = HeaderLength;
        int wire = 0;
        while (true)
        {
            if (pos >= query.Length)
            {
                length = 0;
                return false;
            }

            int len = query[pos];
            if (len == 0)
            {
                pos++;
                wire++;
                break;
            }

            if (len > MaxLabelLength)
            {
                length = 0;
                return false;
            }

            pos += len + 1;
            wire += len + 1;
            if (wire >= MaxNameWireLength)
            {
                length = 0;
                return false;
            }
        }

        if (pos + 4 > query.Length)
        {
            length = 0;
            return false;
        }

        length = pos + 4 - HeaderLength;
        return true;
    }

    private static bool IsAsciiLetter(byte b) => (uint)((b | 0x20) - 'a') <= 'z' - 'a';
}
