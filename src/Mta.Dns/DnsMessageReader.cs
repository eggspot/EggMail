using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace Mta.Dns;

/// <summary>
/// Parses DNS response messages. All input is treated as hostile: every offset and length is bounds-checked,
/// compression pointers must point strictly backwards and are limited in number (so a loop or a pointer chain
/// cannot burn CPU), names are limited to 255 wire bytes and 63-byte labels, record data must have exactly the
/// length its type requires, and the only exception ever thrown is <see cref="DnsException"/>
/// with <see cref="DnsFailureReason.MalformedResponse"/>.
/// </summary>
public static class DnsMessageReader
{
    /// <summary>
    /// A name of at most 255 wire bytes has at most 253 label bytes, each of which can expand to a 4-char escape (\DDD),
    /// plus at most 126 separating dots.
    /// </summary>
    private const int NameBufferLength = 253 * 4 + 126 + 2;

    /// <summary>Legitimate compression chains (name -> suffix pointer -> suffix pointer ...) are never longer than the label count (127).</summary>
    private const int MaxCompressionJumps = 127;

    /// <summary>
    /// Parses a complete response. The question (if present) and answer and authority sections are decoded; the
    /// additional section is counted but not parsed. Trailing bytes after the last parsed record are ignored.
    /// Names are lower-cased; bytes in a name that are not printable ASCII (and '.' or '\' inside a label) are
    /// escaped as in zone-file presentation format (\DDD, \., \\).
    /// </summary>
    /// <exception cref="DnsException">The packet is malformed.</exception>
    public static DnsMessage Parse(ReadOnlySpan<byte> packet)
    {
        if (!DnsWire.TryReadHeader(packet, out var header))
        {
            throw Malformed("message is shorter than the 12-byte header");
        }

        if (header.QuestionCount > 1)
        {
            throw Malformed("more than one question");
        }

        Span<char> nameBuffer = stackalloc char[NameBufferLength];
        int pos = DnsWire.HeaderLength;
        string? questionName = null;
        var questionType = DnsRecordType.A;
        if (header.QuestionCount == 1)
        {
            pos = ReadName(packet, pos, nameBuffer, out int chars);
            questionName = chars == 0 ? string.Empty : new string(nameBuffer[..chars]);
            if (pos + 4 > packet.Length)
            {
                throw Truncated();
            }

            questionType = (DnsRecordType)BinaryPrimitives.ReadUInt16BigEndian(packet[pos..]);
            ushort questionClass = BinaryPrimitives.ReadUInt16BigEndian(packet[(pos + 2)..]);
            pos += 4;
            if (questionClass != DnsWire.ClassIn)
            {
                throw Malformed("question class is not IN");
            }
        }

        string? lastOwner = null;
        var answers = ReadSection(packet, ref pos, header.AnswerCount, nameBuffer, ref lastOwner);
        var authority = ReadSection(packet, ref pos, header.AuthorityCount, nameBuffer, ref lastOwner);

        return new DnsMessage
        {
            Id = header.Id,
            Header = header,
            QuestionName = questionName,
            QuestionType = questionType,
            Answers = answers,
            Authority = authority,
            AdditionalCount = header.AdditionalCount,
        };
    }

    private static DnsRecord[] ReadSection(ReadOnlySpan<byte> packet, ref int pos, int count, Span<char> nameBuffer, ref string? lastOwner)
    {
        if (count == 0)
        {
            return [];
        }

        // Every record needs at least 11 bytes (1-byte root name + 10 fixed), which bounds what a lying header can make us allocate.
        int plausible = Math.Min(count, Math.Max(0, packet.Length - pos) / 11);
        var records = new DnsRecord[plausible];
        int n = 0;
        for (int i = 0; i < count; i++)
        {
            var record = ReadRecord(packet, ref pos, nameBuffer, ref lastOwner);
            if (record is null)
            {
                continue;
            }

            if (n == records.Length)
            {
                // Cannot happen for a well-formed message (records are at least 11 bytes), but never trust the arithmetic.
                Array.Resize(ref records, Math.Max(4, n * 2));
            }

            records[n++] = record;
        }

        if (n == 0)
        {
            return [];
        }

        if (n != records.Length)
        {
            Array.Resize(ref records, n);
        }

        return records;
    }

    private static DnsRecord? ReadRecord(ReadOnlySpan<byte> packet, ref int pos, Span<char> nameBuffer, ref string? lastOwner)
    {
        int p = ReadName(packet, pos, nameBuffer, out int ownerChars);
        string owner = InternOwner(nameBuffer[..ownerChars], ref lastOwner);

        if (p + 10 > packet.Length)
        {
            throw Truncated();
        }

        ushort rawType = BinaryPrimitives.ReadUInt16BigEndian(packet[p..]);
        ushort rawClass = BinaryPrimitives.ReadUInt16BigEndian(packet[(p + 2)..]);
        uint ttl = BinaryPrimitives.ReadUInt32BigEndian(packet[(p + 4)..]);
        int rdLength = BinaryPrimitives.ReadUInt16BigEndian(packet[(p + 8)..]);
        int rdStart = p + 10;
        if (rdStart + rdLength > packet.Length)
        {
            throw Truncated();
        }

        int rdEnd = rdStart + rdLength;
        pos = rdEnd;

        if (rawClass != DnsWire.ClassIn)
        {
            return null;
        }

        // RFC 2181 §8: a TTL with the most significant bit set is treated as zero.
        if (ttl > int.MaxValue)
        {
            ttl = 0;
        }

        var rdata = packet[rdStart..rdEnd];
        switch ((DnsRecordType)rawType)
        {
            case DnsRecordType.A:
                if (rdLength != 4)
                {
                    throw Malformed("A record data is not 4 bytes");
                }

                return new ARecord(owner, ttl, new IPAddress(rdata));

            case DnsRecordType.AAAA:
                if (rdLength != 16)
                {
                    throw Malformed("AAAA record data is not 16 bytes");
                }

                return new AaaaRecord(owner, ttl, new IPAddress(rdata));

            case DnsRecordType.CNAME:
                return new CnameRecord(owner, ttl, ReadRdataName(packet, rdStart, rdEnd, nameBuffer));

            case DnsRecordType.NS:
                return new NsRecord(owner, ttl, ReadRdataName(packet, rdStart, rdEnd, nameBuffer));

            case DnsRecordType.PTR:
                return new PtrRecord(owner, ttl, ReadRdataName(packet, rdStart, rdEnd, nameBuffer));

            case DnsRecordType.MX:
            {
                if (rdLength < 3)
                {
                    throw Malformed("MX record data is too short");
                }

                ushort preference = BinaryPrimitives.ReadUInt16BigEndian(rdata);
                return new MxRecord(owner, ttl, preference, ReadRdataName(packet, rdStart + 2, rdEnd, nameBuffer));
            }

            case DnsRecordType.TXT:
                return new TxtRecord(owner, ttl, DecodeTxt(rdata));

            case DnsRecordType.SOA:
            {
                int q = ReadName(packet, rdStart, nameBuffer, out int c1);
                if (q > rdEnd)
                {
                    throw Malformed("SOA MNAME overruns the record data");
                }

                string mname = c1 == 0 ? string.Empty : new string(nameBuffer[..c1]);
                q = ReadName(packet, q, nameBuffer, out int c2);
                if (q > rdEnd)
                {
                    throw Malformed("SOA RNAME overruns the record data");
                }

                string rname = c2 == 0 ? string.Empty : new string(nameBuffer[..c2]);
                if (rdEnd - q != 20)
                {
                    throw Malformed("SOA fixed fields are not 20 bytes");
                }

                var f = packet[q..rdEnd];
                return new SoaRecord(
                    owner,
                    ttl,
                    mname,
                    rname,
                    BinaryPrimitives.ReadUInt32BigEndian(f),
                    BinaryPrimitives.ReadUInt32BigEndian(f[4..]),
                    BinaryPrimitives.ReadUInt32BigEndian(f[8..]),
                    BinaryPrimitives.ReadUInt32BigEndian(f[12..]),
                    BinaryPrimitives.ReadUInt32BigEndian(f[16..]));
            }

            case DnsRecordType.TLSA:
                if (rdLength < 3)
                {
                    throw Malformed("TLSA record data is too short");
                }

                return new TlsaRecord(owner, ttl, rdata[0], rdata[1], rdata[2], rdata[3..].ToArray());

            default:
                return new UnknownRecord(owner, rawType, ttl, rdata.ToArray());
        }
    }

    private static string ReadRdataName(ReadOnlySpan<byte> packet, int start, int rdEnd, Span<char> nameBuffer)
    {
        int end = ReadName(packet, start, nameBuffer, out int chars);
        if (end != rdEnd)
        {
            throw Malformed("name does not fill the record data exactly");
        }

        return chars == 0 ? string.Empty : new string(nameBuffer[..chars]);
    }

    /// <summary>Reuses the previous owner string when consecutive records share a name (the common case), saving an allocation each.</summary>
    private static string InternOwner(ReadOnlySpan<char> decoded, ref string? last)
    {
        if (decoded.Length == 0)
        {
            return string.Empty;
        }

        if (last is not null && decoded.SequenceEqual(last))
        {
            return last;
        }

        return last = new string(decoded);
    }

    /// <summary>
    /// Concatenates the character-strings of a TXT record (RFC 1035 §3.3.14; SPF/DKIM/DMARC require plain concatenation).
    /// Bytes are mapped 1:1 to chars (Latin-1) so no information is lost; policy records are ASCII anyway.
    /// </summary>
    private static string DecodeTxt(ReadOnlySpan<byte> rdata)
    {
        int total = 0;
        int i = 0;
        while (i < rdata.Length)
        {
            int len = rdata[i];
            if (i + 1 + len > rdata.Length)
            {
                throw Malformed("TXT character-string overruns the record data");
            }

            total += len;
            i += 1 + len;
        }

        if (total == 0)
        {
            return string.Empty;
        }

        if (rdata.Length == total + 1)
        {
            return Encoding.Latin1.GetString(rdata.Slice(1, total));
        }

        char[]? rented = null;
        Span<char> chars = total <= 512 ? stackalloc char[512] : (rented = System.Buffers.ArrayPool<char>.Shared.Rent(total));
        try
        {
            int written = 0;
            i = 0;
            while (i < rdata.Length)
            {
                int len = rdata[i];
                for (int k = 0; k < len; k++)
                {
                    chars[written++] = (char)rdata[i + 1 + k];
                }

                i += 1 + len;
            }

            return new string(chars[..written]);
        }
        finally
        {
            if (rented is not null)
            {
                System.Buffers.ArrayPool<char>.Shared.Return(rented);
            }
        }
    }

    /// <summary>
    /// Decodes a possibly compressed name starting at <paramref name="offset"/> into <paramref name="buffer"/>
    /// (lower-cased, escaped) and returns the offset just after the name in the stream (after the first pointer,
    /// if there is one).
    /// </summary>
    private static int ReadName(ReadOnlySpan<byte> packet, int offset, Span<char> buffer, out int charCount)
    {
        int pos = offset;
        int next = -1;
        int jumps = 0;
        int wireLength = 1; // the terminating root label
        int n = 0;

        while (true)
        {
            if ((uint)pos >= (uint)packet.Length)
            {
                throw Truncated();
            }

            int len = packet[pos];
            if (len == 0)
            {
                if (next < 0)
                {
                    next = pos + 1;
                }

                break;
            }

            if ((len & 0xC0) == 0xC0)
            {
                if (pos + 1 >= packet.Length)
                {
                    throw Truncated();
                }

                int target = ((len & 0x3F) << 8) | packet[pos + 1];
                if (next < 0)
                {
                    next = pos + 2;
                }

                // Only strictly backward pointers: this alone makes loops impossible; the jump cap bounds worst-case work.
                if (target >= pos)
                {
                    throw Malformed("compression pointer does not point backwards");
                }

                if (++jumps > MaxCompressionJumps)
                {
                    throw Malformed("too many compression pointers");
                }

                pos = target;
                continue;
            }

            if ((len & 0xC0) != 0)
            {
                throw Malformed("reserved label type");
            }

            if (pos + 1 + len > packet.Length)
            {
                throw Truncated();
            }

            wireLength += len + 1;
            if (wireLength > DnsWire.MaxNameWireLength)
            {
                throw Malformed("name is longer than 255 bytes");
            }

            if (n > 0)
            {
                buffer[n++] = '.';
            }

            for (int i = 0; i < len; i++)
            {
                byte b = packet[pos + 1 + i];
                if (b is >= (byte)'A' and <= (byte)'Z')
                {
                    buffer[n++] = (char)(b | 0x20);
                }
                else if (b is (byte)'.' or (byte)'\\')
                {
                    buffer[n++] = '\\';
                    buffer[n++] = (char)b;
                }
                else if (b <= 0x20 || b >= 0x7F)
                {
                    buffer[n++] = '\\';
                    buffer[n++] = (char)('0' + b / 100);
                    buffer[n++] = (char)('0' + b / 10 % 10);
                    buffer[n++] = (char)('0' + b % 10);
                }
                else
                {
                    buffer[n++] = (char)b;
                }
            }

            pos += 1 + len;
        }

        charCount = n;
        return next;
    }

    private static DnsException Malformed(string detail) => new("Malformed DNS response: " + detail + ".", DnsFailureReason.MalformedResponse);

    private static DnsException Truncated() => Malformed("message is truncated");
}
