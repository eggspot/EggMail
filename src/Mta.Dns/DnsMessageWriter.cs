using System.Buffers.Binary;

namespace Mta.Dns;

/// <summary>Flags and EDNS settings for a query built by <see cref="DnsMessageWriter"/>.</summary>
/// <param name="RecursionDesired">The RD bit. Stub resolvers always want recursion.</param>
/// <param name="EdnsUdpPayloadSize">The EDNS0 (RFC 6891) requestor's UDP payload size; 0 omits the OPT record entirely. Values below 512 are raised to 512.</param>
/// <param name="DnssecOk">The DO bit in the OPT record (RFC 3225): ask the server to include DNSSEC records and set AD.</param>
/// <param name="AuthenticData">The AD bit in the query header (RFC 6840 §5.7): signals that the client understands AD.</param>
/// <param name="CheckingDisabled">The CD bit: ask the validating resolver not to reject bogus data.</param>
public readonly record struct DnsQueryOptions(
    bool RecursionDesired = true,
    ushort EdnsUdpPayloadSize = DnsQueryOptions.DefaultEdnsUdpPayloadSize,
    bool DnssecOk = false,
    bool AuthenticData = false,
    bool CheckingDisabled = false)
{
    /// <summary>1232 bytes avoids IP fragmentation on a 1280-byte-MTU IPv6 path (DNS Flag Day 2020).</summary>
    public const ushort DefaultEdnsUdpPayloadSize = 1232;

    public static DnsQueryOptions Default => new();
}

/// <summary>Builds DNS query messages (RFC 1035 §4, EDNS0 per RFC 6891). Allocation-free: writes into a caller-supplied span.</summary>
public static class DnsMessageWriter
{
    /// <summary>The size of the OPT pseudo-record with no options: root name, type, class, TTL, RDLENGTH.</summary>
    private const int OptRecordLength = 11;

    /// <summary>The largest query this writer can produce (header + 255-byte name + type/class + OPT).</summary>
    public const int MaxQueryLength = DnsWire.HeaderLength + DnsWire.MaxNameWireLength + 4 + OptRecordLength;

    /// <summary>
    /// Writes a single-question query. <paramref name="name"/> must already be in ASCII presentation form (use
    /// <see cref="DnsName.Normalize"/> for IDNA); its letter case is preserved on the wire, which is what makes 0x20
    /// randomization possible. A single trailing dot is accepted. Returns the number of bytes written.
    /// </summary>
    /// <exception cref="DnsException">The name is invalid (<see cref="DnsFailureReason.InvalidRequest"/>).</exception>
    /// <exception cref="ArgumentException"><paramref name="destination"/> is too small; <see cref="MaxQueryLength"/> bytes always suffice.</exception>
    public static int WriteQuery(Span<byte> destination, ushort id, ReadOnlySpan<char> name, DnsRecordType type, in DnsQueryOptions options)
    {
        if (name.Length > 0 && name[^1] == '.')
        {
            name = name[..^1];
        }

        if (name.Length > DnsWire.MaxNamePresentationLength)
        {
            throw Invalid("name is too long");
        }

        bool edns = options.EdnsUdpPayloadSize != 0;
        int nameWire = name.Length == 0 ? 1 : name.Length + 2;
        int needed = DnsWire.HeaderLength + nameWire + 4 + (edns ? OptRecordLength : 0);
        if (destination.Length < needed)
        {
            throw new ArgumentException($"Destination must be at least {needed} bytes.", nameof(destination));
        }

        int flags = 0;
        if (options.RecursionDesired)
        {
            flags |= DnsWire.FlagRecursionDesired;
        }

        if (options.AuthenticData)
        {
            flags |= DnsWire.FlagAuthenticData;
        }

        if (options.CheckingDisabled)
        {
            flags |= DnsWire.FlagCheckingDisabled;
        }

        BinaryPrimitives.WriteUInt16BigEndian(destination, id);
        BinaryPrimitives.WriteUInt16BigEndian(destination[2..], (ushort)flags);
        BinaryPrimitives.WriteUInt16BigEndian(destination[4..], 1);
        BinaryPrimitives.WriteUInt16BigEndian(destination[6..], 0);
        BinaryPrimitives.WriteUInt16BigEndian(destination[8..], 0);
        BinaryPrimitives.WriteUInt16BigEndian(destination[10..], (ushort)(edns ? 1 : 0));

        int pos = DnsWire.HeaderLength;
        if (name.Length == 0)
        {
            destination[pos++] = 0;
        }
        else
        {
            int labelStart = pos++;
            int labelLength = 0;
            foreach (char c in name)
            {
                if (c == '.')
                {
                    if (labelLength == 0)
                    {
                        throw Invalid("empty label");
                    }

                    destination[labelStart] = (byte)labelLength;
                    labelStart = pos++;
                    labelLength = 0;
                    continue;
                }

                if (c is < '!' or > '~' or '\\')
                {
                    throw Invalid("name contains a character that is not allowed on the wire");
                }

                if (++labelLength > DnsWire.MaxLabelLength)
                {
                    throw Invalid("label is longer than 63 bytes");
                }

                destination[pos++] = (byte)c;
            }

            if (labelLength == 0)
            {
                throw Invalid("empty label");
            }

            destination[labelStart] = (byte)labelLength;
            destination[pos++] = 0;
        }

        BinaryPrimitives.WriteUInt16BigEndian(destination[pos..], (ushort)type);
        BinaryPrimitives.WriteUInt16BigEndian(destination[(pos + 2)..], DnsWire.ClassIn);
        pos += 4;

        if (edns)
        {
            ushort size = Math.Max(options.EdnsUdpPayloadSize, (ushort)512);
            destination[pos] = 0; // root owner name
            BinaryPrimitives.WriteUInt16BigEndian(destination[(pos + 1)..], (ushort)DnsRecordType.OPT);
            BinaryPrimitives.WriteUInt16BigEndian(destination[(pos + 3)..], size); // CLASS carries the UDP payload size
            destination[pos + 5] = 0; // extended RCODE
            destination[pos + 6] = 0; // EDNS version 0
            BinaryPrimitives.WriteUInt16BigEndian(destination[(pos + 7)..], options.DnssecOk ? (ushort)0x8000 : (ushort)0);
            BinaryPrimitives.WriteUInt16BigEndian(destination[(pos + 9)..], 0); // RDLENGTH
            pos += OptRecordLength;
        }

        return pos;
    }

    /// <summary>Convenience overload that allocates the exact-size result array.</summary>
    public static byte[] BuildQuery(ushort id, string name, DnsRecordType type, in DnsQueryOptions options)
    {
        ArgumentNullException.ThrowIfNull(name);
        Span<byte> buffer = stackalloc byte[MaxQueryLength];
        int n = WriteQuery(buffer, id, name, type, in options);
        return buffer[..n].ToArray();
    }

    private static DnsException Invalid(string reason) => new("Cannot encode DNS query: " + reason + ".", DnsFailureReason.InvalidRequest);
}
