namespace Mta.Dns;

/// <summary>A parsed DNS response message (see <see cref="DnsMessageReader"/>).</summary>
public sealed class DnsMessage
{
    public ushort Id { get; init; }

    public DnsHeader Header { get; init; }

    public DnsRcode Rcode => Header.Rcode;

    public bool Truncated => Header.Truncated;

    /// <summary>The AD bit exactly as the server sent it. Do not trust it unless the server is a trusted local validating resolver.</summary>
    public bool AuthenticData => Header.AuthenticData;

    /// <summary>The question name, lower-case without a trailing dot; null when the message has no question section.</summary>
    public string? QuestionName { get; init; }

    public DnsRecordType QuestionType { get; init; }

    public IReadOnlyList<DnsRecord> Answers { get; init; } = [];

    /// <summary>The authority section (SOA for negative answers, NS for referrals).</summary>
    public IReadOnlyList<DnsRecord> Authority { get; init; } = [];

    /// <summary>The number of records in the additional section. The section itself is not parsed.</summary>
    public int AdditionalCount { get; init; }

    /// <summary>
    /// The negative-caching TTL per RFC 2308 §5: the smaller of the authority SOA's own TTL and its MINIMUM field.
    /// Null when the authority section carries no SOA.
    /// </summary>
    public uint? NegativeTtl
    {
        get
        {
            foreach (var record in Authority)
            {
                if (record is SoaRecord soa)
                {
                    return Math.Min(soa.Ttl, soa.Minimum);
                }
            }

            return null;
        }
    }
}
