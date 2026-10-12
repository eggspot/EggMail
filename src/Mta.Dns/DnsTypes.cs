using System.Net;

namespace Mta.Dns;

public enum DnsRecordType : ushort
{
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    OPT = 41,
    TLSA = 52,
    ANY = 255,
}

public enum DnsRcode : byte
{
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,   // NXDOMAIN
    NotImplemented = 4,
    Refused = 5,
}

/// <summary>A resource record from a DNS answer. The name is lower-case without a trailing dot.</summary>
public abstract record DnsRecord(string Name, DnsRecordType Type, uint Ttl);

public sealed record ARecord(string Name, uint Ttl, IPAddress Address) : DnsRecord(Name, DnsRecordType.A, Ttl);

public sealed record AaaaRecord(string Name, uint Ttl, IPAddress Address) : DnsRecord(Name, DnsRecordType.AAAA, Ttl);

public sealed record CnameRecord(string Name, uint Ttl, string Target) : DnsRecord(Name, DnsRecordType.CNAME, Ttl);

public sealed record PtrRecord(string Name, uint Ttl, string Target) : DnsRecord(Name, DnsRecordType.PTR, Ttl);

public sealed record NsRecord(string Name, uint Ttl, string Target) : DnsRecord(Name, DnsRecordType.NS, Ttl);

public sealed record MxRecord(string Name, uint Ttl, ushort Preference, string Exchange) : DnsRecord(Name, DnsRecordType.MX, Ttl);

/// <summary>A TXT record. <see cref="Text"/> is all character-strings concatenated (as SPF/DKIM/DMARC require).</summary>
public sealed record TxtRecord(string Name, uint Ttl, string Text) : DnsRecord(Name, DnsRecordType.TXT, Ttl);

public sealed record SoaRecord(string Name, uint Ttl, string MName, string RName, uint Serial, uint Refresh, uint Retry, uint Expire, uint Minimum)
    : DnsRecord(Name, DnsRecordType.SOA, Ttl);

/// <summary>TLSA record (RFC 6698): certificate usage, selector, matching type, association data.</summary>
public sealed record TlsaRecord(string Name, uint Ttl, byte Usage, byte Selector, byte MatchingType, byte[] Data)
    : DnsRecord(Name, DnsRecordType.TLSA, Ttl);

/// <summary>A record of a type the resolver does not decode.</summary>
public sealed record UnknownRecord(string Name, ushort RawType, uint Ttl, byte[] Data)
    : DnsRecord(Name, (DnsRecordType)RawType, Ttl);

/// <summary>The outcome of one DNS query.</summary>
public sealed class DnsResponse
{
    public DnsRcode Rcode { get; init; }

    /// <summary>The AD (authenticated data) bit; trustworthy only when the resolver is a trusted local validating resolver.</summary>
    public bool AuthenticatedData { get; init; }

    /// <summary>Answer records matching the question after CNAME chasing (CNAME records themselves are included).</summary>
    public IReadOnlyList<DnsRecord> Answers { get; init; } = [];

    /// <summary>Minimum TTL of the answers, or the negative-caching TTL for empty answers.</summary>
    public uint Ttl { get; init; }

    public bool IsNxDomain => Rcode == DnsRcode.NameError;

    public bool IsSuccess => Rcode == DnsRcode.NoError;

    public IEnumerable<T> Get<T>() where T : DnsRecord => Answers.OfType<T>();
}

/// <summary>Raised for transport-level resolution failures (timeouts, malformed responses). NXDOMAIN is a normal <see cref="DnsResponse"/>.</summary>
public sealed class DnsException : Exception
{
    public DnsException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>Resolves DNS names. Implementations cache and are safe for concurrent use.</summary>
public interface IDnsResolver
{
    ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default);
}

/// <summary>Sends one DNS message and returns the response bytes (UDP with TCP fallback in the real implementation).</summary>
public interface IDnsTransport
{
    ValueTask<ReadOnlyMemory<byte>> ExchangeAsync(ReadOnlyMemory<byte> query, CancellationToken cancellationToken);
}
