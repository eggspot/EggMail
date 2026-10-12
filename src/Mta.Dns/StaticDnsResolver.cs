using System.Collections.Concurrent;

namespace Mta.Dns;

/// <summary>
/// An in-memory resolver for tests and for hosts that pin answers. Names are case-insensitive; a name with no
/// entries for the requested type yields NOERROR with no answers (NODATA) when the name is known, otherwise NXDOMAIN.
/// </summary>
public sealed class StaticDnsResolver : IDnsResolver
{
    private readonly ConcurrentDictionary<string, List<DnsRecord>> _records = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<(string, DnsRecordType), DnsRcode> _failures = new();

    private const int MaxCnameDepth = 8;

    private readonly ConcurrentDictionary<(string, DnsRecordType), int> _queryCounts = new();
    private int _totalQueries;

    public bool AuthenticatedData { get; set; }

    /// <summary>The total number of <see cref="QueryAsync"/> calls made by callers (CNAME chasing inside the resolver is not counted).</summary>
    public int QueryCount => Volatile.Read(ref _totalQueries);

    /// <summary>How many times (name, type) was queried; the name is normalized like <see cref="DnsName"/> does.</summary>
    public int GetQueryCount(string name, DnsRecordType type) =>
        _queryCounts.TryGetValue((Normalize(name), type), out int count) ? count : 0;

    public StaticDnsResolver Add(DnsRecord record)
    {
        var list = _records.GetOrAdd(Normalize(record.Name), _ => []);
        lock (list) { list.Add(record); }
        return this;
    }

    public StaticDnsResolver AddTxt(string name, string text, uint ttl = 300) => Add(new TxtRecord(Normalize(name), ttl, text));

    public StaticDnsResolver AddMx(string name, ushort preference, string exchange, uint ttl = 300) =>
        Add(new MxRecord(Normalize(name), ttl, preference, Normalize(exchange)));

    public StaticDnsResolver AddA(string name, string address, uint ttl = 300) =>
        Add(new ARecord(Normalize(name), ttl, System.Net.IPAddress.Parse(address)));

    public StaticDnsResolver AddAaaa(string name, string address, uint ttl = 300) =>
        Add(new AaaaRecord(Normalize(name), ttl, System.Net.IPAddress.Parse(address)));

    public StaticDnsResolver AddCname(string name, string target, uint ttl = 300) =>
        Add(new CnameRecord(Normalize(name), ttl, Normalize(target)));

    public StaticDnsResolver AddNs(string name, string nameServer, uint ttl = 300) =>
        Add(new NsRecord(Normalize(name), ttl, Normalize(nameServer)));

    /// <summary>Adds a PTR record at the reverse name of <paramref name="address"/> (in-addr.arpa / ip6.arpa).</summary>
    public StaticDnsResolver AddPtr(System.Net.IPAddress address, string target, uint ttl = 300) =>
        Add(new PtrRecord(DnsName.ReverseArpaName(address), ttl, Normalize(target)));

    /// <summary>Adds a DANE TLSA record at <c>_port._tcp.host</c>.</summary>
    public StaticDnsResolver AddTlsa(string host, int port, byte usage, byte selector, byte matchingType, byte[] data, uint ttl = 300) =>
        Add(new TlsaRecord(DnsName.TlsaName(host, port), ttl, usage, selector, matchingType, data));

    /// <summary>Makes queries for (name, type) return the given rcode (for example SERVFAIL).</summary>
    public StaticDnsResolver Fail(string name, DnsRecordType type, DnsRcode rcode = DnsRcode.ServerFailure)
    {
        _failures[(Normalize(name), type)] = rcode;
        return this;
    }

    public ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref _totalQueries);
        _queryCounts.AddOrUpdate((Normalize(name), type), 1, static (_, c) => c + 1);
        return ValueTask.FromResult(Resolve(name, type, 0));
    }

    private DnsResponse Resolve(string name, DnsRecordType type, int depth)
    {
        string n = Normalize(name);
        if (_failures.TryGetValue((n, type), out var rcode))
        {
            return new DnsResponse { Rcode = rcode };
        }

        if (!_records.TryGetValue(n, out var list))
        {
            return new DnsResponse { Rcode = DnsRcode.NameError, Ttl = 300 };
        }

        DnsRecord[] answers;
        lock (list)
        {
            answers = list.Where(r => r.Type == type || (type == DnsRecordType.ANY)).ToArray();
            if (answers.Length == 0)
            {
                var cname = list.OfType<CnameRecord>().FirstOrDefault();
                if (cname is not null && type != DnsRecordType.CNAME)
                {
                    if (depth >= MaxCnameDepth)
                    {
                        return new DnsResponse { Rcode = DnsRcode.ServerFailure };
                    }

                    var chased = Resolve(cname.Target, type, depth + 1);
                    return new DnsResponse
                    {
                        Rcode = chased.Rcode,
                        AuthenticatedData = AuthenticatedData,
                        Answers = [cname, .. chased.Answers],
                        Ttl = Math.Min(cname.Ttl, chased.Ttl),
                    };
                }
            }
        }

        return new DnsResponse
        {
            Rcode = DnsRcode.NoError,
            AuthenticatedData = AuthenticatedData,
            Answers = answers,
            Ttl = answers.Length == 0 ? 300 : answers.Min(a => a.Ttl),
        };
    }

    private static string Normalize(string name) => name.TrimEnd('.').ToLowerInvariant();
}
