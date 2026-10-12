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

    public bool AuthenticatedData { get; set; }

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

    /// <summary>Makes queries for (name, type) return the given rcode (for example SERVFAIL).</summary>
    public StaticDnsResolver Fail(string name, DnsRecordType type, DnsRcode rcode = DnsRcode.ServerFailure)
    {
        _failures[(Normalize(name), type)] = rcode;
        return this;
    }

    public ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default)
    {
        string n = Normalize(name);
        if (_failures.TryGetValue((n, type), out var rcode))
        {
            return ValueTask.FromResult(new DnsResponse { Rcode = rcode });
        }

        if (!_records.TryGetValue(n, out var list))
        {
            return ValueTask.FromResult(new DnsResponse { Rcode = DnsRcode.NameError, Ttl = 300 });
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
                    var chased = QueryAsync(cname.Target, type, cancellationToken).AsTask().GetAwaiter().GetResult();
                    return ValueTask.FromResult(new DnsResponse
                    {
                        Rcode = chased.Rcode,
                        AuthenticatedData = AuthenticatedData,
                        Answers = [cname, .. chased.Answers],
                        Ttl = Math.Min(cname.Ttl, chased.Ttl),
                    });
                }
            }
        }

        return ValueTask.FromResult(new DnsResponse
        {
            Rcode = DnsRcode.NoError,
            AuthenticatedData = AuthenticatedData,
            Answers = answers,
            Ttl = answers.Length == 0 ? 300 : answers.Min(a => a.Ttl),
        });
    }

    private static string Normalize(string name) => name.TrimEnd('.').ToLowerInvariant();
}
