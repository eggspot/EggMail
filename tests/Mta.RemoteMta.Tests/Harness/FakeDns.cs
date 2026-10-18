using System.Collections.Concurrent;
using System.Net;
using Mta.Dns;

namespace Mta.RemoteMta.Tests.Harness;

/// <summary>
/// The fake DNS zones of a lab: MX, A/AAAA, CNAME, TXT (MTA-STS, TLS-RPT), TLSA, with the AD bit settable per name (what a validating
/// resolver would say), answers that fail or hang, and a log of every query. Unlike <see cref="StaticDnsResolver"/> the AD bit is not one flag
/// for the whole resolver, so a test can have a secure MX set with an insecure TLSA set (or the other way round), which is how DANE is attacked.
/// </summary>
public sealed class FakeDns : IDnsResolver
{
    private const int MaxCnameDepth = 8;

    private readonly ConcurrentDictionary<string, List<DnsRecord>> _records = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<(string, DnsRecordType), Behaviour> _behaviours = new();
    private readonly ConcurrentDictionary<string, bool> _secure = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<(string Name, DnsRecordType Type)> _queries = new();

    private enum Behaviour { Servfail, Refused, Throw, Hang }

    /// <summary>Mark every answer as authenticated (AD bit), as a validating resolver would for a signed zone.</summary>
    public bool SecureEverything { get; set; }

    public IReadOnlyCollection<(string Name, DnsRecordType Type)> Queries => _queries.ToArray();

    public int QueryCount(string name, DnsRecordType type) => _queries.Count(q => q.Type == type && string.Equals(q.Name, Normalize(name), StringComparison.Ordinal));

    public FakeDns Add(DnsRecord record)
    {
        var list = _records.GetOrAdd(Normalize(record.Name), _ => []);
        lock (list)
        {
            list.Add(record);
        }

        return this;
    }

    public FakeDns Mx(string domain, ushort preference, string host) => Add(new MxRecord(Normalize(domain), 300, preference, Normalize(host)));

    /// <summary>RFC 7505: the domain explicitly accepts no mail.</summary>
    public FakeDns NullMx(string domain) => Add(new MxRecord(Normalize(domain), 300, 0, string.Empty));

    public FakeDns A(string host, string address) => Add(new ARecord(Normalize(host), 300, IPAddress.Parse(address)));

    public FakeDns Aaaa(string host, string address) => Add(new AaaaRecord(Normalize(host), 300, IPAddress.Parse(address)));

    public FakeDns Cname(string name, string target) => Add(new CnameRecord(Normalize(name), 300, Normalize(target)));

    public FakeDns Txt(string name, string text) => Add(new TxtRecord(Normalize(name), 300, text));

    /// <summary><c>_mta-sts.domain TXT "v=STSv1; id=..."</c>.</summary>
    public FakeDns MtaStsId(string domain, string id) => Txt("_mta-sts." + domain, "v=STSv1; id=" + id);

    /// <summary><c>_smtp._tls.domain TXT "v=TLSRPTv1; rua=..."</c>.</summary>
    public FakeDns TlsRptAddress(string domain, string rua) => Txt("_smtp._tls." + domain, "v=TLSRPTv1; rua=" + rua);

    public FakeDns Tlsa(string host, int port, byte usage, byte selector, byte matchingType, byte[] data) =>
        Add(new TlsaRecord(DnsName.TlsaName(Normalize(host), port), 300, usage, selector, matchingType, data));

    /// <summary>The names whose answers carry the AD bit.</summary>
    public FakeDns Secure(params string[] names)
    {
        foreach (string n in names)
        {
            _secure[Normalize(n)] = true;
        }

        return this;
    }

    /// <summary>Removes the AD bit again (the signature of the zone "expired").</summary>
    public FakeDns Insecure(params string[] names)
    {
        foreach (string n in names)
        {
            _secure.TryRemove(Normalize(n), out _);
        }

        return this;
    }

    public FakeDns RemoveAll(string name)
    {
        _records.TryRemove(Normalize(name), out _);
        return this;
    }

    public FakeDns Remove(string name, DnsRecordType type)
    {
        if (_records.TryGetValue(Normalize(name), out var list))
        {
            lock (list)
            {
                list.RemoveAll(r => r.Type == type);
            }
        }

        return this;
    }

    /// <summary>SERVFAIL for (name, type): what a validating resolver answers when DNSSEC validation fails.</summary>
    public FakeDns Servfail(string name, DnsRecordType type)
    {
        _behaviours[(Normalize(name), type)] = Behaviour.Servfail;
        return this;
    }

    /// <summary>The resolver cannot be reached (a transport failure, <see cref="DnsException"/>).</summary>
    public FakeDns Unreachable(string name, DnsRecordType type)
    {
        _behaviours[(Normalize(name), type)] = Behaviour.Throw;
        return this;
    }

    public FakeDns Heal(string name, DnsRecordType type)
    {
        _behaviours.TryRemove((Normalize(name), type), out _);
        return this;
    }

    public async ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default)
    {
        string n = Normalize(name);
        _queries.Enqueue((n, type));
        if (_behaviours.TryGetValue((n, type), out var behaviour))
        {
            switch (behaviour)
            {
                case Behaviour.Servfail:
                    return new DnsResponse { Rcode = DnsRcode.ServerFailure };
                case Behaviour.Refused:
                    return new DnsResponse { Rcode = DnsRcode.Refused };
                case Behaviour.Throw:
                    throw new DnsException("simulated resolver failure for " + n, DnsFailureReason.Timeout);
                case Behaviour.Hang:
                    await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
                    break;
            }
        }

        return Resolve(n, type, 0, SecureEverything || _secure.ContainsKey(n));
    }

    private DnsResponse Resolve(string n, DnsRecordType type, int depth, bool secure)
    {
        if (!_records.TryGetValue(n, out var list))
        {
            return new DnsResponse { Rcode = DnsRcode.NameError, Ttl = 300 };
        }

        DnsRecord[] answers;
        lock (list)
        {
            answers = list.Where(r => r.Type == type).ToArray();
            if (answers.Length == 0 && type != DnsRecordType.CNAME && list.OfType<CnameRecord>().FirstOrDefault() is { } cname)
            {
                if (depth >= MaxCnameDepth)
                {
                    return new DnsResponse { Rcode = DnsRcode.ServerFailure };
                }

                var chased = Resolve(Normalize(cname.Target), type, depth + 1, secure);
                return new DnsResponse { Rcode = chased.Rcode, AuthenticatedData = secure && chased.AuthenticatedData, Answers = [cname, .. chased.Answers], Ttl = Math.Min(cname.Ttl, chased.Ttl) };
            }
        }

        return new DnsResponse { Rcode = DnsRcode.NoError, AuthenticatedData = secure, Answers = answers, Ttl = answers.Length == 0 ? 300 : answers.Min(a => a.Ttl) };
    }

    private static string Normalize(string name) => name.TrimEnd('.').ToLowerInvariant();
}
