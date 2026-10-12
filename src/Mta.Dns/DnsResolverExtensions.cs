using System.Net;

namespace Mta.Dns;

public static class DnsResolverExtensions
{
    public static async ValueTask<IReadOnlyList<TxtRecord>> GetTxtAsync(this IDnsResolver resolver, string name, CancellationToken ct = default)
    {
        var r = await resolver.QueryAsync(name, DnsRecordType.TXT, ct).ConfigureAwait(false);
        return r.Get<TxtRecord>().ToList();
    }

    public static async ValueTask<IReadOnlyList<MxRecord>> GetMxAsync(this IDnsResolver resolver, string name, CancellationToken ct = default)
    {
        var r = await resolver.QueryAsync(name, DnsRecordType.MX, ct).ConfigureAwait(false);
        return r.Get<MxRecord>().OrderBy(m => m.Preference).ToList();
    }

    /// <summary>The TXT records of <paramref name="name"/> as strings (character-strings already concatenated). NXDOMAIN, NODATA and failures all give an empty list; use <see cref="IDnsResolver.QueryAsync"/> when they must be told apart.</summary>
    public static async ValueTask<IReadOnlyList<string>> GetTxtTextsAsync(this IDnsResolver resolver, string name, CancellationToken ct = default)
    {
        var r = await resolver.QueryAsync(name, DnsRecordType.TXT, ct).ConfigureAwait(false);
        return r.Get<TxtRecord>().Select(t => t.Text).ToList();
    }

    /// <summary>The A and AAAA addresses of <paramref name="name"/> (queried concurrently; IPv4 first). Failures give an empty list.</summary>
    public static async ValueTask<IReadOnlyList<IPAddress>> GetAddressesAsync(this IDnsResolver resolver, string name, CancellationToken ct = default)
    {
        var a = resolver.QueryAsync(name, DnsRecordType.A, ct).AsTask();
        var aaaa = resolver.QueryAsync(name, DnsRecordType.AAAA, ct).AsTask();
        await Task.WhenAll(a, aaaa).ConfigureAwait(false);
        return [.. a.Result.Get<ARecord>().Select(x => x.Address), .. aaaa.Result.Get<AaaaRecord>().Select(x => x.Address)];
    }

    /// <summary>The PTR targets for <paramref name="address"/> (queries the in-addr.arpa / ip6.arpa name).</summary>
    public static async ValueTask<IReadOnlyList<string>> GetPtrNamesAsync(this IDnsResolver resolver, IPAddress address, CancellationToken ct = default)
    {
        var r = await resolver.QueryAsync(DnsName.ReverseArpaName(address), DnsRecordType.PTR, ct).ConfigureAwait(false);
        return r.Get<PtrRecord>().Select(p => p.Target).ToList();
    }

    /// <summary>The DANE TLSA records for <paramref name="host"/> and <paramref name="port"/> (queries <c>_port._tcp.host</c>). Check <see cref="DnsResponse.AuthenticatedData"/> via <see cref="IDnsResolver.QueryAsync"/> before trusting them.</summary>
    public static async ValueTask<IReadOnlyList<TlsaRecord>> GetTlsaAsync(this IDnsResolver resolver, string host, int port = 25, CancellationToken ct = default)
    {
        var r = await resolver.QueryAsync(DnsName.TlsaName(host, port), DnsRecordType.TLSA, ct).ConfigureAwait(false);
        return r.Get<TlsaRecord>().ToList();
    }
}
