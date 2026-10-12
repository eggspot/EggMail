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
}
