using System.Collections.Concurrent;
using Mta.Core;

namespace Mta.Delivery;

/// <summary>
/// The signed bounce (VERP) envelope sender of a delivery, kept per signing key, tenant, sending domain, return-path host, destination domain and hour: the token only changes with those, so
/// signing it and parsing the address once serves every delivery of that hour instead of one HMAC, one base32 string and one parse per delivery. Bounded:
/// when the table is full it is cleared (old hours and gone tenants), never grown.
/// </summary>
internal sealed class BounceAddressCache(int maxEntries = 4096)
{
    private readonly ConcurrentDictionary<(int KeyId, Guid TenantId, Guid DomainId, string Host, string Destination, long Hour), EmailAddress> _table = new();

    public int Count => _table.Count;

    /// <summary>
    /// The cached address, or the one <paramref name="create"/> makes (which is then kept). <paramref name="create"/> returns null when the address cannot be built
    /// (nothing is kept and null is returned, the caller falls back); it runs on a miss only, and a concurrent miss may run it more than once with the same result.
    /// </summary>
    public EmailAddress? GetOrCreate<TState>(int keyId, Guid tenantId, Guid domainId, string host, string destination, long hour, TState state, Func<TState, EmailAddress?> create)
    {
        var key = (keyId, tenantId, domainId, host, destination, hour);
        if (_table.TryGetValue(key, out EmailAddress cached))
        {
            return cached;
        }

        EmailAddress? made = create(state);
        if (made is not { } address)
        {
            return null;
        }

        if (_table.Count >= maxEntries)
        {
            _table.Clear();
        }

        _table[key] = address;
        return address;
    }
}
