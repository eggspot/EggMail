using System.Net;
using System.Net.Sockets;

namespace Mta.Host.Ingest;

/// <summary>
/// Messages-per-minute counters of the receive path (design sections 11.4 and 11.9): fixed one-minute windows in memory, per process. Every kind of counter lives in its own
/// bounded dictionary with its own eviction, so a flood from many addresses can only make the per-remote limiter forget remote addresses: it can never push a domain's counter out
/// and so never resets a domain's limit. At the maximum, expired windows go first and then the oldest.
/// </summary>
public sealed class BoundedWindowCounter
{
    private readonly object _gate = new();
    private readonly Dictionary<string, (long Window, int Count)> _entries;
    private Queue<string> _order = new();   // keys in the order they first appeared: what "oldest" means when every window is current
    private readonly int _maxEntries;
    private readonly string _kind;

    /// <param name="kind">The label of the eviction metric (<c>domain</c> or <c>remote</c>).</param>
    /// <param name="maxEntries">The most entries held (100,000 in the receive path).</param>
    public BoundedWindowCounter(string kind, int maxEntries)
    {
        if (maxEntries < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maxEntries));
        }

        _kind = kind;
        _maxEntries = maxEntries;
        _entries = new Dictionary<string, (long, int)>(Math.Min(maxEntries, 1024), StringComparer.Ordinal);
    }

    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _entries.Count;
            }
        }
    }

    /// <summary>Messages already counted for <paramref name="key"/> in the current minute.</summary>
    public int Peek(string key, DateTimeOffset now)
    {
        long window = Window(now);
        lock (_gate)
        {
            return _entries.TryGetValue(key, out var entry) && entry.Window == window ? entry.Count : 0;
        }
    }

    /// <summary>Counts one message for <paramref name="key"/>; returns the count in the current minute including this one.</summary>
    public int Add(string key, DateTimeOffset now)
    {
        long window = Window(now);
        lock (_gate)
        {
            if (_entries.TryGetValue(key, out var entry) && entry.Window == window)
            {
                _entries[key] = (window, entry.Count + 1);
                return entry.Count + 1;
            }

            if (_entries.Count >= _maxEntries && !_entries.ContainsKey(key))
            {
                Evict(window);
            }

            _entries[key] = (window, 1);
            _order.Enqueue(key);
            if (_order.Count > 2 * _maxEntries)
            {
                _order = new Queue<string>(_entries.Keys);   // keys swept out as expired leave stale places in the queue; start it again from what is in the table
            }

            return 1;
        }
    }

    private void Evict(long window)
    {
        // Expired windows first.
        List<string>? expired = null;
        foreach (var (key, entry) in _entries)
        {
            if (entry.Window < window)
            {
                (expired ??= []).Add(key);
            }
        }

        if (expired is not null)
        {
            foreach (string key in expired)
            {
                _entries.Remove(key);
            }

            InboundMetrics.LimiterEvictions.Add(expired.Count, new KeyValuePair<string, object?>("limiter", _kind));
            return;
        }

        // Everything is current: drop the oldest sixteenth of the table, oldest first by when the key first appeared (a batch keeps this scan rare).
        int drop = Math.Max(1, _maxEntries / 16);
        int dropped = 0;
        while (dropped < drop && _order.Count > 0)
        {
            if (_entries.Remove(_order.Dequeue()))
            {
                dropped++;
            }
        }

        InboundMetrics.LimiterEvictions.Add(dropped, new KeyValuePair<string, object?>("limiter", _kind));
    }

    private static long Window(DateTimeOffset now) => now.ToUnixTimeSeconds() / 60;
}

/// <summary>The rate limits of the receive path: per domain, and per remote address for a domain (an IPv6 client by its /64).</summary>
public sealed class InboundRateLimiter
{
    public const int MaxEntries = 100_000;

    private readonly BoundedWindowCounter _domains;
    private readonly BoundedWindowCounter _remotes;

    public InboundRateLimiter(int maxEntries = MaxEntries)
    {
        _domains = new BoundedWindowCounter("domain", maxEntries);
        _remotes = new BoundedWindowCounter("remote", maxEntries);
    }

    public int DomainEntries => _domains.Count;

    public int RemoteEntries => _remotes.Count;

    /// <summary>Whether one more message for the domain from this client would stay within both limits (nothing is counted).</summary>
    public bool Allows(Guid domainId, IPAddress client, int perMinuteForDomain, int perMinuteForRemote, DateTimeOffset now) =>
        _domains.Peek(DomainKey(domainId), now) < perMinuteForDomain && _remotes.Peek(RemoteKey(domainId, client), now) < perMinuteForRemote;

    /// <summary>Counts one accepted recipient against both limits.</summary>
    public void Count(Guid domainId, IPAddress client, DateTimeOffset now)
    {
        _domains.Add(DomainKey(domainId), now);
        _remotes.Add(RemoteKey(domainId, client), now);
    }

    private static string DomainKey(Guid domainId) => domainId.ToString("N");

    private static string RemoteKey(Guid domainId, IPAddress client) => domainId.ToString("N") + "|" + NetworkKey.Remote(client);
}

/// <summary>How the receive path groups client addresses: the same address, with an IPv4-mapped IPv6 address normalized, and an IPv6 address by its /64 (a host with a /64 has 2^64 addresses to rotate through).</summary>
public static class NetworkKey
{
    /// <summary>The address as the rest of the system sees it: <c>::ffff:a.b.c.d</c> becomes <c>a.b.c.d</c>.</summary>
    public static IPAddress Normalize(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    /// <summary>Key of the per-remote limiter: the IPv4 address, or the /64 of an IPv6 address.</summary>
    public static string Remote(IPAddress address)
    {
        address = Normalize(address);
        if (address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return address.ToString();
        }

        Span<byte> bytes = stackalloc byte[16];
        address.TryWriteBytes(bytes, out _);
        return "6:" + Convert.ToHexString(bytes[..8]);
    }

    /// <summary>Key of the verification slots: the IPv4 /24 or the IPv6 /64.</summary>
    public static string Slot(IPAddress address)
    {
        address = Normalize(address);
        Span<byte> bytes = stackalloc byte[16];
        address.TryWriteBytes(bytes, out int written);
        return address.AddressFamily == AddressFamily.InterNetworkV6 ? "6:" + Convert.ToHexString(bytes[..8]) : "4:" + Convert.ToHexString(bytes[..3]);
    }

    /// <summary>Whether the address is one a public sender cannot have: loopback, private (RFC 1918, unique local), link-local or carrier-grade NAT. Behind source NAT every sender looks like one of these.</summary>
    public static bool IsInternal(IPAddress address)
    {
        address = Normalize(address);
        if (IPAddress.IsLoopback(address))
        {
            return true;
        }

        Span<byte> b = stackalloc byte[16];
        address.TryWriteBytes(b, out _);
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return b[0] == 10 || (b[0] == 172 && (b[1] & 0xF0) == 16) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) || (b[0] == 100 && (b[1] & 0xC0) == 64) || b[0] == 0;
        }

        return address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || (b[0] & 0xFE) == 0xFC;
    }
}
