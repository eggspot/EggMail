using System.Net;
using System.Net.Sockets;

namespace Mta.Host.Ingest;

public sealed class BoundedWindowCounter
{
    private readonly object _gate = new();
    private readonly Dictionary<string, (long Window, int Count)> _entries;
    private Queue<string> _keysInArrivalOrder = new();
    private readonly int _maxEntries;
    private readonly string _kind;

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

    public int Peek(string key, DateTimeOffset now)
    {
        long window = Window(now);
        lock (_gate)
        {
            return _entries.TryGetValue(key, out var entry) && entry.Window == window ? entry.Count : 0;
        }
    }

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
            _keysInArrivalOrder.Enqueue(key);
            if (_keysInArrivalOrder.Count > 2 * _maxEntries)
            {
                DropStalePlacesFromArrivalOrder();
            }

            return 1;
        }
    }

    private void DropStalePlacesFromArrivalOrder() => _keysInArrivalOrder = new Queue<string>(_entries.Keys);

    private void Evict(long window)
    {
        if (!TryEvictExpiredWindows(window))
        {
            EvictOldestSixteenth();
        }
    }

    private bool TryEvictExpiredWindows(long window)
    {
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
            return true;
        }

        return false;
    }

    private void EvictOldestSixteenth()
    {
        int drop = Math.Max(1, _maxEntries / 16);
        int dropped = 0;
        while (dropped < drop && _keysInArrivalOrder.Count > 0)
        {
            if (_entries.Remove(_keysInArrivalOrder.Dequeue()))
            {
                dropped++;
            }
        }

        InboundMetrics.LimiterEvictions.Add(dropped, new KeyValuePair<string, object?>("limiter", _kind));
    }

    private static long Window(DateTimeOffset now) => now.ToUnixTimeSeconds() / 60;
}

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

    public bool Allows(Guid domainId, IPAddress client, int perMinuteForDomain, int perMinuteForRemote, DateTimeOffset now) =>
        _domains.Peek(DomainKey(domainId), now) < perMinuteForDomain && _remotes.Peek(RemoteKey(domainId, client), now) < perMinuteForRemote;

    public void Count(Guid domainId, IPAddress client, DateTimeOffset now)
    {
        _domains.Add(DomainKey(domainId), now);
        _remotes.Add(RemoteKey(domainId, client), now);
    }

    private readonly object _gate = new();

    public bool TryCount(Guid domainId, IPAddress client, int perMinuteForDomain, int perMinuteForRemote, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (!Allows(domainId, client, perMinuteForDomain, perMinuteForRemote, now))
            {
                return false;
            }

            Count(domainId, client, now);
            return true;
        }
    }

    private static string DomainKey(Guid domainId) => domainId.ToString("N");

    private static string RemoteKey(Guid domainId, IPAddress client) => domainId.ToString("N") + "|" + NetworkKey.Remote(client);
}

public static class NetworkKey
{
    public static IPAddress Normalize(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

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

    public static string Slot(IPAddress address)
    {
        address = Normalize(address);
        Span<byte> bytes = stackalloc byte[16];
        address.TryWriteBytes(bytes, out int written);
        return address.AddressFamily == AddressFamily.InterNetworkV6 ? "6:" + Convert.ToHexString(bytes[..8]) : "4:" + Convert.ToHexString(bytes[..3]);
    }

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
