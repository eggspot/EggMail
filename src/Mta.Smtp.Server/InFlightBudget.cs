using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace Mta.Smtp.Server;

/// <summary>Cap on message bytes being received concurrently; exhaustion produces 452 (decision: bounded memory).</summary>
public sealed class InFlightBudget
{
    private readonly long _limit;
    private long _used;

    public InFlightBudget(long limit) => _limit = limit;

    public long Used => Interlocked.Read(ref _used);

    public bool TryReserve(long bytes)
    {
        long now = Interlocked.Add(ref _used, bytes);
        if (now <= _limit)
        {
            return true;
        }

        Interlocked.Add(ref _used, -bytes);
        return false;
    }

    public void Release(long bytes) => Interlocked.Add(ref _used, -bytes);
}

/// <summary>A cap on in-flight bytes per client network (an IPv4 address or an IPv6 /64), so one sender cannot take the whole budget of a listener. Entries exist only while bytes are reserved.</summary>
internal sealed class KeyedInFlightBudget
{
    private readonly long _limitPerKey;
    private readonly ConcurrentDictionary<string, long> _used = new();

    public KeyedInFlightBudget(long limitPerKey) => _limitPerKey = limitPerKey;

    public bool TryReserve(string key, long bytes)
    {
        while (true)
        {
            if (!_used.TryGetValue(key, out long current))
            {
                if (bytes > _limitPerKey)
                {
                    return false;
                }

                if (_used.TryAdd(key, bytes))
                {
                    return true;
                }

                continue;
            }

            if (current + bytes > _limitPerKey)
            {
                return false;
            }

            if (_used.TryUpdate(key, current + bytes, current))
            {
                return true;
            }
        }
    }

    public void Release(string key, long bytes)
    {
        while (_used.TryGetValue(key, out long current))
        {
            if (current <= bytes)
            {
                if (_used.TryRemove(new KeyValuePair<string, long>(key, current)))
                {
                    return;
                }
            }
            else if (_used.TryUpdate(key, current - bytes, current))
            {
                return;
            }
        }
    }

    /// <summary>The key of a client: its IPv4 address (an IPv4-mapped IPv6 address included) or the /64 of its IPv6 address.</summary>
    public static string KeyOf(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return address.ToString();
        }

        Span<byte> bytes = stackalloc byte[16];
        address.TryWriteBytes(bytes, out _);
        return "6:" + Convert.ToHexString(bytes[..8]);
    }
}

/// <summary>What one session reserves its message memory from: the listener's own budget (when it has one), the client network's share of it (when set) and the server-wide budget. All of them or none.</summary>
internal sealed class SessionBudget(InFlightBudget global, InFlightBudget? listener, KeyedInFlightBudget? perRemote, string remoteKey)
{
    public bool TryReserve(long bytes)
    {
        if (listener is not null && !listener.TryReserve(bytes))
        {
            return false;
        }

        if (perRemote is not null && !perRemote.TryReserve(remoteKey, bytes))
        {
            listener?.Release(bytes);
            return false;
        }

        if (!global.TryReserve(bytes))
        {
            perRemote?.Release(remoteKey, bytes);
            listener?.Release(bytes);
            return false;
        }

        return true;
    }

    public void Release(long bytes)
    {
        if (bytes == 0)
        {
            return;
        }

        global.Release(bytes);
        perRemote?.Release(remoteKey, bytes);
        listener?.Release(bytes);
    }
}
