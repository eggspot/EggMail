using System.Collections.Concurrent;
using System.Net;

namespace Mta.Smtp.Server;

/// <summary>Global and per-address connection caps shared by all listeners (limits are keyed globally, not per port).</summary>
public sealed class ConnectionLimiter
{
    private readonly int _maxTotal;
    private readonly int _maxPerIp;
    private readonly ConcurrentDictionary<IPAddress, int> _perIp = new();
    private int _total;

    public ConnectionLimiter(int maxTotal, int maxPerIp)
    {
        _maxTotal = maxTotal;
        _maxPerIp = maxPerIp;
    }

    public int Total => Volatile.Read(ref _total);

    /// <summary>Registers a connection. Returns false (and registers nothing) if a cap would be exceeded.</summary>
    public bool TryAcquire(IPAddress address)
    {
        address = Normalize(address);
        if (Interlocked.Increment(ref _total) > _maxTotal)
        {
            Interlocked.Decrement(ref _total);
            return false;
        }

        int count = _perIp.AddOrUpdate(address, 1, static (_, c) => c + 1);
        if (count > _maxPerIp)
        {
            Release(address);
            return false;
        }

        return true;
    }

    public void Release(IPAddress address)
    {
        address = Normalize(address);
        Interlocked.Decrement(ref _total);
        while (true)
        {
            if (!_perIp.TryGetValue(address, out int c))
            {
                return;
            }

            if (c <= 1)
            {
                if (_perIp.TryRemove(new KeyValuePair<IPAddress, int>(address, c)))
                {
                    return;
                }
            }
            else if (_perIp.TryUpdate(address, c - 1, c))
            {
                return;
            }
        }
    }

    private static IPAddress Normalize(IPAddress a) => a.IsIPv4MappedToIPv6 ? a.MapToIPv4() : a;
}
