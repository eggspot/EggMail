namespace Mta.Host.Ingest;

internal sealed class LookupBudget
{
    public const int PerClientPerSecond = 10;
    public const int PerProcessPerSecond = 200;
    public const int MaxTrackedClients = 4096;

    private readonly object _gate = new();
    private readonly Dictionary<string, (long Second, int Count)> _clients = new(StringComparer.Ordinal);
    private readonly Func<long> _seconds;
    private long _window = long.MinValue;
    private int _inWindow;

    public LookupBudget(Func<long>? seconds = null) => _seconds = seconds ?? (static () => Environment.TickCount64 / 1000);

    public int TrackedClients
    {
        get
        {
            lock (_gate)
            {
                return _clients.Count;
            }
        }
    }

    public bool TryTake(string clientKey)
    {
        long second = _seconds();
        lock (_gate)
        {
            if (_clients.Count >= MaxTrackedClients && !_clients.ContainsKey(clientKey))
            {
                DropClientsOfEarlierSeconds(second);
                if (_clients.Count >= MaxTrackedClients)
                {
                    return false;
                }
            }

            if (!TryTakeFromClientBudget(clientKey, second))
            {
                return false;
            }

            if (_window != second)
            {
                _window = second;
                _inWindow = 0;
            }

            return ++_inWindow <= PerProcessPerSecond;
        }
    }

    private void DropClientsOfEarlierSeconds(long second)
    {
        foreach (string key in _clients.Where(e => e.Value.Second < second).Select(e => e.Key).ToList())
        {
            _clients.Remove(key);
        }
    }

    private bool TryTakeFromClientBudget(string clientKey, long second)
    {
        int count = _clients.TryGetValue(clientKey, out var entry) && entry.Second == second ? entry.Count + 1 : 1;
        _clients[clientKey] = (second, count);
        return count <= PerClientPerSecond;
    }
}
