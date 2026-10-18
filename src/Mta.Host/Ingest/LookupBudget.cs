namespace Mta.Host.Ingest;

/// <summary>
/// The budget of uncached storage lookups the bounce listener allows (names of the form <c>bounce.&lt;anything&gt;</c> each cost one lookup the first time they are asked about): a few a second for each
/// client, with a backstop for the whole process. Only a caller with a valid signed token can cause a lookup at all. Both limits are counted per second of a clock that is read through a function, so a test
/// moves it by hand.
/// <para>
/// The table of clients is bounded (4,096): when it is full of clients seen in the current second a new client is refused until the next second (the entries of earlier seconds are dropped first). Everything is
/// done under one lock: the count of the process and the table are updated together, so the process-wide limit is exact however many threads ask at the turn of a second.
/// </para>
/// </summary>
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

    /// <summary>Clients currently tracked (for tests).</summary>
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

    /// <summary>Takes one lookup for <paramref name="clientKey"/>; false when the client, the table or the process is over its limit for this second.</summary>
    public bool TryTake(string clientKey)
    {
        long second = _seconds();
        lock (_gate)
        {
            if (_clients.Count >= MaxTrackedClients && !_clients.ContainsKey(clientKey))
            {
                // Full: the entries of earlier seconds go first; a client that is still new after that is refused for the rest of this second.
                foreach (string key in _clients.Where(e => e.Value.Second < second).Select(e => e.Key).ToList())
                {
                    _clients.Remove(key);
                }

                if (_clients.Count >= MaxTrackedClients)
                {
                    return false;
                }
            }

            // The client's own budget first: a client past it is refused without touching the process-wide count, so one client cannot use up what the others need.
            int count = _clients.TryGetValue(clientKey, out var entry) && entry.Second == second ? entry.Count + 1 : 1;
            _clients[clientKey] = (second, count);
            if (count > PerClientPerSecond)
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
}
