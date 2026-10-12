namespace Mta.Smtp.Server;

/// <summary>Global cap on message bytes being received concurrently; exhaustion produces 452 (decision: bounded memory).</summary>
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
