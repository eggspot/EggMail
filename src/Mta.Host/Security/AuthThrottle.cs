using System.Collections.Concurrent;
using Mta.Core;

namespace Mta.Host.Security;

/// <summary>
/// Failed-login tracking shared by SMTP AUTH and the dashboard/API login so an attacker does not get a fresh budget per port
/// (design §7.1). Keys are IP addresses and user names; a key that reaches the limit within the window is locked out until the
/// window of its oldest counted failure expires. Memory is bounded: expired entries are dropped opportunistically.
/// </summary>
public sealed class AuthThrottle
{
    private readonly IClock _clock;
    private readonly int _maxFailures;
    private readonly TimeSpan _window;
    private readonly int _maxKeys;
    private readonly ConcurrentDictionary<string, Queue<DateTimeOffset>> _failures = new(StringComparer.OrdinalIgnoreCase);

    public AuthThrottle(IClock? clock = null, int maxFailures = 10, TimeSpan? window = null, int maxKeys = 100_000)
    {
        _clock = clock ?? SystemClock.Instance;
        _maxFailures = maxFailures;
        _window = window ?? TimeSpan.FromMinutes(15);
        _maxKeys = maxKeys;
    }

    /// <summary>True if any of the keys is currently locked out. If so, <paramref name="retryAfter"/> says for how long.</summary>
    public bool IsLockedOut(out TimeSpan retryAfter, params string[] keys)
    {
        var now = _clock.UtcNow;
        retryAfter = TimeSpan.Zero;
        bool locked = false;
        foreach (string key in keys)
        {
            if (!_failures.TryGetValue(key, out var q))
            {
                continue;
            }

            lock (q)
            {
                Trim(q, now);
                if (q.Count >= _maxFailures)
                {
                    locked = true;
                    var until = q.Peek() + _window;
                    if (until - now > retryAfter)
                    {
                        retryAfter = until - now;
                    }
                }
            }
        }

        return locked;
    }

    public void RecordFailure(params string[] keys)
    {
        var now = _clock.UtcNow;
        if (_failures.Count > _maxKeys)
        {
            Sweep(now);
        }

        foreach (string key in keys)
        {
            var q = _failures.GetOrAdd(key, _ => new Queue<DateTimeOffset>());
            lock (q)
            {
                Trim(q, now);
                q.Enqueue(now);
            }
        }
    }

    public void RecordSuccess(params string[] keys)
    {
        foreach (string key in keys)
        {
            _failures.TryRemove(key, out _);
        }
    }

    private void Trim(Queue<DateTimeOffset> q, DateTimeOffset now)
    {
        while (q.Count > 0 && now - q.Peek() > _window)
        {
            q.Dequeue();
        }
    }

    private void Sweep(DateTimeOffset now)
    {
        foreach (var (key, q) in _failures)
        {
            lock (q)
            {
                Trim(q, now);
                if (q.Count == 0)
                {
                    _failures.TryRemove(key, out _);
                }
            }
        }
    }
}
