using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Mta.Core;
using Mta.Storage;

namespace Mta.Host.Security;

/// <summary>
/// Failed-login tracking shared by SMTP AUTH and the dashboard/API login so an attacker does not get a fresh budget per port
/// (design §7.1). Keys are IP addresses and user names; a key that reaches the limit within the window is locked out until the
/// window of its oldest counted failure expires. Memory is bounded: expired entries are dropped opportunistically.
/// <para><b>Replicas.</b> With a shared <see cref="IReplicaCoordination"/> (PostgreSQL) the failures are counted in the database, in buckets of a fifteenth of the window per hashed
/// key (a sliding window with that resolution: a failure counts until the end of its bucket plus the window), so the budget is for all replicas together and an attacker who
/// spreads attempts over replicas gets the same budget as one who does not (DESIGN-DECIDED, decision 79). The cost is one indexed read per login attempt and one small write per
/// failed attempt, next to a PBKDF2 verification of 600,000 iterations; nothing on the mail path. If the database cannot be reached the throttle falls back to this process's own
/// counts (a failed-login lockout must not take sign-in down with the database, and the credential lookup would fail anyway). Without a shared store (SQLite, one process) the
/// in-memory counts are exact. Use <see cref="CheckAsync"/>, <see cref="RecordFailureAsync"/> and <see cref="RecordSuccessAsync"/>; the synchronous methods see this process only.</para>
/// </summary>
public sealed class AuthThrottle
{
    private readonly IClock _clock;
    private readonly int _maxFailures;
    private readonly TimeSpan _window;
    private readonly int _maxKeys;
    private readonly ConcurrentDictionary<string, Queue<DateTimeOffset>> _failures = new(StringComparer.OrdinalIgnoreCase);
    private readonly IReplicaCoordination? _shared;
    private readonly IMtaLog _log;
    private readonly long _bucketSeconds;
    private long _lastFallbackWarning;

    public AuthThrottle(IClock? clock = null, int maxFailures = 10, TimeSpan? window = null, int maxKeys = 100_000, IReplicaCoordination? shared = null, IMtaLog? log = null)
    {
        _clock = clock ?? SystemClock.Instance;
        _maxFailures = maxFailures;
        _window = window ?? TimeSpan.FromMinutes(15);
        _maxKeys = maxKeys;
        _shared = shared;
        _log = log ?? NullMtaLog.Instance;
        _bucketSeconds = Math.Max(1, (long)_window.TotalSeconds / 15);
    }

    /// <summary>True when failures are counted in the database, for all replicas together.</summary>
    public bool IsShared => _shared is not null;

    /// <summary>
    /// How long the caller is locked out for if any of the keys is (after counting the failures of every replica), or null if none is. A shared store that cannot be
    /// reached is answered from this process's own counts.
    /// </summary>
    public async ValueTask<TimeSpan?> CheckAsync(CancellationToken cancellationToken, params string[] keys)
    {
        if (_shared is not null)
        {
            try
            {
                return await CheckSharedAsync(_shared, keys, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                WarnFallback(ex);
            }
        }

        return IsLockedOut(out TimeSpan retryAfter, keys) ? retryAfter : null;
    }

    /// <summary>Counts a failed login against every key, in this process and (if shared) for all replicas.</summary>
    public async ValueTask RecordFailureAsync(CancellationToken cancellationToken, params string[] keys)
    {
        RecordFailure(keys);
        if (_shared is not null)
        {
            try
            {
                long minBucket = MinBucket(_clock.UtcNow);
                await _shared.AddAuthFailuresAsync(Hash(keys), BucketOf(_clock.UtcNow), minBucket, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                WarnFallback(ex);
            }
        }
    }

    /// <summary>Forgets the failures of the keys (a successful login), in this process and (if shared) for all replicas.</summary>
    public async ValueTask RecordSuccessAsync(CancellationToken cancellationToken, params string[] keys)
    {
        RecordSuccess(keys);
        if (_shared is not null)
        {
            try
            {
                await _shared.ClearAuthFailuresAsync(Hash(keys), cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                WarnFallback(ex);
            }
        }
    }

    private async ValueTask<TimeSpan?> CheckSharedAsync(IReplicaCoordination shared, string[] keys, CancellationToken ct)
    {
        DateTimeOffset now = _clock.UtcNow;
        string[] hashes = Hash(keys);
        IReadOnlyList<AuthFailureCount> counts = await shared.GetAuthFailuresAsync(hashes, MinBucket(now), ct).ConfigureAwait(false);
        TimeSpan? retryAfter = null;
        foreach (var perKey in counts.GroupBy(c => c.KeyHash, StringComparer.Ordinal))
        {
            long total = perKey.Sum(c => c.Count);
            if (total < _maxFailures)
            {
                continue;
            }

            // Unlocked once enough of the oldest failures have aged out that fewer than the budget remain.
            long remaining = total;
            TimeSpan wait = TimeSpan.Zero;
            foreach (AuthFailureCount bucket in perKey.OrderBy(c => c.Bucket))
            {
                remaining -= bucket.Count;
                if (remaining < _maxFailures)
                {
                    wait = BucketEnd(bucket.Bucket) + _window - now;
                    break;
                }
            }

            if (wait < TimeSpan.FromSeconds(1))
            {
                wait = TimeSpan.FromSeconds(1);
            }

            if (retryAfter is null || wait > retryAfter)
            {
                retryAfter = wait;
            }
        }

        return retryAfter;
    }

    private long BucketOf(DateTimeOffset at) => at.ToUnixTimeSeconds() / _bucketSeconds;

    private long MinBucket(DateTimeOffset now) => Math.Max(0, (now - _window).ToUnixTimeSeconds() / _bucketSeconds);

    private DateTimeOffset BucketEnd(long bucket) => DateTimeOffset.FromUnixTimeSeconds((bucket + 1) * _bucketSeconds);

    /// <summary>The database holds a digest of each key, not the address or user name: fixed length whatever a client sends, and nothing personal in an ephemeral table.</summary>
    private static string[] Hash(string[] keys)
    {
        var hashes = new string[keys.Length];
        for (int i = 0; i < keys.Length; i++)
        {
            hashes[i] = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(keys[i].ToLowerInvariant())));
        }

        return hashes;
    }

    private void WarnFallback(Exception ex)
    {
        long now = Environment.TickCount64;
        long last = Interlocked.Read(ref _lastFallbackWarning);
        if ((last == 0 || now - last > 60_000) && Interlocked.CompareExchange(ref _lastFallbackWarning, now, last) == last)
        {
            _log.Write(MtaLogLevel.Warning, "auth", "the shared failed-login counts are unavailable; this process counts failures on its own until the database is back", ex);
        }
    }

    /// <summary>True if any of the keys is currently locked out by failures this process saw. If so, <paramref name="retryAfter"/> says for how long. See <see cref="CheckAsync"/> for the view of all replicas.</summary>
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
