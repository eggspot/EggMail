using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Mta.Core;
using Mta.Storage;

namespace Mta.Host.Security;

/// <summary>
/// What <see cref="AuthThrottle.CheckAsync"/> found: how long the caller is locked out for (null: not locked out), and which of the checked keys have failures on record, so that a
/// later successful login clears only those.
/// </summary>
public readonly record struct AuthLockoutCheck(TimeSpan? RetryAfter, IReadOnlyList<string> DigestsWithFailures)
{
    /// <summary>Nothing locked, nothing on record.</summary>
    public static AuthLockoutCheck Clear => new(null, []);

    /// <summary>True if any checked key is locked out.</summary>
    public bool IsLockedOut => RetryAfter is not null;
}

/// <summary>
/// Failed-login tracking shared by SMTP AUTH and the dashboard/API login so an attacker does not get a fresh budget per port
/// (design §7.1). Keys are IP addresses and user names; a key that reaches the limit within the window is locked out until the
/// window of its oldest counted failure expires. Memory is bounded: expired entries are dropped opportunistically.
/// <para><b>Replicas.</b> With a shared <see cref="IReplicaCoordination"/> (PostgreSQL) the failures are counted in the database, in buckets of a fifteenth of the window per key
/// (a sliding window with that resolution: a failure counts until the end of its bucket plus the window), so the budget is for all replicas together and an attacker who
/// spreads attempts over replicas gets the same budget as one who does not (DESIGN-DECIDED, decision 82). The cost per login attempt is one indexed read; per failed attempt one small
/// write; a successful login adds one delete only if the read found failures on record for the keys it clears, so ordinary logins cost no more than the read. All next to a PBKDF2
/// verification of 600,000 iterations; nothing on the mail path. The keys are stored as HMAC-SHA256 digests under a key that is itself protected by Data Protection, so a copy of the
/// table alone does not say which addresses or user names failed. Writes are not cancelled with the request that caused them (a client that hangs up must not buy a free guess)
/// but are bounded to two seconds; if the database cannot be reached the throttle falls back to this process's own counts (a failed-login lockout must not take sign-in down with
/// the database, and the credential lookup would fail anyway). Without a shared store (SQLite, one process) the in-memory counts are exact. Use <see cref="CheckAsync"/>,
/// <see cref="RecordFailureAsync"/> and <see cref="RecordSuccessAsync"/>; the synchronous methods see this process only.</para>
/// </summary>
public sealed class AuthThrottle
{
    private static readonly TimeSpan SharedCallTimeout = TimeSpan.FromSeconds(2);

    private readonly IClock _clock;
    private readonly int _maxFailures;
    private readonly TimeSpan _window;
    private readonly int _maxKeys;
    private readonly ConcurrentDictionary<string, Queue<DateTimeOffset>> _failures = new(StringComparer.OrdinalIgnoreCase);
    private readonly IReplicaCoordination? _shared;
    private readonly byte[]? _digestKey;
    private readonly IMtaLog _log;
    private readonly long _bucketSeconds;
    private long _lastFallbackWarning;

    /// <param name="shared">Where all replicas count failures together, or null (one process).</param>
    /// <param name="digestKey">The secret the keys are digested with before they reach <paramref name="shared"/>; required with it, the same on every replica.</param>
    public AuthThrottle(IClock? clock = null, int maxFailures = 10, TimeSpan? window = null, int maxKeys = 100_000, IReplicaCoordination? shared = null, byte[]? digestKey = null, IMtaLog? log = null)
    {
        if (shared is not null && (digestKey is null || digestKey.Length < 16))
        {
            throw new ArgumentException("A shared failed-login store needs a digest key of at least 16 bytes.", nameof(digestKey));
        }

        _clock = clock ?? SystemClock.Instance;
        _maxFailures = maxFailures;
        _window = window ?? TimeSpan.FromMinutes(15);
        _maxKeys = maxKeys;
        _shared = shared;
        _digestKey = digestKey;
        _log = log ?? NullMtaLog.Instance;
        _bucketSeconds = Math.Max(1, (long)_window.TotalSeconds / 15);
    }

    /// <summary>True when failures are counted in the database, for all replicas together.</summary>
    public bool IsShared => _shared is not null;

    /// <summary>
    /// Whether any of the keys is locked out, and for how long, after counting the failures of every replica. A shared store that cannot be reached (or does not answer within
    /// two seconds) is answered from this process's own counts.
    /// </summary>
    public async ValueTask<AuthLockoutCheck> CheckAsync(CancellationToken cancellationToken, params string[] keys)
    {
        if (_shared is not null)
        {
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(SharedCallTimeout);
                return await CheckSharedAsync(_shared, keys, timeout.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
            {
                WarnFallback(ex);
            }
        }

        return IsLockedOut(out TimeSpan retryAfter, keys) ? new AuthLockoutCheck(retryAfter, []) : AuthLockoutCheck.Clear;
    }

    /// <summary>Counts a failed login against every key, in this process and (if shared) for all replicas.</summary>
    public async ValueTask RecordFailureAsync(params string[] keys)
    {
        RecordFailure(keys);
        if (_shared is not null)
        {
            try
            {
                using var timeout = new CancellationTokenSource(SharedCallTimeout);
                DateTimeOffset now = _clock.UtcNow;
                await _shared.AddAuthFailuresAsync(Digest(keys), BucketOf(now), MinBucket(now), timeout.Token).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                WarnFallback(ex);
            }
        }
    }

    /// <summary>
    /// Forgets the failures of the keys (a successful login), in this process and (if shared) for all replicas. <paramref name="check"/> is what the login attempt's
    /// <see cref="CheckAsync"/> returned: the shared failures are deleted only for keys it found on record, so a login that follows no failure costs no round trip.
    /// </summary>
    public async ValueTask RecordSuccessAsync(AuthLockoutCheck check, params string[] keys)
    {
        RecordSuccess(keys);
        if (_shared is not null && check.DigestsWithFailures.Count > 0)
        {
            string[] toClear = [.. Digest(keys).Where(d => check.DigestsWithFailures.Contains(d, StringComparer.Ordinal))];
            if (toClear.Length == 0)
            {
                return;
            }

            try
            {
                using var timeout = new CancellationTokenSource(SharedCallTimeout);
                await _shared.ClearAuthFailuresAsync(toClear, timeout.Token).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                WarnFallback(ex);
            }
        }
    }

    private async ValueTask<AuthLockoutCheck> CheckSharedAsync(IReplicaCoordination shared, string[] keys, CancellationToken ct)
    {
        DateTimeOffset now = _clock.UtcNow;
        IReadOnlyList<AuthFailureCount> counts = await shared.GetAuthFailuresAsync(Digest(keys), MinBucket(now), ct).ConfigureAwait(false);
        TimeSpan? retryAfter = null;
        foreach (var perKey in counts.GroupBy(c => c.KeyDigest, StringComparer.Ordinal))
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

        return new AuthLockoutCheck(retryAfter, [.. counts.Select(c => c.KeyDigest).Distinct(StringComparer.Ordinal)]);
    }

    private long BucketOf(DateTimeOffset at) => at.ToUnixTimeSeconds() / _bucketSeconds;

    private long MinBucket(DateTimeOffset now) => Math.Max(0, (now - _window).ToUnixTimeSeconds() / _bucketSeconds);

    private DateTimeOffset BucketEnd(long bucket) => DateTimeOffset.FromUnixTimeSeconds((bucket + 1) * _bucketSeconds);

    /// <summary>
    /// What is stored for a key: HMAC-SHA256 under the deployment's digest key of the key in one case, in hexadecimal. Fixed length whatever a client sends, one budget however the
    /// name is cased, and meaningless without the key (which only the replicas, through Data Protection, can read).
    /// </summary>
    public string[] Digest(string[] keys)
    {
        var digests = new string[keys.Length];
        for (int i = 0; i < keys.Length; i++)
        {
            digests[i] = Convert.ToHexString(HMACSHA256.HashData(_digestKey!, Encoding.UTF8.GetBytes(keys[i].ToLowerInvariant())));
        }

        return digests;
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
