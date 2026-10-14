namespace Mta.Storage.InMemory;

/// <summary>
/// <see cref="IReplicaCoordination"/> inside one process: several runtimes sharing one <see cref="InMemoryStorage"/> behave like replicas on one database. It is the
/// reference the PostgreSQL implementation is checked against by the shared conformance suite, and lets the host logic be tested without a database server. Time is the
/// storage's clock, standing in for the database's.
/// </summary>
public sealed class InMemoryReplicaCoordination(Mta.Core.IClock clock) : IReplicaCoordination
{
    /// <summary>Replicas silent for this long are forgotten (the same figure as in the PostgreSQL implementation).</summary>
    internal static readonly TimeSpan ForgetAfter = TimeSpan.FromMinutes(5);

    /// <summary>Signals expired for this long are deleted (the same figure as in the PostgreSQL implementation).</summary>
    internal static readonly TimeSpan SignalRetention = TimeSpan.FromHours(1);

    private readonly object _gate = new();
    private readonly Dictionary<string, DateTimeOffset> _beats = new(StringComparer.Ordinal);
    private readonly Dictionary<(PeerSignalKind Kind, string Key, string ReplicaName), (DateTimeOffset RaisedAt, DateTimeOffset ValidUntil, TimeSpan Cooldown)> _signals = [];
    private readonly Dictionary<(string KeyDigest, long Bucket), long> _failures = [];

    public ValueTask<IReadOnlyList<string>> HeartbeatAsync(string replicaName, TimeSpan liveFor, CancellationToken ct)
    {
        lock (_gate)
        {
            DateTimeOffset now = clock.UtcNow;
            _beats[replicaName] = now;
            foreach (string name in _beats.Where(b => now - b.Value > ForgetAfter).Select(b => b.Key).ToList())
            {
                _beats.Remove(name);
            }

            foreach (var key in _signals.Keys.Where(k => !_beats.ContainsKey(k.ReplicaName)).ToList())
            {
                _signals.Remove(key);
            }

            IReadOnlyList<string> live = [.. _beats.Where(b => now - b.Value <= liveFor).Select(b => b.Key).Order(StringComparer.Ordinal)];
            return ValueTask.FromResult(live);
        }
    }

    public ValueTask LeaveAsync(string replicaName, CancellationToken ct)
    {
        lock (_gate)
        {
            _beats.Remove(replicaName);
            foreach (var key in _signals.Keys.Where(k => k.ReplicaName == replicaName).ToList())
            {
                _signals.Remove(key);
            }
        }

        return ValueTask.CompletedTask;
    }

    public ValueTask PublishSignalsAsync(string replicaName, IReadOnlyList<PeerSignal> signals, CancellationToken ct)
    {
        lock (_gate)
        {
            DateTimeOffset now = clock.UtcNow;
            foreach (PeerSignal s in signals)
            {
                _signals[(s.Kind, s.Key, replicaName)] = (now, now + s.ValidFor, s.Cooldown);
            }

            foreach (var key in _signals.Where(s => now - s.Value.ValidUntil > SignalRetention).Select(s => s.Key).ToList())
            {
                _signals.Remove(key);
            }
        }

        return ValueTask.CompletedTask;
    }

    public ValueTask<IReadOnlyList<ReceivedPeerSignal>> GetSignalsAsync(string replicaName, CancellationToken ct)
    {
        lock (_gate)
        {
            DateTimeOffset now = clock.UtcNow;
            IReadOnlyList<ReceivedPeerSignal> result = [.. _signals.Where(s => s.Key.ReplicaName != replicaName && s.Value.ValidUntil > now)
                .OrderBy(s => s.Key.ReplicaName, StringComparer.Ordinal).ThenBy(s => s.Key.Key, StringComparer.Ordinal).ThenBy(s => s.Key.Kind)
                .Select(s => new ReceivedPeerSignal(s.Key.ReplicaName, new PeerSignal(s.Key.Kind, s.Key.Key, s.Value.ValidUntil - now, s.Value.Cooldown), s.Value.RaisedAt))];
            return ValueTask.FromResult(result);
        }
    }

    public ValueTask<IReadOnlyList<AuthFailureCount>> GetAuthFailuresAsync(IReadOnlyList<string> keyDigests, long minBucket, CancellationToken ct)
    {
        lock (_gate)
        {
            IReadOnlyList<AuthFailureCount> result = [.. _failures.Where(f => f.Key.Bucket >= minBucket && keyDigests.Contains(f.Key.KeyDigest)).Select(f => new AuthFailureCount(f.Key.KeyDigest, f.Key.Bucket, f.Value))
                .OrderBy(f => f.KeyDigest, StringComparer.Ordinal).ThenBy(f => f.Bucket)];
            return ValueTask.FromResult(result);
        }
    }

    public ValueTask AddAuthFailuresAsync(IReadOnlyList<string> keyDigests, long bucket, long pruneBeforeBucket, CancellationToken ct)
    {
        lock (_gate)
        {
            foreach (string digest in keyDigests.Distinct(StringComparer.Ordinal))
            {
                _failures[(digest, bucket)] = _failures.GetValueOrDefault((digest, bucket)) + 1;
            }

            foreach (var key in _failures.Keys.Where(k => k.Bucket < pruneBeforeBucket).ToList())
            {
                _failures.Remove(key);
            }
        }

        return ValueTask.CompletedTask;
    }

    public ValueTask ClearAuthFailuresAsync(IReadOnlyList<string> keyDigests, CancellationToken ct)
    {
        lock (_gate)
        {
            foreach (var key in _failures.Keys.Where(k => keyDigests.Contains(k.KeyDigest)).ToList())
            {
                _failures.Remove(key);
            }
        }

        return ValueTask.CompletedTask;
    }
}
