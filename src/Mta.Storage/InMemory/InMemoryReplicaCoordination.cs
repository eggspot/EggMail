namespace Mta.Storage.InMemory;

/// <summary>
/// <see cref="IReplicaCoordination"/> inside one process: several runtimes sharing one <see cref="InMemoryStorage"/> behave like replicas on one database. It is the
/// reference the PostgreSQL implementation is checked against by the shared conformance suite, and lets the host logic be tested without a database server.
/// </summary>
public sealed class InMemoryReplicaCoordination : IReplicaCoordination
{
    /// <summary>Replicas silent for this long are forgotten (the same figure as in the PostgreSQL implementation).</summary>
    internal static readonly TimeSpan ForgetAfter = TimeSpan.FromMinutes(5);

    /// <summary>Signals expired for this long are deleted (the same figure as in the PostgreSQL implementation).</summary>
    internal static readonly TimeSpan SignalRetention = TimeSpan.FromHours(1);

    private readonly object _gate = new();
    private readonly Dictionary<string, DateTimeOffset> _beats = new(StringComparer.Ordinal);
    private readonly Dictionary<(PeerSignalKind Kind, string Key, string ReplicaId), PeerSignal> _signals = [];
    private readonly Dictionary<(string KeyHash, long Bucket), long> _failures = [];

    public ValueTask<IReadOnlyList<string>> HeartbeatAsync(string replicaId, DateTimeOffset now, TimeSpan liveFor, CancellationToken ct)
    {
        lock (_gate)
        {
            _beats[replicaId] = now;
            foreach (string id in _beats.Where(b => now - b.Value > ForgetAfter).Select(b => b.Key).ToList())
            {
                _beats.Remove(id);
                foreach (var key in _signals.Keys.Where(k => k.ReplicaId == id).ToList())
                {
                    _signals.Remove(key);
                }
            }

            IReadOnlyList<string> live = [.. _beats.Where(b => now - b.Value <= liveFor).Select(b => b.Key).Order(StringComparer.Ordinal)];
            return ValueTask.FromResult(live);
        }
    }

    public ValueTask LeaveAsync(string replicaId, CancellationToken ct)
    {
        lock (_gate)
        {
            _beats.Remove(replicaId);
            foreach (var key in _signals.Keys.Where(k => k.ReplicaId == replicaId).ToList())
            {
                _signals.Remove(key);
            }
        }

        return ValueTask.CompletedTask;
    }

    public ValueTask PublishSignalsAsync(IReadOnlyList<PeerSignal> signals, DateTimeOffset now, CancellationToken ct)
    {
        lock (_gate)
        {
            foreach (PeerSignal s in signals)
            {
                _signals[(s.Kind, s.Key, s.ReplicaId)] = s;
            }

            foreach (var key in _signals.Where(s => now - s.Value.Until > SignalRetention).Select(s => s.Key).ToList())
            {
                _signals.Remove(key);
            }
        }

        return ValueTask.CompletedTask;
    }

    public ValueTask<IReadOnlyList<PeerSignal>> GetSignalsAsync(string replicaId, DateTimeOffset now, CancellationToken ct)
    {
        lock (_gate)
        {
            IReadOnlyList<PeerSignal> result = [.. _signals.Values.Where(s => s.ReplicaId != replicaId && s.Until > now).OrderBy(s => s.ReplicaId, StringComparer.Ordinal).ThenBy(s => s.Key, StringComparer.Ordinal)];
            return ValueTask.FromResult(result);
        }
    }

    public ValueTask<IReadOnlyList<AuthFailureCount>> GetAuthFailuresAsync(IReadOnlyList<string> keyHashes, long minBucket, CancellationToken ct)
    {
        lock (_gate)
        {
            IReadOnlyList<AuthFailureCount> result = [.. _failures.Where(f => f.Key.Bucket >= minBucket && keyHashes.Contains(f.Key.KeyHash)).Select(f => new AuthFailureCount(f.Key.KeyHash, f.Key.Bucket, f.Value))
                .OrderBy(f => f.KeyHash, StringComparer.Ordinal).ThenBy(f => f.Bucket)];
            return ValueTask.FromResult(result);
        }
    }

    public ValueTask AddAuthFailuresAsync(IReadOnlyList<string> keyHashes, long bucket, long pruneBeforeBucket, CancellationToken ct)
    {
        lock (_gate)
        {
            foreach (string hash in keyHashes.Distinct(StringComparer.Ordinal))
            {
                _failures[(hash, bucket)] = _failures.GetValueOrDefault((hash, bucket)) + 1;
            }

            foreach (var key in _failures.Keys.Where(k => k.Bucket < pruneBeforeBucket).ToList())
            {
                _failures.Remove(key);
            }
        }

        return ValueTask.CompletedTask;
    }

    public ValueTask ClearAuthFailuresAsync(IReadOnlyList<string> keyHashes, CancellationToken ct)
    {
        lock (_gate)
        {
            foreach (var key in _failures.Keys.Where(k => keyHashes.Contains(k.KeyHash)).ToList())
            {
                _failures.Remove(key);
            }
        }

        return ValueTask.CompletedTask;
    }
}
