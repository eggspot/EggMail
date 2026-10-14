namespace Mta.Storage;

/// <summary>What a <see cref="PeerSignal"/> tells the other replicas.</summary>
public enum PeerSignalKind : byte
{
    /// <summary>A circuit breaker opened: <see cref="PeerSignal.Key"/> names the route or MX host, <see cref="PeerSignal.Until"/> is when it may be probed again, <see cref="PeerSignal.Value"/> the cooldown in ticks.</summary>
    CircuitOpened = 0,

    /// <summary>A destination asked this replica to slow down (a throttling reply, or a burst of refused connections): <see cref="PeerSignal.Key"/> names the destination and route.</summary>
    DestinationSlowedDown = 1,
}

/// <summary>
/// A fact one replica learned about a remote destination that the others should act on before they learn it the hard way. It is valid until <see cref="Until"/>;
/// a replica publishes at most one signal per kind and key (a newer one replaces its older one).
/// </summary>
public sealed record PeerSignal(PeerSignalKind Kind, string Key, string ReplicaId, DateTimeOffset At, DateTimeOffset Until, long Value);

/// <summary>Failed logins counted for one hashed key (an address or a user name) in one time bucket.</summary>
public sealed record AuthFailureCount(string KeyHash, long Bucket, long Count);

/// <summary>
/// What replicas of one deployment on a shared database exchange periodically and that is too volatile (or too security-relevant) for the config tables: who is alive
/// (so per-destination limits can be shared out), what the others learned about remote destinations, and the failed-login counts behind the lockout. Only the
/// PostgreSQL backend and the in-memory backend implement it; <see cref="IStorage.Replicas"/> is null for SQLite, which is one process by design. Nothing here is part of
/// the backend switch bundle: it is ephemeral and rebuilt within seconds by the running replicas.
/// </summary>
public interface IReplicaCoordination
{
    /// <summary>
    /// Records that <paramref name="replicaId"/> is alive at <paramref name="now"/> and returns the ids of every replica seen within <paramref name="liveFor"/> (this one included),
    /// ordinally sorted so that every replica derives the same rank for each. Replicas silent for much longer are forgotten.
    /// </summary>
    ValueTask<IReadOnlyList<string>> HeartbeatAsync(string replicaId, DateTimeOffset now, TimeSpan liveFor, CancellationToken ct);

    /// <summary>Removes <paramref name="replicaId"/> and its signals (graceful shutdown), so the others take over its share without waiting for it to time out.</summary>
    ValueTask LeaveAsync(string replicaId, CancellationToken ct);

    /// <summary>Publishes signals of <see cref="PeerSignal.ReplicaId"/> (replacing its earlier signal of the same kind and key) and drops signals that expired long ago.</summary>
    ValueTask PublishSignalsAsync(IReadOnlyList<PeerSignal> signals, DateTimeOffset now, CancellationToken ct);

    /// <summary>The signals of every replica except <paramref name="replicaId"/> that are still valid at <paramref name="now"/>.</summary>
    ValueTask<IReadOnlyList<PeerSignal>> GetSignalsAsync(string replicaId, DateTimeOffset now, CancellationToken ct);

    /// <summary>The failed-login counts of the keys in buckets from <paramref name="minBucket"/> on (all replicas together).</summary>
    ValueTask<IReadOnlyList<AuthFailureCount>> GetAuthFailuresAsync(IReadOnlyList<string> keyHashes, long minBucket, CancellationToken ct);

    /// <summary>Adds one failure to each key in <paramref name="bucket"/> (atomically, so replicas add up) and deletes the buckets before <paramref name="pruneBeforeBucket"/>.</summary>
    ValueTask AddAuthFailuresAsync(IReadOnlyList<string> keyHashes, long bucket, long pruneBeforeBucket, CancellationToken ct);

    /// <summary>Forgets every failure of the keys (a successful login).</summary>
    ValueTask ClearAuthFailuresAsync(IReadOnlyList<string> keyHashes, CancellationToken ct);
}
