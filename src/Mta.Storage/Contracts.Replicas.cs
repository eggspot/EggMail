namespace Mta.Storage;

/// <summary>What a <see cref="PeerSignal"/> tells the other replicas.</summary>
public enum PeerSignalKind : byte
{
    /// <summary>A circuit breaker opened: <see cref="PeerSignal.Key"/> names the route or MX host, <see cref="PeerSignal.ValidFor"/> is how long until it may be probed again, <see cref="PeerSignal.Cooldown"/> the cooldown that was applied.</summary>
    CircuitOpened = 0,

    /// <summary>A destination asked this replica to slow down (a throttling reply, or a burst of refused connections): <see cref="PeerSignal.Key"/> names the destination and route. <see cref="PeerSignal.Cooldown"/> is zero.</summary>
    DestinationSlowedDown = 1,
}

/// <summary>
/// A fact one replica learned about a remote destination that the others should act on before they learn it the hard way. Durations, not instants: the replicas' clocks are never
/// compared, the database stamps and ages the signal with its own clock. A replica publishes at most one signal per kind and key (a newer one replaces its older one).
/// </summary>
/// <param name="Kind">What happened.</param>
/// <param name="Key">The destination, route or MX host the signal is about.</param>
/// <param name="ValidFor">How long the signal stays worth acting on, counted from publishing; when read back, what is left of it.</param>
/// <param name="Cooldown">For <see cref="PeerSignalKind.CircuitOpened"/>, the cooldown the publisher applied; otherwise zero.</param>
public sealed record PeerSignal(PeerSignalKind Kind, string Key, TimeSpan ValidFor, TimeSpan Cooldown);

/// <summary>A <see cref="PeerSignal"/> published by another replica, as read back.</summary>
/// <param name="ReplicaName">The replica that published it.</param>
/// <param name="Signal">The signal, with <see cref="PeerSignal.ValidFor"/> reduced to what is left.</param>
/// <param name="RaisedAt">When it was published, by the database's clock: only good for telling a newer publication of the same signal from the one already seen.</param>
public sealed record ReceivedPeerSignal(string ReplicaName, PeerSignal Signal, DateTimeOffset RaisedAt);

/// <summary>Failed logins counted for one digest of a key (an address or a user name) in one time bucket.</summary>
public sealed record AuthFailureCount(string KeyDigest, long Bucket, long Count);

/// <summary>
/// What replicas of one deployment on a shared database exchange periodically and that is too volatile (or too security-relevant) for the config tables: who is alive
/// (so per-destination limits can be shared out), what the others learned about remote destinations, and the failed-login counts behind the lockout. Only the
/// PostgreSQL backend and the in-memory backend implement it; <see cref="IStorage.Replicas"/> is null for SQLite, which is one process by design. Nothing here is part of
/// the backend switch bundle: it is ephemeral and rebuilt within seconds by the running replicas.
/// </summary>
public interface IReplicaCoordination
{
    /// <summary>
    /// Records that <paramref name="replicaName"/> is alive and returns the names of every replica seen within <paramref name="liveFor"/> (this one included), ordinally sorted so that
    /// every replica derives the same rank for each. Time is the database's: replica clocks are not compared. Replicas silent for minutes are forgotten together with their signals.
    /// </summary>
    ValueTask<IReadOnlyList<string>> HeartbeatAsync(string replicaName, TimeSpan liveFor, CancellationToken ct);

    /// <summary>Removes <paramref name="replicaName"/> and its signals (graceful shutdown), so the others take over its share without waiting for it to time out.</summary>
    ValueTask LeaveAsync(string replicaName, CancellationToken ct);

    /// <summary>Publishes signals of <paramref name="replicaName"/> (replacing its earlier signal of the same kind and key) and drops signals that expired long ago.</summary>
    ValueTask PublishSignalsAsync(string replicaName, IReadOnlyList<PeerSignal> signals, CancellationToken ct);

    /// <summary>The signals of every replica except <paramref name="replicaName"/> that are still valid.</summary>
    ValueTask<IReadOnlyList<ReceivedPeerSignal>> GetSignalsAsync(string replicaName, CancellationToken ct);

    /// <summary>The failed-login counts of the keys in buckets from <paramref name="minBucket"/> on (all replicas together).</summary>
    ValueTask<IReadOnlyList<AuthFailureCount>> GetAuthFailuresAsync(IReadOnlyList<string> keyDigests, long minBucket, CancellationToken ct);

    /// <summary>Adds one failure to each key in <paramref name="bucket"/> (atomically, so replicas add up) and deletes the buckets before <paramref name="pruneBeforeBucket"/>.</summary>
    ValueTask AddAuthFailuresAsync(IReadOnlyList<string> keyDigests, long bucket, long pruneBeforeBucket, CancellationToken ct);

    /// <summary>Forgets every failure of the keys (a successful login).</summary>
    ValueTask ClearAuthFailuresAsync(IReadOnlyList<string> keyDigests, CancellationToken ct);
}
