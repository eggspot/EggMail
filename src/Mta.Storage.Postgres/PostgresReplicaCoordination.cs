using Npgsql;
using NpgsqlTypes;

namespace Mta.Storage.Postgres;

/// <summary>
/// <see cref="IReplicaCoordination"/> on PostgreSQL: three small tables written with single atomic statements (no advisory lock, no transaction spanning round trips),
/// so replicas add to each other. Every statement is on a periodic path (a few per replica every few seconds) or on the failed-login path; none is on the delivery hot path.
/// They run on a data source of their own (<see cref="PostgresRuntime.Coordination"/>, two connections) so that claims cannot starve them. Heartbeats, liveness, signal
/// validity and retention use the database server's clock (<c>clock_timestamp()</c>): replica clocks are never compared. Signals carry durations, not instants.
/// </summary>
internal sealed class PostgresReplicaCoordination(PostgresRuntime rt) : IReplicaCoordination
{
    private const double ForgetReplicaAfterSeconds = 5 * 60;
    private const double SignalRetentionSeconds = 60 * 60;

    public async ValueTask<IReadOnlyList<string>> HeartbeatAsync(string replicaName, TimeSpan liveFor, CancellationToken ct)
    {
        return await RunAsync(async () =>
        {
            await using NpgsqlConnection connection = await rt.Coordination.OpenConnectionAsync(ct).ConfigureAwait(false);
            await using (NpgsqlBatch batch = new(connection)
            {
                BatchCommands =
                {
                    Command("INSERT INTO replica_heartbeat (replica_name, beat_at) VALUES ($1, clock_timestamp()) ON CONFLICT (replica_name) DO UPDATE SET beat_at = excluded.beat_at", Text(replicaName)),
                    Command("DELETE FROM replica_heartbeat WHERE beat_at < clock_timestamp() - make_interval(secs => $1)", Seconds(ForgetReplicaAfterSeconds)),
                    Command("DELETE FROM replica_signal s WHERE NOT EXISTS (SELECT 1 FROM replica_heartbeat h WHERE h.replica_name = s.replica_name)"),
                },
            })
            {
                await batch.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            }

            await using NpgsqlCommand select = new("SELECT replica_name FROM replica_heartbeat WHERE beat_at >= clock_timestamp() - make_interval(secs => $1) ORDER BY replica_name COLLATE \"C\"", connection);
            select.Parameters.Add(Seconds(liveFor.TotalSeconds));
            var live = new List<string>();
            await using NpgsqlDataReader reader = await select.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                live.Add(reader.GetString(0));
            }

            return (IReadOnlyList<string>)live;
        }).ConfigureAwait(false);
    }

    public async ValueTask LeaveAsync(string replicaName, CancellationToken ct)
    {
        await RunAsync(async () =>
        {
            await using NpgsqlConnection connection = await rt.Coordination.OpenConnectionAsync(ct).ConfigureAwait(false);
            await using NpgsqlBatch batch = new(connection)
            {
                BatchCommands =
                {
                    Command("DELETE FROM replica_signal WHERE replica_name = $1", Text(replicaName)),
                    Command("DELETE FROM replica_heartbeat WHERE replica_name = $1", Text(replicaName)),
                },
            };
            await batch.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            return 0;
        }).ConfigureAwait(false);
    }

    public async ValueTask PublishSignalsAsync(string replicaName, IReadOnlyList<PeerSignal> signals, CancellationToken ct)
    {
        await RunAsync(async () =>
        {
            await using NpgsqlConnection connection = await rt.Coordination.OpenConnectionAsync(ct).ConfigureAwait(false);
            await using NpgsqlBatch batch = new(connection);
            foreach (PeerSignal s in signals)
            {
                batch.BatchCommands.Add(Command(
                    "INSERT INTO replica_signal (signal_kind, signal_key, replica_name, raised_at, valid_until, cooldown_ms) " +
                    "VALUES ($1, $2, $3, clock_timestamp(), clock_timestamp() + make_interval(secs => $4), $5) " +
                    "ON CONFLICT (signal_kind, signal_key, replica_name) DO UPDATE SET raised_at = excluded.raised_at, valid_until = excluded.valid_until, cooldown_ms = excluded.cooldown_ms",
                    new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Smallint, Value = (short)s.Kind }, Text(s.Key), Text(replicaName), Seconds(s.ValidFor.TotalSeconds),
                    new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Bigint, Value = (long)s.Cooldown.TotalMilliseconds }));
            }

            batch.BatchCommands.Add(Command("DELETE FROM replica_signal WHERE valid_until < clock_timestamp() - make_interval(secs => $1)", Seconds(SignalRetentionSeconds)));
            await batch.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            return 0;
        }).ConfigureAwait(false);
    }

    public async ValueTask<IReadOnlyList<ReceivedPeerSignal>> GetSignalsAsync(string replicaName, CancellationToken ct)
    {
        return await RunAsync(async () =>
        {
            await using NpgsqlConnection connection = await rt.Coordination.OpenConnectionAsync(ct).ConfigureAwait(false);
            await using NpgsqlCommand cmd = new(
                "SELECT replica_name, signal_kind, signal_key, raised_at, valid_until - clock_timestamp(), cooldown_ms FROM replica_signal " +
                "WHERE replica_name <> $1 AND valid_until > clock_timestamp() ORDER BY replica_name COLLATE \"C\", signal_key COLLATE \"C\", signal_kind", connection);
            cmd.Parameters.Add(Text(replicaName));
            var list = new List<ReceivedPeerSignal>();
            await using NpgsqlDataReader reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                list.Add(new ReceivedPeerSignal(reader.GetString(0), new PeerSignal((PeerSignalKind)reader.GetInt16(1), reader.GetString(2), reader.GetFieldValue<TimeSpan>(4), TimeSpan.FromMilliseconds(reader.GetInt64(5))), reader.GetFieldValue<DateTimeOffset>(3)));
            }

            return (IReadOnlyList<ReceivedPeerSignal>)list;
        }).ConfigureAwait(false);
    }

    public async ValueTask<IReadOnlyList<AuthFailureCount>> GetAuthFailuresAsync(IReadOnlyList<string> keyDigests, long minBucket, CancellationToken ct)
    {
        if (keyDigests.Count == 0)
        {
            return [];
        }

        return await RunAsync(async () =>
        {
            await using NpgsqlConnection connection = await rt.Coordination.OpenConnectionAsync(ct).ConfigureAwait(false);
            await using NpgsqlCommand cmd = new("SELECT key_digest, bucket_index, failure_count FROM auth_failure WHERE key_digest = ANY($1) AND bucket_index >= $2 ORDER BY key_digest COLLATE \"C\", bucket_index", connection);
            cmd.Parameters.Add(Texts(keyDigests));
            cmd.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Bigint, Value = minBucket });
            var list = new List<AuthFailureCount>();
            await using NpgsqlDataReader reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                list.Add(new AuthFailureCount(reader.GetString(0), reader.GetInt64(1), reader.GetInt64(2)));
            }

            return (IReadOnlyList<AuthFailureCount>)list;
        }).ConfigureAwait(false);
    }

    public async ValueTask AddAuthFailuresAsync(IReadOnlyList<string> keyDigests, long bucket, long pruneBeforeBucket, CancellationToken ct)
    {
        string[] digests = [.. keyDigests.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)];   // a fixed order, so two replicas cannot deadlock on each other's rows
        if (digests.Length == 0)
        {
            return;
        }

        await RunAsync(async () =>
        {
            await using NpgsqlConnection connection = await rt.Coordination.OpenConnectionAsync(ct).ConfigureAwait(false);
            await using NpgsqlBatch batch = new(connection)
            {
                BatchCommands =
                {
                    Command("INSERT INTO auth_failure (key_digest, bucket_index, failure_count) SELECT d, $2, 1 FROM unnest($1::text[]) AS d ORDER BY d COLLATE \"C\" ON CONFLICT (key_digest, bucket_index) DO UPDATE SET failure_count = auth_failure.failure_count + 1",
                        Texts(digests), new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Bigint, Value = bucket }),
                    // Old buckets in a fixed order, and rows another replica holds locked are left for the next failure: pruning never waits for, or deadlocks with, a concurrent writer.
                    Command("DELETE FROM auth_failure WHERE (key_digest, bucket_index) IN (SELECT key_digest, bucket_index FROM auth_failure WHERE bucket_index < $1 ORDER BY key_digest COLLATE \"C\", bucket_index FOR UPDATE SKIP LOCKED)",
                        new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Bigint, Value = pruneBeforeBucket }),
                },
            };
            await batch.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            return 0;
        }).ConfigureAwait(false);
    }

    public async ValueTask ClearAuthFailuresAsync(IReadOnlyList<string> keyDigests, CancellationToken ct)
    {
        if (keyDigests.Count == 0)
        {
            return;
        }

        await RunAsync(async () =>
        {
            await using NpgsqlConnection connection = await rt.Coordination.OpenConnectionAsync(ct).ConfigureAwait(false);
            await using NpgsqlCommand cmd = new(
                "DELETE FROM auth_failure WHERE (key_digest, bucket_index) IN (SELECT key_digest, bucket_index FROM auth_failure WHERE key_digest = ANY($1) ORDER BY key_digest COLLATE \"C\", bucket_index FOR UPDATE)", connection);
            cmd.Parameters.Add(Texts(keyDigests));
            await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            return 0;
        }).ConfigureAwait(false);
    }

    private async ValueTask<T> RunAsync<T>(Func<Task<T>> action)
    {
        try
        {
            return await action().ConfigureAwait(false);
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex))
        {
            throw rt.Unavailable(ex);
        }
    }

    private static NpgsqlBatchCommand Command(string sql, params NpgsqlParameter[] parameters)
    {
        var command = new NpgsqlBatchCommand(sql);
        foreach (NpgsqlParameter p in parameters)
        {
            command.Parameters.Add(p);
        }

        return command;
    }

    private static NpgsqlParameter Text(string value) => new() { NpgsqlDbType = NpgsqlDbType.Text, Value = value };

    private static NpgsqlParameter Texts(IEnumerable<string> values) => new() { NpgsqlDbType = NpgsqlDbType.Array | NpgsqlDbType.Text, Value = values.ToArray() };

    private static NpgsqlParameter Seconds(double value) => new() { NpgsqlDbType = NpgsqlDbType.Double, Value = Math.Max(0, value) };
}
