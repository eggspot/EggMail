using Npgsql;
using NpgsqlTypes;

namespace Mta.Storage.Postgres;

/// <summary>
/// <see cref="IReplicaCoordination"/> on PostgreSQL: three small tables written with single atomic statements (no advisory lock, no transaction spanning round trips),
/// so replicas add to each other. Every statement is on a periodic path (a few per replica every few seconds) or on the failed-login path; none is on the delivery hot path.
/// Times come from the callers' clocks (the same assumption as the lease facility: replica clocks agree to within the liveness window).
/// </summary>
internal sealed class PostgresReplicaCoordination(PostgresRuntime rt) : IReplicaCoordination
{
    private static readonly TimeSpan ForgetAfter = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan SignalRetention = TimeSpan.FromHours(1);

    public async ValueTask<IReadOnlyList<string>> HeartbeatAsync(string replicaId, DateTimeOffset now, TimeSpan liveFor, CancellationToken ct)
    {
        return await RunAsync(async () =>
        {
            await using NpgsqlConnection connection = await rt.Data.OpenConnectionAsync(ct).ConfigureAwait(false);
            await using (NpgsqlBatch batch = new(connection)
            {
                BatchCommands =
                {
                    Command("INSERT INTO replica_heartbeat (replica_name, started_at, beat_at) VALUES ($1, $2, $2) ON CONFLICT (replica_name) DO UPDATE SET beat_at = excluded.beat_at",
                        Text(replicaId), Time(now)),
                    Command("DELETE FROM replica_heartbeat WHERE beat_at < $1", Time(now - ForgetAfter)),
                    Command("DELETE FROM replica_signal s WHERE NOT EXISTS (SELECT 1 FROM replica_heartbeat h WHERE h.replica_name = s.replica_name)"),
                },
            })
            {
                await batch.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            }

            await using NpgsqlCommand select = new("SELECT replica_name FROM replica_heartbeat WHERE beat_at >= $1 ORDER BY replica_name COLLATE \"C\"", connection);
            select.Parameters.Add(Time(now - liveFor));
            var live = new List<string>();
            await using NpgsqlDataReader reader = await select.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                live.Add(reader.GetString(0));
            }

            return (IReadOnlyList<string>)live;
        }).ConfigureAwait(false);
    }

    public async ValueTask LeaveAsync(string replicaId, CancellationToken ct)
    {
        await RunAsync(async () =>
        {
            await using NpgsqlConnection connection = await rt.Data.OpenConnectionAsync(ct).ConfigureAwait(false);
            await using NpgsqlBatch batch = new(connection)
            {
                BatchCommands =
                {
                    Command("DELETE FROM replica_signal WHERE replica_name = $1", Text(replicaId)),
                    Command("DELETE FROM replica_heartbeat WHERE replica_name = $1", Text(replicaId)),
                },
            };
            await batch.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            return 0;
        }).ConfigureAwait(false);
    }

    public async ValueTask PublishSignalsAsync(IReadOnlyList<PeerSignal> signals, DateTimeOffset now, CancellationToken ct)
    {
        await RunAsync(async () =>
        {
            await using NpgsqlConnection connection = await rt.Data.OpenConnectionAsync(ct).ConfigureAwait(false);
            await using NpgsqlBatch batch = new(connection);
            foreach (PeerSignal s in signals)
            {
                batch.BatchCommands.Add(Command(
                    "INSERT INTO replica_signal (kind, key, replica_name, at, until, value) VALUES ($1, $2, $3, $4, $5, $6) " +
                    "ON CONFLICT (kind, key, replica_name) DO UPDATE SET at = excluded.at, until = excluded.until, value = excluded.value",
                    new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Smallint, Value = (short)s.Kind }, Text(s.Key), Text(s.ReplicaId), Time(s.At), Time(s.Until),
                    new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Bigint, Value = s.Value }));
            }

            batch.BatchCommands.Add(Command("DELETE FROM replica_signal WHERE until < $1", Time(now - SignalRetention)));
            await batch.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            return 0;
        }).ConfigureAwait(false);
    }

    public async ValueTask<IReadOnlyList<PeerSignal>> GetSignalsAsync(string replicaId, DateTimeOffset now, CancellationToken ct)
    {
        return await RunAsync(async () =>
        {
            await using NpgsqlConnection connection = await rt.Data.OpenConnectionAsync(ct).ConfigureAwait(false);
            await using NpgsqlCommand cmd = new("SELECT kind, key, replica_name, at, until, value FROM replica_signal WHERE replica_name <> $1 AND until > $2 ORDER BY replica_name COLLATE \"C\", key COLLATE \"C\"", connection);
            cmd.Parameters.Add(Text(replicaId));
            cmd.Parameters.Add(Time(now));
            var list = new List<PeerSignal>();
            await using NpgsqlDataReader reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                list.Add(new PeerSignal((PeerSignalKind)reader.GetInt16(0), reader.GetString(1), reader.GetString(2), reader.GetFieldValue<DateTimeOffset>(3), reader.GetFieldValue<DateTimeOffset>(4), reader.GetInt64(5)));
            }

            return (IReadOnlyList<PeerSignal>)list;
        }).ConfigureAwait(false);
    }

    public async ValueTask<IReadOnlyList<AuthFailureCount>> GetAuthFailuresAsync(IReadOnlyList<string> keyHashes, long minBucket, CancellationToken ct)
    {
        if (keyHashes.Count == 0)
        {
            return [];
        }

        return await RunAsync(async () =>
        {
            await using NpgsqlConnection connection = await rt.Data.OpenConnectionAsync(ct).ConfigureAwait(false);
            await using NpgsqlCommand cmd = new("SELECT key_hash, bucket, count FROM auth_failure WHERE key_hash = ANY($1) AND bucket >= $2 ORDER BY key_hash COLLATE \"C\", bucket", connection);
            cmd.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Array | NpgsqlDbType.Text, Value = keyHashes.ToArray() });
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

    public async ValueTask AddAuthFailuresAsync(IReadOnlyList<string> keyHashes, long bucket, long pruneBeforeBucket, CancellationToken ct)
    {
        string[] hashes = [.. keyHashes.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)];   // a fixed order, so two replicas cannot deadlock on each other's rows
        if (hashes.Length == 0)
        {
            return;
        }

        await RunAsync(async () =>
        {
            await using NpgsqlConnection connection = await rt.Data.OpenConnectionAsync(ct).ConfigureAwait(false);
            await using NpgsqlBatch batch = new(connection)
            {
                BatchCommands =
                {
                    Command("INSERT INTO auth_failure (key_hash, bucket, count) SELECT h, $2, 1 FROM unnest($1::text[]) AS h ORDER BY h COLLATE \"C\" ON CONFLICT (key_hash, bucket) DO UPDATE SET count = auth_failure.count + 1",
                        new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Array | NpgsqlDbType.Text, Value = hashes }, new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Bigint, Value = bucket }),
                    Command("DELETE FROM auth_failure WHERE bucket < $1", new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Bigint, Value = pruneBeforeBucket }),
                },
            };
            await batch.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            return 0;
        }).ConfigureAwait(false);
    }

    public async ValueTask ClearAuthFailuresAsync(IReadOnlyList<string> keyHashes, CancellationToken ct)
    {
        if (keyHashes.Count == 0)
        {
            return;
        }

        await RunAsync(async () =>
        {
            await using NpgsqlConnection connection = await rt.Data.OpenConnectionAsync(ct).ConfigureAwait(false);
            await using NpgsqlCommand cmd = new("DELETE FROM auth_failure WHERE key_hash = ANY($1)", connection);
            cmd.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Array | NpgsqlDbType.Text, Value = keyHashes.ToArray() });
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

    private static NpgsqlParameter Time(DateTimeOffset value) => new() { NpgsqlDbType = NpgsqlDbType.TimestampTz, Value = value.UtcDateTime };
}
