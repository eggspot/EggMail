using System.Collections.Concurrent;
using System.Globalization;
using System.Text.RegularExpressions;
using Mta.Storage.Logic;
using Npgsql;

namespace Mta.Storage.Postgres;

/// <summary>One day partition of one history table.</summary>
internal readonly record struct DayPartition(string Table, string Name, int Day, bool DetachPending);

/// <summary>
/// Day partitions of the five history tables (design §4.3). The Npgsql provider has no partition API (efcore.pg#1035), so
/// the DDL is written here. Creating and dropping partitions needs ownership of the tables, so it runs on the <b>owner</b>
/// data source; with a single connection string that is simply the same connection.
/// <para>Creation takes a transaction-level advisory lock (<c>pg_advisory_xact_lock</c>, never a session lock, so it works
/// behind PgBouncer in transaction mode). Retention is <c>DETACH PARTITION … CONCURRENTLY</c> followed by <c>DROP</c>; because
/// a concurrent detach cannot run inside a transaction block, the maintenance job holds its lock in a separate transaction
/// on another connection (see <see cref="PostgresMaintenance"/>).</para>
/// </summary>
internal sealed class PostgresPartitions(NpgsqlDataSource owner)
{
    /// <summary>The partitioned tables. All are keyed with a leading <c>day</c> (days since 1970-01-01 of the UUIDv7 message id).</summary>
    public static readonly string[] Tables = ["message_index", "message_recipient", "message_event", "message_content", "message_raw_retained"];

    /// <summary>The tables that follow <c>Retention:MetadataDays</c>; the others follow <c>Content:RetentionDays</c>.</summary>
    public static readonly string[] MetadataTables = ["message_index", "message_recipient", "message_event"];

    public static readonly string[] ContentTables = ["message_content", "message_raw_retained"];

    private static readonly Regex Bound = new(@"FROM \('?(?<from>-?\d+)'?\) TO \('?(?<to>-?\d+)'?\)", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    // Days known to have all five partitions in this process; cleared for days we drop, re-checked on a missing-partition error.
    private readonly ConcurrentDictionary<int, bool> _known = new();

    public static string NameOf(string table, int day) =>
        table + "_p" + StorageTime.DayStart(day).UtcDateTime.ToString("yyyyMMdd", CultureInfo.InvariantCulture);

    /// <summary>Makes sure the partitions of <paramref name="day"/> exist (cheap when this process already knows them).</summary>
    public async ValueTask EnsureDayAsync(int day, bool force, CancellationToken cancellationToken)
    {
        if (!force && _known.ContainsKey(day))
        {
            return;
        }

        await EnsureRangeAsync(day, day, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates every missing partition for days <paramref name="firstDay"/>..<paramref name="lastDay"/>. Returns how many were created.</summary>
    public async Task<int> EnsureRangeAsync(int firstDay, int lastDay, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await owner.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await using (var lockCmd = new NpgsqlCommand("SELECT pg_advisory_xact_lock($1)", connection, tx))
        {
            lockCmd.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlTypes.NpgsqlDbType.Bigint, Value = AdvisoryLocks.PartitionDdl });
            await lockCmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        int created = 0;
        for (int day = firstDay; day <= lastDay; day++)
        {
            foreach (string table in Tables)
            {
                string name = NameOf(table, day);
                // CREATE TABLE IF NOT EXISTS … PARTITION OF is a no-op notice when the partition exists.
                await using var create = new NpgsqlCommand(
                    $"CREATE TABLE IF NOT EXISTS {name} PARTITION OF {table} FOR VALUES FROM ({day.ToString(CultureInfo.InvariantCulture)}) TO ({(day + 1).ToString(CultureInfo.InvariantCulture)})",
                    connection, tx);
                await using var exists = new NpgsqlCommand("SELECT to_regclass($1) IS NOT NULL", connection, tx);
                exists.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlTypes.NpgsqlDbType.Text, Value = name });
                bool before = (bool)(await exists.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false))!;
                if (!before)
                {
                    await create.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                    created++;
                }
            }
        }

        await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
        for (int day = firstDay; day <= lastDay; day++)
        {
            _known[day] = true;
        }

        return created;
    }

    /// <summary>Lists the existing partitions of the history tables, including detaches that were interrupted.</summary>
    public async Task<IReadOnlyList<DayPartition>> ListAsync(CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await owner.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = new NpgsqlCommand(
            "SELECT p.relname, c.relname, pg_get_expr(c.relpartbound, c.oid), i.inhdetachpending " +
            "FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid JOIN pg_class p ON p.oid = i.inhparent " +
            "WHERE p.relnamespace = 'public'::regnamespace AND p.relname = ANY($1)", connection);
        cmd.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlTypes.NpgsqlDbType.Array | NpgsqlTypes.NpgsqlDbType.Text, Value = Tables });
        var list = new List<DayPartition>();
        await using NpgsqlDataReader r = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await r.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            string? bound = r.IsDBNull(2) ? null : r.GetString(2);
            Match m = bound is null ? Match.Empty : Bound.Match(bound);
            if (!m.Success)
            {
                continue; // not a range partition we created (for example a DEFAULT partition): leave it alone
            }

            list.Add(new DayPartition(r.GetString(0), r.GetString(1), int.Parse(m.Groups["from"].Value, CultureInfo.InvariantCulture), r.GetBoolean(3)));
        }

        return list;
    }

    /// <summary>
    /// Detaches (concurrently) and drops the partitions of <paramref name="tables"/> older than <paramref name="cutoffDay"/>
    /// (a partition holds exactly one day, so "day below the cutoff" is the whole partition). Returns the rows that were in
    /// them. Must not be called inside a transaction.
    /// </summary>
    public async Task<(long Rows, int Partitions)> DropBeforeAsync(IReadOnlyCollection<string> tables, int cutoffDay, CancellationToken cancellationToken)
    {
        long rows = 0;
        int dropped = 0;
        foreach (DayPartition p in (await ListAsync(cancellationToken).ConfigureAwait(false)).Where(p => tables.Contains(p.Table) && p.Day < cutoffDay).OrderBy(p => p.Day))
        {
            await using NpgsqlConnection connection = await owner.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            if (!p.DetachPending)
            {
                await using var count = new NpgsqlCommand($"SELECT count(*) FROM {p.Name}", connection);
                rows += Convert.ToInt64(await count.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture);
                await using var detach = new NpgsqlCommand($"ALTER TABLE {p.Table} DETACH PARTITION {p.Name} CONCURRENTLY", connection) { CommandTimeout = 300 };
                await detach.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }
            else
            {
                // An earlier detach was interrupted (cancelled or the connection died): finish it.
                await using var finalize = new NpgsqlCommand($"ALTER TABLE {p.Table} DETACH PARTITION {p.Name} FINALIZE", connection) { CommandTimeout = 300 };
                await finalize.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            await using var drop = new NpgsqlCommand($"DROP TABLE IF EXISTS {p.Name}", connection);
            await drop.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            dropped++;
            _known.TryRemove(p.Day, out _);
        }

        return (rows, dropped);
    }

    /// <summary>Forgets every known day (a write failed with a missing partition, so the cache cannot be trusted).</summary>
    public void ForgetAll() => _known.Clear();
}
