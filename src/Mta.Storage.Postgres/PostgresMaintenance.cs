using System.Diagnostics;
using System.Globalization;
using Mta.Storage.Logic;
using Npgsql;

namespace Mta.Storage.Postgres;

/// <summary>
/// Background upkeep on PostgreSQL (design §4.3). Every job runs under its own transaction-level advisory lock
/// (<c>pg_try_advisory_xact_lock</c>), so calling <see cref="RunAsync"/> from several replicas runs each job on one of them
/// and the others report it as skipped. The lock is held by a dedicated connection inside an open transaction while the work
/// uses other connections: <c>DETACH PARTITION … CONCURRENTLY</c> cannot run inside a transaction block, and a session-level
/// lock would break behind PgBouncer in transaction mode.
/// </summary>
internal sealed class PostgresMaintenance(PostgresRuntime rt, PostgresQueueStore queue, PostgresStatsStore stats) : IStorageMaintenance
{
    public async ValueTask<IReadOnlyList<MaintenanceReport>> RunAsync(DateTimeOffset now, CancellationToken ct)
    {
        try
        {
            return await RunCoreAsync(StorageTime.Normalize(now), ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex))
        {
            throw rt.Unavailable(ex);
        }
    }

    private async Task<IReadOnlyList<MaintenanceReport>> RunCoreAsync(DateTimeOffset now, CancellationToken ct)
    {
        var reports = new List<MaintenanceReport>();
        RetentionOptions r = rt.Options.Retention;

        async Task Job(string name, Func<Task<(long Rows, string? Detail)>> body)
        {
            long start = Stopwatch.GetTimestamp();
            await using AdvisoryLock? held = await AdvisoryLock.TryAcquireAsync(rt.Owner, AdvisoryLockKeys.Job(name), ct).ConfigureAwait(false);
            if (held is null)
            {
                reports.Add(new MaintenanceReport(name, Stopwatch.GetElapsedTime(start), 0, "skipped: another node is running this job"));
                return;
            }

            (long rows, string? detail) = await body().ConfigureAwait(false);
            reports.Add(new MaintenanceReport(name, Stopwatch.GetElapsedTime(start), rows, detail));
        }

        await stats.FlushAsync(ct).ConfigureAwait(false);

        if (rt.IsFull)
        {
            await Job("partitions.create", async () =>
            {
                int today = StorageTime.DayNumber(now);
                int created = await rt.Partitions.EnsureRangeAsync(today - 1, today + Math.Max(1, rt.Options.Postgres.PartitionsAheadDays), ct).ConfigureAwait(false);
                return (created, $"day partitions for {Math.Max(1, rt.Options.Postgres.PartitionsAheadDays)} days ahead");
            }).ConfigureAwait(false);

            bool dropped = false;
            await Job("retention.metadata", async () =>
            {
                if (RetentionCutoffs.DayKeyCutoff(now, r.MetadataDays) is not { } day)
                {
                    return (0, "unlimited");
                }

                (long rows, int partitions) = await rt.Partitions.DropBeforeAsync(PostgresPartitions.MetadataTables, day, ct).ConfigureAwait(false);
                dropped |= partitions > 0;
                return (rows, $"{partitions} partitions detached and dropped");
            }).ConfigureAwait(false);

            await Job("retention.content", async () =>
            {
                if (RetentionCutoffs.DayKeyCutoff(now, rt.Options.Content.RetentionDays) is not { } day)
                {
                    return (0, "unlimited");
                }

                (long rows, int partitions) = await rt.Partitions.DropBeforeAsync(PostgresPartitions.ContentTables, day, ct).ConfigureAwait(false);
                dropped |= partitions > 0;
                return (rows, $"{partitions} partitions detached and dropped");
            }).ConfigureAwait(false);

            // Autovacuum never analyzes a partitioned parent, so planner statistics for the history tables go stale.
            await Job("analyze.history", async () =>
            {
                if (!dropped)
                {
                    return (0, "no partitions dropped this run");
                }

                foreach (string table in PostgresPartitions.Tables)
                {
                    await ExecuteOwnerAsync("ANALYZE " + table, ct).ConfigureAwait(false);
                }

                return (PostgresPartitions.Tables.Length, "ANALYZE of the partitioned parents");
            }).ConfigureAwait(false);
        }
        else
        {
            reports.Add(new MaintenanceReport("retention.metadata", TimeSpan.Zero, 0, "history not recorded (StatsOnly)"));
            reports.Add(new MaintenanceReport("retention.content", TimeSpan.Zero, 0, "history not recorded (StatsOnly)"));
        }

        await Job("retention.webhook_outbox", async () =>
            RetentionCutoffs.InstantCutoff(now, r.WebhookOutboxDays) is { } c
                ? (await BatchDeleteAsync("webhook_outbox", "finished_at IS NOT NULL AND finished_at < $1", c, ct).ConfigureAwait(false), null)
                : (0, "unlimited")).ConfigureAwait(false);

        await Job("retention.webhook_attempts", async () =>
            RetentionCutoffs.InstantCutoff(now, r.WebhookAttemptLogDays) is { } c
                ? (await BatchDeleteAsync("webhook_attempt", "at < $1", c, ct).ConfigureAwait(false), null)
                : (0, "unlimited")).ConfigureAwait(false);

        await Job("stats.rollup", async () => (await RollupAsync(now, ct).ConfigureAwait(false), null)).ConfigureAwait(false);

        await Job("stats.retention", async () =>
        {
            long total = 0;
            if (RetentionCutoffs.StatsCutoff(now, r.StatsHourlyDays) is { } hourly)
            {
                total += await BatchDeleteAsync("stat_aggregate", "daily = false AND period_start < $1", hourly, ct).ConfigureAwait(false);
            }

            if (RetentionCutoffs.StatsCutoff(now, r.StatsDailyDays) is { } daily)
            {
                total += await BatchDeleteAsync("stat_aggregate", "daily = true AND period_start < $1", daily, ct).ConfigureAwait(false);
            }

            return (total, null);
        }).ConfigureAwait(false);

        await Job("idempotency.expired", async () => (await BatchDeleteAsync("api_idempotency_key", "expires_at <= $1", now, ct).ConfigureAwait(false), null)).ConfigureAwait(false);

        // Leases of dead workers are already claimable (a claim only needs lease_until <= now); this clears the stale owner names.
        await Job("queue.leases", async () => (await queue.ReleaseExpiredLeasesAsync(now, ct).ConfigureAwait(false), "clears expired lease owners")).ConfigureAwait(false);

        return reports;
    }

    private async Task ExecuteOwnerAsync(string sql, CancellationToken ct)
    {
        await using NpgsqlConnection connection = await rt.Owner.OpenConnectionAsync(ct).ConfigureAwait(false);
        await using var cmd = new NpgsqlCommand(sql, connection) { CommandTimeout = 600 };
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Deletes rows in batches of <c>RetentionDeleteBatchSize</c>, each its own short transaction, with a pause between them.</summary>
    private async Task<long> BatchDeleteAsync(string table, string where, DateTimeOffset cutoff, CancellationToken ct)
    {
        PostgresOptions o = rt.Options.Postgres;
        long total = 0;
        while (true)
        {
            await using NpgsqlConnection connection = await rt.Data.OpenConnectionAsync(ct).ConfigureAwait(false);
            await using var cmd = new NpgsqlCommand(
                $"DELETE FROM {table} WHERE ctid IN (SELECT ctid FROM {table} WHERE {where} LIMIT $2)", connection);
            cmd.Parameters.Time(cutoff).Long(o.RetentionDeleteBatchSize);
            int n = await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            total += n;
            if (n < o.RetentionDeleteBatchSize)
            {
                return total;
            }

            await Task.Delay(o.RetentionDeletePause, ct).ConfigureAwait(false);
        }
    }

    private const string RollupInsertSql =
        "INSERT INTO stat_aggregate (daily, period_start, tenant_id, sending_domain, recipient_domain, accepted, delivered, deferred, hard_bounce, soft_bounce, expired, complained, rejected, suppressed) " +
        "SELECT true, $1, tenant_id, sending_domain, " +
        "CASE WHEN recipient_domain <> 'other' AND rn <= $3 THEN recipient_domain ELSE 'other' END AS dom, " +
        "SUM(accepted)::bigint, SUM(delivered)::bigint, SUM(deferred)::bigint, SUM(hard_bounce)::bigint, SUM(soft_bounce)::bigint, SUM(expired)::bigint, SUM(complained)::bigint, SUM(rejected)::bigint, SUM(suppressed)::bigint FROM (" +
        "SELECT tenant_id, sending_domain, recipient_domain, accepted, delivered, deferred, hard_bounce, soft_bounce, expired, complained, rejected, suppressed, " +
        "ROW_NUMBER() OVER (PARTITION BY tenant_id, sending_domain ORDER BY (recipient_domain = 'other') ASC, total DESC, recipient_domain ASC) AS rn FROM (" +
        "SELECT tenant_id, sending_domain, recipient_domain, SUM(accepted)::bigint AS accepted, SUM(delivered)::bigint AS delivered, SUM(deferred)::bigint AS deferred, SUM(hard_bounce)::bigint AS hard_bounce, " +
        "SUM(soft_bounce)::bigint AS soft_bounce, SUM(expired)::bigint AS expired, SUM(complained)::bigint AS complained, SUM(rejected)::bigint AS rejected, SUM(suppressed)::bigint AS suppressed, " +
        "SUM(accepted + delivered + deferred + hard_bounce + soft_bounce + expired + complained + rejected + suppressed)::bigint AS total " +
        "FROM stat_aggregate WHERE daily = false AND period_start >= $1 AND period_start < $2 GROUP BY tenant_id, sending_domain, recipient_domain) a) b " +
        "GROUP BY tenant_id, sending_domain, dom";

    /// <summary>Hourly to daily: one transaction per completed day (delete the day's rows, insert the ranked sums), then the watermark.</summary>
    private async Task<long> RollupAsync(DateTimeOffset now, CancellationToken ct)
    {
        int? watermark = null;
        int? firstDay = null;
        await using NpgsqlConnection connection = await rt.Data.OpenConnectionAsync(ct).ConfigureAwait(false);
        await using (var cmd = new NpgsqlCommand("SELECT value FROM stat_meta WHERE key = 'rollup_watermark'", connection))
        {
            if (await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false) is { } v)
            {
                watermark = Convert.ToInt32(v, CultureInfo.InvariantCulture);
            }
        }

        await using (var cmd = new NpgsqlCommand("SELECT MIN(period_start) FROM stat_aggregate WHERE daily = false", connection))
        {
            await using NpgsqlDataReader fr = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            if (await fr.ReadAsync(ct).ConfigureAwait(false) && !fr.IsDBNull(0))
            {
                firstDay = StorageTime.DayNumber(fr.GetInstant(0));
            }
        }

        (int first0, int last) = StatsRollup.DaysToRoll(now, watermark, firstDay);
        if (last < first0)
        {
            return 0;
        }

        var days = new List<int>();
        await using (var cmd = new NpgsqlCommand(
            "SELECT DISTINCT floor(extract(epoch FROM period_start) / 86400)::int FROM stat_aggregate WHERE daily = false AND period_start >= $1 AND period_start < $2 ORDER BY 1", connection))
        {
            cmd.Parameters.Time(StorageTime.DayStart(first0)).Time(StorageTime.DayStart(last + 1));
            await using NpgsqlDataReader r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await r.ReadAsync(ct).ConfigureAwait(false))
            {
                days.Add(r.GetInt32(0));
            }
        }

        long written = 0;
        int topN = rt.Options.Retention.RecipientDomainTopNDaily;
        foreach (int day in days)
        {
            await using NpgsqlTransaction tx = await connection.BeginTransactionAsync(ct).ConfigureAwait(false);
            DateTimeOffset start = StorageTime.DayStart(day);
            await using (var del = new NpgsqlCommand("DELETE FROM stat_aggregate WHERE daily = true AND period_start = $1", connection, tx))
            {
                del.Parameters.Time(start);
                await del.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            }

            await using (var ins = new NpgsqlCommand(RollupInsertSql, connection, tx))
            {
                ins.Parameters.Time(start).Time(start.AddDays(1)).Long(topN);
                written += await ins.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            }

            await tx.CommitAsync(ct).ConfigureAwait(false);
        }

        await using (var set = new NpgsqlCommand(
            "INSERT INTO stat_meta (key, value) VALUES ('rollup_watermark', $1) ON CONFLICT (key) DO UPDATE SET value = excluded.value", connection))
        {
            set.Parameters.Long(last);
            await set.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        return written;
    }

    public async ValueTask<StorageHealth> GetHealthAsync(CancellationToken ct)
    {
        var warnings = new List<string>();
        var details = new Dictionary<string, string>
        {
            ["backend"] = "postgres",
            ["history_mode"] = rt.Options.History.Mode.ToString(),
            ["role_split"] = rt.SingleRole ? "false" : "true",
            ["runtime_role"] = rt.RuntimeRole ?? "",
            ["owner_role"] = rt.OwnerRole ?? "",
            ["schema_version_expected"] = PostgresMigrator.CurrentVersion.ToString(CultureInfo.InvariantCulture),
        };

        bool ready;
        try
        {
            // One connection at a time: the connection of the first query is returned before the next one is opened.
            await using (NpgsqlConnection c = await rt.Data.OpenConnectionAsync(ct).ConfigureAwait(false))
            await using (var cmd = new NpgsqlCommand("SELECT current_setting('server_version'), pg_is_in_recovery()", c))
            {
                await using NpgsqlDataReader r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
                await r.ReadAsync(ct).ConfigureAwait(false);
                details["server_version"] = r.GetString(0);
                if (r.GetBoolean(1))
                {
                    warnings.Add("postgres_read_only_replica");
                }
            }

            int version = await PostgresMigrator.GetDatabaseVersionAsync(rt.Data, ct).ConfigureAwait(false);
            details["schema_version"] = version.ToString(CultureInfo.InvariantCulture);
            ready = version == PostgresMigrator.CurrentVersion;
            if (!ready)
            {
                warnings.Add("postgres_schema_version_mismatch");
            }

            if (rt.IsFull && ready)
            {
                IReadOnlyList<DayPartition> partitions = await rt.Partitions.ListAsync(ct).ConfigureAwait(false);
                details["partitions"] = partitions.Count.ToString(CultureInfo.InvariantCulture);
                int today = StorageTime.DayNumber(rt.Clock.UtcNow);
                foreach (string table in PostgresPartitions.Tables)
                {
                    if (!partitions.Any(p => p.Table == table && p.Day == today))
                    {
                        warnings.Add("postgres_partition_missing:" + table);
                    }
                }
            }
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex))
        {
            ready = false;
            warnings.Add("postgres_unavailable");
            details["error"] = rt.Unavailable(ex).Message;
        }

        if (rt.SingleRole)
        {
            warnings.Add("postgres_single_role");
        }

        foreach (string knob in StorageOptionsValidation.UnlimitedRetentionKnobs(rt.Options))
        {
            warnings.Add("retention_unlimited:" + knob);
        }

        return new StorageHealth(ready, warnings, details);
    }

    /// <summary>PostgreSQL is backed up with <c>pg_dump</c> / base backups / PITR by the database operator; there is nothing to do in-process.</summary>
    public ValueTask<string?> BackupAsync(string directory, CancellationToken ct) => ValueTask.FromResult<string?>(null);
}

/// <summary>
/// A transaction-level advisory lock held on a dedicated connection: the connection stays inside an open transaction until
/// disposed, while the protected work runs on other connections (needed for statements that cannot run in a transaction block).
/// </summary>
internal sealed class AdvisoryLock : IAsyncDisposable
{
    private readonly NpgsqlConnection _connection;
    private readonly NpgsqlTransaction _transaction;

    private AdvisoryLock(NpgsqlConnection connection, NpgsqlTransaction transaction)
    {
        _connection = connection;
        _transaction = transaction;
    }

    /// <summary>Takes the lock without waiting; null when another session holds it.</summary>
    public static async Task<AdvisoryLock?> TryAcquireAsync(NpgsqlDataSource dataSource, long key, CancellationToken ct)
    {
        NpgsqlConnection connection = await dataSource.OpenConnectionAsync(ct).ConfigureAwait(false);
        try
        {
            NpgsqlTransaction tx = await connection.BeginTransactionAsync(ct).ConfigureAwait(false);
            await using var cmd = new NpgsqlCommand("SELECT pg_try_advisory_xact_lock($1)", connection, tx);
            cmd.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlTypes.NpgsqlDbType.Bigint, Value = key });
            if ((bool)(await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false))!)
            {
                return new AdvisoryLock(connection, tx);
            }

            await tx.DisposeAsync().ConfigureAwait(false);
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }

        await connection.DisposeAsync().ConfigureAwait(false);
        return null;
    }

    public async ValueTask DisposeAsync()
    {
        await _transaction.CommitAsync().ConfigureAwait(false);
        await _transaction.DisposeAsync().ConfigureAwait(false);
        await _connection.DisposeAsync().ConfigureAwait(false);
    }
}
