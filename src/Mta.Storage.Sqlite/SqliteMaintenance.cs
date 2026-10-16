using System.Diagnostics;
using System.Globalization;
using Microsoft.Data.Sqlite;
using Mta.Core;
using Mta.Storage.Logic;

namespace Mta.Storage.Sqlite;

/// <summary>A file that failed its startup integrity check and was moved aside.</summary>
public sealed record QuarantineEvent(string File, string QuarantinedTo, string Reason, DateTimeOffset At);

internal static class MaintenanceSql
{
    private static Stmt Batch(string table, string keys, string where) =>
        new($"DELETE FROM {table} WHERE ({keys}) IN (SELECT {keys} FROM {table} WHERE {where} LIMIT @n)", "@c", "@n");

    public static readonly Stmt Events = Batch("message_event", "day, message_id, event_id", "day < @c");
    public static readonly Stmt Recipients = Batch("message_recipient", "day, message_id, recipient", "day < @c");
    public static readonly Stmt Index = Batch("message_index", "day, message_id", "day < @c");
    public static readonly Stmt Content = new("DELETE FROM message_content WHERE rowid IN (SELECT rowid FROM message_content WHERE day < @c LIMIT @n)", "@c", "@n");
    public static readonly Stmt RetainedRaw = new("DELETE FROM message_raw_retained WHERE rowid IN (SELECT rowid FROM message_raw_retained WHERE day < @c LIMIT @n)", "@c", "@n");
    public static readonly Stmt Outbox = new("DELETE FROM webhook_outbox WHERE id IN (SELECT id FROM webhook_outbox WHERE finished_at IS NOT NULL AND finished_at < @c LIMIT @n)", "@c", "@n");
    public static readonly Stmt Attempts = new("DELETE FROM webhook_attempt WHERE seq IN (SELECT seq FROM webhook_attempt WHERE \"at\" < @c LIMIT @n)", "@c", "@n");
    public static readonly Stmt Idempotency = Batch("api_idempotency_key", "tenant_id, idempotency_key", "expires_at <= @c");
    public static readonly Stmt HourlyStats = Batch("stat_aggregate", "daily, period_start, tenant_id, sending_domain, recipient_domain", "daily = 0 AND period_start < @c");
    public static readonly Stmt DailyStats = Batch("stat_aggregate", "daily, period_start, tenant_id, sending_domain, recipient_domain", "daily = 1 AND period_start < @c");
}

internal sealed class SqliteMaintenance(SqliteRuntime rt, SqliteQueueStore queue, SqliteStatsStore stats, string dataDirectory, IReadOnlyList<QuarantineEvent> quarantine) : IStorageMaintenance
{
    public async ValueTask<IReadOnlyList<MaintenanceReport>> RunAsync(DateTimeOffset now, CancellationToken ct)
    {
        if (rt.Fence.IsClosed)
        {
            // A fenced source stays untouched until the switch is finalized or rolled back; a target is not live yet.
            return [];
        }

        now = StorageTime.Normalize(now);
        var reports = new List<MaintenanceReport>();
        RetentionOptions r = rt.Options.Retention;
        var touched = new HashSet<SqliteFileWriter>();

        async Task Job(string name, SqliteFileWriter writer, Func<Task<long>> body, string? detail = null)
        {
            long start = Stopwatch.GetTimestamp();
            long rows = await body().ConfigureAwait(false);
            if (rows > 0)
            {
                touched.Add(writer);
            }

            reports.Add(new MaintenanceReport(name, Stopwatch.GetElapsedTime(start), rows, detail));
        }

        await stats.FlushAsync(ct).ConfigureAwait(false);

        if (rt.IsFull)
        {
            SqliteFileWriter h = rt.HistoryWriter!;
            await Job("retention.metadata", h, async () =>
            {
                if (RetentionCutoffs.DayKeyCutoff(now, r.MetadataDays) is not { } day)
                {
                    return 0;
                }

                long total = 0;
                total += await BatchDeleteAsync(h, MaintenanceSql.Events, day, ct).ConfigureAwait(false);
                total += await BatchDeleteAsync(h, MaintenanceSql.Recipients, day, ct).ConfigureAwait(false);
                total += await BatchDeleteAsync(h, MaintenanceSql.Index, day, ct).ConfigureAwait(false);
                return total;
            }).ConfigureAwait(false);

            await Job("retention.content", h, async () =>
            {
                if (RetentionCutoffs.DayKeyCutoff(now, rt.Options.Content.RetentionDays) is not { } day)
                {
                    return 0;
                }

                long total = await BatchDeleteAsync(h, MaintenanceSql.Content, day, ct).ConfigureAwait(false);
                return total + await BatchDeleteAsync(h, MaintenanceSql.RetainedRaw, day, ct).ConfigureAwait(false);
            }).ConfigureAwait(false);
        }
        else
        {
            reports.Add(new MaintenanceReport("retention.metadata", TimeSpan.Zero, 0, "history not recorded (StatsOnly)"));
            reports.Add(new MaintenanceReport("retention.content", TimeSpan.Zero, 0, "history not recorded (StatsOnly)"));
        }

        await Job("retention.webhook_outbox", rt.QueueWriter, async () =>
            RetentionCutoffs.InstantCutoff(now, r.WebhookOutboxDays) is { } c ? await BatchDeleteAsync(rt.QueueWriter, MaintenanceSql.Outbox, StorageTime.ToUnixMs(c), ct).ConfigureAwait(false) : 0).ConfigureAwait(false);

        await Job("retention.webhook_attempts", rt.StatsWriter, async () =>
            RetentionCutoffs.InstantCutoff(now, r.WebhookAttemptLogDays) is { } c ? await BatchDeleteAsync(rt.StatsWriter, MaintenanceSql.Attempts, StorageTime.ToUnixMs(c), ct).ConfigureAwait(false) : 0).ConfigureAwait(false);

        await Job("stats.rollup", rt.StatsWriter, () => RollupAsync(now, ct)).ConfigureAwait(false);

        await Job("stats.retention", rt.StatsWriter, async () =>
        {
            long total = 0;
            if (RetentionCutoffs.StatsCutoff(now, r.StatsHourlyDays) is { } hourly)
            {
                total += await BatchDeleteAsync(rt.StatsWriter, MaintenanceSql.HourlyStats, StorageTime.ToUnixMs(hourly), ct).ConfigureAwait(false);
            }

            if (RetentionCutoffs.StatsCutoff(now, r.StatsDailyDays) is { } daily)
            {
                total += await BatchDeleteAsync(rt.StatsWriter, MaintenanceSql.DailyStats, StorageTime.ToUnixMs(daily), ct).ConfigureAwait(false);
            }

            return total;
        }).ConfigureAwait(false);

        await Job("idempotency.expired", rt.QueueWriter, async () => await BatchDeleteAsync(rt.QueueWriter, MaintenanceSql.Idempotency, StorageTime.ToUnixMs(now), ct).ConfigureAwait(false)).ConfigureAwait(false);

        await Job("inbound_retention", rt.QueueWriter, async () =>
        {
            IReadOnlyDictionary<Guid, int?> retention = await rt.ConfigStore.GetInboundRetentionByDomainAsync(ct).ConfigureAwait(false);
            SqliteOptions sqlite = rt.Options.Sqlite;
            return await rt.InboundMessages.PurgeExpiredAsync(retention, rt.Options.Inbound.RetentionDays, rt.Options.Inbound.MaxRetentionDays, now, sqlite.RetentionDeleteBatchSize, sqlite.RetentionDeletePause, ct).ConfigureAwait(false);
        }).ConfigureAwait(false);

        await Job("queue.reconcile", rt.QueueWriter, async () => await queue.ReconcileSpoolAsync(ct).ConfigureAwait(false),
            "finishes interrupted retained-raw hand-overs between queue.db and history.db").ConfigureAwait(false);

        // Housekeeping: return freed pages after deletes, then checkpoint the WAL (PASSIVE never blocks; TRUNCATE only when idle).
        long housekeeping = Stopwatch.GetTimestamp();
        long pages = 0;
        foreach (SqliteFileWriter w in rt.Writers)
        {
            if (touched.Contains(w) && !w.File.IsMemory)
            {
                pages += await w.SubmitAsync(0, static (ctx, _) => IncrementalVacuum(ctx.Connection), ct, exclusive: true).ConfigureAwait(false);
            }

            if (!w.File.IsMemory)
            {
                await w.SubmitAsync(0, static (ctx, _) => Checkpoint(ctx.Connection, "PASSIVE"), ct, exclusive: true).ConfigureAwait(false);
            }
        }

        reports.Add(new MaintenanceReport("vacuum.incremental", Stopwatch.GetElapsedTime(housekeeping), pages, null));

        long truncated = 0;
        foreach (SqliteFileWriter w in rt.Writers)
        {
            if (!w.File.IsMemory && w.Metrics.QueueDepth == 0)
            {
                truncated += await w.SubmitAsync(0, static (ctx, _) => Checkpoint(ctx.Connection, "TRUNCATE"), ct, exclusive: true).ConfigureAwait(false);
            }
        }

        reports.Add(new MaintenanceReport("wal.checkpoint", TimeSpan.Zero, truncated, "PASSIVE after batches, TRUNCATE when idle"));
        return reports;
    }

    private async Task<long> BatchDeleteAsync(SqliteFileWriter writer, Stmt stmt, long cutoff, CancellationToken ct)
    {
        SqliteOptions s = rt.Options.Sqlite;
        long total = 0;
        while (true)
        {
            int n = await writer.SubmitAsync((stmt, cutoff, s.RetentionDeleteBatchSize), static (ctx, st) =>
                ctx.Command(st.stmt).Set(0, st.cutoff).Set(1, (long)st.Item3).ExecuteNonQuery(), ct).ConfigureAwait(false);
            total += n;
            if (n < s.RetentionDeleteBatchSize)
            {
                return total;
            }

            // Short pause so intake and claims interleave with the deletes.
            await Task.Delay(s.RetentionDeletePause, ct).ConfigureAwait(false);
        }
    }

    private async Task<long> RollupAsync(DateTimeOffset now, CancellationToken ct)
    {
        SqliteFileWriter w = rt.StatsWriter;
        (int? watermark, int? firstDay) = await rt.ReadAsync(rt.Stats, w, 0, static (c, _) =>
        {
            int? wm = null;
            using (SqliteCommand cmd = c.CreateCommand())
            {
                cmd.CommandText = "SELECT value FROM stat_meta WHERE key = 'rollup_watermark'";
                if (cmd.ExecuteScalar() is { } v)
                {
                    wm = Convert.ToInt32(v, CultureInfo.InvariantCulture);
                }
            }

            int? first = null;
            using (SqliteCommand cmd = c.CreateCommand())
            {
                cmd.CommandText = "SELECT MIN(period_start) FROM stat_aggregate WHERE daily = 0";
                if (cmd.ExecuteScalar() is { } v and not DBNull)
                {
                    first = StorageTime.DayNumber(StorageTime.FromUnixMs(Convert.ToInt64(v, CultureInfo.InvariantCulture)));
                }
            }

            return (wm, first);
        }).ConfigureAwait(false);

        (int first, int last) = StatsRollup.DaysToRoll(now, watermark, firstDay);
        if (last < first)
        {
            return 0;
        }

        var days = await rt.ReadAsync(rt.Stats, w, (first, last), static (c, range) =>
        {
            using SqliteCommand cmd = c.CreateCommand();
            cmd.CommandText = "SELECT DISTINCT period_start / 86400000 FROM stat_aggregate WHERE daily = 0 AND period_start >= @from AND period_start < @to ORDER BY 1";
            cmd.Parameters.AddWithValue("@from", StorageTime.ToUnixMs(StorageTime.DayStart(range.first)));
            cmd.Parameters.AddWithValue("@to", StorageTime.ToUnixMs(StorageTime.DayStart(range.last + 1)));
            var list = new List<int>();
            using SqliteDataReader r = cmd.ExecuteReader();
            while (r.Read())
            {
                list.Add((int)r.GetInt64(0));
            }

            return list;
        }).ConfigureAwait(false);

        long written = 0;
        int topN = rt.Options.Retention.RecipientDomainTopNDaily;
        foreach (int day in days)
        {
            written += await w.SubmitAsync((day, topN), static (ctx, s) =>
            {
                long start = StorageTime.ToUnixMs(StorageTime.DayStart(s.day));
                ctx.Command(StatsSql.RollupDelete).Set(0, start).ExecuteNonQuery();
                return ctx.Command(StatsSql.RollupInsert).Set(0, start).Set(1, start + 86_400_000L).Set(2, (long)s.topN).ExecuteNonQuery();
            }, ct).ConfigureAwait(false);
        }

        await w.SubmitAsync(last, static (ctx, watermarkDay) => ctx.Command(StatsSql.WatermarkSet).Set(0, (long)watermarkDay).ExecuteNonQuery(), ct).ConfigureAwait(false);
        return written;
    }

    private static int IncrementalVacuum(SqliteConnection c)
    {
        long free = Convert.ToInt64(SqliteFile.Scalar(c, "PRAGMA freelist_count"), CultureInfo.InvariantCulture);
        if (free <= 0)
        {
            return 0;
        }

        SqliteFile.Execute(c, "PRAGMA incremental_vacuum");
        return (int)Math.Min(free, int.MaxValue);
    }

    private static int Checkpoint(SqliteConnection c, string mode)
    {
        using SqliteCommand cmd = c.CreateCommand();
        cmd.CommandText = "PRAGMA wal_checkpoint(" + mode + ")";
        using SqliteDataReader r = cmd.ExecuteReader();
        return r.Read() && r.GetInt32(0) == 0 ? Math.Max(0, r.GetInt32(2)) : 0;
    }

    public ValueTask<StorageHealth> GetHealthAsync(CancellationToken ct)
    {
        var warnings = new List<string>();
        var details = new Dictionary<string, string>
        {
            ["backend"] = "sqlite",
            ["data_directory"] = dataDirectory,
            ["history_mode"] = rt.Options.History.Mode.ToString(),
            ["queue_persistence"] = rt.Options.Sqlite.QueuePersistence.ToString(),
        };

        var offFiles = new List<string>();
        foreach (SqliteFile f in rt.Files)
        {
            details["sync_mode." + f.Name] = f.IsMemory ? "memory" : f.Sync.ToString();
            details["wal_bytes." + f.Name] = f.WalSize().ToString(CultureInfo.InvariantCulture);
            if (!f.IsMemory && f.Sync == SqliteSyncMode.Off)
            {
                offFiles.Add(f.FileName);
            }
        }

        if (offFiles.Count > 0)
        {
            warnings.Add("sqlite_sync_off");
            details["sqlite_sync_off.files"] = string.Join(',', offFiles);
        }

        if (rt.Queue.IsMemory)
        {
            warnings.Add("queue_persistence_memory");
        }

        foreach (QuarantineEvent q in quarantine)
        {
            warnings.Add("sqlite_quarantined:" + q.File);
            details["quarantine." + q.File] = q.QuarantinedTo + " (" + q.Reason + ")";
        }

        foreach (string knob in StorageOptionsValidation.UnlimitedRetentionKnobs(rt.Options))
        {
            warnings.Add("retention_unlimited:" + knob);
        }

        foreach (SqliteFileWriter w in rt.Writers)
        {
            WriterMetrics m = w.Metrics;
            string k = "writer." + w.File.Name + ".";
            details[k + "batches"] = m.Batches.ToString(CultureInfo.InvariantCulture);
            details[k + "commands"] = m.Commands.ToString(CultureInfo.InvariantCulture);
            details[k + "max_batch"] = m.MaxBatchSize.ToString(CultureInfo.InvariantCulture);
            details[k + "queue_depth"] = m.QueueDepth.ToString(CultureInfo.InvariantCulture);
            details[k + "last_commit_ms"] = m.LastCommit.TotalMilliseconds.ToString("F3", CultureInfo.InvariantCulture);
        }

        return ValueTask.FromResult(new StorageHealth(true, warnings, details));
    }

    public async ValueTask<string?> BackupAsync(string directory, CancellationToken ct)
    {
        string target = Path.Combine(directory, "eggmail-backup-" + rt.Clock.UtcNow.ToString("yyyyMMddTHHmmssfff'Z'", CultureInfo.InvariantCulture));
        // The files are written under a work name and the directory is renamed when it is complete: a backup that is cancelled by a shutdown, fails (a full
        // disk) or is killed half-way never has the name of a backup, which the scheduler would count as the newest one.
        string work = target + ".partial";
        if (Directory.Exists(work))
        {
            Directory.Delete(work, recursive: true);   // the work directory of a killed run that had this very name (the same millisecond)
        }

        Directory.CreateDirectory(work);
        try
        {
            foreach (SqliteFile f in rt.Files)
            {
                if (f.IsMemory)
                {
                    continue;
                }

                // VACUUM INTO reads a consistent snapshot on its own connection; WAL lets the writer keep committing meanwhile.
                await Task.Run(() =>
                {
                    using SqliteConnection c = f.OpenReader();
                    using SqliteCommand cmd = c.CreateCommand();
                    cmd.CommandText = "VACUUM INTO @path";
                    cmd.Parameters.AddWithValue("@path", Path.Combine(work, f.FileName));
                    cmd.ExecuteNonQuery();
                }, ct).ConfigureAwait(false);
            }

            Directory.Move(work, target);
        }
        catch
        {
            try
            {
                Directory.Delete(work, recursive: true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // The scheduler removes leftovers of this name at its next run.
            }

            throw;
        }

        return target;
    }
}
