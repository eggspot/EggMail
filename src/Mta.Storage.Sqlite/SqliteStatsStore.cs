using Microsoft.Data.Sqlite;
using Mta.Core;
using Mta.Storage.Logic;

namespace Mta.Storage.Sqlite;

internal static class StatsSql
{
    public static readonly Stmt Upsert = new(
        "INSERT INTO stat_aggregate (daily, period_start, tenant_id, sending_domain, recipient_domain, accepted, delivered, deferred, hard_bounce, soft_bounce, expired, complained, rejected, suppressed) " +
        "VALUES (@daily, @p, @t, @s, @r, @c0, @c1, @c2, @c3, @c4, @c5, @c6, @c7, @c8) " +
        "ON CONFLICT (daily, period_start, tenant_id, sending_domain, recipient_domain) DO UPDATE SET " +
        "accepted = stat_aggregate.accepted + excluded.accepted, delivered = stat_aggregate.delivered + excluded.delivered, " +
        "deferred = stat_aggregate.deferred + excluded.deferred, hard_bounce = stat_aggregate.hard_bounce + excluded.hard_bounce, " +
        "soft_bounce = stat_aggregate.soft_bounce + excluded.soft_bounce, expired = stat_aggregate.expired + excluded.expired, " +
        "complained = stat_aggregate.complained + excluded.complained, rejected = stat_aggregate.rejected + excluded.rejected, " +
        "suppressed = stat_aggregate.suppressed + excluded.suppressed",
        "@daily", "@p", "@t", "@s", "@r", "@c0", "@c1", "@c2", "@c3", "@c4", "@c5", "@c6", "@c7", "@c8");

    public static readonly Stmt HourSeries = new(
        "SELECT tenant_id, sending_domain, recipient_domain FROM stat_aggregate WHERE daily = 0 AND period_start = @p", "@p");

    public static readonly Stmt RingInsert = new(
        "INSERT INTO recent_event (\"at\", tenant_id, event_type, recipient_domain, detail) VALUES (@at, @t, @type, @dom, @detail)",
        "@at", "@t", "@type", "@dom", "@detail");

    public static readonly Stmt RingTrim = new("DELETE FROM recent_event WHERE seq <= (SELECT MAX(seq) FROM recent_event) - @cap", "@cap");

    public static readonly Stmt AttemptInsert = new(
        "INSERT INTO webhook_attempt (outbox_id, endpoint_id, tenant_id, \"at\", status_code, duration_ms, error_class, response_snippet) VALUES (@o, @e, @t, @at, @code, @dur, @err, @snip)",
        "@o", "@e", "@t", "@at", "@code", "@dur", "@err", "@snip");

    public static readonly Stmt WatermarkGet = new("SELECT value FROM stat_meta WHERE key = 'rollup_watermark'");

    public static readonly Stmt WatermarkSet = new("INSERT INTO stat_meta (key, value) VALUES ('rollup_watermark', @v) ON CONFLICT (key) DO UPDATE SET value = excluded.value", "@v");

    public static readonly Stmt FirstHourly = new("SELECT MIN(period_start) FROM stat_aggregate WHERE daily = 0");

    public static readonly Stmt HourlyDays = new(
        "SELECT DISTINCT period_start / 86400000 FROM stat_aggregate WHERE daily = 0 AND period_start >= @from AND period_start < @to", "@from", "@to");

    public static readonly Stmt RollupDelete = new("DELETE FROM stat_aggregate WHERE daily = 1 AND period_start = @s", "@s");

    /// <summary>
    /// Folds one day of hourly rows into daily rows: ranks the recipient domains of each (tenant, sending domain) group by
    /// total volume (ties by name, "other" last) and keeps the top N; everything else becomes "other".
    /// </summary>
    public static readonly Stmt RollupInsert = new(
        "INSERT INTO stat_aggregate (daily, period_start, tenant_id, sending_domain, recipient_domain, accepted, delivered, deferred, hard_bounce, soft_bounce, expired, complained, rejected, suppressed) " +
        "SELECT 1, @s, tenant_id, sending_domain, " +
        "CASE WHEN recipient_domain <> 'other' AND rn <= @n THEN recipient_domain ELSE 'other' END AS dom, " +
        "SUM(accepted), SUM(delivered), SUM(deferred), SUM(hard_bounce), SUM(soft_bounce), SUM(expired), SUM(complained), SUM(rejected), SUM(suppressed) FROM (" +
        "SELECT tenant_id, sending_domain, recipient_domain, accepted, delivered, deferred, hard_bounce, soft_bounce, expired, complained, rejected, suppressed, " +
        "ROW_NUMBER() OVER (PARTITION BY tenant_id, sending_domain ORDER BY (recipient_domain = 'other') ASC, total DESC, recipient_domain ASC) AS rn FROM (" +
        "SELECT tenant_id, sending_domain, recipient_domain, SUM(accepted) AS accepted, SUM(delivered) AS delivered, SUM(deferred) AS deferred, SUM(hard_bounce) AS hard_bounce, " +
        "SUM(soft_bounce) AS soft_bounce, SUM(expired) AS expired, SUM(complained) AS complained, SUM(rejected) AS rejected, SUM(suppressed) AS suppressed, " +
        "SUM(accepted) + SUM(delivered) + SUM(deferred) + SUM(hard_bounce) + SUM(soft_bounce) + SUM(expired) + SUM(complained) + SUM(rejected) + SUM(suppressed) AS total " +
        "FROM stat_aggregate WHERE daily = 0 AND period_start >= @s AND period_start < @e GROUP BY tenant_id, sending_domain, recipient_domain)) " +
        "GROUP BY tenant_id, sending_domain, dom",
        "@s", "@e", "@n");
}

internal readonly record struct FlushState(List<StatDelta> Deltas, List<RecentEvent> Ring, int RingCapacity);

/// <summary>Statistics, the recent-events ring and the webhook attempt log on stats.db.</summary>
internal sealed class SqliteStatsStore : IStatsStore
{
    private readonly SqliteRuntime _rt;
    private readonly StatsBucketer _bucketer;
    private WriterContext? _activeContext; // only touched on the stats writer thread

    public SqliteStatsStore(SqliteRuntime rt)
    {
        _rt = rt;
        _bucketer = new StatsBucketer(rt.Options.Retention, LoadHourSeries);
    }

    /// <summary>Called by the writer when a batch is rolled back: the bucketer's cache may be ahead of the store.</summary>
    internal void ResetBucketer() => _bucketer.Reset();

    private IEnumerable<(Guid Tenant, string Sending, string Recipient)> LoadHourSeries(DateTimeOffset hour)
    {
        var list = new List<(Guid, string, string)>();
        using SqliteDataReader r = _activeContext!.Command(StatsSql.HourSeries).Set(0, StorageTime.ToUnixMs(hour)).ExecuteReader();
        while (r.Read())
        {
            list.Add((r.GetGuid(0), r.GetString(1), r.GetString(2)));
        }

        return list;
    }

    public void Add(in StatKey key, StatCounter counter, long count = 1) => _rt.Aggregator.Add(key, counter, count);

    public async ValueTask FlushAsync(CancellationToken cancellationToken)
    {
        List<StatDelta> deltas = _rt.Aggregator.Drain(_rt.Clock.UtcNow);
        List<RecentEvent> ring = _rt.Aggregator.DrainRecent();
        if (deltas.Count == 0 && ring.Count == 0)
        {
            return;
        }

        try
        {
            await _rt.StatsWriter.SubmitAsync(new FlushState(deltas, ring, Math.Max(0, _rt.Options.History.RecentEvents)), FlushCommand(this), cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            _rt.Aggregator.Restore(deltas);
            _rt.Aggregator.RestoreRecent(ring);
            throw;
        }
    }

    private static Func<WriterContext, FlushState, int> FlushCommand(SqliteStatsStore self) => (ctx, s) =>
    {
        self._activeContext = ctx;
        try
        {
            SqliteCommand upsert = ctx.Command(StatsSql.Upsert);
            foreach (StatDelta d in self._bucketer.Apply(s.Deltas))
            {
                upsert.Set(0, 0).Set(1, StorageTime.ToUnixMs(d.Key.HourStart)).Set(2, d.Key.TenantId).Set(3, d.Key.SendingDomain).Set(4, d.Key.RecipientDomain);
                for (int i = 0; i < StatDelta.CounterCount; i++)
                {
                    upsert.Set(5 + i, d.Counts[i]);
                }

                upsert.ExecuteNonQuery();
            }

            if (s.RingCapacity > 0 && s.Ring.Count > 0)
            {
                SqliteCommand ring = ctx.Command(StatsSql.RingInsert);
                foreach (RecentEvent e in s.Ring)
                {
                    ring.Set(0, StorageTime.ToUnixMs(e.At)).Set(1, e.TenantId).Set(2, e.EventType).Set(3, e.RecipientDomain).Set(4, e.Detail).ExecuteNonQuery();
                }

                ctx.Command(StatsSql.RingTrim).Set(0, (long)s.RingCapacity).ExecuteNonQuery();
            }

            return 0;
        }
        finally
        {
            self._activeContext = null;
        }
    };

    internal static readonly Func<WriterContext, (Guid OutboxId, Guid EndpointId, Guid TenantId, WebhookAttemptRecord Attempt), int> InsertWebhookAttempt = static (ctx, s) =>
        ctx.Command(StatsSql.AttemptInsert)
            .Set(0, s.OutboxId).Set(1, s.EndpointId).Set(2, s.TenantId).Set(3, StorageTime.ToUnixMs(s.Attempt.At)).Set(4, s.Attempt.StatusCode)
            .Set(5, (long)s.Attempt.Duration.TotalMilliseconds).Set(6, s.Attempt.ErrorClass).Set(7, s.Attempt.ResponseSnippet)
            .ExecuteNonQuery();

    public ValueTask<IReadOnlyList<StatRow>> QueryAsync(Guid? tenantId, DateTimeOffset from, DateTimeOffset to, bool daily, CancellationToken cancellationToken)
    {
        using SqliteConnection c = _rt.Stats.OpenReader();
        using SqliteCommand cmd = c.CreateCommand();
        cmd.CommandText =
            "SELECT period_start, tenant_id, sending_domain, recipient_domain, accepted, delivered, deferred, hard_bounce, soft_bounce, expired, complained, rejected, suppressed " +
            "FROM stat_aggregate WHERE daily = @d AND period_start >= @from AND period_start < @to" + (tenantId is null ? "" : " AND tenant_id = @t") +
            " ORDER BY period_start, tenant_id, sending_domain, recipient_domain";
        cmd.Parameters.AddWithValue("@d", daily ? 1 : 0);
        cmd.Parameters.AddWithValue("@from", StorageTime.ToUnixMs(from));
        cmd.Parameters.AddWithValue("@to", StorageTime.ToUnixMs(to));
        if (tenantId is { } t)
        {
            cmd.Parameters.AddWithValue("@t", t);
        }

        var rows = new List<StatRow>();
        using SqliteDataReader r = cmd.ExecuteReader();
        while (r.Read())
        {
            rows.Add(new StatRow
            {
                PeriodStart = r.GetInstant(0),
                Daily = daily,
                TenantId = r.GetGuid(1),
                SendingDomain = r.GetString(2),
                RecipientDomain = r.GetString(3),
                Accepted = r.GetInt64(4),
                Delivered = r.GetInt64(5),
                Deferred = r.GetInt64(6),
                HardBounce = r.GetInt64(7),
                SoftBounce = r.GetInt64(8),
                Expired = r.GetInt64(9),
                Complained = r.GetInt64(10),
                Rejected = r.GetInt64(11),
                Suppressed = r.GetInt64(12),
            });
        }

        return ValueTask.FromResult<IReadOnlyList<StatRow>>(rows);
    }

    public ValueTask<IReadOnlyList<RecentEvent>> GetRecentEventsAsync(Guid? tenantId, int max, CancellationToken cancellationToken)
    {
        using SqliteConnection c = _rt.Stats.OpenReader();
        using SqliteCommand cmd = c.CreateCommand();
        cmd.CommandText = "SELECT \"at\", tenant_id, event_type, recipient_domain, detail FROM recent_event" + (tenantId is null ? "" : " WHERE tenant_id = @t") + " ORDER BY seq DESC LIMIT @n";
        if (tenantId is { } t)
        {
            cmd.Parameters.AddWithValue("@t", t);
        }

        cmd.Parameters.AddWithValue("@n", (long)Math.Max(0, max));
        var list = new List<RecentEvent>();
        using SqliteDataReader r = cmd.ExecuteReader();
        while (r.Read())
        {
            list.Add(new RecentEvent(r.GetInstant(0), r.GetGuid(1), r.GetString(2), r.GetString(3), r.GetNullableString(4)));
        }

        return ValueTask.FromResult<IReadOnlyList<RecentEvent>>(list);
    }
}
