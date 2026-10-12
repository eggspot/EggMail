using Mta.Storage.Logic;
using Npgsql;

namespace Mta.Storage.Postgres;

/// <summary>
/// Statistics, the recent-events ring and the shared hourly upsert (design §4.5). Counters accumulate in memory
/// (<see cref="StatsAggregator"/>) and are flushed about every 10 s, on <see cref="FlushAsync"/> and on dispose: one
/// transaction with <c>INSERT … ON CONFLICT DO UPDATE</c> (all series in one statement via <c>unnest</c>), the ring rows and
/// the ring trim. The recipient-domain top-N is the shared <see cref="StatsBucketer"/>, so the result is identical to SQLite.
/// <para>Several replicas flush the same hourly rows. Rows are written in a fixed key order so two flushes cannot deadlock;
/// the top-N is approximate across flushes and replicas of one hour (documented gap), and the daily rollup re-ranks by real volume.</para>
/// </summary>
internal sealed class PostgresStatsStore : IStatsStore
{
    private const int UpsertChunk = 2000;

    private const string UpsertSql =
        "INSERT INTO stat_aggregate (daily, period_start, tenant_id, sending_domain, recipient_domain, accepted, delivered, deferred, hard_bounce, soft_bounce, expired, complained, rejected, suppressed) " +
        "SELECT false, u.p, u.t, u.s, u.r, u.c0, u.c1, u.c2, u.c3, u.c4, u.c5, u.c6, u.c7, u.c8 " +
        "FROM unnest($1::timestamptz[], $2::uuid[], $3::text[], $4::text[], $5::bigint[], $6::bigint[], $7::bigint[], $8::bigint[], $9::bigint[], $10::bigint[], $11::bigint[], $12::bigint[], $13::bigint[]) AS u(p, t, s, r, c0, c1, c2, c3, c4, c5, c6, c7, c8) " +
        "ON CONFLICT (daily, period_start, tenant_id, sending_domain, recipient_domain) DO UPDATE SET " +
        "accepted = stat_aggregate.accepted + excluded.accepted, delivered = stat_aggregate.delivered + excluded.delivered, " +
        "deferred = stat_aggregate.deferred + excluded.deferred, hard_bounce = stat_aggregate.hard_bounce + excluded.hard_bounce, " +
        "soft_bounce = stat_aggregate.soft_bounce + excluded.soft_bounce, expired = stat_aggregate.expired + excluded.expired, " +
        "complained = stat_aggregate.complained + excluded.complained, rejected = stat_aggregate.rejected + excluded.rejected, " +
        "suppressed = stat_aggregate.suppressed + excluded.suppressed";

    private readonly PostgresRuntime _rt;
    private readonly StatsBucketer _bucketer;
    private readonly SemaphoreSlim _flushGate = new(1, 1);
    private Dictionary<DateTimeOffset, List<(Guid, string, string)>> _preloaded = [];

    public PostgresStatsStore(PostgresRuntime rt)
    {
        _rt = rt;
        _bucketer = new StatsBucketer(rt.Options.Retention, hour => _preloaded.TryGetValue(hour, out var list) ? list : []);
    }

    public void Add(in StatKey key, StatCounter counter, long count = 1) => _rt.Aggregator.Add(key, counter, count);

    public async ValueTask FlushAsync(CancellationToken cancellationToken)
    {
        await _flushGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            List<StatDelta> deltas = _rt.Aggregator.Drain(_rt.Clock.UtcNow);
            List<RecentEvent> ring = _rt.Aggregator.DrainRecent();
            if (deltas.Count == 0 && ring.Count == 0)
            {
                return;
            }

            try
            {
                await WriteAsync(deltas, ring, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _rt.Aggregator.Restore(deltas);
                _rt.Aggregator.RestoreRecent(ring);
                if (PostgresErrors.IsUnavailable(ex))
                {
                    throw PostgresErrors.Unavailable(ex);
                }

                throw;
            }
        }
        finally
        {
            _flushGate.Release();
        }
    }

    private async Task WriteAsync(List<StatDelta> deltas, List<RecentEvent> ring, CancellationToken ct)
    {
        await using NpgsqlConnection connection = await _rt.Data.OpenConnectionAsync(ct).ConfigureAwait(false);
        await using NpgsqlTransaction tx = await connection.BeginTransactionAsync(ct).ConfigureAwait(false);

        // The cache of "which series does this hour already have" is reloaded from the table for every flush, so other
        // replicas' series count too and a rolled-back flush cannot leave it ahead of the store.
        _bucketer.Reset();
        _preloaded = [];
        foreach (DateTimeOffset hour in deltas.Select(d => d.Key.HourStart).Distinct())
        {
            var list = new List<(Guid, string, string)>();
            await using var cmd = new NpgsqlCommand("SELECT tenant_id, sending_domain, recipient_domain FROM stat_aggregate WHERE daily = false AND period_start = $1", connection, tx);
            cmd.Parameters.Time(hour);
            await using NpgsqlDataReader r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await r.ReadAsync(ct).ConfigureAwait(false))
            {
                list.Add((r.GetGuid(0), r.GetString(1), r.GetString(2)));
            }

            _preloaded[hour] = list;
        }

        StatDelta[] rows = _bucketer.Apply(deltas)
            .OrderBy(d => d.Key.HourStart)
            .ThenBy(d => d.Key.TenantId.ToString(), StringComparer.Ordinal)
            .ThenBy(d => d.Key.SendingDomain, StringComparer.Ordinal)
            .ThenBy(d => d.Key.RecipientDomain, StringComparer.Ordinal)
            .ToArray();
        for (int offset = 0; offset < rows.Length; offset += UpsertChunk)
        {
            StatDelta[] chunk = rows[offset..Math.Min(rows.Length, offset + UpsertChunk)];
            await using var upsert = new NpgsqlCommand(UpsertSql, connection, tx);
            upsert.Parameters.TimeArray(chunk.Select(d => d.Key.HourStart).ToArray())
                .UuidArray(chunk.Select(d => d.Key.TenantId).ToArray())
                .TextArray(chunk.Select(d => d.Key.SendingDomain).ToArray())
                .TextArray(chunk.Select(d => d.Key.RecipientDomain).ToArray());
            for (int i = 0; i < StatDelta.CounterCount; i++)
            {
                int counter = i;
                upsert.Parameters.LongArray(chunk.Select(d => d.Counts[counter]).ToArray());
            }

            await upsert.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        int capacity = Math.Max(0, _rt.Options.History.RecentEvents);
        if (capacity > 0 && ring.Count > 0)
        {
            await using var insert = new NpgsqlCommand(
                "INSERT INTO recent_event (at, tenant_id, event_type, recipient_domain, detail) SELECT u.at, u.t, u.type, u.dom, u.detail " +
                "FROM unnest($1, $2, $3, $4, $5) WITH ORDINALITY AS u(at, t, type, dom, detail, ord) ORDER BY u.ord", connection, tx);
            insert.Parameters.TimeArray(ring.Select(e => StorageTime.Normalize(e.At)).ToArray())
                .UuidArray(ring.Select(e => e.TenantId).ToArray())
                .TextArray(ring.Select(e => e.EventType).ToArray())
                .TextArray(ring.Select(e => e.RecipientDomain).ToArray())
                .TextArray(ring.Select(e => e.Detail).ToArray());
            await insert.ExecuteNonQueryAsync(ct).ConfigureAwait(false);

            await using var trim = new NpgsqlCommand("DELETE FROM recent_event WHERE seq <= (SELECT MAX(seq) FROM recent_event) - $1", connection, tx);
            trim.Parameters.Long(capacity);
            await trim.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        await tx.CommitAsync(ct).ConfigureAwait(false);
    }

    public async ValueTask<IReadOnlyList<StatRow>> QueryAsync(Guid? tenantId, DateTimeOffset from, DateTimeOffset to, bool daily, CancellationToken cancellationToken)
    {
        try
        {
            await using NpgsqlConnection c = await _rt.Data.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var cmd = new NpgsqlCommand(
                "SELECT period_start, tenant_id, sending_domain, recipient_domain, accepted, delivered, deferred, hard_bounce, soft_bounce, expired, complained, rejected, suppressed " +
                "FROM stat_aggregate WHERE daily = $1 AND period_start >= $2 AND period_start < $3 AND ($4::uuid IS NULL OR tenant_id = $4) " +
                "ORDER BY period_start, tenant_id, sending_domain, recipient_domain", c);
            cmd.Parameters.Bool(daily).Time(from).Time(to).Uuid(tenantId);
            var rows = new List<StatRow>();
            await using NpgsqlDataReader r = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await r.ReadAsync(cancellationToken).ConfigureAwait(false))
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

            return rows;
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex))
        {
            throw PostgresErrors.Unavailable(ex);
        }
    }

    public async ValueTask<IReadOnlyList<RecentEvent>> GetRecentEventsAsync(Guid? tenantId, int max, CancellationToken cancellationToken)
    {
        try
        {
            await using NpgsqlConnection c = await _rt.Data.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var cmd = new NpgsqlCommand(
                "SELECT at, tenant_id, event_type, recipient_domain, detail FROM recent_event WHERE ($1::uuid IS NULL OR tenant_id = $1) ORDER BY seq DESC LIMIT $2", c);
            cmd.Parameters.Uuid(tenantId).Long(Math.Max(0, max));
            var list = new List<RecentEvent>();
            await using NpgsqlDataReader r = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await r.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                list.Add(new RecentEvent(r.GetInstant(0), r.GetGuid(1), r.GetString(2), r.GetString(3), r.GetNullableString(4)));
            }

            return list;
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex))
        {
            throw PostgresErrors.Unavailable(ex);
        }
    }
}
