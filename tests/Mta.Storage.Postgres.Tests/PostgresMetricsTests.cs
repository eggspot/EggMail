using System.Collections.Concurrent;
using System.Diagnostics.Metrics;

namespace Mta.Storage.Postgres.Tests;

/// <summary>
/// The PostgreSQL command latency and connection pool metrics come from Npgsql's own meter (<c>Npgsql</c>), which EggMail's exporters include
/// next to the <c>Mta.*</c> meters. This pins the instrument names the operations guide documents, so an Npgsql upgrade that renames one is
/// noticed here and not by an empty dashboard.
/// </summary>
public class PostgresMetricsTests : PgTestBase
{
    /// <summary>The Npgsql instruments the operations guide lists (OpenTelemetry names; Prometheus replaces dots by underscores and appends the unit).</summary>
    internal static readonly string[] DocumentedNpgsqlInstruments =
    [
        "db.client.operation.duration",
        "db.client.operation.npgsql.executing",
        "db.client.operation.npgsql.prepared_ratio",
        "db.client.operation.failed",
        "db.client.connection.count",
        "db.client.connection.max",
        "db.client.connection.npgsql.pending_requests",
        "db.client.connection.npgsql.timeouts",
        "db.client.connection.npgsql.create_time",
    ];

    [Fact]
    public async Task Npgsql_reports_command_latency_and_pool_state_through_its_meter()
    {
        var seen = new ConcurrentDictionary<string, ConcurrentQueue<(double Value, string Tags)>>();
        var published = new ConcurrentDictionary<string, string>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == "Npgsql")
            {
                published[instrument.Name] = $"{instrument.GetType().Name} unit={instrument.Unit}";
                l.EnableMeasurementEvents(instrument);
            }
        };
        void Record(Instrument i, double v, ReadOnlySpan<KeyValuePair<string, object?>> tags)
        {
            string text = string.Join(",", tags.ToArray().Select(t => $"{t.Key}={t.Value}"));
            seen.GetOrAdd(i.Name, _ => new()).Enqueue((v, text));
        }

        listener.SetMeasurementEventCallback<long>((i, v, t, _) => Record(i, v, t));
        listener.SetMeasurementEventCallback<int>((i, v, t, _) => Record(i, v, t));
        listener.SetMeasurementEventCallback<double>((i, v, t, _) => Record(i, v, t));
        listener.Start();

        for (int i = 0; i < 5; i++)
        {
            await AcceptAsync();
        }

        await Storage.Deliveries.GetQueueStatsAsync(default);
        listener.RecordObservableInstruments();

        foreach (string name in DocumentedNpgsqlInstruments)
        {
            Assert.True(published.ContainsKey(name), $"Npgsql does not publish {name}. Published:\n{string.Join("\n", published.OrderBy(p => p.Key).Select(p => p.Key + " " + p.Value))}");
        }

        Assert.Contains(seen["db.client.operation.duration"], x => x.Value > 0);
        Assert.Contains(seen["db.client.connection.max"], x => x.Value >= 1);

        // The pool carries the data source's fixed name, not the connection string (host, user and database would leak into every scrape).
        Assert.Contains(seen["db.client.connection.max"], x => x.Tags.Contains("db.client.connection.pool.name=eggmail-runtime", StringComparison.Ordinal));
        Assert.DoesNotContain(seen["db.client.connection.max"], x => x.Tags.Contains("Host=", StringComparison.Ordinal));
    }
}
