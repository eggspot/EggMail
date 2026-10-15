using System.Diagnostics.Metrics;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using Mta.Delivery;
using Mta.Host.Backup;
using Mta.Host.Tls;
using Mta.Observability;
using Mta.Smtp.Client;
using Mta.Smtp.Server;
using Mta.Storage.Sqlite;
using Mta.Webhooks;
using Npgsql;

namespace Mta.Host.Tests;

/// <summary>
/// The metric table in docs/operations.md and the instruments in the code must be the same set, with the same types. Adding an instrument
/// without documenting it, or documenting one that does not exist, fails here. Also fails for a new <c>Mta.*</c> meter nobody listed.
/// </summary>
public partial class MetricsDocumentationTests
{
    /// <summary>Every production meter. A new meter must be added here, and its instruments to the table.</summary>
    private static readonly string[] ProductionMeters =
    [
        "Mta.Smtp.Server", "Mta.Smtp.Client", "Mta.Delivery", "Mta.Webhooks", "Mta.Storage.Sqlite", "Mta.Tls", "Mta.Backup", "Mta.Bounce",
    ];

    /// <summary>The Npgsql instruments the guide lists (pinned against a live server in the PostgreSQL tests).</summary>
    private static readonly string[] DocumentedNpgsql =
    [
        "db.client.operation.duration", "db.client.operation.failed", "db.client.operation.npgsql.executing", "db.client.operation.npgsql.prepared_ratio",
        "db.client.connection.count", "db.client.connection.max", "db.client.connection.npgsql.pending_requests", "db.client.connection.npgsql.timeouts",
        "db.client.connection.npgsql.create_time",
    ];

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "EggMail.slnx")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new InvalidOperationException("EggMail.slnx not found above " + AppContext.BaseDirectory);
    }

    /// <summary>Rows of the metric table: name, type.</summary>
    private static Dictionary<string, string> DocumentedMetrics()
    {
        string[] lines = File.ReadAllLines(Path.Combine(RepoRoot(), "docs", "operations.md"));
        int start = Array.FindIndex(lines, l => l.StartsWith("## Monitoring", StringComparison.Ordinal));
        Assert.True(start >= 0, "docs/operations.md has no Monitoring section");
        var rows = new Dictionary<string, string>(StringComparer.Ordinal);
        for (int i = start + 1; i < lines.Length && !lines[i].StartsWith("## ", StringComparison.Ordinal); i++)
        {
            Match m = MetricRow().Match(lines[i]);
            if (m.Success)
            {
                Assert.True(rows.TryAdd(m.Groups[1].Value, m.Groups[2].Value), $"{m.Groups[1].Value} is documented twice");
            }
        }

        return rows;
    }

    [GeneratedRegex(@"^\| `([a-z][a-z0-9_]*)` \| (counter|gauge|histogram) \|")]
    private static partial Regex MetricRow();

    /// <summary>The instruments of the production meters, found the way an exporter finds them.</summary>
    private static List<Instrument> ProductionInstruments(IEnumerable<string> meterNames)
    {
        foreach (Type t in new[] { typeof(SmtpMetrics), typeof(SmtpClientMetrics), typeof(DeliveryMetrics), typeof(WebhookMetrics), typeof(SqliteMetrics), typeof(TlsMetrics), typeof(BackupMetrics), typeof(Mta.Host.Ingest.BounceMetrics) })
        {
            RuntimeHelpers.RunClassConstructor(t.TypeHandle);   // a meter's instruments exist once its static class has been touched
        }

        var names = meterNames.ToHashSet(StringComparer.Ordinal);
        var found = new List<Instrument>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, _) =>
        {
            if (names.Contains(instrument.Meter.Name))
            {
                found.Add(instrument);
            }
        };
        listener.Start();
        return found;
    }

    private static List<Instrument> NpgsqlInstruments()
    {
        // Building a data source (it never connects) registers Npgsql's pool and command instruments.
        using NpgsqlDataSource source = new NpgsqlDataSourceBuilder("Host=localhost;Database=none") { Name = "docs-test" }.Build();
        var found = new List<Instrument>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, _) =>
        {
            if (instrument.Meter.Name == "Npgsql")
            {
                found.Add(instrument);
            }
        };
        listener.Start();
        return found;
    }

    [Fact]
    public void Every_documented_mta_metric_exists_and_every_mta_instrument_is_documented()
    {
        var documented = DocumentedMetrics().Where(r => r.Key.StartsWith("mta_", StringComparison.Ordinal)).ToDictionary(r => r.Key, r => r.Value);
        var code = ProductionInstruments(ProductionMeters).ToDictionary(PrometheusTextExporter.NameFor, PrometheusTextExporter.TypeFor, StringComparer.Ordinal);

        Assert.Empty(code.Keys.Except(documented.Keys).Order());   // in the code, missing from docs/operations.md
        Assert.Empty(documented.Keys.Except(code.Keys).Order());   // in docs/operations.md, not in the code
        foreach ((string name, string type) in code)
        {
            Assert.True(documented[name] == type, $"{name} is a {type} in the code but documented as a {documented[name]}");
        }
    }

    [Fact]
    public void Every_mta_meter_in_the_process_is_a_listed_production_meter()
    {
        ProductionInstruments(ProductionMeters);
        var seen = new HashSet<string>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, _) =>
        {
            if (instrument.Meter.Name.StartsWith("Mta.", StringComparison.Ordinal) && !instrument.Meter.Name.StartsWith("Mta.Test", StringComparison.Ordinal))
            {
                seen.Add(instrument.Meter.Name);
            }
        };
        listener.Start();

        Assert.Empty(seen.Except(ProductionMeters).Order());
    }

    [Fact]
    public void The_documented_npgsql_metrics_are_published_by_the_npgsql_version_in_use()
    {
        var documented = DocumentedMetrics().Where(r => r.Key.StartsWith("db_client_", StringComparison.Ordinal)).ToDictionary(r => r.Key, r => r.Value);
        var instruments = NpgsqlInstruments().Where(i => DocumentedNpgsql.Contains(i.Name)).ToList();

        Assert.Equal(DocumentedNpgsql.Order(), instruments.Select(i => i.Name).Order());
        Assert.Equal(instruments.Select(PrometheusTextExporter.NameFor).Order(), documented.Keys.Order());
        foreach (Instrument i in instruments)
        {
            Assert.True(documented[PrometheusTextExporter.NameFor(i)] == PrometheusTextExporter.TypeFor(i), $"{i.Name} type");
        }
    }

    [Fact]
    public void Every_documented_metric_has_a_help_text_and_a_label_column()
    {
        // The table has four columns: metric, type, labels, meaning. A row without them is an unfinished row.
        string[] lines = File.ReadAllLines(Path.Combine(RepoRoot(), "docs", "operations.md"));
        foreach (string line in lines.Where(l => MetricRow().IsMatch(l)))
        {
            string[] cells = line.Split('|', StringSplitOptions.None);
            Assert.True(cells.Length == 6 && cells[3].Trim().Length > 0 && cells[4].Trim().Length > 10, "incomplete metric row: " + line);
        }
    }
}
