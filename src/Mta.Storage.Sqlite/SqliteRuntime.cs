using Microsoft.Data.Sqlite;
using Mta.Core;
using Mta.Storage.Logic;
using Mta.Storage.Model;
using Mta.Storage.Transfer;

namespace Mta.Storage.Sqlite;

/// <summary>An enabled webhook endpoint as the fan-out needs it.</summary>
internal readonly record struct WebhookTarget(Guid EndpointId, Guid TenantId, IReadOnlyList<string> EventTypes);

/// <summary>Everything the SQLite stores share: options, clock, the four files with their writers, and the stats buffer.</summary>
internal sealed class SqliteRuntime
{
    private WebhookTarget[] _targets = [];
    private long _targetsVersion = -1;

    public SqliteRuntime(StorageOptions options, IClock clock, IMtaLog log)
    {
        Options = options;
        Clock = clock;
        Log = log;
        Aggregator = new StatsAggregator(options.Retention, options.History);
    }

    public StorageOptions Options { get; }

    public IClock Clock { get; }

    public IMtaLog Log { get; }

    public StatsAggregator Aggregator { get; }

    /// <summary>The backend switch gate: closed on a fenced source and on a target that is not activated yet.</summary>
    public SwitchGate Fence { get; } = new();

    public bool IsFull => Options.History.Mode == HistoryMode.Full;

    public SqliteFile Queue { get; set; } = null!;

    public SqliteFile Stats { get; set; } = null!;

    public SqliteFile Config { get; set; } = null!;

    public SqliteFile? History { get; set; }

    public SqliteFileWriter QueueWriter { get; set; } = null!;

    public SqliteFileWriter StatsWriter { get; set; } = null!;

    public SqliteFileWriter ConfigWriter { get; set; } = null!;

    public SqliteFileWriter? HistoryWriter { get; set; }

    public EfConfigStore<ConfigDbContext> ConfigStore { get; set; } = null!;

    public StatsBucketer Bucketer { get; set; } = null!;

    public IEnumerable<SqliteFileWriter> Writers
    {
        get
        {
            yield return QueueWriter;
            yield return StatsWriter;
            yield return ConfigWriter;
            if (HistoryWriter is not null)
            {
                yield return HistoryWriter;
            }
        }
    }

    public IEnumerable<SqliteFile> Files
    {
        get
        {
            yield return Queue;
            yield return Stats;
            yield return Config;
            if (History is not null)
            {
                yield return History;
            }
        }
    }

    /// <summary>
    /// Runs a read against a file. File-backed databases use a short pooled connection on the calling thread; the in-memory
    /// queue has one connection owned by its writer, so the read is executed there.
    /// </summary>
    public ValueTask<T> ReadAsync<TState, T>(SqliteFile file, SqliteFileWriter writer, TState state, Func<SqliteConnection, TState, T> read)
    {
        if (file.IsMemory)
        {
            return writer.SubmitAsync((read, state), static (ctx, s) => s.read(ctx.Connection, s.state));
        }

        using SqliteConnection connection = file.OpenReader();
        return ValueTask.FromResult(read(connection, state));
    }

    /// <summary>The enabled endpoints, refreshed whenever the config store reports a webhook endpoint change.</summary>
    public async ValueTask<WebhookTarget[]> GetWebhookTargetsAsync(CancellationToken cancellationToken)
    {
        long version = ConfigStore.WebhookEndpointVersion;
        if (version == Volatile.Read(ref _targetsVersion))
        {
            return Volatile.Read(ref _targets);
        }

        var endpoints = await ConfigStore.GetWebhookEndpointsAsync(null, cancellationToken).ConfigureAwait(false);
        WebhookTarget[] targets = endpoints.Where(e => e.Enabled).Select(e => new WebhookTarget(e.Id, e.TenantId, e.EventTypes)).ToArray();
        Volatile.Write(ref _targets, targets);
        Volatile.Write(ref _targetsVersion, version);
        return targets;
    }
}

internal static class SqliteReaderExtensions
{
    public static DateTimeOffset GetInstant(this SqliteDataReader reader, int ordinal) => StorageTime.FromUnixMs(reader.GetInt64(ordinal));

    public static DateTimeOffset? GetNullableInstant(this SqliteDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : StorageTime.FromUnixMs(reader.GetInt64(ordinal));

    public static string? GetNullableString(this SqliteDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    public static int? GetNullableInt(this SqliteDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetInt32(ordinal);

    public static Guid? GetNullableGuid(this SqliteDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetGuid(ordinal);

    public static bool GetFlag(this SqliteDataReader reader, int ordinal) => reader.GetInt64(ordinal) != 0;
}
