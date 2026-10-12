using Mta.Core;
using Mta.Storage.Logic;
using Mta.Storage.Model;
using Npgsql;

namespace Mta.Storage.Postgres;

/// <summary>An enabled webhook endpoint as the fan-out needs it.</summary>
internal readonly record struct WebhookTarget(Guid EndpointId, Guid TenantId, IReadOnlyList<string> EventTypes);

/// <summary>Everything the PostgreSQL stores share: options, clock, the two data sources, the stats buffer and the partition manager.</summary>
internal sealed class PostgresRuntime
{
    private WebhookTarget[] _targets = [];
    private long _targetsVersion = -1;
    private long _targetsLoadedAt;

    /// <summary>Another replica can change endpoints without this process noticing, so the cached list is also refreshed by age.</summary>
    private const long TargetsMaxAgeMs = 5000;

    public PostgresRuntime(StorageOptions options, IClock clock, IMtaLog log)
    {
        Options = options;
        Clock = clock;
        Log = log;
        Aggregator = new StatsAggregator(options.Retention, options.History);

        PostgresOptions pg = options.Postgres;
        string? runtime = pg.RuntimeConnectionString;
        string? owner = pg.OwnerConnectionString;
        if (string.IsNullOrWhiteSpace(runtime) && string.IsNullOrWhiteSpace(owner))
        {
            throw new ArgumentException("Postgres:RuntimeConnectionString (or Postgres:OwnerConnectionString) is required for the PostgreSQL backend.");
        }

        // One connection string given: it serves both roles.
        runtime = string.IsNullOrWhiteSpace(runtime) ? owner! : runtime;
        owner = string.IsNullOrWhiteSpace(owner) ? runtime : owner;
        RuntimeRole = new NpgsqlConnectionStringBuilder(runtime).Username;
        OwnerRole = new NpgsqlConnectionStringBuilder(owner).Username;
        SingleRole = string.Equals(runtime, owner, StringComparison.Ordinal);

        Data = BuildDataSource(runtime, pg, runtimePool: true);
        Owner = SingleRole ? Data : BuildDataSource(owner, pg, runtimePool: false);
        Partitions = new PostgresPartitions(Owner);
    }

    public StorageOptions Options { get; }

    public IClock Clock { get; }

    public IMtaLog Log { get; }

    public StatsAggregator Aggregator { get; }

    public bool IsFull => Options.History.Mode == HistoryMode.Full;

    /// <summary>Normal operation: claims, intake, history, statistics, configuration.</summary>
    public NpgsqlDataSource Data { get; }

    /// <summary>Schema owner: migrations and partition DDL. The same object as <see cref="Data"/> when one connection string was given.</summary>
    public NpgsqlDataSource Owner { get; }

    public bool SingleRole { get; }

    public string? RuntimeRole { get; }

    public string? OwnerRole { get; }

    public PostgresPartitions Partitions { get; }

    public EfConfigStore<PostgresDbContext> ConfigStore { get; set; } = null!;

    private static NpgsqlDataSource BuildDataSource(string connectionString, PostgresOptions pg, bool runtimePool)
    {
        var builder = new NpgsqlConnectionStringBuilder(connectionString);
        if (!builder.ContainsKey("Application Name") || string.IsNullOrEmpty(builder.ApplicationName))
        {
            builder.ApplicationName = "eggmail";
        }

        if (!builder.ContainsKey("Maximum Pool Size"))
        {
            builder.MaxPoolSize = runtimePool ? Math.Max(1, pg.MaxPoolSize) : 4;
        }

        if (!builder.ContainsKey("Command Timeout"))
        {
            builder.CommandTimeout = Math.Max(1, pg.CommandTimeoutSeconds);
        }

        if (runtimePool && !builder.ContainsKey("Max Auto Prepare"))
        {
            // Hot-path statements repeat verbatim; Npgsql prepares them after two uses. Set "Max Auto Prepare=0" behind a
            // pooler that does not support prepared statements.
            builder.MaxAutoPrepare = 64;
            builder.AutoPrepareMinUsages = 2;
        }

        return new NpgsqlDataSourceBuilder(builder.ConnectionString).Build();
    }

    /// <summary>The enabled endpoints, refreshed whenever the config store reports a webhook endpoint change.</summary>
    public async ValueTask<WebhookTarget[]> GetWebhookTargetsAsync(CancellationToken cancellationToken)
    {
        long version = ConfigStore.WebhookEndpointVersion;
        if (version == Volatile.Read(ref _targetsVersion) && Environment.TickCount64 - Volatile.Read(ref _targetsLoadedAt) < TargetsMaxAgeMs)
        {
            return Volatile.Read(ref _targets);
        }

        var endpoints = await ConfigStore.GetWebhookEndpointsAsync(null, cancellationToken).ConfigureAwait(false);
        WebhookTarget[] targets = endpoints.Where(e => e.Enabled).Select(e => new WebhookTarget(e.Id, e.TenantId, e.EventTypes)).ToArray();
        Volatile.Write(ref _targets, targets);
        Volatile.Write(ref _targetsVersion, version);
        Volatile.Write(ref _targetsLoadedAt, Environment.TickCount64);
        return targets;
    }
}
