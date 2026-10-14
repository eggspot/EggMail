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
    private readonly SemaphoreSlim _targetsGate = new(1, 1);

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
        // Always its own small pool, even with one connection string: partition DDL and advisory-lock holders must never compete
        // with request traffic for connections (a request that holds a runtime connection may need a partition created).
        Owner = BuildDataSource(owner, pg, runtimePool: false);
        Partitions = new PostgresPartitions(Owner);
    }

    public StorageOptions Options { get; }

    public IClock Clock { get; }

    public IMtaLog Log { get; }

    public StatsAggregator Aggregator { get; }

    /// <summary>The backend switch gate: closed on a fenced source and on a target that is not activated yet.</summary>
    public Mta.Storage.Transfer.SwitchGate Fence { get; } = new();

    public bool IsFull => Options.History.Mode == HistoryMode.Full;

    /// <summary>Normal operation: claims, intake, history, statistics, configuration.</summary>
    public NpgsqlDataSource Data { get; }

    /// <summary>Schema owner: migrations, partition DDL and maintenance locks. A small pool of its own; it connects as the runtime role when only one connection string was given.</summary>
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

        // The name becomes the "db.client.connection.pool.name" label of Npgsql's pool metrics. Unnamed, Npgsql uses the connection string
        // (host, user, database), which is both long and an information leak in a scrape; two fixed names are bounded and say what they are.
        return new NpgsqlDataSourceBuilder(builder.ConnectionString) { Name = runtimePool ? "eggmail-runtime" : "eggmail-owner" }.Build();
    }

    /// <summary>
    /// The exception to throw for an availability failure. When the failure shows connections that broke (reset, closed, server
    /// shutdown) it also discards the idle pooled connections: after the server went away they are dead, and Npgsql only notices on
    /// first use, which would otherwise fail one request per pooled connection. A plain timeout (pool wait, connect or command) is
    /// not evidence that the idle connections are dead, and discarding healthy ones would only make a busy moment worse.
    /// </summary>
    public StorageUnavailableException Unavailable(Exception inner)
    {
        if (PostgresErrors.IsBrokenConnection(inner))
        {
            Data.Clear();
            Owner.Clear();
        }

        return PostgresErrors.Unavailable(inner);
    }

    /// <summary>
    /// Whether an enabled endpoint of the tenant subscribes to the event type according to the loaded list; null when that list is not current
    /// (not loaded, changed, or older than <see cref="TargetsMaxAgeMs"/>), in which case the caller must assume yes and let the fan-out refresh it.
    /// </summary>
    public bool? AnyWebhookSubscriber(Guid tenantId, string eventType)
    {
        if (!IsFresh(ConfigStore.WebhookEndpointVersion))
        {
            return null;
        }

        foreach (WebhookTarget target in Volatile.Read(ref _targets))
        {
            if (target.TenantId == tenantId && WebhookSubscriptions.Matches(target.EventTypes, eventType))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>The enabled endpoints, refreshed whenever the config store reports a webhook endpoint change.</summary>
    public async ValueTask<WebhookTarget[]> GetWebhookTargetsAsync(CancellationToken cancellationToken)
    {
        long version = ConfigStore.WebhookEndpointVersion;
        if (IsFresh(version))
        {
            return Volatile.Read(ref _targets);
        }

        // One refresh at a time: the configuration read is synchronous, and dozens of delivery workers that all notice an
        // expired list at the same moment must not each block a thread and take a pooled connection for it. When only the age
        // expired (no local change) the others keep using the list they have; after a local endpoint change they wait for the new one.
        bool ageOnly = version == Volatile.Read(ref _targetsVersion) && Volatile.Read(ref _targetsVersion) >= 0;
        if (ageOnly)
        {
            if (!await _targetsGate.WaitAsync(0, cancellationToken).ConfigureAwait(false))
            {
                return Volatile.Read(ref _targets);
            }
        }
        else
        {
            await _targetsGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        }

        try
        {
            if (IsFresh(version))
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
        finally
        {
            _targetsGate.Release();
        }
    }

    private bool IsFresh(long version) =>
        version == Volatile.Read(ref _targetsVersion) && Environment.TickCount64 - Volatile.Read(ref _targetsLoadedAt) < TargetsMaxAgeMs;
}
