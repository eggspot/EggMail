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
        Coordination = BuildCoordinationDataSource(runtime, pg);

        if (!string.IsNullOrWhiteSpace(pg.ReadOnlyConnectionString))
        {
            ReadOnlyRole = new NpgsqlConnectionStringBuilder(pg.ReadOnlyConnectionString).Username;
            if (string.IsNullOrWhiteSpace(ReadOnlyRole))
            {
                throw new ArgumentException("Postgres:ReadOnlyConnectionString must name the role to connect as (Username=...): the migration grants that role its SELECT privileges.");
            }
            Reader = BuildReaderDataSource(pg.ReadOnlyConnectionString, pg);
            SeparateReader = true;
        }
        else
        {
            Reader = Data;
        }
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

    /// <summary>
    /// The dashboard's read queries (history search, detail, events, retained raw, statistics). The read-only role with a <c>statement_timeout</c> when
    /// <c>Postgres:ReadOnlyConnectionString</c> is set (design section 4.3), otherwise the same data source as <see cref="Data"/>.
    /// </summary>
    public NpgsqlDataSource Reader { get; }

    /// <summary>True when <see cref="Reader"/> is its own data source (a read-only connection string was given).</summary>
    public bool SeparateReader { get; }

    public string? ReadOnlyRole { get; }

    /// <summary>The read-only role the migration has to grant (null when there is none, or it is the runtime or owner role, which can read already).</summary>
    public string? ReadOnlyRoleToGrant =>
        SeparateReader && !string.IsNullOrWhiteSpace(ReadOnlyRole)
        && !string.Equals(ReadOnlyRole, RuntimeRole, StringComparison.Ordinal) && !string.Equals(ReadOnlyRole, OwnerRole, StringComparison.Ordinal)
            ? ReadOnlyRole : null;

    /// <summary>
    /// The replica coordination (heartbeat, signals, failed-login counts): a pool of two connections of its own, so a burst of claims or intake cannot starve the heartbeat (a
    /// replica that cannot beat is dropped by the others) nor can a stuck coordination statement take a connection from the mail path.
    /// </summary>
    public NpgsqlDataSource Coordination { get; }

    /// <summary>Schema owner: migrations, partition DDL and maintenance locks. A small pool of its own; it connects as the runtime role when only one connection string was given.</summary>
    public NpgsqlDataSource Owner { get; }

    public bool SingleRole { get; }

    public string? RuntimeRole { get; }

    public string? OwnerRole { get; }

    public PostgresPartitions Partitions { get; }

    public EfConfigStore<PostgresDbContext> ConfigStore { get; set; } = null!;

    public EfInboundMessageStore<PostgresDbContext> InboundMessages { get; set; } = null!;

    private static NpgsqlDataSource BuildReaderDataSource(string connectionString, PostgresOptions pg)
    {
        var builder = new NpgsqlConnectionStringBuilder(connectionString);
        if (!builder.ContainsKey("Application Name") || string.IsNullOrEmpty(builder.ApplicationName))
        {
            builder.ApplicationName = "eggmail-readonly";
        }

        if (!builder.ContainsKey("Maximum Pool Size"))
        {
            builder.MaxPoolSize = Math.Max(1, pg.ReadOnlyMaxPoolSize);
        }

        if (!builder.ContainsKey("Command Timeout"))
        {
            // The server's statement_timeout fires first, so a slow query is reported as such rather than as a client-side timeout.
            builder.CommandTimeout = Math.Max(pg.CommandTimeoutSeconds, pg.ReadOnlyStatementTimeoutSeconds + 5);
        }

        // Startup options, not SET: they are the session defaults, so the connection reset when a connection returns to the pool (DISCARD ALL) keeps them.
        // A pooler in front of the database must pass the "options" startup parameter (PgBouncer: ignore_startup_parameters = options); the role can also carry the same settings (ALTER ROLE ... SET).
        string timeouts = string.Create(System.Globalization.CultureInfo.InvariantCulture,
            $"-c statement_timeout={pg.ReadOnlyStatementTimeoutSeconds * 1000} -c idle_in_transaction_session_timeout={pg.ReadOnlyIdleInTransactionTimeoutSeconds * 1000} -c default_transaction_read_only=on");
        builder.Options = string.IsNullOrWhiteSpace(builder.Options) ? timeouts : builder.Options + " " + timeouts;
        return new NpgsqlDataSourceBuilder(builder.ConnectionString).Build();
    }

    private static NpgsqlDataSource BuildCoordinationDataSource(string connectionString, PostgresOptions pg)
    {
        var builder = new NpgsqlConnectionStringBuilder(connectionString) { ApplicationName = "eggmail-coordination", MaxPoolSize = 2, MinPoolSize = 0, MaxAutoPrepare = 0 };
        builder.Timeout = Math.Min(builder.Timeout > 0 ? builder.Timeout : 15, 5);
        builder.CommandTimeout = Math.Clamp(pg.CommandTimeoutSeconds, 1, 5);
        return new NpgsqlDataSourceBuilder(builder.ConnectionString) { Name = "eggmail-coordination" }.Build();
    }

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
            Coordination.Clear();
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
