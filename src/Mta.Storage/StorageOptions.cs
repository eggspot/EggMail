namespace Mta.Storage;

public enum StorageBackend : byte
{
    Sqlite = 0,
    Postgres,

    /// <summary>In-process, non-persistent backend used by tests of other components (addition; never selected by configuration).</summary>
    InMemory,
}

/// <summary>How much per-message history is recorded (decision 29). Independent of the backend.</summary>
public enum HistoryMode : byte
{
    StatsOnly = 0,
    Full,
}

public enum SqliteSyncMode : byte
{
    Off = 0,
    Normal,
    Full,
}

public enum QueuePersistence : byte
{
    Persistent = 0,
    Memory,
}

/// <summary>Top-level storage configuration. Defaults follow decisions J and Q: SQLite backend, <see cref="HistoryMode.Full"/> history.</summary>
public sealed class StorageOptions
{
    public StorageBackend Backend { get; init; } = StorageBackend.Sqlite;

    public HistoryOptions History { get; init; } = new();
    public RetentionOptions Retention { get; init; } = new();
    public SqliteOptions Sqlite { get; init; } = new();
    public PostgresOptions Postgres { get; init; } = new();
    public ContentOptions Content { get; init; } = new();
    public QueueOptions Queue { get; init; } = new();
    public InboundStorageOptions Inbound { get; init; } = new();
}

public sealed class HistoryOptions
{
    public HistoryMode Mode { get; init; } = HistoryMode.Full;

    /// <summary>Size of the content-free recent-events ring (always kept, both modes).</summary>
    public int RecentEvents { get; init; } = 1000;
}

public sealed class QueueOptions
{
    /// <summary>Maximum time a delivery may stay queued (<c>Queue:MaxLifetime</c>, default 5 days).</summary>
    public TimeSpan MaxLifetime { get; init; } = TimeSpan.FromDays(5);

    /// <summary>How long an API idempotency key is remembered (addition; default 24 hours).</summary>
    public TimeSpan IdempotencyKeyLifetime { get; init; } = TimeSpan.FromHours(24);
}

/// <summary>Storage side of inbound mail (design section 11). The receive path has its own <c>Inbound:*</c> limits.</summary>
public sealed class InboundStorageOptions
{
    /// <summary>
    /// Days a received message (row and body) is kept when its domain sets no value (<c>Inbound:RetentionDays</c>). <c>0</c> keeps forever, like every
    /// retention knob (design section 5.1); negative is invalid.
    /// </summary>
    public int RetentionDays { get; init; } = 7;

    /// <summary>
    /// The longest retention any domain gets (<c>Inbound:MaxRetentionDays</c>): a domain's own value (and the default) is cut to it, and "forever" (0) becomes it. <c>0</c>: no ceiling.
    /// The operator's guard against a tenant keeping other people's mail without limit.
    /// </summary>
    public int MaxRetentionDays { get; init; }
}

public sealed class ContentOptions
{
    public bool Retain { get; init; } = true;          // Content:Mode = Retain | None
    public int RetentionDays { get; init; } = 7;       // 6..30, no unlimited (decision O)
    public bool StoreAttachments { get; init; }
    public bool AllowAttachmentStorage { get; init; }
    public int MaxStoredBodyBytes { get; init; } = 256 * 1024;
    public bool StoreSubject { get; init; } = true;
}

/// <summary>Retention knobs. 0 means keep forever (decision 28) except for <see cref="ContentOptions.RetentionDays"/>.</summary>
public sealed class RetentionOptions
{
    public int MetadataDays { get; init; } = 30;
    public int StatsHourlyDays { get; init; } = 30;
    public int StatsDailyDays { get; init; } = 400;
    public int WebhookOutboxDays { get; init; } = 7;
    public int WebhookAttemptLogDays { get; init; } = 7;
    public int RecipientDomainTopNHourly { get; init; } = 20;
    public int RecipientDomainTopNDaily { get; init; } = 10;
    public int MaxSeriesPerHour { get; init; } = 200_000;
}

public sealed class SqliteOptions
{
    /// <summary>Directory holding queue.db, stats.db, config.db and history.db.</summary>
    public string DataDirectory { get; init; } = "/data";

    public SqliteSyncMode SyncMode { get; init; } = SqliteSyncMode.Off;
    public SqliteSyncMode ConfigSyncMode { get; init; } = SqliteSyncMode.Full;
    public QueuePersistence QueuePersistence { get; init; } = QueuePersistence.Persistent;

    /// <summary>Run PRAGMA quick_check (true) or integrity_check (false) at startup.</summary>
    public bool QuickCheck { get; init; } = true;

    /// <summary>Writer group-commit window.</summary>
    public TimeSpan WriterBatchWindow { get; init; } = TimeSpan.FromMilliseconds(2);
    public int WriterMaxBatch { get; init; } = 512;
    public int WriterQueueCapacity { get; init; } = 8192;

    // Additions (SQLite tuning knobs; behaviour-neutral):

    /// <summary>Rows per batched retention DELETE (about 5k, design §4.5).</summary>
    public int RetentionDeleteBatchSize { get; init; } = 5000;

    /// <summary>Pause between retention DELETE batches so the writer stays available to intake.</summary>
    public TimeSpan RetentionDeletePause { get; init; } = TimeSpan.FromMilliseconds(20);

    /// <summary>PRAGMA busy_timeout for every connection.</summary>
    public TimeSpan BusyTimeout { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>PRAGMA journal_size_limit: the WAL file is truncated to at most this size after a checkpoint.</summary>
    public long JournalSizeLimitBytes { get; init; } = 64L * 1024 * 1024;

    /// <summary>How often the statistics aggregate is flushed to stats.db (design §4.5: about 10 s).</summary>
    public TimeSpan StatsFlushInterval { get; init; } = TimeSpan.FromSeconds(10);

    // Advisory storage-pressure indicator (decision C, decision 108; provisional defaults, calibrate with benchmarks):

    /// <summary>Writer queue depth (commands waiting for one file's writer) that counts as "deep".</summary>
    public int PressureQueueDepth { get; init; } = 1000;

    /// <summary>How long the queue must stay at or over <see cref="PressureQueueDepth"/> before the indicator turns advisory.</summary>
    public TimeSpan PressureQueueDuration { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>p99 commit latency over <see cref="PressureWindow"/> above which the indicator turns advisory.</summary>
    public TimeSpan PressureCommitP99 { get; init; } = TimeSpan.FromMilliseconds(100);

    /// <summary>How far back the commit latency p99 looks.</summary>
    public TimeSpan PressureWindow { get; init; } = TimeSpan.FromMinutes(5);
}

public sealed class PostgresOptions
{
    public string? OwnerConnectionString { get; init; }
    public string? RuntimeConnectionString { get; init; }

    /// <summary>Auto: <c>InitializeAsync</c> migrates the schema as the owner role (serialized across replicas by an advisory lock). Never: the schema must already be current; use <c>mta migrate-db</c> or the generated script.</summary>
    public bool AutoMigrate { get; init; } = true;

    /// <summary>Maximum Npgsql pool size of the runtime connection (the owner connection has a small pool of its own).</summary>
    public int MaxPoolSize { get; init; } = 32;

    /// <summary>How many days ahead the maintenance job creates history partitions.</summary>
    public int PartitionsAheadDays { get; init; } = 7;

    // Additions (PostgreSQL tuning knobs; behaviour-neutral):

    /// <summary>How often the statistics aggregate is flushed (design §4.5: about 10 s). <c>TimeSpan.Zero</c> disables the timer (tests).</summary>
    public TimeSpan StatsFlushInterval { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Rows per batched retention DELETE (tables that are not day partitioned).</summary>
    public int RetentionDeleteBatchSize { get; init; } = 5000;

    /// <summary>Pause between retention DELETE batches so intake and claims interleave with them.</summary>
    public TimeSpan RetentionDeletePause { get; init; } = TimeSpan.FromMilliseconds(20);

    /// <summary>Command timeout in seconds for hot-path statements (Npgsql default 30).</summary>
    public int CommandTimeoutSeconds { get; init; } = 30;

    /// <summary>
    /// Optional third role (design section 4.3): a login that can only <c>SELECT</c> the history and statistics tables, used for the dashboard's
    /// queries (message search, detail, events, retained raw, statistics). The schema migration grants it exactly those tables. Unset: those queries
    /// run as the runtime role.
    /// </summary>
    public string? ReadOnlyConnectionString { get; init; }

    /// <summary><c>statement_timeout</c> of the read-only connections, so a heavy dashboard query cannot hold the database (design: for example 5 s).</summary>
    public int ReadOnlyStatementTimeoutSeconds { get; init; } = 5;

    /// <summary><c>idle_in_transaction_session_timeout</c> of the read-only connections.</summary>
    public int ReadOnlyIdleInTransactionTimeoutSeconds { get; init; } = 10;

    /// <summary>Maximum Npgsql pool size of the read-only connections (design: about 8 for the dashboard).</summary>
    public int ReadOnlyMaxPoolSize { get; init; } = 8;

    // Advisory storage-pressure indicator (decision 109; provisional defaults, calibrate with benchmarks):

    /// <summary>Samples one <see cref="PressureWindow"/> may hold (the sampler's ring is allocated once at that size).</summary>
    public const int MaxPressureSamples = 4096;

    /// <summary>How far back the runtime pool's samples are judged: at most <see cref="MaxPressureSamples"/> times <see cref="PressureSampleInterval"/>.</summary>
    public TimeSpan PressureWindow { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>How often the runtime pool is sampled (waiting callers, connections in use, the limit).</summary>
    public TimeSpan PressureSampleInterval { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Share of the samples in <see cref="PressureWindow"/> that found a caller waiting for a connection, 1 to 100, above which the indicator turns advisory.</summary>
    public int PressureWaitingPercent { get; init; } = 50;
}
