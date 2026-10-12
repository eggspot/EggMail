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
}

public sealed class PostgresOptions
{
    public string? OwnerConnectionString { get; init; }
    public string? RuntimeConnectionString { get; init; }

    /// <summary>Auto (migrate at start under EF's lock) or Never (use the migrate-db command).</summary>
    public bool AutoMigrate { get; init; } = true;

    public int MaxPoolSize { get; init; } = 32;
    public int PartitionsAheadDays { get; init; } = 7;
}
