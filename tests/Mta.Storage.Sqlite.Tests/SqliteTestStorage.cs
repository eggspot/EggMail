using Mta.Storage.Tests;

namespace Mta.Storage.Sqlite.Tests;

/// <summary>Creates SQLite storages in private temp directories. Shared by every suite.</summary>
public static class SqliteTestStorage
{
    public static string NewDirectory()
    {
        string dir = Path.Combine(Path.GetTempPath(), "eggmail-sqlite-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    public static void TryDelete(string dir)
    {
        try
        {
            if (Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    public static StorageOptions WithDirectory(StorageOptions o, string dir, Action<SqliteOptionsBuilder>? tune = null)
    {
        var b = new SqliteOptionsBuilder(o.Sqlite) { DataDirectory = dir };
        tune?.Invoke(b);
        return new StorageOptions
        {
            Backend = StorageBackend.Sqlite,
            History = o.History,
            Retention = o.Retention,
            Sqlite = b.Build(),
            Postgres = o.Postgres,
            Content = o.Content,
            Queue = o.Queue,
        };
    }
}

/// <summary>Mutable mirror of the init-only <see cref="SqliteOptions"/> for tests.</summary>
public sealed class SqliteOptionsBuilder(SqliteOptions s)
{
    public string DataDirectory { get; set; } = s.DataDirectory;
    public SqliteSyncMode SyncMode { get; set; } = s.SyncMode;
    public SqliteSyncMode ConfigSyncMode { get; set; } = s.ConfigSyncMode;
    public QueuePersistence QueuePersistence { get; set; } = s.QueuePersistence;
    public bool QuickCheck { get; set; } = s.QuickCheck;
    public TimeSpan WriterBatchWindow { get; set; } = s.WriterBatchWindow;
    public int WriterMaxBatch { get; set; } = s.WriterMaxBatch;
    public int WriterQueueCapacity { get; set; } = s.WriterQueueCapacity;
    public int RetentionDeleteBatchSize { get; set; } = s.RetentionDeleteBatchSize;
    public TimeSpan RetentionDeletePause { get; set; } = TimeSpan.FromMilliseconds(1);
    public TimeSpan StatsFlushInterval { get; set; } = TimeSpan.Zero;

    public SqliteOptions Build() => new()
    {
        DataDirectory = DataDirectory,
        SyncMode = SyncMode,
        ConfigSyncMode = ConfigSyncMode,
        QueuePersistence = QueuePersistence,
        QuickCheck = QuickCheck,
        WriterBatchWindow = WriterBatchWindow,
        WriterMaxBatch = WriterMaxBatch,
        WriterQueueCapacity = WriterQueueCapacity,
        RetentionDeleteBatchSize = RetentionDeleteBatchSize,
        RetentionDeletePause = RetentionDeletePause,
        StatsFlushInterval = StatsFlushInterval,
    };
}
