using System.Globalization;
using Microsoft.Data.Sqlite;
using Mta.Storage.Tests;
using Xunit.Abstractions;

namespace Mta.Storage.Sqlite.Tests;

// The accelerated lifecycle suite against the SQLite backend. The rows are counted straight from the data files (read-only connections), so the
// retention rules are checked on disk and not only through the API. A tiny delete batch makes every retention job run its batch loop several times.

public abstract class SqliteLifecycleBase(ITestOutputHelper output) : LifecycleConformance(output)
{
    private string? _dir;

    protected virtual SqliteSyncMode Sync => SqliteSyncMode.Off;

    protected virtual int DeleteBatchSize => 7;

    protected string DataDirectory => _dir!;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }

        _dir = SqliteTestStorage.NewDirectory();
        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b =>
        {
            b.SyncMode = Sync;
            b.RetentionDeleteBatchSize = DeleteBatchSize;
        }), Clock));
    }

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }
    }

    protected override ValueTask<long?> CountRowsAsync(LifecycleTable table)
    {
        (string file, string sql) = table switch
        {
            LifecycleTable.MessageIndex => ("history", "SELECT count(*) FROM message_index"),
            LifecycleTable.MessageRecipient => ("history", "SELECT count(*) FROM message_recipient"),
            LifecycleTable.MessageEvent => ("history", "SELECT count(*) FROM message_event"),
            LifecycleTable.MessageContent => ("history", "SELECT count(*) FROM message_content"),
            LifecycleTable.RawRetained => ("history", "SELECT count(*) FROM message_raw_retained"),
            LifecycleTable.WebhookOutbox => ("queue", "SELECT count(*) FROM webhook_outbox"),
            LifecycleTable.Idempotency => ("queue", "SELECT count(*) FROM api_idempotency_key"),
            LifecycleTable.DeliveryQueue => ("queue", "SELECT count(*) FROM delivery_queue"),
            LifecycleTable.MessageSpool => ("queue", "SELECT count(*) FROM message_spool"),
            LifecycleTable.WebhookAttempt => ("stats", "SELECT count(*) FROM webhook_attempt"),
            LifecycleTable.StatsHourly => ("stats", "SELECT count(*) FROM stat_aggregate WHERE daily = 0"),
            LifecycleTable.StatsDaily => ("stats", "SELECT count(*) FROM stat_aggregate WHERE daily = 1"),
            LifecycleTable.RecentEvent => ("stats", "SELECT count(*) FROM recent_event"),
            _ => throw new ArgumentOutOfRangeException(nameof(table)),
        };

        string path = Path.Combine(_dir!, file + ".db");
        if (!File.Exists(path))
        {
            return ValueTask.FromResult<long?>(0);
        }

        using var c = new SqliteConnection($"Data Source={path};Mode=ReadOnly;Pooling=False");
        c.Open();
        using SqliteCommand cmd = c.CreateCommand();
        cmd.CommandText = sql;
        return ValueTask.FromResult<long?>(Convert.ToInt64(cmd.ExecuteScalar(), CultureInfo.InvariantCulture));
    }
}

public class SqliteLifecycleFull(ITestOutputHelper output) : SqliteLifecycleBase(output);

public class SqliteLifecycleStatsOnly(ITestOutputHelper output) : SqliteLifecycleBase(output)
{
    protected override HistoryMode Mode => HistoryMode.StatsOnly;
}

/// <summary>The default delete batch (5000): one batch per job, the production shape.</summary>
public class SqliteLifecycleDefaultBatch(ITestOutputHelper output) : SqliteLifecycleBase(output)
{
    protected override int DeleteBatchSize => 5000;
}

/// <summary>The other sync modes repeat only the cheap scenarios: the retention rules do not depend on how the file is synced.</summary>
public class SqliteLifecycleSyncNormal(ITestOutputHelper output) : SqliteLifecycleBase(output)
{
    protected override SqliteSyncMode Sync => SqliteSyncMode.Normal;

    protected override bool Heavy => false;
}

public class SqliteLifecycleSyncFull(ITestOutputHelper output) : SqliteLifecycleBase(output)
{
    protected override SqliteSyncMode Sync => SqliteSyncMode.Full;

    protected override bool Heavy => false;
}
