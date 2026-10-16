using Mta.Storage.Tests;
using Npgsql;
using Xunit.Abstractions;

namespace Mta.Storage.Postgres.Tests;

// The accelerated lifecycle suite against the PostgreSQL backend: the same abstract scenarios as SQLite and the in-memory backend. The rows are
// counted with the administrator's connection, so partition drops and batched deletes are checked in the tables and not only through the API.

public abstract class PgLifecycleBase(ITestOutputHelper output) : LifecycleConformance(output)
{
    private readonly PgHarness _pg = new();

    protected virtual int DeleteBatchSize => 7;

    protected override Task<IStorage> CreateAsync(StorageOptions options) =>
        _pg.CreateAsync(options, Clock, o => new PostgresOptions
        {
            RuntimeConnectionString = o.RuntimeConnectionString,
            MaxPoolSize = o.MaxPoolSize,
            StatsFlushInterval = o.StatsFlushInterval,
            RetentionDeletePause = o.RetentionDeletePause,
            RetentionDeleteBatchSize = DeleteBatchSize,
        });

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await _pg.DisposeAsync();
    }

    protected override async ValueTask<long?> CountRowsAsync(LifecycleTable table)
    {
        string sql = table switch
        {
            LifecycleTable.MessageIndex => "SELECT count(*) FROM message_index",
            LifecycleTable.MessageRecipient => "SELECT count(*) FROM message_recipient",
            LifecycleTable.MessageEvent => "SELECT count(*) FROM message_event",
            LifecycleTable.MessageContent => "SELECT count(*) FROM message_content",
            LifecycleTable.RawRetained => "SELECT count(*) FROM message_raw_retained",
            LifecycleTable.WebhookOutbox => "SELECT count(*) FROM webhook_outbox",
            LifecycleTable.Idempotency => "SELECT count(*) FROM api_idempotency_key",
            LifecycleTable.DeliveryQueue => "SELECT count(*) FROM delivery_queue",
            LifecycleTable.MessageSpool => "SELECT count(*) FROM message_spool",
            LifecycleTable.WebhookAttempt => "SELECT count(*) FROM webhook_attempt",
            LifecycleTable.StatsHourly => "SELECT count(*) FROM stat_aggregate WHERE NOT daily",
            LifecycleTable.StatsDaily => "SELECT count(*) FROM stat_aggregate WHERE daily",
            LifecycleTable.RecentEvent => "SELECT count(*) FROM recent_event",
            _ => throw new ArgumentOutOfRangeException(nameof(table)),
        };

        await using var c = new NpgsqlConnection(_pg.Current!.ConnectionString);
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql, c);
        return Convert.ToInt64(await cmd.ExecuteScalarAsync(), System.Globalization.CultureInfo.InvariantCulture);
    }
}

public class PgLifecycleFull(ITestOutputHelper output) : PgLifecycleBase(output);

public class PgLifecycleStatsOnly(ITestOutputHelper output) : PgLifecycleBase(output)
{
    protected override HistoryMode Mode => HistoryMode.StatsOnly;
}
