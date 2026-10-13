using BenchmarkDotNet.Attributes;
using Mta.Storage;
using Mta.Storage.Postgres;
using Mta.Storage.Postgres.Tests;
using Npgsql;

namespace Mta.Benchmarks.Storage;

/// <summary>
/// Starts the throwaway PostgreSQL cluster of the storage tests (<c>tests/Mta.Storage.Postgres.Tests/Support/PostgresTestServer.cs</c>,
/// linked into this project) with its real durability: <c>fsync</c>, <c>full_page_writes</c> and <c>synchronous_commit</c> stay on.
/// <c>EGGMAIL_TEST_POSTGRES</c> points the benchmarks at an existing server instead (then its own settings apply).
/// </summary>
internal sealed class PostgresBenchDatabase : IAsyncDisposable
{
    private TestDatabase? _database;

    public static async Task<PostgresBenchDatabase> CreateAsync(bool synchronousCommit, int poolSize)
    {
        Environment.SetEnvironmentVariable("EGGMAIL_TEST_PG_DURABLE", "1");
        if (PostgresTestServer.UnavailableReason is { } reason)
        {
            throw new InvalidOperationException(reason);
        }

        TestDatabase db = await PostgresTestServer.Instance.CreateDatabaseAsync();
        var builder = new NpgsqlConnectionStringBuilder(db.ConnectionString) { MaxPoolSize = poolSize, Pooling = true };
        if (!synchronousCommit)
        {
            // Per-session: commits return before the WAL is flushed (a crash can lose the last fraction of a second; no corruption).
            builder.Options = "-c synchronous_commit=off";
        }

        return new PostgresBenchDatabase { _database = db, ConnectionString = builder.ConnectionString, Description = PostgresTestServer.Instance.Description };
    }

    public string ConnectionString { get; private init; } = "";

    public string Description { get; private init; } = "";

    public async ValueTask DisposeAsync()
    {
        if (_database is not null)
        {
            await _database.DisposeAsync();
        }
    }
}

/// <summary>
/// PostgreSQL intake throughput: <c>AcceptAsync</c> with 1, 8 and 64 concurrent callers, <c>synchronous_commit</c> on (a WAL fsync
/// per commit, the durable default) and off, and 2 KB / 100 KB messages with the default <c>History:Mode=Full</c> (index, recipients,
/// content and the queued event commit in the same transaction). One operation is one acknowledged message. Run with
/// <c>dotnet run -c Release --project bench/Mta.Benchmarks -- --filter "*PostgresAccept*"</c>. Not durable-by-accident:
/// there is no group-commit writer, PostgreSQL itself batches concurrent commits into one WAL flush.
/// </summary>
[ShortRunJob]
[MemoryDiagnoser]
public class PostgresAcceptBenchmarks
{
    private const int MessagesPerInvoke = 1000;
    private static readonly Guid Tenant = Guid.Parse("a0000000-0000-7000-8000-000000000001");

    private PostgresBenchDatabase _database = null!;
    private PostgresStorage _storage = null!;
    private byte[] _raw = [];

    [Params(1, 8, 64)]
    public int Writers { get; set; }

    [Params(true, false)]
    public bool SynchronousCommit { get; set; }

    [Params(2 * 1024, 100 * 1024)]
    public int MessageSize { get; set; }

    [GlobalSetup]
    public async Task Setup()
    {
        _database = await PostgresBenchDatabase.CreateAsync(SynchronousCommit, Writers + 2);
        _storage = PostgresStorage.Create(new StorageOptions
        {
            Backend = StorageBackend.Postgres,
            Postgres = new PostgresOptions { RuntimeConnectionString = _database.ConnectionString, MaxPoolSize = Writers + 2 },
        });
        await _storage.InitializeAsync(default);
        _raw = new byte[MessageSize];
        new Random(1).NextBytes(_raw);
    }

    [GlobalCleanup]
    public async Task Cleanup()
    {
        await _storage.DisposeAsync();
        await _database.DisposeAsync();
    }

    [Benchmark(OperationsPerInvoke = MessagesPerInvoke)]
    public async Task Accept()
    {
        int remaining = MessagesPerInvoke;
        await Task.WhenAll(Enumerable.Range(0, Writers).Select(async _ =>
        {
            while (Interlocked.Decrement(ref remaining) >= 0)
            {
                await _storage.Intake.AcceptAsync(BenchMessages.Create(Tenant, _raw), default);
            }
        }));
    }
}

/// <summary>
/// The delivery side on PostgreSQL: accept 100 messages (8 callers), claim them with one <c>FOR UPDATE SKIP LOCKED</c> statement and
/// record <c>Delivered</c> for each (one transaction per message: queue row, spool, history event, retained status). One operation
/// is the whole cycle of one message, so the figure includes intake, as in the SQLite benchmark.
/// </summary>
[ShortRunJob]
[MemoryDiagnoser]
public class PostgresClaimCompleteBenchmarks
{
    private const int Batch = 100;
    private static readonly Guid Tenant = Guid.Parse("a0000000-0000-7000-8000-000000000001");

    private PostgresBenchDatabase _database = null!;
    private PostgresStorage _storage = null!;
    private byte[] _raw = [];

    [Params(true, false)]
    public bool SynchronousCommit { get; set; }

    [GlobalSetup]
    public async Task Setup()
    {
        _database = await PostgresBenchDatabase.CreateAsync(SynchronousCommit, 16);
        _storage = PostgresStorage.Create(new StorageOptions
        {
            Backend = StorageBackend.Postgres,
            Postgres = new PostgresOptions { RuntimeConnectionString = _database.ConnectionString, MaxPoolSize = 16 },
        });
        await _storage.InitializeAsync(default);
        _raw = new byte[2048];
        new Random(1).NextBytes(_raw);
    }

    [GlobalCleanup]
    public async Task Cleanup()
    {
        await _storage.DisposeAsync();
        await _database.DisposeAsync();
    }

    [Benchmark(OperationsPerInvoke = Batch)]
    public async Task AcceptClaimComplete()
    {
        int remaining = Batch;
        await Task.WhenAll(Enumerable.Range(0, 8).Select(async _ =>
        {
            while (Interlocked.Decrement(ref remaining) >= 0)
            {
                await _storage.Intake.AcceptAsync(BenchMessages.Create(Tenant, _raw), default);
            }
        }));

        var claimed = await _storage.Deliveries.ClaimAsync("bench", Batch, DateTimeOffset.UtcNow, TimeSpan.FromMinutes(1), default);
        await Task.WhenAll(claimed.Select(d => _storage.Deliveries.RecordAttemptAsync(new DeliveryAttempt
        {
            DeliveryId = d.DeliveryId,
            Outcome = DeliveryOutcome.Delivered,
            At = DateTimeOffset.UtcNow,
            SmtpCode = 250,
            MxHost = "mx.example.org",
        }, default).AsTask()));
    }
}
