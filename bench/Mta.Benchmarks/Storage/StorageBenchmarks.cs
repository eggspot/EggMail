using BenchmarkDotNet.Attributes;
using Mta.Core;
using Mta.Storage;
using Mta.Storage.Sqlite;

namespace Mta.Benchmarks.Storage;

/// <summary>
/// SQLite intake throughput: <c>AcceptAsync</c> with 1, 8 and 64 concurrent callers, the three sync modes and 2 KB / 100 KB
/// messages, with the default <c>History:Mode=Full</c> (a content/index/event write follows every queue commit). One
/// operation is one acknowledged message. Run with
/// <c>dotnet run -c Release --project bench/Mta.Benchmarks -- --filter "*StorageAccept*"</c>.
/// Per fairness rule 1 of docs/benchmarks.md, <c>Off</c> results are only meaningful next to the <c>Normal</c> and <c>Full</c> pair.
/// </summary>
[ShortRunJob]
[MemoryDiagnoser]
public class StorageAcceptBenchmarks
{
    private const int MessagesPerInvoke = 1000;
    private static readonly Guid Tenant = Guid.Parse("a0000000-0000-7000-8000-000000000001");

    private string _dir = "";
    private SqliteStorage _storage = null!;
    private byte[] _raw = [];

    [Params(1, 8, 64)]
    public int Writers { get; set; }

    [Params(SqliteSyncMode.Off, SqliteSyncMode.Normal, SqliteSyncMode.Full)]
    public SqliteSyncMode SyncMode { get; set; }

    [Params(2 * 1024, 100 * 1024)]
    public int MessageSize { get; set; }

    [GlobalSetup]
    public async Task Setup()
    {
        _dir = Path.Combine(Path.GetTempPath(), "eggmail-bench-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _storage = SqliteStorage.Create(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = _dir, SyncMode = SyncMode } });
        await _storage.InitializeAsync(default);
        _raw = new byte[MessageSize];
        new Random(1).NextBytes(_raw);
    }

    [GlobalCleanup]
    public async Task Cleanup()
    {
        await _storage.DisposeAsync();
        Directory.Delete(_dir, recursive: true);
    }

    private AcceptedMessage NewMessage() => BenchMessages.Create(Tenant, _raw);

    [Benchmark(OperationsPerInvoke = MessagesPerInvoke)]
    public async Task Accept()
    {
        int remaining = MessagesPerInvoke;
        await Task.WhenAll(Enumerable.Range(0, Writers).Select(async _ =>
        {
            while (Interlocked.Decrement(ref remaining) >= 0)
            {
                await _storage.Intake.AcceptAsync(NewMessage(), default);
            }
        }));
    }
}

/// <summary>
/// The delivery side: accept 100 messages (8 callers), claim them in one call and record <c>Delivered</c> for each. One
/// operation is the whole cycle of one message, so the figure includes intake. <c>Sqlite:SyncMode</c> as in
/// <see cref="StorageAcceptBenchmarks"/>.
/// </summary>
[ShortRunJob]
[MemoryDiagnoser]
public class StorageClaimCompleteBenchmarks
{
    private const int Batch = 100;
    private static readonly Guid Tenant = Guid.Parse("a0000000-0000-7000-8000-000000000001");

    private string _dir = "";
    private SqliteStorage _storage = null!;
    private byte[] _raw = [];

    [Params(SqliteSyncMode.Off, SqliteSyncMode.Normal, SqliteSyncMode.Full)]
    public SqliteSyncMode SyncMode { get; set; }

    [GlobalSetup]
    public async Task Setup()
    {
        _dir = Path.Combine(Path.GetTempPath(), "eggmail-bench-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _storage = SqliteStorage.Create(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = _dir, SyncMode = SyncMode } });
        await _storage.InitializeAsync(default);
        _raw = new byte[2048];
        new Random(1).NextBytes(_raw);
    }

    [GlobalCleanup]
    public async Task Cleanup()
    {
        await _storage.DisposeAsync();
        Directory.Delete(_dir, recursive: true);
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

internal static class BenchMessages
{
    public static AcceptedMessage Create(Guid tenant, byte[] raw)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return new AcceptedMessage
        {
            MessageId = Ids.New(),
            TenantId = tenant,
            Source = MessageSource.Smtp,
            EnvelopeFrom = EmailAddress.Parse("sender@example.com"),
            Recipients = [new AcceptedRecipient(Ids.New(), EmailAddress.Parse("rcpt@example.org"))],
            Raw = raw,
            ReceivedAt = now,
            ExpiresAt = now.AddDays(5),
            SendingDomain = "example.com",
            Content = new MessageContent("Benchmark message", "plain text body", "<p>html body</p>", [], false),
        };
    }
}
