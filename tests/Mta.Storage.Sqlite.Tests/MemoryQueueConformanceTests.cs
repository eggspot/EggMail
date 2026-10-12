using Mta.Storage.Tests;

namespace Mta.Storage.Sqlite.Tests;

// QueuePersistence=Memory keeps the queue in an in-memory SQLite database owned by the queue writer. The intake, delivery
// and webhook suites must behave exactly as with a file.

public class SqliteIntakeMemoryQueue : IntakeConformance
{
    private string? _dir;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }

        _dir = SqliteTestStorage.NewDirectory();
        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b => b.QueuePersistence = QueuePersistence.Memory), Clock));
    }

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }
    }
}

public class SqliteDeliveryMemoryQueue : DeliveryConformance
{
    private string? _dir;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }

        _dir = SqliteTestStorage.NewDirectory();
        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b => b.QueuePersistence = QueuePersistence.Memory), Clock));
    }

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }
    }
}

public class SqliteWebhookMemoryQueue : WebhookConformance
{
    private string? _dir;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }

        _dir = SqliteTestStorage.NewDirectory();
        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b => b.QueuePersistence = QueuePersistence.Memory), Clock));
    }

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }
    }
}
