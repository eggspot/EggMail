using Mta.Storage.Tests;

namespace Mta.Storage.Sqlite.Tests;

// The whole shared conformance suite against the SQLite backend. Suites that must behave identically under both history
// levels run twice; the intake and delivery suites also run under every sync mode.

public class SqliteIntakeFull : IntakeConformance
{
    private string? _dir;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }

        _dir = SqliteTestStorage.NewDirectory();
        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b => b.SyncMode = SqliteSyncMode.Off), Clock));
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

public class SqliteIntakeStatsOnly : IntakeConformance
{
    private string? _dir;

    protected override HistoryMode Mode => HistoryMode.StatsOnly;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }

        _dir = SqliteTestStorage.NewDirectory();
        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b => b.SyncMode = SqliteSyncMode.Off), Clock));
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

public class SqliteDeliveryFull : DeliveryConformance
{
    private string? _dir;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }

        _dir = SqliteTestStorage.NewDirectory();
        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b => b.SyncMode = SqliteSyncMode.Off), Clock));
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

public class SqliteDeliveryStatsOnly : DeliveryConformance
{
    private string? _dir;

    protected override HistoryMode Mode => HistoryMode.StatsOnly;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }

        _dir = SqliteTestStorage.NewDirectory();
        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b => b.SyncMode = SqliteSyncMode.Off), Clock));
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

public class SqliteStatsFull : StatsConformance
{
    private string? _dir;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }

        _dir = SqliteTestStorage.NewDirectory();
        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b => b.SyncMode = SqliteSyncMode.Off), Clock));
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

public class SqliteStatsStatsOnly : StatsConformance
{
    private string? _dir;

    protected override HistoryMode Mode => HistoryMode.StatsOnly;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }

        _dir = SqliteTestStorage.NewDirectory();
        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b => b.SyncMode = SqliteSyncMode.Off), Clock));
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

public class SqliteWebhookFull : WebhookConformance
{
    private string? _dir;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }

        _dir = SqliteTestStorage.NewDirectory();
        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b => b.SyncMode = SqliteSyncMode.Off), Clock));
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

public class SqliteWebhookStatsOnly : WebhookConformance
{
    private string? _dir;

    protected override HistoryMode Mode => HistoryMode.StatsOnly;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }

        _dir = SqliteTestStorage.NewDirectory();
        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b => b.SyncMode = SqliteSyncMode.Off), Clock));
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

public class SqliteMaintenanceFull : MaintenanceConformance
{
    private string? _dir;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }

        _dir = SqliteTestStorage.NewDirectory();
        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b => b.SyncMode = SqliteSyncMode.Off), Clock));
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

public class SqliteMaintenanceStatsOnly : MaintenanceConformance
{
    private string? _dir;

    protected override HistoryMode Mode => HistoryMode.StatsOnly;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }

        _dir = SqliteTestStorage.NewDirectory();
        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b => b.SyncMode = SqliteSyncMode.Off), Clock));
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

public class SqliteHistory : HistoryConformance
{
    private string? _dir;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }

        _dir = SqliteTestStorage.NewDirectory();
        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b => b.SyncMode = SqliteSyncMode.Off), Clock));
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

public class SqliteStatsOnlyHistory : StatsOnlyHistoryConformance
{
    private string? _dir;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }

        _dir = SqliteTestStorage.NewDirectory();
        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b => b.SyncMode = SqliteSyncMode.Off), Clock));
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

public class SqliteRuntimeState : RuntimeStateConformance
{
    private string? _dir;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }

        _dir = SqliteTestStorage.NewDirectory();
        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b => b.SyncMode = SqliteSyncMode.Off), Clock));
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

public class SqliteConfig : ConfigConformance
{
    private string? _dir;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }

        _dir = SqliteTestStorage.NewDirectory();
        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b => b.SyncMode = SqliteSyncMode.Off), Clock));
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

public class SqliteIntakeNormalSync : IntakeConformance
{
    private string? _dir;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }

        _dir = SqliteTestStorage.NewDirectory();
        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b => b.SyncMode = SqliteSyncMode.Normal), Clock));
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

public class SqliteDeliveryNormalSync : DeliveryConformance
{
    private string? _dir;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }

        _dir = SqliteTestStorage.NewDirectory();
        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b => b.SyncMode = SqliteSyncMode.Normal), Clock));
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

public class SqliteIntakeFullSync : IntakeConformance
{
    private string? _dir;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }

        _dir = SqliteTestStorage.NewDirectory();
        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b => b.SyncMode = SqliteSyncMode.Full), Clock));
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

public class SqliteDeliveryFullSync : DeliveryConformance
{
    private string? _dir;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }

        _dir = SqliteTestStorage.NewDirectory();
        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b => b.SyncMode = SqliteSyncMode.Full), Clock));
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


public class SqliteTransferFull : TransferConformance
{
    private string? _dir;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }

        _dir = SqliteTestStorage.NewDirectory();
        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b => b.SyncMode = SqliteSyncMode.Off), Clock));
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

public class SqliteTransferStatsOnly : TransferConformance
{
    private string? _dir;

    protected override HistoryMode Mode => HistoryMode.StatsOnly;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }

        _dir = SqliteTestStorage.NewDirectory();
        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b => b.SyncMode = SqliteSyncMode.Off), Clock));
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

public class SqliteTransferMemoryQueue : TransferConformance
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

public class SqliteInboundFull : InboundConformance
{
    private string? _dir;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }

        _dir = SqliteTestStorage.NewDirectory();
        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b => b.SyncMode = SqliteSyncMode.Off), Clock));
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

public class SqliteInboundStatsOnly : InboundConformance
{
    private string? _dir;

    protected override HistoryMode Mode => HistoryMode.StatsOnly;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }

        _dir = SqliteTestStorage.NewDirectory();
        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b => b.SyncMode = SqliteSyncMode.Off), Clock));
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
