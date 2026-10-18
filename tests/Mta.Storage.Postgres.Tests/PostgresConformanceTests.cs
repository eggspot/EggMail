using Mta.Storage.Tests;

namespace Mta.Storage.Postgres.Tests;

// The whole shared conformance suite against the PostgreSQL backend: the same abstract classes that InMemory and SQLite run.
// Suites that must behave identically under both history levels run twice. Every test gets a fresh database.

public class PgIntakeFull : IntakeConformance
{
    private readonly PgHarness _pg = new();

    protected override Task<IStorage> CreateAsync(StorageOptions options) => _pg.CreateAsync(options, Clock);

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await _pg.DisposeAsync();
    }
}

public class PgIntakeStatsOnly : IntakeConformance
{
    private readonly PgHarness _pg = new();

    protected override HistoryMode Mode => HistoryMode.StatsOnly;

    protected override Task<IStorage> CreateAsync(StorageOptions options) => _pg.CreateAsync(options, Clock);

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await _pg.DisposeAsync();
    }
}

public class PgDeliveryFull : DeliveryConformance
{
    private readonly PgHarness _pg = new();

    protected override Task<IStorage> CreateAsync(StorageOptions options) => _pg.CreateAsync(options, Clock);

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await _pg.DisposeAsync();
    }
}

public class PgDeliveryStatsOnly : DeliveryConformance
{
    private readonly PgHarness _pg = new();

    protected override HistoryMode Mode => HistoryMode.StatsOnly;

    protected override Task<IStorage> CreateAsync(StorageOptions options) => _pg.CreateAsync(options, Clock);

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await _pg.DisposeAsync();
    }
}

public class PgStatsFull : StatsConformance
{
    private readonly PgHarness _pg = new();

    protected override Task<IStorage> CreateAsync(StorageOptions options) => _pg.CreateAsync(options, Clock);

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await _pg.DisposeAsync();
    }
}

public class PgStatsStatsOnly : StatsConformance
{
    private readonly PgHarness _pg = new();

    protected override HistoryMode Mode => HistoryMode.StatsOnly;

    protected override Task<IStorage> CreateAsync(StorageOptions options) => _pg.CreateAsync(options, Clock);

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await _pg.DisposeAsync();
    }
}

public class PgWebhookFull : WebhookConformance
{
    private readonly PgHarness _pg = new();

    protected override bool SubscriberAnswerIsPrecise => false;

    protected override Task<IStorage> CreateAsync(StorageOptions options) => _pg.CreateAsync(options, Clock);

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await _pg.DisposeAsync();
    }
}

public class PgWebhookStatsOnly : WebhookConformance
{
    private readonly PgHarness _pg = new();

    protected override bool SubscriberAnswerIsPrecise => false;

    protected override HistoryMode Mode => HistoryMode.StatsOnly;

    protected override Task<IStorage> CreateAsync(StorageOptions options) => _pg.CreateAsync(options, Clock);

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await _pg.DisposeAsync();
    }
}

public class PgMaintenanceFull : MaintenanceConformance
{
    private readonly PgHarness _pg = new();

    protected override Task<IStorage> CreateAsync(StorageOptions options) => _pg.CreateAsync(options, Clock);

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await _pg.DisposeAsync();
    }
}

public class PgMaintenanceStatsOnly : MaintenanceConformance
{
    private readonly PgHarness _pg = new();

    protected override HistoryMode Mode => HistoryMode.StatsOnly;

    protected override Task<IStorage> CreateAsync(StorageOptions options) => _pg.CreateAsync(options, Clock);

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await _pg.DisposeAsync();
    }
}

public class PgHistory : HistoryConformance
{
    private readonly PgHarness _pg = new();

    protected override Task<IStorage> CreateAsync(StorageOptions options) => _pg.CreateAsync(options, Clock);

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await _pg.DisposeAsync();
    }
}

public class PgStatsOnlyHistory : StatsOnlyHistoryConformance
{
    private readonly PgHarness _pg = new();

    protected override Task<IStorage> CreateAsync(StorageOptions options) => _pg.CreateAsync(options, Clock);

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await _pg.DisposeAsync();
    }
}

public class PgRuntimeState : RuntimeStateConformance
{
    private readonly PgHarness _pg = new();

    protected override Task<IStorage> CreateAsync(StorageOptions options) => _pg.CreateAsync(options, Clock);

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await _pg.DisposeAsync();
    }
}

public class PgReplicaCoordinationConformance : ReplicaCoordinationConformance
{
    private readonly PgHarness _pg = new();

    protected override Task<IStorage> CreateAsync(StorageOptions options) => _pg.CreateAsync(options, Clock);

    /// <summary>The coordination runs on the database server's clock, which only real time moves.</summary>
    protected override Task PassTimeAsync(TimeSpan by) => Task.Delay(by);

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await _pg.DisposeAsync();
    }
}

public class PgConfig : ConfigConformance
{
    private readonly PgHarness _pg = new();

    protected override Task<IStorage> CreateAsync(StorageOptions options) => _pg.CreateAsync(options, Clock);

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await _pg.DisposeAsync();
    }
}

public class PgTransferFull : TransferConformance
{
    private readonly PgHarness _pg = new();

    protected override Task<IStorage> CreateAsync(StorageOptions options) => _pg.CreateAsync(options, Clock);

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await _pg.DisposeAsync();
    }
}

public class PgTransferStatsOnly : TransferConformance
{
    private readonly PgHarness _pg = new();

    protected override HistoryMode Mode => HistoryMode.StatsOnly;

    protected override Task<IStorage> CreateAsync(StorageOptions options) => _pg.CreateAsync(options, Clock);

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await _pg.DisposeAsync();
    }
}

public class PgInboundFull : InboundConformance
{
    private readonly PgHarness _pg = new();

    protected override Task<IStorage> CreateAsync(StorageOptions options) => _pg.CreateAsync(options, Clock);

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await _pg.DisposeAsync();
    }
}


public class PgInboundStatsOnly : InboundConformance
{
    private readonly PgHarness _pg = new();

    protected override HistoryMode Mode => HistoryMode.StatsOnly;

    protected override Task<IStorage> CreateAsync(StorageOptions options) => _pg.CreateAsync(options, Clock);

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await _pg.DisposeAsync();
    }
}

public class PgInjection : InjectionConformance
{
    private readonly PgHarness _pg = new();

    protected override Task<IStorage> CreateAsync(StorageOptions options) => _pg.CreateAsync(options, Clock);

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await _pg.DisposeAsync();
    }
}
