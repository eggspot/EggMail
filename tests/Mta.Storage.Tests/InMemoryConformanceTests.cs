using Mta.Storage.InMemory;

namespace Mta.Storage.Tests;

// The in-memory backend runs the whole conformance suite. Suites that must behave identically under both history
// levels run twice; history suites run in the mode they test.

public class InMemoryIntakeFull : IntakeConformance
{
    protected override Task<IStorage> CreateAsync(StorageOptions options) => Task.FromResult<IStorage>(new InMemoryStorage(options, Clock, null, TimeSpan.Zero));
}

public class InMemoryIntakeStatsOnly : IntakeConformance
{
    protected override HistoryMode Mode => HistoryMode.StatsOnly;

    protected override Task<IStorage> CreateAsync(StorageOptions options) => Task.FromResult<IStorage>(new InMemoryStorage(options, Clock, null, TimeSpan.Zero));
}

public class InMemoryDeliveryFull : DeliveryConformance
{
    protected override Task<IStorage> CreateAsync(StorageOptions options) => Task.FromResult<IStorage>(new InMemoryStorage(options, Clock, null, TimeSpan.Zero));
}

public class InMemoryDeliveryStatsOnly : DeliveryConformance
{
    protected override HistoryMode Mode => HistoryMode.StatsOnly;

    protected override Task<IStorage> CreateAsync(StorageOptions options) => Task.FromResult<IStorage>(new InMemoryStorage(options, Clock, null, TimeSpan.Zero));
}

public class InMemoryHistory : HistoryConformance
{
    protected override Task<IStorage> CreateAsync(StorageOptions options) => Task.FromResult<IStorage>(new InMemoryStorage(options, Clock, null, TimeSpan.Zero));
}

public class InMemoryStatsOnlyHistory : StatsOnlyHistoryConformance
{
    protected override Task<IStorage> CreateAsync(StorageOptions options) => Task.FromResult<IStorage>(new InMemoryStorage(options, Clock, null, TimeSpan.Zero));
}

public class InMemoryStatsFull : StatsConformance
{
    protected override Task<IStorage> CreateAsync(StorageOptions options) => Task.FromResult<IStorage>(new InMemoryStorage(options, Clock, null, TimeSpan.Zero));
}

public class InMemoryStatsStatsOnly : StatsConformance
{
    protected override HistoryMode Mode => HistoryMode.StatsOnly;

    protected override Task<IStorage> CreateAsync(StorageOptions options) => Task.FromResult<IStorage>(new InMemoryStorage(options, Clock, null, TimeSpan.Zero));
}

public class InMemoryWebhookFull : WebhookConformance
{
    protected override Task<IStorage> CreateAsync(StorageOptions options) => Task.FromResult<IStorage>(new InMemoryStorage(options, Clock, null, TimeSpan.Zero));
}

public class InMemoryWebhookStatsOnly : WebhookConformance
{
    protected override HistoryMode Mode => HistoryMode.StatsOnly;

    protected override Task<IStorage> CreateAsync(StorageOptions options) => Task.FromResult<IStorage>(new InMemoryStorage(options, Clock, null, TimeSpan.Zero));
}

public class InMemoryConfig : ConfigConformance
{
    protected override Task<IStorage> CreateAsync(StorageOptions options) => Task.FromResult<IStorage>(new InMemoryStorage(options, Clock, null, TimeSpan.Zero));
}

public class InMemoryMaintenanceFull : MaintenanceConformance
{
    protected override Task<IStorage> CreateAsync(StorageOptions options) => Task.FromResult<IStorage>(new InMemoryStorage(options, Clock, null, TimeSpan.Zero));
}

public class InMemoryMaintenanceStatsOnly : MaintenanceConformance
{
    protected override HistoryMode Mode => HistoryMode.StatsOnly;

    protected override Task<IStorage> CreateAsync(StorageOptions options) => Task.FromResult<IStorage>(new InMemoryStorage(options, Clock, null, TimeSpan.Zero));
}
