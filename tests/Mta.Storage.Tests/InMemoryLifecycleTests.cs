using Mta.Storage.InMemory;
using Xunit.Abstractions;

namespace Mta.Storage.Tests;

// The accelerated lifecycle suite against the in-memory reference backend: the model the other two backends are held to.

public class InMemoryLifecycleFull(ITestOutputHelper output) : LifecycleConformance(output)
{
    protected override Task<IStorage> CreateAsync(StorageOptions options) => Task.FromResult<IStorage>(new InMemoryStorage(options, Clock, null, TimeSpan.Zero));
}

public class InMemoryLifecycleStatsOnly(ITestOutputHelper output) : LifecycleConformance(output)
{
    protected override HistoryMode Mode => HistoryMode.StatsOnly;

    protected override Task<IStorage> CreateAsync(StorageOptions options) => Task.FromResult<IStorage>(new InMemoryStorage(options, Clock, null, TimeSpan.Zero));
}
