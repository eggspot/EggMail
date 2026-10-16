using Mta.Storage.InMemory;

namespace Mta.Storage.Tests;

public class InMemoryUnknownMessageId : UnknownMessageIdConformance
{
    protected override Task<IStorage> CreateAsync(StorageOptions options) => Task.FromResult<IStorage>(new InMemoryStorage(options, Clock, null, TimeSpan.Zero));
}
