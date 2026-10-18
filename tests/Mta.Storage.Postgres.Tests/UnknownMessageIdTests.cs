using Mta.Storage.Tests;

namespace Mta.Storage.Postgres.Tests;

public class PgUnknownMessageId : UnknownMessageIdConformance
{
    private readonly PgHarness _pg = new();

    protected override Task<IStorage> CreateAsync(StorageOptions options) => _pg.CreateAsync(options, Clock);

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await _pg.DisposeAsync();
    }
}
