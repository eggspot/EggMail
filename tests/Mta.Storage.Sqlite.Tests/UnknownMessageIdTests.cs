using Mta.Storage.Tests;

namespace Mta.Storage.Sqlite.Tests;

public class SqliteUnknownMessageId : UnknownMessageIdConformance
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
