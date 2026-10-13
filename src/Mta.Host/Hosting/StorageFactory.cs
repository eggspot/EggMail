using Mta.Core;
using Mta.Storage;
using Mta.Storage.Postgres;
using Mta.Storage.Sqlite;

namespace Mta.Host.Hosting;

/// <summary>Creates the configured storage backend (not yet initialized).</summary>
public static class StorageFactory
{
    public static IStorage Create(StorageOptions options, IClock clock, IMtaLog log) => options.Backend switch
    {
        StorageBackend.Sqlite => SqliteStorage.Create(options, clock, log),
        StorageBackend.Postgres => PostgresStorage.Create(options, clock, log),
        _ => throw new ArgumentOutOfRangeException(nameof(options)),
    };
}
