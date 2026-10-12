using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Mta.Storage.Model;

namespace Mta.Storage.Sqlite;

/// <summary>
/// SQLite specifics of the shared model. Every <see cref="DateTimeOffset"/> is stored as UTC unix milliseconds in an
/// INTEGER column, so ordering and range predicates run in SQLite instead of on the client (the provider cannot translate
/// <c>DateTimeOffset</c> comparisons of text columns). Guids keep the provider default: upper-case canonical TEXT, whose
/// byte order equals the time order of a UUIDv7.
/// </summary>
public sealed class SqliteModelHooks : IStorageModelHooks
{
    public static readonly SqliteModelHooks Instance = new();

    public void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        configurationBuilder.Properties<DateTimeOffset>().HaveConversion<UnixMillisecondsConverter>();
        configurationBuilder.Properties<DateTimeOffset?>().HaveConversion<UnixMillisecondsConverter>();
    }

    public void OnModelBuilt(ModelBuilder modelBuilder)
    {
    }
}

public sealed class UnixMillisecondsConverter : ValueConverter<DateTimeOffset, long>
{
    public UnixMillisecondsConverter()
        : base(v => v.ToUnixTimeMilliseconds(), v => DateTimeOffset.FromUnixTimeMilliseconds(v))
    {
    }
}
