using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Mta.Storage.Logic;
using Mta.Storage.Model;

namespace Mta.Storage.Postgres;

/// <summary>
/// PostgreSQL specifics of the shared model. Timestamps are native <c>timestamptz</c>; the converter writes them as UTC
/// truncated to whole milliseconds, because Npgsql refuses a <see cref="DateTimeOffset"/> with a non-zero offset and
/// because SQLite and the in-memory backend keep millisecond precision (decision E: identical observable behaviour).
/// Every <c>text</c> column uses the <c>"C"</c> collation, which orders by bytes exactly like SQLite's default BINARY
/// collation, so ordering and range comparisons do not depend on the collation the database happened to be created with.
/// Guids are native <c>uuid</c>, whose comparison is the byte order of the canonical text (so UUIDv7 ids sort by time).
/// </summary>
public sealed class PostgresModelHooks : IStorageModelHooks
{
    public static readonly PostgresModelHooks Instance = new();

    /// <summary>The collation applied to text columns (byte order, independent of the database default).</summary>
    public const string TextCollation = "C";

    public void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        configurationBuilder.Properties<DateTimeOffset>().HaveConversion<UtcMillisecondsConverter>();
        configurationBuilder.Properties<DateTimeOffset?>().HaveConversion<NullableUtcMillisecondsConverter>();
    }

    public void OnModelBuilt(ModelBuilder modelBuilder)
    {
        foreach (var entity in modelBuilder.Model.GetEntityTypes())
        {
            foreach (var property in entity.GetProperties())
            {
                if (property.ClrType == typeof(string))
                {
                    property.SetCollation(TextCollation);
                }
            }

            // The shared model writes partial-index predicates in SQLite's integer boolean dialect.
            foreach (var index in entity.GetIndexes())
            {
                if (index.GetFilter() == "awaiting_retention = 1")
                {
                    index.SetFilter("awaiting_retention");
                }
            }
        }
    }
}

public sealed class UtcMillisecondsConverter : ValueConverter<DateTimeOffset, DateTimeOffset>
{
    public UtcMillisecondsConverter()
        : base(v => StorageTime.Normalize(v), v => v)
    {
    }
}

public sealed class NullableUtcMillisecondsConverter : ValueConverter<DateTimeOffset?, DateTimeOffset?>
{
    public NullableUtcMillisecondsConverter()
        : base(v => StorageTime.Normalize(v), v => v)
    {
    }
}
