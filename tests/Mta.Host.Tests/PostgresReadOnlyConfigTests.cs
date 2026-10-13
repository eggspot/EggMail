using Microsoft.Extensions.Configuration;
using Mta.Host.Configuration;

namespace Mta.Host.Tests;

/// <summary>The read-only PostgreSQL role of design section 4.3 is configurable (docs/operations.md).</summary>
public class PostgresReadOnlyConfigTests
{
    private static LoadedConfig Load(params (string Key, string? Value)[] values) =>
        ConfigLoader.Load(new ConfigurationBuilder().AddInMemoryCollection(values.ToDictionary(v => v.Key, v => v.Value)).Build());

    [Fact]
    public void The_read_only_connection_and_its_limits_are_bound()
    {
        LoadedConfig l = Load(
            ("Storage:Backend", "Postgres"), ("Storage:Postgres:RuntimeConnectionString", "Host=db;Username=rt"),
            ("Storage:Postgres:ReadOnlyConnectionString", "Host=db;Username=ro"), ("Storage:Postgres:ReadOnlyStatementTimeoutSeconds", "3"),
            ("Storage:Postgres:ReadOnlyIdleInTransactionTimeoutSeconds", "20"), ("Storage:Postgres:ReadOnlyMaxPoolSize", "6"));

        Assert.True(l.IsValid, string.Join("; ", l.Errors));
        var pg = l.Config.Storage.Postgres;
        Assert.Equal("Host=db;Username=ro", pg.ReadOnlyConnectionString);
        Assert.Equal(3, pg.ReadOnlyStatementTimeoutSeconds);
        Assert.Equal(20, pg.ReadOnlyIdleInTransactionTimeoutSeconds);
        Assert.Equal(6, pg.ReadOnlyMaxPoolSize);
    }

    [Fact]
    public void Defaults_are_a_five_second_statement_timeout_and_no_separate_role()
    {
        var pg = Load().Config.Storage.Postgres;
        Assert.Null(pg.ReadOnlyConnectionString);
        Assert.Equal(5, pg.ReadOnlyStatementTimeoutSeconds);
        Assert.Equal(10, pg.ReadOnlyIdleInTransactionTimeoutSeconds);
        Assert.Equal(8, pg.ReadOnlyMaxPoolSize);
    }

    [Theory]
    [InlineData("Storage:Postgres:ReadOnlyStatementTimeoutSeconds", "0")]
    [InlineData("Storage:Postgres:ReadOnlyIdleInTransactionTimeoutSeconds", "0")]
    [InlineData("Storage:Postgres:ReadOnlyMaxPoolSize", "0")]
    public void Unusable_limits_are_reported_at_start(string key, string value)
    {
        Assert.Contains(Load((key, value)).Errors, e => e.Contains(key, StringComparison.Ordinal));
    }
}
