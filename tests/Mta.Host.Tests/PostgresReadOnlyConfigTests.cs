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

    [Theory]
    [InlineData("Host=db;Database=x")]
    [InlineData("Host=db;Username=")]
    public void A_read_only_connection_string_must_name_its_user(string connection)
    {
        Assert.Contains(Load(("Storage:Postgres:ReadOnlyConnectionString", connection)).Errors, e => e.Contains("Username", StringComparison.Ordinal));
        Assert.Empty(Load(("Storage:Postgres:ReadOnlyConnectionString", "Host=db;Username=ro")).Errors);
    }

    [Fact]
    public void A_backend_switch_carries_the_read_only_connection_to_the_target_so_it_is_not_silently_dropped()
    {
        var target = new Mta.Storage.StorageOptions
        {
            Backend = Mta.Storage.StorageBackend.Postgres,
            Postgres = new Mta.Storage.PostgresOptions
            {
                RuntimeConnectionString = "Host=db;Username=rt",
                ReadOnlyConnectionString = "Host=db;Username=ro;Password=secret",
                ReadOnlyStatementTimeoutSeconds = 3,
            },
        };

        var pointer = Mta.Host.Switching.SwitchActivator.PointerFor(target);

        var readOnly = Assert.Single(pointer, p => p.Key == "Storage:Postgres:ReadOnlyConnectionString");
        Assert.Equal("Host=db;Username=ro;Password=secret", readOnly.Value);
        Assert.True(readOnly.Secret);   // never printed in a patch or a log
        Assert.Equal("3", Assert.Single(pointer, p => p.Key == "Storage:Postgres:ReadOnlyStatementTimeoutSeconds").Value);
        Assert.DoesNotContain(Mta.Host.Switching.SwitchActivator.PointerFor(new Mta.Storage.StorageOptions { Backend = Mta.Storage.StorageBackend.Postgres, Postgres = new Mta.Storage.PostgresOptions { RuntimeConnectionString = "Host=db;Username=rt" } }),
            p => p.Key.Contains("ReadOnly", StringComparison.Ordinal));
    }
}
