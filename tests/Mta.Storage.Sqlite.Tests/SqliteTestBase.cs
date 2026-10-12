using Microsoft.Data.Sqlite;
using Mta.Storage.Tests;

namespace Mta.Storage.Sqlite.Tests;

/// <summary>Base of the SQLite-specific tests: one data directory per test, reopenable with different settings.</summary>
public abstract class SqliteTestBase : StorageTestBase
{
    private Action<SqliteOptionsBuilder>? _tune;

    protected string Dir { get; private set; } = "";

    protected SqliteStorage Sql => (SqliteStorage)Storage;

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (Dir.Length == 0)
        {
            Dir = SqliteTestStorage.NewDirectory();
        }

        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, Dir, _tune), Clock));
    }

    /// <summary>Closes the storage and opens a new one over the same files with the given settings.</summary>
    protected async Task ReopenAsync(Action<SqliteOptionsBuilder>? tune = null, HistoryMode? mode = null, RetentionOptions? retention = null, ContentOptions? content = null)
    {
        _tune = tune;
        StorageOptions o = Opts(retention: retention, content: content);
        if (mode is { } m)
        {
            o = WithMode(o, m);
        }

        await OpenAsync(o);
    }

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        if (Dir.Length > 0)
        {
            SqliteTestStorage.TryDelete(Dir);
        }
    }

    protected string PathOf(string file) => System.IO.Path.Combine(Dir, file);

    protected static long ScalarLong(string databasePath, string sql)
    {
        using var c = new SqliteConnection($"Data Source={databasePath};Mode=ReadOnly;Pooling=False");
        c.Open();
        using SqliteCommand cmd = c.CreateCommand();
        cmd.CommandText = sql;
        return Convert.ToInt64(cmd.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
    }

    protected static string ScalarText(string databasePath, string sql)
    {
        using var c = new SqliteConnection($"Data Source={databasePath};Mode=ReadOnly;Pooling=False");
        c.Open();
        using SqliteCommand cmd = c.CreateCommand();
        cmd.CommandText = sql;
        return Convert.ToString(cmd.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture) ?? "";
    }

    /// <summary>Runs a statement on the writer connection of a file and returns a scalar (the PRAGMA values are per connection).</summary>
    protected async Task<long> WriterScalarAsync(string file, string sql) =>
        await Sql.Runtime.Writers.Single(w => w.File.Name == file).SubmitAsync(sql, static (ctx, s) => Convert.ToInt64(SqliteFile.Scalar(ctx.Connection, s), System.Globalization.CultureInfo.InvariantCulture), exclusive: true);
}
