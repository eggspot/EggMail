using Microsoft.EntityFrameworkCore;
using Mta.Storage.Model;

namespace Mta.Storage.Sqlite;

/// <summary>
/// Connects the shared <see cref="EfConfigStore{TContext}"/> to config.db: reads use fresh no-tracking contexts over pooled
/// connections; writes run on the config writer's connection inside its transaction (group commit, one writer per file).
/// </summary>
internal sealed class SqliteConfigAccess(SqliteFile file, IStorageModelHooks hooks) : IConfigDbAccess<ConfigDbContext>
{
    private readonly DbContextOptions<ConfigDbContext> _readOptions = new DbContextOptionsBuilder<ConfigDbContext>()
        .UseSqlite(file.ReaderConnectionString)
        .UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking)
        .Options;

    private DbContextOptions<ConfigDbContext>? _writeOptions; // built on the writer thread, bound to its connection

    public SqliteFileWriter Writer { get; set; } = null!;

    public ConfigDbContext CreateReadContext() => new(_readOptions, hooks);

    public ValueTask<T> WriteAsync<T>(Func<ConfigDbContext, T> work, CancellationToken cancellationToken) =>
        Writer.SubmitAsync((work, this), static (ctx, s) =>
        {
            s.Item2._writeOptions ??= new DbContextOptionsBuilder<ConfigDbContext>().UseSqlite(ctx.Connection).Options;
            using var db = new ConfigDbContext(s.Item2._writeOptions, s.Item2.Hooks);
            db.Database.UseTransaction(ctx.Transaction);
            return s.work(db);
        }, cancellationToken);

    private IStorageModelHooks Hooks => hooks;
}
