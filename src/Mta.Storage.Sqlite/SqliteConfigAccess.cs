using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Mta.Storage.Model;

namespace Mta.Storage.Sqlite;

/// <summary>
/// Connects the shared <see cref="EfConfigStore{TContext}"/> to config.db: reads use fresh no-tracking contexts over pooled
/// connections; writes run on the config writer's connection inside its transaction (group commit, one writer per file).
/// </summary>
internal sealed class SqliteConfigAccess(SqliteFile file, IStorageModelHooks hooks) : IConfigDbAccess<ConfigDbContext>
{
    // Reads are on the hot path (suppression check per recipient): pooled contexts avoid building a service scope per query.
    private readonly PooledDbContextFactory<ConfigReadContext> _readPool = new(
        new DbContextOptionsBuilder<ConfigReadContext>()
            .UseSqlite(file.ReaderConnectionString)
            .UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking)
            .UseModelHooks(hooks)
            .Options,
        poolSize: 128);

    private DbContextOptions<ConfigDbContext>? _writeOptions; // built on the writer thread, bound to its connection

    public SqliteFileWriter Writer { get; set; } = null!;

    public ConfigDbContext CreateReadContext() => _readPool.CreateDbContext();

    private static readonly Stmt SuppressedSql = new("SELECT 1 FROM suppression WHERE tenant_id = @t AND address = @a LIMIT 1", "@t", "@a");

    /// <summary>The suppression check per recipient, on an open read connection with a prepared statement (about 15 KB less than the EF query).</summary>
    public bool? TryIsSuppressed(Guid tenantId, string normalizedAddress)
    {
        using ReadLease lease = file.ReadSessions.Rent();
        using RawReader row = lease.Session.Command(SuppressedSql).Set(0, tenantId).Set(1, normalizedAddress).ExecuteReader();
        return row.Read();
    }

    public ValueTask<T> WriteAsync<T>(Func<ConfigDbContext, T> work, CancellationToken cancellationToken) =>
        Writer.SubmitAsync((work, this), static (ctx, s) =>
        {
            s.Item2._writeOptions ??= new DbContextOptionsBuilder<ConfigDbContext>().UseSqlite(ctx.Connection).Options;
            using var db = new ConfigDbContext(s.Item2._writeOptions, s.Item2.Hooks);
            db.Database.UseTransaction(ctx.Transaction);
            return s.work(db);
        }, cancellationToken, needsDriverTransaction: true);

    private IStorageModelHooks Hooks => hooks;
}
