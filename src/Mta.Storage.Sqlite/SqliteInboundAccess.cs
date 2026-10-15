using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage;
using Mta.Storage.Logic;
using Mta.Storage.Model;
using Mta.Storage.Transfer;

namespace Mta.Storage.Sqlite;

/// <summary>
/// Connects the shared <see cref="EfInboundMessageStore{TContext}"/> to queue.db: reads use pooled no-tracking contexts over read connections (or run on the
/// writer when the queue is in memory, whose only connection the writer owns); writes run on the queue writer's connection inside its batch transaction, so
/// they group-commit with intake and the delivery queue.
/// </summary>
internal sealed class SqliteInboundAccess(SqliteRuntime rt, IStorageModelHooks hooks) : IInboundDbAccess<QueueDbContext>
{
    private PooledDbContextFactory<QueueReadContext>? _readPool;
    private DbContextOptions<QueueDbContext>? _writeOptions; // bound to the writer's connection, built on the writer thread

    public SwitchGate Fence => rt.Fence;

    internal IStorageModelHooks Hooks => hooks;

    private PooledDbContextFactory<QueueReadContext> ReadPool => _readPool ??= new PooledDbContextFactory<QueueReadContext>(
        new DbContextOptionsBuilder<QueueReadContext>()
            .UseSqlite(rt.Queue.ReaderConnectionString)
            .UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking)
            .UseModelHooks(hooks)
            .Options,
        poolSize: 32);

    public ValueTask<T> ReadAsync<T>(Func<QueueDbContext, T> query)
    {
        if (rt.Queue.IsMemory)
        {
            return WriteAsync(query, CancellationToken.None);
        }

        using QueueReadContext ctx = ReadPool.CreateDbContext();
        return ValueTask.FromResult(query(ctx));
    }

    public ValueTask<T> WriteAsync<T>(Func<QueueDbContext, T> work, CancellationToken cancellationToken) =>
        rt.QueueWriter.SubmitAsync((work, this), static (ctx, s) =>
        {
            s.Item2._writeOptions ??= new DbContextOptionsBuilder<QueueDbContext>().UseSqlite(ctx.Connection).Options;
            using var db = new QueueDbContext(s.Item2._writeOptions, s.Item2.Hooks);
            db.Database.UseTransaction(ctx.Transaction);
            return s.work(db);
        }, cancellationToken, needsDriverTransaction: true);

    // One writer, one transaction: the single-process claim needs no row locks.
    public IReadOnlyList<Guid> ClaimIds(QueueDbContext context, string owner, int max, DateTimeOffset now, DateTimeOffset until)
    {
        DbConnection connection = context.Database.GetDbConnection();
        using DbCommand cmd = connection.CreateCommand();
        cmd.Transaction = context.Database.CurrentTransaction?.GetDbTransaction();
        cmd.CommandText =
            "UPDATE inbound_message SET lease_owner = @owner, lease_until = @until WHERE id IN (" +
            "SELECT id FROM inbound_message WHERE transfer_switch_id IS NULL AND action_state = 0 AND action_next_attempt_at <= @now AND lease_until <= @now ORDER BY action_next_attempt_at, id LIMIT @max) " +
            "RETURNING id";
        Add(cmd, "@owner", owner);
        Add(cmd, "@until", StorageTime.ToUnixMs(until));
        Add(cmd, "@now", StorageTime.ToUnixMs(now));
        Add(cmd, "@max", (long)max);
        var ids = new List<Guid>();
        using DbDataReader reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            ids.Add(Guid.Parse(reader.GetString(0)));
        }

        return ids;
    }

    private static void Add(DbCommand cmd, string name, object value)
    {
        DbParameter p = cmd.CreateParameter();
        p.ParameterName = name;
        p.Value = value;
        cmd.Parameters.Add(p);
    }
}
