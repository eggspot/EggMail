using Microsoft.EntityFrameworkCore;
using Mta.Storage.Model;
using Mta.Storage.Transfer;

namespace Mta.Storage.Sqlite;

/// <summary>
/// Connects the shared <see cref="EfStorageTransfer"/> to the SQLite files: reads stream on fresh no-tracking contexts over pooled
/// connections (a consistent WAL snapshot, no writer involved); writes run on the part's writer thread inside its transaction,
/// like every other write to that file, so a chunk and its progress record commit together.
/// </summary>
internal sealed class SqliteTransferAccess(SqliteRuntime rt, IStorageModelHooks hooks) : ITransferDbAccess
{
    private readonly Dictionary<TransferPart, object> _writeOptions = [];

    public bool HasPart(TransferPart part) => part != TransferPart.History || rt.History is not null;

    public bool StreamsReads(TransferPart part) => !FileOf(part).IsMemory;

    private SqliteFile FileOf(TransferPart part) => part switch
    {
        TransferPart.Config => rt.Config,
        TransferPart.Stats => rt.Stats,
        TransferPart.Queue => rt.Queue,
        TransferPart.History => rt.History ?? throw new StorageTransferException("This store has no history file (History:Mode=StatsOnly)."),
        _ => throw new ArgumentOutOfRangeException(nameof(part)),
    };

    private SqliteFileWriter WriterOf(TransferPart part) => part switch
    {
        TransferPart.Config => rt.ConfigWriter,
        TransferPart.Stats => rt.StatsWriter,
        TransferPart.Queue => rt.QueueWriter,
        TransferPart.History => rt.HistoryWriter ?? throw new StorageTransferException("This store has no history file (History:Mode=StatsOnly)."),
        _ => throw new ArgumentOutOfRangeException(nameof(part)),
    };

    public DbContext CreateReadContext(TransferPart part)
    {
        string cs = FileOf(part).ReaderConnectionString;
        return part switch
        {
            TransferPart.Config => new ConfigDbContext(ReadOptions<ConfigDbContext>(cs), hooks),
            TransferPart.Stats => new StatsDbContext(ReadOptions<StatsDbContext>(cs), hooks),
            TransferPart.Queue => new QueueDbContext(ReadOptions<QueueDbContext>(cs), hooks),
            _ => new HistoryDbContext(ReadOptions<HistoryDbContext>(cs), hooks),
        };
    }

    private static DbContextOptions<T> ReadOptions<T>(string connectionString) where T : DbContext =>
        new DbContextOptionsBuilder<T>().UseSqlite(connectionString).UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking).Options;

    public async ValueTask<T> WriteAsync<T>(TransferPart part, Func<DbContext, CancellationToken, Task<T>> work, CancellationToken cancellationToken)
    {
        T result = await WriterOf(part).SubmitAsync((work, part, access: this, cancellationToken), static (ctx, s) =>
        {
            using DbContext db = s.access.CreateWriteContext(s.part, ctx);
            db.Database.UseTransaction(ctx.Transaction);

            // The work is asynchronous only in shape: EF over SQLite completes synchronously, and the writer thread has no
            // synchronization context, so waiting here cannot deadlock.
            return s.work(db, s.cancellationToken).GetAwaiter().GetResult();
        }, cancellationToken).ConfigureAwait(false);

        if (part == TransferPart.Config)
        {
            // Rows were written behind the config store's back (endpoints, settings): drop its caches.
            rt.ConfigStore.NotifyExternalChange();
        }

        return result;
    }

    // Built on the writer thread, bound to its connection (one options instance per part).
    private DbContext CreateWriteContext(TransferPart part, WriterContext writer)
    {
        switch (part)
        {
            case TransferPart.Config:
                return new ConfigDbContext(WriteOptions<ConfigDbContext>(part, writer), hooks);
            case TransferPart.Stats:
                return new StatsDbContext(WriteOptions<StatsDbContext>(part, writer), hooks);
            case TransferPart.Queue:
                return new QueueDbContext(WriteOptions<QueueDbContext>(part, writer), hooks);
            default:
                return new HistoryDbContext(WriteOptions<HistoryDbContext>(part, writer), hooks);
        }
    }

    private DbContextOptions<T> WriteOptions<T>(TransferPart part, WriterContext writer) where T : DbContext
    {
        lock (_writeOptions)
        {
            if (!_writeOptions.TryGetValue(part, out object? options))
            {
                options = new DbContextOptionsBuilder<T>().UseSqlite(writer.Connection).Options;
                _writeOptions[part] = options;
            }

            return (DbContextOptions<T>)options;
        }
    }
}
