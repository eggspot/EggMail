using Microsoft.EntityFrameworkCore;
using Mta.Storage.Model;
using Mta.Storage.Transfer;
using Npgsql;

namespace Mta.Storage.Postgres;

/// <summary>
/// Connects the shared <see cref="EfStorageTransfer"/> to PostgreSQL. One database holds all four parts, so a chunk's rows and its
/// progress record are always one transaction. Reads stream on their own connection; writes are one transaction per call.
/// History tables are partitioned by day: <see cref="PrepareHistoryDaysAsync"/> creates the partitions an imported chunk needs,
/// including days older than the application would create on its own.
/// </summary>
internal sealed class PostgresTransferAccess(PostgresRuntime rt, IStorageModelHooks hooks) : ITransferDbAccess
{
    private readonly DbContextOptions<PostgresDbContext> _readOptions = new DbContextOptionsBuilder<PostgresDbContext>()
        .UseNpgsql(rt.Data)
        .UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking)
        .Options;

    public bool HasPart(TransferPart part) => part != TransferPart.History || rt.IsFull;

    public bool StreamsReads(TransferPart part) => true;

    public DbContext CreateReadContext(TransferPart part) => new PostgresDbContext(_readOptions, hooks);

    public async ValueTask<T> WriteAsync<T>(TransferPart part, Func<DbContext, CancellationToken, Task<T>> work, CancellationToken cancellationToken)
    {
        try
        {
            await using NpgsqlConnection connection = await rt.Data.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using NpgsqlTransaction tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
            DbContextOptions<PostgresDbContext> options = new DbContextOptionsBuilder<PostgresDbContext>().UseNpgsql(connection).Options;
            T result;
            await using (var db = new PostgresDbContext(options, hooks))
            {
                await db.Database.UseTransactionAsync(tx, cancellationToken).ConfigureAwait(false);
                result = await work(db, cancellationToken).ConfigureAwait(false);
            }

            await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
            if (part == TransferPart.Config)
            {
                rt.ConfigStore.NotifyExternalChange();
            }

            return result;
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex))
        {
            throw rt.Unavailable(ex);
        }
    }

    public async ValueTask PrepareHistoryDaysAsync(int firstDay, int lastDay, CancellationToken cancellationToken)
    {
        try
        {
            await rt.Partitions.EnsureRangeAsync(firstDay, lastDay, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex))
        {
            throw rt.Unavailable(ex);
        }
    }
}
