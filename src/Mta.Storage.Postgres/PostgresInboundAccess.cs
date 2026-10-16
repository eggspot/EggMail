using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage;
using Mta.Storage.Logic;
using Mta.Storage.Model;
using Mta.Storage.Transfer;
using Npgsql;
using NpgsqlTypes;

namespace Mta.Storage.Postgres;

/// <summary>
/// Connects the shared <see cref="EfInboundMessageStore{TContext}"/> to the inbound tables of the PostgreSQL database: a pooled no-tracking context per read
/// (bounded like the configuration reads, so a burst cannot block the thread pool in Npgsql), one transaction per write, and a claim with
/// <c>FOR UPDATE SKIP LOCKED</c> so any number of replicas take disjoint rows. No advisory lock: inbound writes are independent rows.
/// </summary>
internal sealed class PostgresInboundAccess(PostgresRuntime rt, IStorageModelHooks hooks) : IInboundDbAccess<PostgresDbContext>
{
    private readonly PooledDbContextFactory<PostgresReadContext> _readPool = new(
        new DbContextOptionsBuilder<PostgresReadContext>()
            .UseNpgsql(rt.Data)
            .UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking)
            .UseModelHooks(hooks)
            .Options,
        poolSize: 32);

    private readonly SemaphoreSlim _readGate = new(Math.Clamp(rt.Options.Postgres.MaxPoolSize / 4, 1, 4), Math.Clamp(rt.Options.Postgres.MaxPoolSize / 4, 1, 4));

    public SwitchGate Fence => rt.Fence;

    public async ValueTask<T> ReadAsync<T>(Func<PostgresDbContext, T> query)
    {
        await _readGate.WaitAsync().ConfigureAwait(false);
        try
        {
            return await Task.Run(() =>
            {
                using PostgresReadContext ctx = _readPool.CreateDbContext();
                return query(ctx);
            }).ConfigureAwait(false);
        }
        finally
        {
            _readGate.Release();
        }
    }

    public async ValueTask<T> WriteAsync<T>(Func<PostgresDbContext, T> work, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await rt.Data.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        DbContextOptions<PostgresDbContext> options = new DbContextOptionsBuilder<PostgresDbContext>().UseNpgsql(connection).Options;
        T result;
        await using (var db = new PostgresDbContext(options, hooks))
        {
            await db.Database.UseTransactionAsync(tx, cancellationToken).ConfigureAwait(false);
            result = work(db);
        }

        await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
        return result;
    }

    public Exception? TranslateException(Exception exception) =>
        PostgresErrors.IsDiskFull(exception) ? new StorageFullException("The disk holding the PostgreSQL data is full (53100).", exception)
        : PostgresErrors.IsUnavailable(exception) ? rt.Unavailable(exception)
        : PostgresErrors.IsRetryable(exception) ? PostgresErrors.Unavailable(exception)
        : null;

    public bool IsConstraintViolation(Exception exception) => PostgresErrors.IsConstraint(exception);

    public IReadOnlyList<Guid> ClaimIds(PostgresDbContext context, string owner, int max, DateTimeOffset now, DateTimeOffset until)
    {
        DbConnection connection = context.Database.GetDbConnection();
        using DbCommand cmd = connection.CreateCommand();
        cmd.Transaction = context.Database.CurrentTransaction?.GetDbTransaction();
        cmd.CommandText =
            "UPDATE inbound_message SET lease_owner = @owner, lease_until = @until, action_attempts = action_attempts + 1 WHERE id IN (" +
            "SELECT id FROM inbound_message WHERE transfer_switch_id IS NULL AND action_state = 0 AND action_next_attempt_at <= @now AND lease_until <= @now ORDER BY action_next_attempt_at, id LIMIT @max FOR UPDATE SKIP LOCKED) " +
            "RETURNING id";
        cmd.Parameters.Add(new NpgsqlParameter("owner", NpgsqlDbType.Text) { Value = owner });
        cmd.Parameters.Add(new NpgsqlParameter("until", NpgsqlDbType.TimestampTz) { Value = StorageTime.Normalize(until) });
        cmd.Parameters.Add(new NpgsqlParameter("now", NpgsqlDbType.TimestampTz) { Value = StorageTime.Normalize(now) });
        cmd.Parameters.Add(new NpgsqlParameter("max", NpgsqlDbType.Bigint) { Value = (long)max });
        var ids = new List<Guid>();
        using DbDataReader reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            ids.Add(reader.GetGuid(0));
        }

        return ids;
    }
}
