using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Mta.Storage.Model;
using Npgsql;

namespace Mta.Storage.Postgres;

/// <summary>
/// Connects the shared <see cref="EfConfigStore{TContext}"/> to PostgreSQL: a fresh no-tracking context per read, and per
/// write one transaction that first takes <c>pg_advisory_xact_lock</c>. The lock makes every configuration write (notably the
/// read-modify-write of a lease, decision K) atomic across replicas without session locks, so it also works behind PgBouncer
/// in transaction mode. Config is a cold path; serializing its writes costs nothing that matters.
/// </summary>
internal sealed class PostgresConfigAccess(NpgsqlDataSource dataSource, IStorageModelHooks hooks, int maxPoolSize) : IConfigDbAccess<PostgresDbContext>
{
    // Config reads are on the hot path (a suppression check per recipient, DKIM keys per message): pooled contexts avoid building a
    // service scope per query, like the SQLite provider does.
    private readonly PooledDbContextFactory<PostgresReadContext> _readPool = new(
        new DbContextOptionsBuilder<PostgresReadContext>()
            .UseNpgsql(dataSource)
            .UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking)
            .UseModelHooks(hooks)
            .Options,
        poolSize: 128);

    // The queries are synchronous (shared with SQLite). They run on pool threads, at most a few at a time, so a burst of delivery
    // workers cannot block most of the thread pool in Npgsql and starve the async work that releases pooled connections.
    private readonly SemaphoreSlim _readGate = new(Math.Clamp(maxPoolSize / 4, 1, 4), Math.Clamp(maxPoolSize / 4, 1, 4));

    public PostgresDbContext CreateReadContext() => _readPool.CreateDbContext();

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
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await using (var lockCmd = new NpgsqlCommand("SELECT pg_advisory_xact_lock($1)", connection, tx))
        {
            lockCmd.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlTypes.NpgsqlDbType.Bigint, Value = AdvisoryLockKeys.ConfigWrite });
            await lockCmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

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

    public Exception? TranslateException(Exception exception)
    {
        Exception? translated = PostgresErrors.Translate(exception);
        if (translated is not null && PostgresErrors.IsBrokenConnection(exception))
        {
            dataSource.Clear(); // idle connections of a failed server are dead; do not hand them out again
        }

        return translated;
    }
}
