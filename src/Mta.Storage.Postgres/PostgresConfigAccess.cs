using Microsoft.EntityFrameworkCore;
using Mta.Storage.Model;
using Npgsql;

namespace Mta.Storage.Postgres;

/// <summary>
/// Connects the shared <see cref="EfConfigStore{TContext}"/> to PostgreSQL: a fresh no-tracking context per read, and per
/// write one transaction that first takes <c>pg_advisory_xact_lock</c>. The lock makes every configuration write (notably the
/// read-modify-write of a lease, decision K) atomic across replicas without session locks, so it also works behind PgBouncer
/// in transaction mode. Config is a cold path; serializing its writes costs nothing that matters.
/// </summary>
internal sealed class PostgresConfigAccess(NpgsqlDataSource dataSource, IStorageModelHooks hooks) : IConfigDbAccess<PostgresDbContext>
{
    private readonly DbContextOptions<PostgresDbContext> _readOptions = new DbContextOptionsBuilder<PostgresDbContext>()
        .UseNpgsql(dataSource)
        .UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking)
        .Options;

    public PostgresDbContext CreateReadContext() => new(_readOptions, hooks);

    public async ValueTask<T> WriteAsync<T>(Func<PostgresDbContext, T> work, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await using (var lockCmd = new NpgsqlCommand("SELECT pg_advisory_xact_lock($1)", connection, tx))
        {
            lockCmd.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlTypes.NpgsqlDbType.Bigint, Value = AdvisoryLocks.ConfigWrite });
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
        if (translated is not null)
        {
            dataSource.Clear(); // idle connections of a failed server are dead; do not hand them out again
        }

        return translated;
    }
}
