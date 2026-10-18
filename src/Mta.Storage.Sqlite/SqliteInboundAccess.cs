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
    private readonly Lazy<PooledDbContextFactory<QueueReadContext>> _readPool = new(() => new PooledDbContextFactory<QueueReadContext>(
        new DbContextOptionsBuilder<QueueReadContext>()
            .UseSqlite(rt.Queue.ReaderConnectionString)
            .UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking)
            .UseModelHooks(hooks)
            .Options,
        poolSize: 32));
    private DbContextOptions<QueueDbContext>? _writeOptions; // bound to the writer's connection, built on the writer thread

    public SwitchGate Fence => rt.Fence;

    internal IStorageModelHooks Hooks => hooks;

    public ValueTask<T> ReadAsync<T>(Func<QueueDbContext, T> query)
    {
        if (rt.Queue.IsMemory)
        {
            return WriteAsync(query, CancellationToken.None);
        }

        using QueueReadContext ctx = _readPool.Value.CreateDbContext();
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

    /// <summary>
    /// What a SQLite failure means for the caller. EF wraps the provider exception (<c>DbUpdateException</c> around a <c>SqliteException</c>), so the chain is searched: SQLITE_FULL (13,
    /// whatever its extended code) is <see cref="StorageFullException"/> (the receive path answers <c>452 4.3.1</c>, as for the other queue writes), a busy or locked database, an I/O error or
    /// an unreadable file is <see cref="StorageUnavailableException"/>; anything else (a constraint) is not translated and the store reports it as a conflict.
    /// </summary>
    public Exception? TranslateException(Exception exception) => Translate(exception);

    public bool IsConstraintViolation(Exception exception) => IsConstraint(exception);

    internal static bool IsConstraint(Exception exception)
    {
        for (Exception? e = exception; e is not null; e = e.InnerException)
        {
            if (e is Microsoft.Data.Sqlite.SqliteException sqlite)
            {
                return (sqlite.SqliteErrorCode & 0xFF) == 19;   // SQLITE_CONSTRAINT, whatever the extended code
            }
        }

        return false;
    }

    internal static Exception? Translate(Exception exception)
    {
        if (exception is StorageUnavailableException)
        {
            return exception;   // the writer already translated it
        }

        for (Exception? e = exception; e is not null; e = e.InnerException)
        {
            if (e is Microsoft.Data.Sqlite.SqliteException sqlite)
            {
                return (sqlite.SqliteErrorCode & 0xFF) switch
                {
                    13 => new StorageFullException("The disk holding the SQLite files is full (SQLITE_FULL).", exception),
                    5 or 6 or 8 or 10 or 11 or 14 => new StorageUnavailableException("SQLite could not complete the inbound write (busy, locked, read-only, or an I/O error): " + sqlite.Message, exception),
                    _ => null,
                };
            }
        }

        return null;
    }

    // One writer, one transaction: the single-process claim needs no row locks.
    public IReadOnlyList<Guid> ClaimIds(QueueDbContext context, string owner, int max, DateTimeOffset now, DateTimeOffset until, InboundClaimLimits? limits)
    {
        DbConnection connection = context.Database.GetDbConnection();
        using DbCommand cmd = connection.CreateCommand();
        cmd.Transaction = context.Database.CurrentTransaction?.GetDbTransaction();
        const string Eligible = "transfer_switch_id IS NULL AND action_state = 0 AND action_next_attempt_at <= @now AND lease_until <= @now";
        if (limits is null)
        {
            cmd.CommandText =
                "UPDATE inbound_message SET lease_owner = @owner, lease_until = @until, action_attempts = action_attempts + 1, claim_sequence = claim_sequence + 1 WHERE id IN (" +
                "SELECT id FROM inbound_message WHERE " + Eligible + " ORDER BY action_next_attempt_at, id LIMIT @max) " +
                "RETURNING id";
        }
        else
        {
            // At most MaxPerTenant rows of a tenant (its oldest due ones), tenants in ExcludeTenants left out, then the oldest due first among what is left. One writer: nothing else claims meanwhile.
            string exclusion = string.Empty;
            if (limits.ExcludeTenants is { Count: > 0 } excluded)
            {
                var names = new List<string>();
                foreach (Guid tenant in excluded)
                {
                    string name = "@x" + names.Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
                    names.Add(name);
                    Add(cmd, name, tenant.ToString("D").ToUpperInvariant());
                }

                exclusion = " AND tenant_id NOT IN (" + string.Join(',', names) + ")";
            }

            cmd.CommandText =
                "UPDATE inbound_message SET lease_owner = @owner, lease_until = @until, action_attempts = action_attempts + 1, claim_sequence = claim_sequence + 1 WHERE id IN (" +
                "SELECT id FROM (SELECT id, action_next_attempt_at AS due, ROW_NUMBER() OVER (PARTITION BY tenant_id ORDER BY action_next_attempt_at, id) AS rn FROM inbound_message WHERE " + Eligible + exclusion + ") " +
                "WHERE rn <= @cap ORDER BY due, id LIMIT @max) RETURNING id";
            Add(cmd, "@cap", limits.MaxPerTenant > 0 ? (long)limits.MaxPerTenant : long.MaxValue);
        }

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
