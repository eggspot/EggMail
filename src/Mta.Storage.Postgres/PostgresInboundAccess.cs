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

    public IReadOnlyList<Guid> ClaimIds(PostgresDbContext context, string owner, int max, DateTimeOffset now, DateTimeOffset until, InboundClaimLimits? limits)
    {
        DbConnection connection = context.Database.GetDbConnection();
        using DbCommand cmd = connection.CreateCommand();
        cmd.Transaction = context.Database.CurrentTransaction?.GetDbTransaction();
        if (limits is null)
        {
            cmd.CommandText =
                "UPDATE inbound_message SET lease_owner = @owner, lease_until = @until, action_attempts = action_attempts + 1, claim_sequence = claim_sequence + 1 WHERE id IN (" +
                "SELECT id FROM inbound_message WHERE transfer_switch_id IS NULL AND action_state = 0 AND action_next_attempt_at <= @now AND lease_until <= @now ORDER BY action_next_attempt_at, id LIMIT @max FOR UPDATE SKIP LOCKED) " +
                "RETURNING id";
        }
        else
        {
            // The tenants with pending rows are found by a skip scan of the partial index on (tenant_id, action_next_attempt_at, id) (one probe per tenant), and each of them contributes its oldest
            // due rows through a lateral subquery that stops after the cap: the backlog of one tenant is never read or sorted to find the others' rows (a window over all due rows did exactly that,
            // 75 ms and a spilled sort per poll at 300 000 due rows). The lateral subquery locks what it returns with SKIP LOCKED, so replicas claiming at once take different rows instead of
            // the loser of a race getting nothing; the outer WHERE re-checks the row, which is what makes a claim of a row another replica just took impossible.
            string exclusion = limits.ExcludeTenants is { Count: > 0 } ? " AND id <> ALL(@excluded)" : string.Empty;
            // What the caller already has in flight for a tenant comes off its cap (never below zero): a tenant holds at most MaxPerTenant at once.
            string limit = limits.MaxPerTenant > 0 && limits.SlotsInUse is { Count: > 0 }
                ? "GREATEST(@cap - COALESCE((SELECT u.used FROM unnest(@use_tenant, @use_count) AS u(tenant, used) WHERE u.tenant = t.id), 0), 0)"
                : "@cap";
            cmd.CommandText =
                "WITH RECURSIVE tenants(id) AS (" +
                "(SELECT tenant_id FROM inbound_message WHERE action_state = 0 ORDER BY tenant_id LIMIT 1) " +
                "UNION ALL " +
                "SELECT (SELECT tenant_id FROM inbound_message WHERE action_state = 0 AND tenant_id > tenants.id ORDER BY tenant_id LIMIT 1) FROM tenants WHERE tenants.id IS NOT NULL) " +
                "UPDATE inbound_message m SET lease_owner = @owner, lease_until = @until, action_attempts = m.action_attempts + 1, claim_sequence = m.claim_sequence + 1 FROM (" +
                "SELECT pick.id, pick.due FROM (SELECT id FROM tenants WHERE id IS NOT NULL" + exclusion + ") t CROSS JOIN LATERAL (" +
                "SELECT i.id, i.action_next_attempt_at AS due FROM inbound_message i WHERE i.tenant_id = t.id AND i.transfer_switch_id IS NULL AND i.action_state = 0 " +
                "AND i.action_next_attempt_at <= @now AND i.lease_until <= @now ORDER BY i.action_next_attempt_at, i.id LIMIT " + limit + " FOR UPDATE SKIP LOCKED) pick ORDER BY pick.due, pick.id LIMIT @max) c " +
                "WHERE m.id = c.id AND m.action_state = 0 AND m.lease_until <= @now AND m.transfer_switch_id IS NULL RETURNING m.id";
            cmd.Parameters.Add(new NpgsqlParameter("cap", NpgsqlDbType.Bigint) { Value = limits.MaxPerTenant > 0 ? Math.Min((long)limits.MaxPerTenant, max) : (long)max });
            if (limits.MaxPerTenant > 0 && limits.SlotsInUse is { Count: > 0 } inUse)
            {
                cmd.Parameters.Add(new NpgsqlParameter("use_tenant", NpgsqlDbType.Array | NpgsqlDbType.Uuid) { Value = inUse.Keys.ToArray() });
                cmd.Parameters.Add(new NpgsqlParameter("use_count", NpgsqlDbType.Array | NpgsqlDbType.Integer) { Value = inUse.Values.ToArray() });
            }
            if (limits.ExcludeTenants is { Count: > 0 } excluded)
            {
                cmd.Parameters.Add(new NpgsqlParameter("excluded", NpgsqlDbType.Array | NpgsqlDbType.Uuid) { Value = excluded.ToArray() });
            }
        }

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
