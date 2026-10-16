using Microsoft.EntityFrameworkCore;
using Mta.Storage.Logic;

namespace Mta.Storage.Model;

/// <summary>
/// How <see cref="EfConfigStore{TContext}"/> reaches its database. The SQLite provider serializes writes through the
/// config.db writer (own thread, transaction per batch); PostgreSQL can simply open a context per call.
/// </summary>
public interface IConfigDbAccess<TContext> where TContext : DbContext, IConfigDbSets
{
    /// <summary>A short-lived, no-tracking context for one read; the caller disposes it.</summary>
    TContext CreateReadContext();

    /// <summary>
    /// Runs one synchronous query on a read context and returns its result. The default runs it inline on the caller, which is right
    /// when the database call is local (SQLite). A provider whose reads wait on the network overrides this to bound how many
    /// run at once and to keep them off the caller's thread: the queries are synchronous, and dozens of delivery workers blocking
    /// in them at the same moment starve the thread pool, which then cannot complete the async work that would free the pooled
    /// connections they are waiting for.
    /// </summary>
    ValueTask<T> ReadAsync<T>(Func<TContext, T> query)
    {
        using TContext ctx = CreateReadContext();
        return ValueTask.FromResult(query(ctx));
    }

    /// <summary>
    /// Runs <paramref name="work"/> with a context joined to an open transaction and commits when it returns. The work
    /// must call <c>SaveChanges</c> itself and may run more than once when a batch is retried, so it must be repeatable.
    /// </summary>
    ValueTask<T> WriteAsync<T>(Func<TContext, T> work, CancellationToken cancellationToken);

    /// <summary>
    /// Lets a provider turn its own connectivity failures into <see cref="StorageUnavailableException"/> (the store applies
    /// it to every read and write). Return null to leave the exception alone; the default changes nothing.
    /// </summary>
    Exception? TranslateException(Exception exception) => null;

    /// <summary>
    /// Answers "is this (already normalized) address on the tenant's suppression list" without building an EF query, or returns null to let the
    /// store run its normal query. The check runs once per recipient before every delivery, so a provider with a cheaper way (a prepared statement
    /// on an open connection) supplies it here. The answer must be the same as the query's.
    /// </summary>
    bool? TryIsSuppressed(Guid tenantId, string normalizedAddress) => null;
}

/// <summary>
/// <see cref="IConfigStore"/> over EF Core, shared by every relational provider (design §2.3: one implementation for
/// both). Secrets arrive already protected. Uniqueness violations surface as <see cref="StorageConflictException"/>.
/// </summary>
public sealed partial class EfConfigStore<TContext>(IConfigDbAccess<TContext> db) : IConfigStore where TContext : DbContext, IConfigDbSets
{
    private long _webhookVersion;

    /// <summary>Incremented after every change to webhook endpoints; lets callers cache the endpoint list.</summary>
    public long WebhookEndpointVersion => Interlocked.Read(ref _webhookVersion);

    /// <summary>Drops cached state after rows were written behind the store's back (a backend switch import).</summary>
    public void NotifyExternalChange() => Interlocked.Increment(ref _webhookVersion);

    // Reads are short synchronous queries on a fresh (or pooled) no-tracking context; the access decides where they run.
    private async ValueTask<T> Read<T>(Func<TContext, T> query)
    {
        try
        {
            return await db.ReadAsync(query).ConfigureAwait(false);
        }
        catch (Exception ex) when (db.TranslateException(ex) is { } translated)
        {
            throw translated;
        }
    }

    private async ValueTask Write(Action<TContext> work, CancellationToken ct) =>
        await Write<object?>(c =>
        {
            work(c);
            return null;
        }, ct).ConfigureAwait(false);

    private async ValueTask<T> Write<T>(Func<TContext, T> work, CancellationToken ct)
    {
        try
        {
            return await db.WriteAsync(work, ct).ConfigureAwait(false);
        }
        catch (DbUpdateException ex) when (db.TranslateException(ex) is null)
        {
            throw new StorageConflictException("A configuration write violated a constraint: " + (ex.InnerException?.Message ?? ex.Message), ex);
        }
        catch (Exception ex) when (db.TranslateException(ex) is { } translated)
        {
            throw translated;
        }
    }

    private static void Upsert<T>(TContext ctx, T entity, params object[] key) where T : class
    {
        var existing = ctx.Find<T>(key);
        if (existing is null)
        {
            ctx.Add(entity);
        }
        else
        {
            ctx.Entry(existing).CurrentValues.SetValues(entity);
        }

        ctx.SaveChanges();
    }

    // Tenants and credentials

    public async ValueTask<IReadOnlyList<Tenant>> GetTenantsAsync(CancellationToken ct) =>
        await Read<IReadOnlyList<Tenant>>(c => c.Tenants.AsNoTracking().OrderBy(t => t.Name).ThenBy(t => t.Id).AsEnumerable().Select(t => t.ToRecord()).ToList()).ConfigureAwait(false);

    public async ValueTask<Tenant?> GetTenantAsync(Guid id, CancellationToken ct) =>
        await Read(c => c.Tenants.AsNoTracking().Where(t => t.Id == id).AsEnumerable().Select(t => t.ToRecord()).FirstOrDefault()).ConfigureAwait(false);

    public async ValueTask<Tenant?> GetTenantBySlugAsync(string slug, CancellationToken ct)
    {
        string s = ConfigMapping.NormalizeSlug(slug);
        return await Read(c => c.Tenants.AsNoTracking().Where(t => t.Slug == s).AsEnumerable().Select(t => t.ToRecord()).FirstOrDefault()).ConfigureAwait(false);
    }

    public async ValueTask UpsertTenantAsync(Tenant tenant, CancellationToken ct)
    {
        var e = tenant.ToEntity();
        await Write(c => Upsert(c, e, e.Id), ct).ConfigureAwait(false);
    }

    public async ValueTask<ApiKeyRecord?> FindApiKeyAsync(byte[] keyHash, CancellationToken ct) =>
        await Read(c => c.ApiKeys.AsNoTracking().Where(k => k.KeyHash == keyHash).AsEnumerable().Select(k => k.ToRecord()).FirstOrDefault()).ConfigureAwait(false);

    public async ValueTask<IReadOnlyList<ApiKeyRecord>> GetApiKeysAsync(Guid tenantId, CancellationToken ct) =>
        await Read<IReadOnlyList<ApiKeyRecord>>(c => c.ApiKeys.AsNoTracking().Where(k => k.TenantId == tenantId).OrderBy(k => k.CreatedAt).ThenBy(k => k.Id).AsEnumerable().Select(k => k.ToRecord()).ToList()).ConfigureAwait(false);

    public async ValueTask AddApiKeyAsync(ApiKeyRecord key, CancellationToken ct)
    {
        var e = key.ToEntity();
        await Write(c =>
        {
            c.ApiKeys.Add(e);
            c.SaveChanges();
        }, ct).ConfigureAwait(false);
    }

    public async ValueTask<bool> RevokeApiKeyAsync(Guid tenantId, Guid keyId, DateTimeOffset at, CancellationToken ct)
    {
        DateTimeOffset when = StorageTime.Normalize(at);
        return await Write(c => c.ApiKeys.Where(k => k.Id == keyId && k.TenantId == tenantId && k.RevokedAt == null)
            .ExecuteUpdate(u => u.SetProperty(k => k.RevokedAt, when)) > 0, ct).ConfigureAwait(false);
    }

    public async ValueTask TouchApiKeyAsync(Guid keyId, DateTimeOffset at, CancellationToken ct)
    {
        DateTimeOffset when = StorageTime.Normalize(at);
        await Write(c => c.ApiKeys.Where(k => k.Id == keyId).ExecuteUpdate(u => u.SetProperty(k => k.LastUsedAt, when)), ct).ConfigureAwait(false);
    }

    public async ValueTask<SmtpCredential?> FindSmtpCredentialAsync(string userName, CancellationToken ct) =>
        await Read(c => c.SmtpCredentials.AsNoTracking().Where(x => x.UserName == userName).AsEnumerable().Select(x => x.ToRecord()).FirstOrDefault()).ConfigureAwait(false);

    public async ValueTask UpsertSmtpCredentialAsync(SmtpCredential credential, CancellationToken ct)
    {
        var e = credential.ToEntity();
        await Write(c => Upsert(c, e, e.Id), ct).ConfigureAwait(false);
    }

    public async ValueTask<IReadOnlyList<SmtpCredential>> GetSmtpCredentialsAsync(Guid tenantId, CancellationToken ct) =>
        await Read<IReadOnlyList<SmtpCredential>>(c => c.SmtpCredentials.AsNoTracking().Where(x => x.TenantId == tenantId).OrderBy(x => x.UserName).AsEnumerable().Select(x => x.ToRecord()).ToList()).ConfigureAwait(false);

    public async ValueTask<bool> DeleteSmtpCredentialAsync(Guid tenantId, Guid credentialId, CancellationToken ct) =>
        await Write(c => c.SmtpCredentials.Where(x => x.Id == credentialId && x.TenantId == tenantId).ExecuteDelete() > 0, ct).ConfigureAwait(false);

    // Dashboard users and sessions (Set<T>() keeps the context interfaces unchanged for providers that implement them)

    public async ValueTask<IReadOnlyList<DashboardUser>> GetDashboardUsersAsync(CancellationToken ct) =>
        await Read<IReadOnlyList<DashboardUser>>(c => c.Set<DashboardUserEntity>().AsNoTracking().OrderBy(u => u.UserName).AsEnumerable().Select(u => u.ToRecord()).ToList()).ConfigureAwait(false);

    public async ValueTask<DashboardUser?> GetDashboardUserAsync(Guid id, CancellationToken ct) =>
        await Read(c => c.Set<DashboardUserEntity>().AsNoTracking().Where(u => u.Id == id).AsEnumerable().Select(u => u.ToRecord()).FirstOrDefault()).ConfigureAwait(false);

    public async ValueTask<DashboardUser?> FindDashboardUserAsync(string userName, CancellationToken ct)
    {
        string n = ConfigMapping.NormalizeUserName(userName);
        return await Read(c => c.Set<DashboardUserEntity>().AsNoTracking().Where(u => u.UserName == n).AsEnumerable().Select(u => u.ToRecord()).FirstOrDefault()).ConfigureAwait(false);
    }

    public async ValueTask UpsertDashboardUserAsync(DashboardUser user, CancellationToken ct)
    {
        var e = user.ToEntity();
        await Write(c => Upsert(c, e, e.Id), ct).ConfigureAwait(false);
    }

    public async ValueTask<bool> DeleteDashboardUserAsync(Guid id, CancellationToken ct) =>
        await Write(c =>
        {
            c.Set<DashboardSessionEntity>().Where(s => s.UserId == id).ExecuteDelete();
            return c.Set<DashboardUserEntity>().Where(u => u.Id == id).ExecuteDelete() > 0;
        }, ct).ConfigureAwait(false);

    public async ValueTask<DashboardUserUpdate> UpdateDashboardUserGuardedAsync(Guid id, Func<DashboardUser, DashboardUser> change, bool endSessions, byte[]? keepSessionHash, CancellationToken ct) =>
        await Write(c =>
        {
            // Config writes are serialized (the SQLite writer thread, the PostgreSQL advisory lock), so read, check and change are atomic.
            var users = c.Set<DashboardUserEntity>();
            var currentEntity = users.AsNoTracking().Where(u => u.Id == id).FirstOrDefault();
            if (currentEntity is null)
            {
                return new DashboardUserUpdate(DashboardUserWriteResult.NotFound, null);
            }

            DashboardUser changed = change(currentEntity.ToRecord());
            var e = (changed with { Id = id }).ToEntity();
            bool isEnabledAdmin = currentEntity.Role == DashboardRole.Admin && currentEntity.Enabled;
            bool staysEnabledAdmin = e.Role == DashboardRole.Admin && e.Enabled;
            if (isEnabledAdmin && !staysEnabledAdmin && !users.Any(u => u.Id != id && u.Role == DashboardRole.Admin && u.Enabled))
            {
                return new DashboardUserUpdate(DashboardUserWriteResult.WouldRemoveLastAdmin, null);
            }

            Upsert(c, e, e.Id);
            if (endSessions)
            {
                var sessions = c.Set<DashboardSessionEntity>().Where(s => s.UserId == id);
                if (keepSessionHash is not null)
                {
                    sessions = sessions.Where(s => s.IdHash != keepSessionHash);
                }

                sessions.ExecuteDelete();
            }

            return new DashboardUserUpdate(DashboardUserWriteResult.Applied, e.ToRecord());
        }, ct).ConfigureAwait(false);

    public async ValueTask<DashboardUserWriteResult> DeleteDashboardUserGuardedAsync(Guid id, CancellationToken ct) =>
        await Write(c =>
        {
            var users = c.Set<DashboardUserEntity>();
            var current = users.AsNoTracking().Where(u => u.Id == id).Select(u => new { u.Role, u.Enabled }).FirstOrDefault();
            if (current is null)
            {
                return DashboardUserWriteResult.NotFound;
            }

            if (current.Role == DashboardRole.Admin && current.Enabled && !users.Any(u => u.Id != id && u.Role == DashboardRole.Admin && u.Enabled))
            {
                return DashboardUserWriteResult.WouldRemoveLastAdmin;
            }

            c.Set<DashboardSessionEntity>().Where(s => s.UserId == id).ExecuteDelete();
            users.Where(u => u.Id == id).ExecuteDelete();
            return DashboardUserWriteResult.Applied;
        }, ct).ConfigureAwait(false);

    public async ValueTask<bool> TryAddDashboardSessionForVerifiedUserAsync(DashboardSession session, DashboardUser verified, CancellationToken ct)
    {
        var e = session.ToEntity();
        return await Write(c =>
        {
            var current = c.Set<DashboardUserEntity>().AsNoTracking().Where(u => u.Id == verified.Id).FirstOrDefault();
            if (current is null || !current.Enabled || current.PasswordHash != verified.PasswordHash || current.Role != verified.Role || current.TenantId != verified.TenantId)
            {
                return false;
            }

            c.Set<DashboardSessionEntity>().Add(e);
            c.SaveChanges();
            return true;
        }, ct).ConfigureAwait(false);
    }

    public async ValueTask AddDashboardSessionAsync(DashboardSession session, CancellationToken ct)
    {
        var e = session.ToEntity();
        await Write(c =>
        {
            c.Set<DashboardSessionEntity>().Add(e);
            c.SaveChanges();
        }, ct).ConfigureAwait(false);
    }

    public async ValueTask<DashboardSession?> FindDashboardSessionAsync(byte[] idHash, CancellationToken ct) =>
        await Read(c => c.Set<DashboardSessionEntity>().AsNoTracking().Where(s => s.IdHash == idHash).AsEnumerable().Select(s => s.ToRecord()).FirstOrDefault()).ConfigureAwait(false);

    public async ValueTask TouchDashboardSessionAsync(byte[] idHash, DateTimeOffset lastSeenAt, CancellationToken ct)
    {
        DateTimeOffset when = StorageTime.Normalize(lastSeenAt);
        await Write(c => c.Set<DashboardSessionEntity>().Where(s => s.IdHash == idHash).ExecuteUpdate(u => u.SetProperty(s => s.LastSeenAt, when)), ct).ConfigureAwait(false);
    }

    public async ValueTask<bool> DeleteDashboardSessionAsync(byte[] idHash, CancellationToken ct) =>
        await Write(c => c.Set<DashboardSessionEntity>().Where(s => s.IdHash == idHash).ExecuteDelete() > 0, ct).ConfigureAwait(false);

    public async ValueTask<int> DeleteDashboardSessionsOfUserAsync(Guid userId, CancellationToken ct) =>
        await Write(c => c.Set<DashboardSessionEntity>().Where(s => s.UserId == userId).ExecuteDelete(), ct).ConfigureAwait(false);

    public async ValueTask<int> DeleteExpiredDashboardSessionsAsync(DateTimeOffset now, CancellationToken ct)
    {
        DateTimeOffset n = StorageTime.Normalize(now);
        return await Write(c => c.Set<DashboardSessionEntity>().Where(s => s.ExpiresAt <= n).ExecuteDelete(), ct).ConfigureAwait(false);
    }

    // Domains and DKIM

    public async ValueTask<IReadOnlyList<DomainRecord>> GetDomainsAsync(Guid? tenantId, CancellationToken ct) =>
        await Read<IReadOnlyList<DomainRecord>>(c => c.Domains.AsNoTracking().Where(d => tenantId == null || d.TenantId == tenantId).OrderBy(d => d.Name).AsEnumerable().Select(d => d.ToRecord()).ToList()).ConfigureAwait(false);

    public async ValueTask<DomainRecord?> GetDomainAsync(Guid domainId, CancellationToken ct) =>
        await Read(c => c.Domains.AsNoTracking().Where(d => d.Id == domainId).AsEnumerable().Select(d => d.ToRecord()).FirstOrDefault()).ConfigureAwait(false);

    public async ValueTask<DomainRecord?> FindDomainByNameAsync(string name, CancellationToken ct)
    {
        string n = ConfigMapping.NormalizeDomain(name);
        return await Read(c => c.Domains.AsNoTracking().Where(d => d.Name == n).AsEnumerable().Select(d => d.ToRecord()).FirstOrDefault()).ConfigureAwait(false);
    }

    public async ValueTask UpsertDomainAsync(DomainRecord domain, CancellationToken ct)
    {
        var e = domain.ToEntity();
        await Write(c => Upsert(c, e, e.Id), ct).ConfigureAwait(false);
    }

    public async ValueTask<IReadOnlyList<DomainRecord>> GetDomainsDueForCheckAsync(DateTimeOffset now, int max, CancellationToken ct)
    {
        DateTimeOffset n = StorageTime.Normalize(now);
        return await Read<IReadOnlyList<DomainRecord>>(c => c.Domains.AsNoTracking().Where(d => d.NextCheckAt != null && d.NextCheckAt <= n)
            .OrderBy(d => d.NextCheckAt).ThenBy(d => d.Name).Take(max).AsEnumerable().Select(d => d.ToRecord()).ToList()).ConfigureAwait(false);
    }

    public async ValueTask DeleteDomainAsync(Guid domainId, CancellationToken ct) =>
        await Write(c =>
        {
            c.DkimKeys.Where(k => k.DomainId == domainId).ExecuteDelete();
            c.Set<DomainRecordCheckEntity>().Where(k => k.DomainId == domainId).ExecuteDelete();
            DeleteInboundOfDomain(c, domainId);
            c.Domains.Where(d => d.Id == domainId).ExecuteDelete();
        }, ct).ConfigureAwait(false);

    public async ValueTask<IReadOnlyList<DkimKeyRecord>> GetDkimKeysAsync(Guid domainId, CancellationToken ct) =>
        await Read<IReadOnlyList<DkimKeyRecord>>(c => c.DkimKeys.AsNoTracking().Where(k => k.DomainId == domainId).OrderBy(k => k.CreatedAt).ThenBy(k => k.Id).AsEnumerable().Select(k => k.ToRecord()).ToList()).ConfigureAwait(false);

    public async ValueTask AddDkimKeyAsync(DkimKeyRecord key, CancellationToken ct)
    {
        var e = key.ToEntity();
        await Write(c =>
        {
            c.DkimKeys.Add(e);
            c.SaveChanges();
        }, ct).ConfigureAwait(false);
    }

    public async ValueTask SetActiveDkimKeyAsync(Guid domainId, Guid keyId, DateTimeOffset at, CancellationToken ct)
    {
        DateTimeOffset when = StorageTime.Normalize(at);
        await Write(c =>
        {
            if (!c.DkimKeys.Any(k => k.Id == keyId && k.DomainId == domainId))
            {
                throw new KeyNotFoundException($"DKIM key {keyId} does not belong to domain {domainId}.");
            }

            c.DkimKeys.Where(k => k.DomainId == domainId && k.Id != keyId && k.Active)
                .ExecuteUpdate(u => u.SetProperty(k => k.Active, false).SetProperty(k => k.RetiredAt, k => k.RetiredAt ?? when));
            c.DkimKeys.Where(k => k.Id == keyId).ExecuteUpdate(u => u.SetProperty(k => k.Active, true).SetProperty(k => k.RetiredAt, (DateTimeOffset?)null));
        }, ct).ConfigureAwait(false);
    }

    public async ValueTask<bool> DeletePendingDkimKeyAsync(Guid domainId, Guid keyId, CancellationToken ct) =>
        await Write(c => c.DkimKeys.Where(k => k.Id == keyId && k.DomainId == domainId && !k.Active && k.RetiredAt == null).ExecuteDelete() > 0, ct).ConfigureAwait(false);

    // Suppressions

    public ValueTask<bool> IsSuppressedAsync(Guid tenantId, string address, CancellationToken ct)
    {
        string a = ConfigMapping.NormalizeAddress(address);
        try
        {
            if (db.TryIsSuppressed(tenantId, a) is { } known)
            {
                return ValueTask.FromResult(known);
            }
        }
        catch (Exception ex)
        {
            // Like the async version this replaced, a failure surfaces when the result is awaited, not when the method is called.
            return ValueTask.FromException<bool>(db.TranslateException(ex) ?? ex);
        }

        return IsSuppressedByQueryAsync(tenantId, a);
    }

    private async ValueTask<bool> IsSuppressedByQueryAsync(Guid tenantId, string normalizedAddress) =>
        await Read(c => c.Suppressions.AsNoTracking().Any(s => s.TenantId == tenantId && s.Address == normalizedAddress)).ConfigureAwait(false);

    public async ValueTask AddSuppressionAsync(SuppressionRecord suppression, CancellationToken ct)
    {
        var e = suppression.ToEntity();
        await Write(c => Upsert(c, e, e.TenantId, e.Address), ct).ConfigureAwait(false);
    }

    public async ValueTask<bool> RemoveSuppressionAsync(Guid tenantId, string address, CancellationToken ct)
    {
        string a = ConfigMapping.NormalizeAddress(address);
        return await Write(c => c.Suppressions.Where(s => s.TenantId == tenantId && s.Address == a).ExecuteDelete() > 0, ct).ConfigureAwait(false);
    }

    public async ValueTask<Page<SuppressionRecord>> GetSuppressionsAsync(Guid tenantId, string? cursor, int limit, CancellationToken ct)
    {
        limit = Math.Clamp(limit, 1, 1000);
        string? after = Cursors.TryDecode(cursor, out string decoded) ? decoded : null;
        return await Read(c =>
        {
            IQueryable<SuppressionEntity> q = c.Suppressions.AsNoTracking().Where(s => s.TenantId == tenantId);
            if (after is not null)
            {
                q = q.Where(s => s.Address.CompareTo(after) > 0);
            }

            var rows = q.OrderBy(s => s.Address).Take(limit + 1).ToList();
            bool more = rows.Count > limit;
            if (more)
            {
                rows.RemoveAt(rows.Count - 1);
            }

            return new Page<SuppressionRecord>(rows.Select(r => r.ToRecord()).ToList(), more ? Cursors.Encode(rows[^1].Address) : null);
        }).ConfigureAwait(false);
    }

    // Webhook endpoints

    public async ValueTask<IReadOnlyList<WebhookEndpointRecord>> GetWebhookEndpointsAsync(Guid? tenantId, CancellationToken ct) =>
        await Read<IReadOnlyList<WebhookEndpointRecord>>(c => c.WebhookEndpoints.AsNoTracking().Where(w => tenantId == null || w.TenantId == tenantId).OrderBy(w => w.CreatedAt).ThenBy(w => w.Id).AsEnumerable().Select(w => w.ToRecord()).ToList()).ConfigureAwait(false);

    public async ValueTask<WebhookEndpointRecord?> GetWebhookEndpointAsync(Guid id, CancellationToken ct) =>
        await Read(c => c.WebhookEndpoints.AsNoTracking().Where(w => w.Id == id).AsEnumerable().Select(w => w.ToRecord()).FirstOrDefault()).ConfigureAwait(false);

    public async ValueTask UpsertWebhookEndpointAsync(WebhookEndpointRecord endpoint, CancellationToken ct)
    {
        var e = endpoint.ToEntity();
        await Write(c => Upsert(c, e, e.Id), ct).ConfigureAwait(false);
        Interlocked.Increment(ref _webhookVersion);
    }

    public async ValueTask DeleteWebhookEndpointAsync(Guid tenantId, Guid id, CancellationToken ct)
    {
        // The schema has no foreign keys (references are soft by design), so the rule that a route's webhook endpoint cannot disappear is kept here, in the same write as the delete.
        await Write(c =>
        {
            if (c.InboundRoutes.Any(r => r.ActionKind == InboundActionKind.Webhook && r.WebhookEndpointId == id && c.WebhookEndpoints.Any(w => w.Id == id && w.TenantId == tenantId)))
            {
                throw new StorageConflictException("The webhook endpoint is the target of inbound routes.", StorageConflictReasons.WebhookEndpointInUse);
            }

            return c.WebhookEndpoints.Where(w => w.Id == id && w.TenantId == tenantId).ExecuteDelete();
        }, ct).ConfigureAwait(false);
        Interlocked.Increment(ref _webhookVersion);
    }

    public async ValueTask<bool> DisableWebhookEndpointAsync(Guid id, string reason, DateTimeOffset at, CancellationToken ct)
    {
        DateTimeOffset when = StorageTime.Normalize(at);
        bool changed = await Write(c => c.WebhookEndpoints.Where(w => w.Id == id && w.Enabled)
            .ExecuteUpdate(u => u.SetProperty(w => w.Enabled, false).SetProperty(w => w.DisabledReason, reason).SetProperty(w => w.DisabledAt, when)) > 0, ct).ConfigureAwait(false);
        Interlocked.Increment(ref _webhookVersion);
        return changed;
    }

    // Settings, policies, routes

    public async ValueTask<IReadOnlyList<SettingRecord>> GetSettingsAsync(Guid? tenantId, CancellationToken ct)
    {
        Guid scope = tenantId ?? Guid.Empty;
        return await Read<IReadOnlyList<SettingRecord>>(c => c.Settings.AsNoTracking().Where(s => s.TenantId == scope).OrderBy(s => s.Key).AsEnumerable().Select(s => s.ToRecord()).ToList()).ConfigureAwait(false);
    }

    public async ValueTask SetSettingAsync(SettingRecord setting, CancellationToken ct)
    {
        var e = setting.ToEntity();
        await Write(c => Upsert(c, e, e.TenantId, e.Key), ct).ConfigureAwait(false);
    }

    public async ValueTask<IReadOnlyList<TlsPolicyRecord>> GetTlsPoliciesAsync(CancellationToken ct) =>
        await Read<IReadOnlyList<TlsPolicyRecord>>(c => c.TlsPolicies.AsNoTracking().OrderBy(t => t.DomainPattern).AsEnumerable().Select(t => t.ToRecord()).ToList()).ConfigureAwait(false);

    public async ValueTask UpsertTlsPolicyAsync(TlsPolicyRecord policy, CancellationToken ct)
    {
        var e = policy.ToEntity();
        await Write(c => Upsert(c, e, e.Id), ct).ConfigureAwait(false);
    }

    public async ValueTask DeleteTlsPolicyAsync(Guid id, CancellationToken ct) =>
        await Write(c => c.TlsPolicies.Where(t => t.Id == id).ExecuteDelete(), ct).ConfigureAwait(false);

    public async ValueTask<IReadOnlyList<RelayRouteRecord>> GetRelayRoutesAsync(CancellationToken ct) =>
        await Read<IReadOnlyList<RelayRouteRecord>>(c => c.RelayRoutes.AsNoTracking().OrderBy(r => r.Priority).ThenBy(r => r.Name).ThenBy(r => r.Id).AsEnumerable().Select(r => r.ToRecord()).ToList()).ConfigureAwait(false);

    public async ValueTask UpsertRelayRouteAsync(RelayRouteRecord route, CancellationToken ct)
    {
        var e = route.ToEntity();
        await Write(c => Upsert(c, e, e.Id), ct).ConfigureAwait(false);
    }

    public async ValueTask DeleteRelayRouteAsync(Guid id, CancellationToken ct) =>
        await Write(c => c.RelayRoutes.Where(r => r.Id == id).ExecuteDelete(), ct).ConfigureAwait(false);

    // Certificates and ACME

    public async ValueTask<IReadOnlyList<CertificateRecord>> GetCertificatesAsync(CancellationToken ct) =>
        await Read<IReadOnlyList<CertificateRecord>>(c => c.Certificates.AsNoTracking().OrderBy(x => x.Name).AsEnumerable().Select(x => x.ToRecord()).ToList()).ConfigureAwait(false);

    public async ValueTask<long> GetCertificateVersionAsync(CancellationToken ct) =>
        await Read(c => c.Certificates.AsNoTracking().Max(x => (long?)x.Version) ?? 0L).ConfigureAwait(false);

    public async ValueTask UpsertCertificateAsync(CertificateRecord certificate, CancellationToken ct)
    {
        var e = certificate.ToEntity();
        await Write(c =>
        {
            e.Version = (c.Certificates.Max(x => (long?)x.Version) ?? 0L) + 1;
            Upsert(c, e, e.Id);
        }, ct).ConfigureAwait(false);
    }

    public async ValueTask<AcmeAccountRecord?> GetAcmeAccountAsync(string directoryUrl, CancellationToken ct) =>
        await Read(c => c.AcmeAccounts.AsNoTracking().Where(a => a.DirectoryUrl == directoryUrl).AsEnumerable().Select(a => a.ToRecord()).FirstOrDefault()).ConfigureAwait(false);

    public async ValueTask UpsertAcmeAccountAsync(AcmeAccountRecord account, CancellationToken ct)
    {
        var e = account.ToEntity();
        await Write(c => Upsert(c, e, e.Id), ct).ConfigureAwait(false);
    }

    public async ValueTask<IReadOnlyList<AcmeRenewalRecord>> GetAcmeRenewalsAsync(CancellationToken ct) =>
        await Read<IReadOnlyList<AcmeRenewalRecord>>(c => c.AcmeRenewals.AsNoTracking().OrderBy(r => r.CertificateName).AsEnumerable().Select(r => r.ToRecord()).ToList()).ConfigureAwait(false);

    public async ValueTask UpsertAcmeRenewalAsync(AcmeRenewalRecord renewal, CancellationToken ct)
    {
        var e = renewal.ToEntity();
        await Write(c => Upsert(c, e, e.CertificateName), ct).ConfigureAwait(false);
    }

    public async ValueTask SetAcmeRenewalAdviceAsync(string certificateName, string? ariJson, CancellationToken ct) =>
        await Write(c =>
        {
            var existing = c.Find<AcmeRenewalEntity>(certificateName);
            if (existing is null)
            {
                c.Add(new AcmeRenewalEntity { CertificateName = certificateName, Status = "issued", AriJson = ariJson });
            }
            else
            {
                existing.AriJson = ariJson;
            }

            c.SaveChanges();
        }, ct).ConfigureAwait(false);

    public async ValueTask SetAcmeRenewalChallengeStateAsync(string certificateName, string? challengeStateJson, CancellationToken ct) =>
        await Write(c =>
        {
            var existing = c.Find<AcmeRenewalEntity>(certificateName);
            if (existing is null)
            {
                c.Add(new AcmeRenewalEntity { CertificateName = certificateName, Status = "ordering", ChallengeStateJson = challengeStateJson });
            }
            else
            {
                existing.ChallengeStateJson = challengeStateJson;
            }

            c.SaveChanges();
        }, ct).ConfigureAwait(false);

    // Leases

    public async ValueTask<LeaseRecord?> TryAcquireLeaseAsync(string name, string owner, TimeSpan duration, DateTimeOffset now, CancellationToken ct) =>
        await Write(c =>
        {
            var existing = c.Leases.AsNoTracking().FirstOrDefault(l => l.Name == name);
            var updated = LeaseRules.Acquire(existing, name, owner, duration, now);
            if (updated is null)
            {
                return null;
            }

            Upsert(c, updated, name);
            return updated.ToRecord();
        }, ct).ConfigureAwait(false);

    public async ValueTask<bool> RenewLeaseAsync(string name, string owner, long fencingToken, TimeSpan duration, DateTimeOffset now, CancellationToken ct) =>
        await Write(c =>
        {
            var existing = c.Leases.AsNoTracking().FirstOrDefault(l => l.Name == name);
            var updated = LeaseRules.Renew(existing, owner, fencingToken, duration, now);
            if (updated is null)
            {
                return false;
            }

            Upsert(c, updated, name);
            return true;
        }, ct).ConfigureAwait(false);

    public async ValueTask ReleaseLeaseAsync(string name, string owner, CancellationToken ct) =>
        await Write(c =>
        {
            var existing = c.Leases.AsNoTracking().FirstOrDefault(l => l.Name == name);
            if (LeaseRules.Release(existing, owner) is { } updated)
            {
                Upsert(c, updated, name);
            }
        }, ct).ConfigureAwait(false);

    // Backend switch

    public async ValueTask<SwitchStateRecord?> GetSwitchStateAsync(CancellationToken ct) =>
        await Read(c => c.SwitchStates.AsNoTracking().Where(s => s.Id == 1).AsEnumerable().Select(s => s.ToRecord()).FirstOrDefault()).ConfigureAwait(false);

    public async ValueTask SetSwitchStateAsync(SwitchStateRecord state, CancellationToken ct)
    {
        var e = state.ToEntity();
        await Write(c => Upsert(c, e, 1), ct).ConfigureAwait(false);
    }
}
