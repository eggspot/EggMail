using Microsoft.EntityFrameworkCore;
using Mta.Core;
using Mta.Storage.Logic;

namespace Mta.Storage.Model;

/// <summary>
/// How <see cref="EfInboundMessageStore{TContext}"/> reaches the queue part of its database. SQLite serializes writes through the queue
/// writer (group commit, own thread); PostgreSQL opens a transaction per write. Only the claim is provider SQL.
/// </summary>
public interface IInboundDbAccess<TContext> where TContext : DbContext, IQueueDbSets
{
    /// <summary>Runs one synchronous query on a no-tracking read context; the access decides where it runs.</summary>
    ValueTask<T> ReadAsync<T>(Func<TContext, T> query);

    /// <summary>Runs <paramref name="work"/> with a context joined to an open transaction and commits when it returns. The work calls <c>SaveChanges</c> itself and may run again when a batch is retried.</summary>
    ValueTask<T> WriteAsync<T>(Func<TContext, T> work, CancellationToken cancellationToken);

    /// <summary>The backend switch gate: the store neither accepts mail nor hands out actions while it is closed.</summary>
    Transfer.SwitchGate Fence { get; }

    /// <summary>Lets a provider turn its connectivity failures into <see cref="StorageUnavailableException"/>. Null leaves the exception alone.</summary>
    Exception? TranslateException(Exception exception) => null;

    /// <summary>
    /// Leases up to <paramref name="max"/> pending actions that are due at <paramref name="now"/> and not held by a backend switch, oldest due first, and returns their
    /// ids. Runs inside the write transaction of <paramref name="context"/>. PostgreSQL adds <c>FOR UPDATE SKIP LOCKED</c> so replicas take disjoint rows.
    /// </summary>
    IReadOnlyList<Guid> ClaimIds(TContext context, string owner, int max, DateTimeOffset now, DateTimeOffset until);
}

/// <summary>
/// <see cref="IInboundMessageStore"/> over EF Core for both relational providers (the queue part of the model). Inbound mail is not the hot path of the
/// product, so the shared EF code wins over hand-written statements per provider; the claim is the one provider-specific statement.
/// </summary>
public sealed class EfInboundMessageStore<TContext>(IInboundDbAccess<TContext> db) : IInboundMessageStore where TContext : DbContext, IQueueDbSets
{
    private const int MaxErrorLength = 1000;
    private const int EraseBatchSize = 1000;

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

    private async ValueTask<T> Write<T>(Func<TContext, T> work, CancellationToken cancellationToken)
    {
        try
        {
            return await db.WriteAsync(work, cancellationToken).ConfigureAwait(false);
        }
        catch (DbUpdateException ex) when (db.TranslateException(ex) is null)
        {
            throw new StorageConflictException("An inbound write violated a constraint: " + (ex.InnerException?.Message ?? ex.Message), ex);
        }
        catch (Exception ex) when (db.TranslateException(ex) is { } translated)
        {
            throw translated;
        }
    }

    public async ValueTask AcceptAsync(IReadOnlyList<InboundMessageDraft> drafts, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(drafts);
        if (drafts.Count == 0)
        {
            throw new ArgumentException("A transaction needs at least one message.", nameof(drafts));
        }

        db.Fence.ThrowIfClosed();
        var messages = new List<InboundMessageEntity>(drafts.Count);
        var bodies = new List<InboundMessageRawEntity>(drafts.Count);
        foreach (InboundMessageDraft draft in drafts)
        {
            if (draft.Id.Version != 7)
            {
                throw new ArgumentException("An inbound message id must be a UUIDv7 (Ids.New).", nameof(drafts));
            }

            InboundMessageEntity entity = draft.ToEntity();
            messages.Add(entity);
            if (entity.HasRaw)
            {
                // A copy: the caller reuses the draft (and the memory behind Raw) when this returns.
                bodies.Add(new InboundMessageRawEntity { MessageId = entity.Id, TenantId = entity.TenantId, Raw = draft.Raw.ToArray() });
            }
        }

        await Write(c =>
        {
            c.InboundMessages.AddRange(messages.Select(Copy));
            c.InboundRaw.AddRange(bodies.Select(b => new InboundMessageRawEntity { MessageId = b.MessageId, TenantId = b.TenantId, Raw = b.Raw }));
            c.SaveChanges();
            return 0;
        }, cancellationToken).ConfigureAwait(false);
    }

    // A fresh instance per attempt: a batch that is replayed must not hand EF an entity a failed context still tracks.
    private static InboundMessageEntity Copy(InboundMessageEntity e) => new()
    {
        Id = e.Id, TenantId = e.TenantId, DomainId = e.DomainId, Domain = e.Domain, ReceivedAt = e.ReceivedAt, RemoteAddress = e.RemoteAddress, Helo = e.Helo, TlsUsed = e.TlsUsed,
        EnvelopeFrom = e.EnvelopeFrom, EnvelopeTo = e.EnvelopeTo, Subject = e.Subject, Size = e.Size, Spf = e.Spf, SpfDomain = e.SpfDomain, SpfHelo = e.SpfHelo, Dkim = e.Dkim, DkimDomain = e.DkimDomain,
        Dmarc = e.Dmarc, DmarcPolicy = e.DmarcPolicy, Arc = e.Arc, Disposition = e.Disposition, RouteId = e.RouteId, ActionKind = e.ActionKind, ActionState = e.ActionState,
        ActionAttempts = e.ActionAttempts, RetryGeneration = e.RetryGeneration, ActionNextAttemptAt = e.ActionNextAttemptAt, ActionFinishedAt = e.ActionFinishedAt, ActionLastError = e.ActionLastError,
        ForwardMessageId = e.ForwardMessageId, HasRaw = e.HasRaw, LeaseOwner = e.LeaseOwner, LeaseUntil = e.LeaseUntil, TransferSwitchId = e.TransferSwitchId,
    };

    public async ValueTask<Page<InboundMessage>> SearchAsync(InboundMessageQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        int limit = Math.Clamp(query.Limit, 1, 500);
        Guid? cursor = null;
        if (query.Cursor is not null)
        {
            if (!Cursors.TryDecode(query.Cursor, out string raw) || !Guid.TryParse(raw, out Guid parsed))
            {
                return new Page<InboundMessage>([], null);
            }

            cursor = parsed;
        }

        List<InboundMessage> rows = await Read(c =>
        {
            IQueryable<InboundMessageEntity> q = Filter(c.InboundMessages.AsNoTracking(), query);
            if (cursor is { } after)
            {
                q = q.Where(x => x.Id.CompareTo(after) < 0);
            }

            return q.OrderByDescending(x => x.Id).Take(limit + 1).AsEnumerable().Select(x => x.ToRecord()).ToList();
        }).ConfigureAwait(false);

        bool more = rows.Count > limit;
        if (more)
        {
            rows.RemoveAt(rows.Count - 1);
        }

        return new Page<InboundMessage>(rows, more ? Cursors.Encode(rows[^1].Id.ToString("D")) : null);
    }

    /// <summary>The filters of a search or an erasure (the tenant always, then the optional ones); paging is the caller's.</summary>
    private static IQueryable<InboundMessageEntity> Filter(IQueryable<InboundMessageEntity> q, InboundMessageQuery query)
    {
        Guid tenant = query.TenantId;
        q = q.Where(x => x.TenantId == tenant);
        if (query.DomainId is { } domain)
        {
            q = q.Where(x => x.DomainId == domain);
        }

        if (query.Recipient?.Trim().ToLowerInvariant() is { } recipient)
        {
            q = q.Where(x => x.EnvelopeTo == recipient);
        }

        if (query.Sender?.Trim().ToLowerInvariant() is { } sender)
        {
            q = q.Where(x => x.EnvelopeFrom == sender);
        }

        if (!string.IsNullOrEmpty(query.SubjectContains))
        {
            string subject = InboundMapping.AsciiLower(query.SubjectContains);
            q = q.Where(x => x.Subject != null && x.Subject.ToLower().Contains(subject));
        }

        if (query.RouteId is { } route)
        {
            q = q.Where(x => x.RouteId == route);
        }

        if (query.ActionKind is { } kind)
        {
            q = q.Where(x => x.ActionKind == kind);
        }

        if (query.ActionState is { } state)
        {
            q = q.Where(x => x.ActionState == state);
        }

        if (query.Dmarc is { } dmarc)
        {
            q = q.Where(x => x.Dmarc == dmarc);
        }

        if (query.DmarcFlagged is { } flagged)
        {
            q = flagged ? q.Where(x => x.Disposition == InboundDmarcDisposition.Flagged) : q.Where(x => x.Disposition == InboundDmarcDisposition.None);
        }

        if (StorageTime.Normalize(query.From) is { } from)
        {
            q = q.Where(x => x.ReceivedAt >= from);
        }

        if (StorageTime.Normalize(query.To) is { } to)
        {
            q = q.Where(x => x.ReceivedAt < to);
        }

        return q;
    }

    public async ValueTask<long> DeleteMatchingAsync(InboundMessageQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        if (!InboundRules.HasFilter(query))
        {
            throw new ArgumentException("An erasure needs at least one filter besides the tenant.", nameof(query));
        }

        long total = 0;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int n = await Write(c =>
            {
                Guid[] ids = Filter(c.InboundMessages.AsNoTracking(), query).OrderBy(x => x.Id).Select(x => x.Id).Take(EraseBatchSize).ToArray();
                if (ids.Length == 0)
                {
                    return 0;
                }

                c.InboundRaw.Where(x => ids.Contains(x.MessageId)).ExecuteDelete();
                return c.InboundMessages.Where(x => ids.Contains(x.Id)).ExecuteDelete();
            }, cancellationToken).ConfigureAwait(false);
            total += n;
            if (n < EraseBatchSize)
            {
                return total;
            }
        }
    }

    public async ValueTask<InboundMessage?> GetAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken) =>
        await Read(c => c.InboundMessages.AsNoTracking().Where(x => x.Id == messageId && x.TenantId == tenantId).AsEnumerable().Select(x => x.ToRecord()).FirstOrDefault()).ConfigureAwait(false);

    public async ValueTask<byte[]?> GetRawAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken) =>
        await Read(c => c.InboundRaw.AsNoTracking().Where(x => x.MessageId == messageId && x.TenantId == tenantId).Select(x => x.Raw).FirstOrDefault()).ConfigureAwait(false);

    public async ValueTask<bool> DeleteAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken) =>
        await Write(c =>
        {
            c.InboundRaw.Where(x => x.MessageId == messageId && x.TenantId == tenantId).ExecuteDelete();
            return c.InboundMessages.Where(x => x.Id == messageId && x.TenantId == tenantId).ExecuteDelete() > 0;
        }, cancellationToken).ConfigureAwait(false);

    public async ValueTask<InboundRetryResult> RetryActionAsync(Guid tenantId, Guid messageId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        DateTimeOffset at = StorageTime.Normalize(now);
        return await Write(c =>
        {
            var row = c.InboundMessages.AsNoTracking().Where(x => x.Id == messageId && x.TenantId == tenantId).Select(x => new { x.ActionKind, x.ActionState, x.HasRaw }).FirstOrDefault();
            if (row is null)
            {
                return InboundRetryResult.NotFound;
            }

            if (row.ActionKind is not (InboundActionKind.Webhook or InboundActionKind.Forward) || !row.HasRaw)
            {
                return InboundRetryResult.NotRetryable;
            }

            if (row.ActionState == InboundActionState.Pending)
            {
                return InboundRetryResult.AlreadyPending;
            }

            c.InboundMessages.Where(x => x.Id == messageId).ExecuteUpdate(s => s
                .SetProperty(x => x.ActionState, InboundActionState.Pending)
                .SetProperty(x => x.ActionAttempts, 0)
                .SetProperty(x => x.RetryGeneration, x => x.RetryGeneration + 1)
                .SetProperty(x => x.ActionNextAttemptAt, (DateTimeOffset?)at)
                .SetProperty(x => x.ActionFinishedAt, (DateTimeOffset?)null)
                .SetProperty(x => x.LeaseOwner, (string?)null)
                .SetProperty(x => x.LeaseUntil, InboundMapping.NoLease));
            return InboundRetryResult.Queued;
        }, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<IReadOnlyList<ClaimedInboundAction>> ClaimActionsAsync(string owner, int max, DateTimeOffset now, TimeSpan lease, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(owner);
        if (max <= 0 || db.Fence.IsClosed)
        {
            return [];
        }

        DateTimeOffset at = StorageTime.Normalize(now);
        DateTimeOffset until = StorageTime.Normalize(now + lease);
        return await Write(c =>
        {
            IReadOnlyList<Guid> ids = db.ClaimIds(c, owner, max, at, until);
            if (ids.Count == 0)
            {
                return (IReadOnlyList<ClaimedInboundAction>)[];
            }

            Guid[] idArray = [.. ids];
            List<InboundMessageEntity> rows = c.InboundMessages.AsNoTracking().Where(x => idArray.Contains(x.Id)).ToList();
            Dictionary<Guid, byte[]> bodies = c.InboundRaw.AsNoTracking().Where(x => idArray.Contains(x.MessageId)).Select(x => new { x.MessageId, x.Raw }).ToList().ToDictionary(x => x.MessageId, x => x.Raw);
            return rows.OrderBy(x => x.ActionNextAttemptAt).ThenBy(x => InboundMapping.IdText(x.Id), StringComparer.Ordinal)
                .Select(x => new ClaimedInboundAction(x.ToRecord(), bodies.GetValueOrDefault(x.Id))).ToList();
        }, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<bool> ExtendActionLeaseAsync(Guid messageId, string owner, DateTimeOffset until, CancellationToken cancellationToken)
    {
        DateTimeOffset when = StorageTime.Normalize(until);
        return await Write(c => c.InboundMessages.Where(x => x.Id == messageId && x.LeaseOwner == owner).ExecuteUpdate(s => s.SetProperty(x => x.LeaseUntil, when)) > 0, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<bool> CompleteActionAsync(Guid messageId, string owner, InboundActionOutcome outcome, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(outcome);
        if (outcome.State == InboundActionState.Pending && outcome.NextAttemptAt is null)
        {
            throw new ArgumentException("A pending outcome needs NextAttemptAt.", nameof(outcome));
        }

        DateTimeOffset at = StorageTime.Normalize(outcome.At);
        DateTimeOffset? next = outcome.State == InboundActionState.Pending ? StorageTime.Normalize(outcome.NextAttemptAt) : null;
        DateTimeOffset? finished = outcome.State == InboundActionState.Pending ? null : at;
        string? error = outcome.State == InboundActionState.Done ? null : InboundErrorText.Clean(outcome.Error, MaxErrorLength);
        Guid? forward = outcome.ForwardMessageId;
        bool free = outcome.FreeBody;
        InboundActionState state = outcome.State;
        return await Write(c =>
        {
            int changed = c.InboundMessages.Where(x => x.Id == messageId && x.LeaseOwner == owner).ExecuteUpdate(s => s
                .SetProperty(x => x.ActionAttempts, x => x.ActionAttempts + 1)
                .SetProperty(x => x.ActionState, state)
                .SetProperty(x => x.ActionNextAttemptAt, next)
                .SetProperty(x => x.ActionFinishedAt, finished)
                .SetProperty(x => x.ActionLastError, error)
                .SetProperty(x => x.LeaseOwner, (string?)null)
                .SetProperty(x => x.LeaseUntil, InboundMapping.NoLease));
            if (changed == 0)
            {
                return false;
            }

            if (forward is { } forwardId)
            {
                c.InboundMessages.Where(x => x.Id == messageId).ExecuteUpdate(s => s.SetProperty(x => x.ForwardMessageId, (Guid?)forwardId));
            }

            if (free)
            {
                c.InboundRaw.Where(x => x.MessageId == messageId).ExecuteDelete();
                c.InboundMessages.Where(x => x.Id == messageId).ExecuteUpdate(s => s.SetProperty(x => x.HasRaw, false));
            }

            return true;
        }, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<int> ReleaseOwnedActionLeasesAsync(string owner, CancellationToken cancellationToken) =>
        await Write(c => c.InboundMessages.Where(x => x.LeaseOwner == owner).ExecuteUpdate(s => s
            .SetProperty(x => x.LeaseOwner, (string?)null)
            .SetProperty(x => x.LeaseUntil, InboundMapping.NoLease)), cancellationToken).ConfigureAwait(false);

    public async ValueTask<InboundUsage> GetUsageAsync(Guid? tenantId, Guid? domainId, CancellationToken cancellationToken) =>
        await Read(c =>
        {
            IQueryable<InboundMessageEntity> q = c.InboundMessages.AsNoTracking();
            if (tenantId is { } tenant)
            {
                q = q.Where(x => x.TenantId == tenant);
            }

            if (domainId is { } domain)
            {
                q = q.Where(x => x.DomainId == domain);
            }

            long messages = q.LongCount();
            if (messages == 0)
            {
                return new InboundUsage(0, 0, 0, 0, null);
            }

            long bytes = q.Where(x => x.HasRaw).Sum(x => x.Size);
            long pending = q.LongCount(x => x.ActionState == InboundActionState.Pending);
            long failed = q.LongCount(x => x.ActionState == InboundActionState.Failed);
            DateTimeOffset? oldest = pending == 0 ? null : q.Where(x => x.ActionState == InboundActionState.Pending).OrderBy(x => x.ReceivedAt).Select(x => (DateTimeOffset?)x.ReceivedAt).FirstOrDefault();
            return new InboundUsage(messages, bytes, pending, failed, oldest);
        }).ConfigureAwait(false);

    /// <summary>
    /// The retention job (design section 11.8): deletes, in batches, the messages whose action is not pending and that were received before the cutoff of their domain.
    /// <paramref name="domainRetentionDays"/> holds the explicit setting of the domains that have one (null days: the server default); every other domain uses
    /// <paramref name="defaultDays"/>. 0 keeps forever. Returns the rows deleted.
    /// </summary>
    public async ValueTask<long> PurgeExpiredAsync(IReadOnlyDictionary<Guid, int?> domainRetentionDays, int defaultDays, int ceilingDays, DateTimeOffset now, int batchSize, TimeSpan pause, CancellationToken cancellationToken)
    {
        long total = 0;
        Guid[] explicitDomains = [.. domainRetentionDays.Where(d => d.Value is not null).Select(d => d.Key)];
        foreach (var (domainId, days) in domainRetentionDays)
        {
            int effective = InboundRules.ResolveRetentionDays(days, defaultDays, ceilingDays);
            if (days is not null && InboundRules.RetentionCutoff(now, effective) is { } cutoff)
            {
                Guid domain = domainId;
                total += await PurgeAsync(q => q.Where(x => x.DomainId == domain), StorageTime.Normalize(cutoff), batchSize, pause, cancellationToken).ConfigureAwait(false);
            }
        }

        if (InboundRules.RetentionCutoff(now, InboundRules.ResolveRetentionDays(null, defaultDays, ceilingDays)) is { } defaultCutoff)
        {
            total += await PurgeAsync(q => q.Where(x => !explicitDomains.Contains(x.DomainId)), StorageTime.Normalize(defaultCutoff), batchSize, pause, cancellationToken).ConfigureAwait(false);
        }

        return total;
    }

    private async ValueTask<long> PurgeAsync(Func<IQueryable<InboundMessageEntity>, IQueryable<InboundMessageEntity>> scope, DateTimeOffset cutoff, int batchSize, TimeSpan pause, CancellationToken cancellationToken)
    {
        long deleted = 0;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int n = await Write(c =>
            {
                Guid[] ids = scope(c.InboundMessages.AsNoTracking()).Where(x => x.ActionState != InboundActionState.Pending && x.ReceivedAt < cutoff)
                    .OrderBy(x => x.ReceivedAt).Select(x => x.Id).Take(batchSize).ToArray();
                if (ids.Length == 0)
                {
                    return 0;
                }

                c.InboundRaw.Where(x => ids.Contains(x.MessageId)).ExecuteDelete();
                return c.InboundMessages.Where(x => ids.Contains(x.Id) && x.ActionState != InboundActionState.Pending).ExecuteDelete();
            }, cancellationToken).ConfigureAwait(false);
            deleted += n;
            if (n < batchSize)
            {
                return deleted;
            }

            if (pause > TimeSpan.Zero)
            {
                await Task.Delay(pause, cancellationToken).ConfigureAwait(false);
            }
        }
    }
}

/// <summary>Bounds and cleans the failure text kept on a message: a sentence for people, without control characters or unbounded length.</summary>
public static class InboundErrorText
{
    public static string? Clean(string? error, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(error))
        {
            return null;
        }

        var sb = new System.Text.StringBuilder(Math.Min(error.Length, maxLength));
        foreach (char c in error)
        {
            if (sb.Length >= maxLength)
            {
                break;
            }

            sb.Append(char.IsControl(c) ? ' ' : c);
        }

        if (sb.Length > 0 && char.IsHighSurrogate(sb[^1]))
        {
            sb.Length--;
        }

        string text = sb.ToString().Trim();
        return text.Length == 0 ? null : text;
    }
}
