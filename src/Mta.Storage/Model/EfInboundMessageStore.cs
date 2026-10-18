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

    /// <summary>
    /// Lets a provider turn its availability failures into <see cref="StorageUnavailableException"/> (and a full disk into <see cref="StorageFullException"/>, a subclass, so the receive path can
    /// answer <c>452 4.3.1</c>). Null leaves the exception alone.
    /// </summary>
    Exception? TranslateException(Exception exception) => null;

    /// <summary>True only for a constraint violation (SQLite <c>SQLITE_CONSTRAINT</c>, PostgreSQL class 23): the one failure a write reports as a <see cref="StorageConflictException"/>. Everything else is rethrown as it is.</summary>
    bool IsConstraintViolation(Exception exception) => false;

    /// <summary>
    /// Leases up to <paramref name="max"/> pending actions that are due at <paramref name="now"/> and not held by a backend switch, oldest due first, and returns their
    /// ids. Runs inside the write transaction of <paramref name="context"/>. PostgreSQL adds <c>FOR UPDATE SKIP LOCKED</c> so replicas take disjoint rows.
    /// </summary>
    IReadOnlyList<Guid> ClaimIds(TContext context, string owner, int max, DateTimeOffset now, DateTimeOffset until, InboundClaimLimits? limits);
}

/// <summary>
/// <see cref="IInboundMessageStore"/> over EF Core for both relational providers (the queue part of the model). Inbound mail is not the hot path of the
/// product, so the shared EF code wins over hand-written statements per provider; the claim is the one provider-specific statement.
/// </summary>
public sealed class EfInboundMessageStore<TContext>(IInboundDbAccess<TContext> db) : IInboundMessageStore where TContext : DbContext, IQueueDbSets
{
    private const int MaxErrorLength = 1000;

    /// <summary>The most rows one erasure or retention write deletes (settable for tests).</summary>
    internal int MaxBatchRows { get; set; } = InboundRules.MaxBatchRows;

    /// <summary>The most stored body bytes one erasure or retention write deletes; a few large messages are a batch of their own (settable for tests).</summary>
    internal long MaxBatchBytes { get; set; } = InboundRules.MaxBatchBytes;

    /// <summary>The pause between the batches of an erasure, so the queue writer serves intake and deliveries in between (settable for tests).</summary>
    internal TimeSpan ErasePause { get; set; } = TimeSpan.FromMilliseconds(25);

    /// <summary>Test seam: how the pause between batches is taken (a test counts the pauses instead of timing them).</summary>
    internal Func<TimeSpan, CancellationToken, Task> DelayAsync { get; set; } = static (pause, ct) => Task.Delay(pause, ct);

    /// <summary>Test seam: runs between the read that finds a batch and the write that deletes it, the window in which a retry or a claim can change the rows.</summary>
    internal Func<Task>? BetweenReadAndWrite { get; set; }

    /// <summary>Test seam: counts the batches (writes) an erasure or a retention pass made.</summary>
    internal int BatchesWritten { get; private set; }

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
        catch (Exception ex) when (db.TranslateException(ex) is { } translated)
        {
            throw translated;
        }
        catch (Exception ex) when (db.IsConstraintViolation(ex))
        {
            throw new StorageConflictException("An inbound write violated a constraint: " + (ex.InnerException?.Message ?? ex.Message), ex);
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
        ActionAttempts = e.ActionAttempts, RetryGeneration = e.RetryGeneration, ActionNextAttemptAt = e.ActionNextAttemptAt, ActionFinishedAt = e.ActionFinishedAt, ActionLastError = e.ActionLastError, ActionNote = e.ActionNote,
        ForwardMessageId = e.ForwardMessageId, HasRaw = e.HasRaw, LeaseOwner = e.LeaseOwner, ClaimSequence = e.ClaimSequence, LeaseUntil = e.LeaseUntil, TransferSwitchId = e.TransferSwitchId,
    };

    public async ValueTask<Page<InboundMessage>> SearchAsync(InboundMessageQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        int limit = Math.Clamp(query.Limit, 1, InboundRules.MaxPageSize);
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

        return await DeleteInBatchesAsync(q => Filter(q, query), settledOnly: false, byId: true, MaxBatchRows, ErasePause, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<InboundMessage?> GetAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken) =>
        await Read(c => c.InboundMessages.AsNoTracking().Where(x => x.Id == messageId && x.TenantId == tenantId).AsEnumerable().Select(x => x.ToRecord()).FirstOrDefault()).ConfigureAwait(false);

    public async ValueTask<byte[]?> GetRawAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken) =>
        await Read(c => c.InboundRaw.AsNoTracking().Where(x => x.MessageId == messageId && x.TenantId == tenantId).Select(x => x.Raw).FirstOrDefault()).ConfigureAwait(false);

    public async ValueTask<bool> DeleteAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken) =>
        await Write(c =>
        {
            bool deleted = c.InboundMessages.Where(x => x.Id == messageId && x.TenantId == tenantId).ExecuteDelete() > 0;
            c.InboundRaw.Where(x => x.MessageId == messageId && x.TenantId == tenantId && !c.InboundMessages.Any(m => m.Id == x.MessageId)).ExecuteDelete();
            return deleted;
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

            // The state is in the predicate too: a retry that races another one (or a claim that just made the action pending) must not clear a lease or bump the generation twice.
            int changed = c.InboundMessages.Where(x => x.Id == messageId && x.ActionState != InboundActionState.Pending).ExecuteUpdate(s => s
                .SetProperty(x => x.ActionState, InboundActionState.Pending)
                .SetProperty(x => x.ActionAttempts, 0)
                .SetProperty(x => x.RetryGeneration, x => x.RetryGeneration + 1)
                .SetProperty(x => x.ActionNextAttemptAt, (DateTimeOffset?)at)
                .SetProperty(x => x.ActionFinishedAt, (DateTimeOffset?)null)
                .SetProperty(x => x.ActionNote, (string?)null)
                .SetProperty(x => x.LeaseOwner, (string?)null)
                .SetProperty(x => x.LeaseUntil, InboundMapping.NoLease));
            if (changed > 0)
            {
                return InboundRetryResult.Queued;
            }

            // Nothing changed: either another retry or a claim made it pending first, or the message was deleted (retention, an erasure) after the read above.
            return c.InboundMessages.AsNoTracking().Any(x => x.Id == messageId && x.TenantId == tenantId) ? InboundRetryResult.AlreadyPending : InboundRetryResult.NotFound;
        }, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<long> CountActionsAsync(InboundActionState state, CancellationToken cancellationToken) =>
        await Read(c => c.InboundMessages.AsNoTracking().LongCount(x => x.ActionState == state)).ConfigureAwait(false);

    public async ValueTask<IReadOnlyList<ClaimedInboundAction>> ClaimActionsAsync(string owner, int max, DateTimeOffset now, TimeSpan lease, CancellationToken cancellationToken, InboundClaimLimits? limits = null)
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
            IReadOnlyList<Guid> ids = db.ClaimIds(c, owner, max, at, until, limits is { MaxPerTenant: <= 0, ExcludeTenants: null or { Count: 0 } } ? null : limits);
            if (ids.Count == 0)
            {
                return (IReadOnlyList<ClaimedInboundAction>)[];
            }

            Guid[] idArray = [.. ids];
            List<InboundMessageEntity> rows = c.InboundMessages.AsNoTracking().Where(x => idArray.Contains(x.Id)).ToList();
            Dictionary<Guid, byte[]> bodies = c.InboundRaw.AsNoTracking().Where(x => idArray.Contains(x.MessageId)).Select(x => new { x.MessageId, x.Raw }).ToList().ToDictionary(x => x.MessageId, x => x.Raw);
            return rows.OrderBy(x => x.ActionNextAttemptAt).ThenBy(x => InboundMapping.IdText(x.Id), StringComparer.Ordinal)
                .Select(x => new ClaimedInboundAction(x.ToRecord(), bodies.GetValueOrDefault(x.Id), x.ClaimSequence)).ToList();
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
        string? note = outcome.State == InboundActionState.Done ? InboundErrorText.CleanNote(outcome.Note) : null;
        Guid? forward = outcome.ForwardMessageId;
        long? claimToken = outcome.ClaimToken;
        bool free = outcome.FreeBody;
        InboundActionState state = outcome.State;
        return await Write(c =>
        {
            // The token grows with every claim and never goes back down: a completion from an earlier claim is refused even under the same owner name, after a release or a retry too.
            int changed = c.InboundMessages.Where(x => x.Id == messageId && x.LeaseOwner == owner && (claimToken == null || x.ClaimSequence == claimToken)).ExecuteUpdate(s => s
                .SetProperty(x => x.ActionState, state)
                .SetProperty(x => x.ActionNextAttemptAt, next)
                .SetProperty(x => x.ActionFinishedAt, finished)
                .SetProperty(x => x.ActionLastError, error)
                .SetProperty(x => x.ActionNote, note)
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
        await Write(c => c.InboundMessages.Where(x => x.LeaseOwner == owner && x.ActionState == InboundActionState.Pending).ExecuteUpdate(s => s
            .SetProperty(x => x.ActionAttempts, x => x.ActionAttempts > 0 ? x.ActionAttempts - 1 : 0)   // the attempt the claim counted was not made
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

            // One pass over the rows of the scope (the (tenant, id) index), however many numbers are wanted.
            var totals = q.GroupBy(_ => 1).Select(g => new
            {
                Messages = g.LongCount(),
                Bytes = g.Where(x => x.HasRaw).Sum(x => (long?)x.Size) ?? 0,
                Pending = g.LongCount(x => x.ActionState == InboundActionState.Pending),
                Failed = g.LongCount(x => x.ActionState == InboundActionState.Failed),
            }).FirstOrDefault();
            if (totals is null || totals.Messages == 0)
            {
                return new InboundUsage(0, 0, 0, 0, null);
            }

            DateTimeOffset? oldest = totals.Pending == 0 ? null : q.Where(x => x.ActionState == InboundActionState.Pending).OrderBy(x => x.ReceivedAt).Select(x => (DateTimeOffset?)x.ReceivedAt).FirstOrDefault();
            return new InboundUsage(totals.Messages, totals.Bytes, totals.Pending, totals.Failed, oldest);
        }).ConfigureAwait(false);

    /// <summary>
    /// The retention job (design section 11.8): deletes, in batches, the messages whose action is not pending and that were received before the cutoff of their domain.
    /// <paramref name="domainRetentionDays"/> holds the explicit setting of the domains that have one (null days: the server default); every other domain uses
    /// <paramref name="defaultDays"/>. 0 keeps forever. Returns the rows deleted.
    /// </summary>
    public async ValueTask<long> PurgeExpiredAsync(IReadOnlyDictionary<Guid, int?> domainRetentionDays, int defaultDays, int ceilingDays, DateTimeOffset now, int batchSize, TimeSpan pause, CancellationToken cancellationToken)
    {
        long total = 0;
        int rows = Math.Clamp(batchSize, 1, Math.Max(1, MaxBatchRows));
        Guid[] explicitDomains = [.. domainRetentionDays.Where(d => d.Value is not null).Select(d => d.Key)];
        foreach (var (domainId, days) in domainRetentionDays)
        {
            int effective = InboundRules.ResolveRetentionDays(days, defaultDays, ceilingDays);
            if (days is not null && InboundRules.RetentionCutoff(now, effective) is { } cutoff)
            {
                Guid domain = domainId;
                DateTimeOffset when = StorageTime.Normalize(cutoff);
                total += await DeleteInBatchesAsync(q => q.Where(x => x.DomainId == domain && x.ReceivedAt < when), settledOnly: true, byId: false, rows, pause, cancellationToken).ConfigureAwait(false);
            }
        }

        if (InboundRules.RetentionCutoff(now, InboundRules.ResolveRetentionDays(null, defaultDays, ceilingDays)) is { } defaultCutoff)
        {
            DateTimeOffset when = StorageTime.Normalize(defaultCutoff);
            total += await DeleteInBatchesAsync(q => q.Where(x => !explicitDomains.Contains(x.DomainId) && x.ReceivedAt < when), settledOnly: true, byId: false, rows, pause, cancellationToken).ConfigureAwait(false);
        }

        return total;
    }

    /// <summary>
    /// Deletes the rows <paramref name="scope"/> selects, a bounded batch at a time: at most <paramref name="rows"/> rows and <see cref="MaxBatchBytes"/> of stored bodies per write, so one
    /// write never holds the SQLite queue writer (or a PostgreSQL transaction) for long, with a pause between batches. The candidates are found on a read connection, oldest first, continuing
    /// after the last one handled (a sparse filter is scanned once, not once per batch); the delete is a short write by id. <paramref name="settledOnly"/> (retention) adds the pending guard to
    /// the delete itself, so an action made pending by a retry between the read and the write keeps its message and its body.
    /// </summary>
    private async ValueTask<long> DeleteInBatchesAsync(Func<IQueryable<InboundMessageEntity>, IQueryable<InboundMessageEntity>> scope, bool settledOnly, bool byId, int rows, TimeSpan pause, CancellationToken cancellationToken)
    {
        long deleted = 0;
        (DateTimeOffset At, Guid Id)? after = null;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var position = after;
            var found = await Read(c =>
            {
                IQueryable<InboundMessageEntity> q = scope(c.InboundMessages.AsNoTracking());
                if (settledOnly)
                {
                    q = q.Where(x => x.ActionState != InboundActionState.Pending);
                }

                if (byId)
                {
                    // Erasure walks the ids (UUIDv7, the (tenant_id, id) and (domain_id, id) indexes): no sort of the matches in a temporary B-tree for every batch.
                    if (position is { } lastId)
                    {
                        Guid id = lastId.Id;
                        q = q.Where(x => x.Id.CompareTo(id) > 0);
                    }

                    return q.OrderBy(x => x.Id).Select(x => new { x.Id, x.ReceivedAt, x.Size }).Take(rows).ToList();
                }

                // Retention walks the age (the received_at indexes), continuing after the last row handled.
                if (position is { } last)
                {
                    DateTimeOffset at = last.At;
                    Guid id = last.Id;
                    q = q.Where(x => x.ReceivedAt > at || (x.ReceivedAt == at && x.Id.CompareTo(id) > 0));
                }

                return q.OrderBy(x => x.ReceivedAt).ThenBy(x => x.Id).Select(x => new { x.Id, x.ReceivedAt, x.Size }).Take(rows).ToList();
            }).ConfigureAwait(false);
            if (found.Count == 0)
            {
                return deleted;
            }

            // The byte budget: take rows until the bodies add up to it (always at least one).
            int take = 0;
            long bytes = 0;
            while (take < found.Count && (take == 0 || bytes + found[take].Size <= MaxBatchBytes))
            {
                bytes += found[take].Size;
                take++;
            }

            Guid[] ids = [.. found.Take(take).Select(x => x.Id)];
            after = (found[take - 1].ReceivedAt, found[take - 1].Id);
            if (BetweenReadAndWrite is { } hook)
            {
                await hook().ConfigureAwait(false);
            }

            BatchesWritten++;
            deleted += await Write(c =>
            {
                // The message first, with its guard; a body goes only when its message is gone, so a message that survives the guard never loses its body.
                int n = (settledOnly
                    ? c.InboundMessages.Where(x => ids.Contains(x.Id) && x.ActionState != InboundActionState.Pending)
                    : c.InboundMessages.Where(x => ids.Contains(x.Id))).ExecuteDelete();
                c.InboundRaw.Where(x => ids.Contains(x.MessageId) && !c.InboundMessages.Any(m => m.Id == x.MessageId)).ExecuteDelete();
                return n;
            }, cancellationToken).ConfigureAwait(false);

            if (found.Count < rows && take == found.Count)
            {
                return deleted;
            }

            if (pause > TimeSpan.Zero)
            {
                await DelayAsync(pause, cancellationToken).ConfigureAwait(false);
            }
        }
    }
}
