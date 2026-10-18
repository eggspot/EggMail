using Mta.Storage.Logic;
using Mta.Storage.Model;

namespace Mta.Storage.InMemory;

/// <summary>The inbound message store of the in-memory backend: the reference the SQLite and PostgreSQL stores are checked against by the conformance suite.</summary>
internal sealed class MemoryInbound(MemoryState s) : IInboundMessageStore
{
    private static ValueTask<T> R<T>(T value) => ValueTask.FromResult(value);

    public ValueTask AcceptAsync(IReadOnlyList<InboundMessageDraft> drafts, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(drafts);
        if (drafts.Count == 0)
        {
            throw new ArgumentException("A transaction needs at least one message.", nameof(drafts));
        }

        s.Fence.ThrowIfClosed();
        var entities = new List<(InboundMessageEntity Message, InboundMessageRawEntity? Body)>(drafts.Count);
        foreach (InboundMessageDraft draft in drafts)
        {
            if (draft.Id.Version != 7)
            {
                throw new ArgumentException("An inbound message id must be a UUIDv7 (Ids.New).", nameof(drafts));
            }

            InboundMessageEntity e = draft.ToEntity();
            entities.Add((e, e.HasRaw ? new InboundMessageRawEntity { MessageId = e.Id, TenantId = e.TenantId, Raw = draft.Raw.ToArray() } : null));
        }

        lock (s.Gate)
        {
            // All or nothing, like one transaction.
            if (entities.Any(e => s.InboundMessages.ContainsKey(e.Message.Id)) || entities.Select(e => e.Message.Id).Distinct().Count() != entities.Count)
            {
                throw new StorageConflictException("An inbound message id is already stored.");
            }

            foreach ((InboundMessageEntity message, InboundMessageRawEntity? body) in entities)
            {
                s.InboundMessages[message.Id] = message;
                if (body is not null)
                {
                    s.InboundRaw[message.Id] = body;
                }
            }
        }

        return default;
    }

    public ValueTask<Page<InboundMessage>> SearchAsync(InboundMessageQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        int limit = Math.Clamp(query.Limit, 1, InboundRules.MaxPageSize);
        string? cursor = null;
        if (query.Cursor is not null)
        {
            if (!Cursors.TryDecode(query.Cursor, out string raw) || !Guid.TryParse(raw, out Guid parsed))
            {
                return R(new Page<InboundMessage>([], null));
            }

            cursor = InboundMapping.IdText(parsed);
        }

        lock (s.Gate)
        {
            IEnumerable<InboundMessageEntity> q = s.InboundMessages.Values.Where(x => Matches(x, query));
            if (cursor is not null)
            {
                q = q.Where(x => string.CompareOrdinal(InboundMapping.IdText(x.Id), cursor) < 0);
            }

            List<InboundMessage> rows = q.OrderByDescending(x => InboundMapping.IdText(x.Id), StringComparer.Ordinal).Take(limit + 1).Select(x => x.ToRecord()).ToList();
            bool more = rows.Count > limit;
            if (more)
            {
                rows.RemoveAt(rows.Count - 1);
            }

            return R(new Page<InboundMessage>(rows, more ? Cursors.Encode(rows[^1].Id.ToString("D")) : null));
        }
    }

    // The filters of a search or an erasure: the same meaning as EfInboundMessageStore.Filter.
    private static bool Matches(InboundMessageEntity x, InboundMessageQuery query)
    {
        if (x.TenantId != query.TenantId || (query.DomainId is { } domain && x.DomainId != domain))
        {
            return false;
        }

        if (query.Recipient?.Trim().ToLowerInvariant() is { } recipient && x.EnvelopeTo != recipient)
        {
            return false;
        }

        if (query.Sender?.Trim().ToLowerInvariant() is { } sender && x.EnvelopeFrom != sender)
        {
            return false;
        }

        if (!string.IsNullOrEmpty(query.SubjectContains) && (x.Subject is null || !InboundMapping.AsciiLower(x.Subject).Contains(InboundMapping.AsciiLower(query.SubjectContains), StringComparison.Ordinal)))
        {
            return false;
        }

        if ((query.RouteId is { } route && x.RouteId != route) || (query.ActionKind is { } kind && x.ActionKind != kind) || (query.ActionState is { } state && x.ActionState != state)
            || (query.Dmarc is { } dmarc && x.Dmarc != dmarc) || (query.DmarcFlagged is { } flagged && (x.Disposition == InboundDmarcDisposition.Flagged) != flagged))
        {
            return false;
        }

        return (StorageTime.Normalize(query.From) is not { } from || x.ReceivedAt >= from) && (StorageTime.Normalize(query.To) is not { } to || x.ReceivedAt < to);
    }

    public ValueTask<long> DeleteMatchingAsync(InboundMessageQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        if (!InboundRules.HasFilter(query))
        {
            throw new ArgumentException("An erasure needs at least one filter besides the tenant.", nameof(query));
        }

        lock (s.Gate)
        {
            List<Guid> ids = s.InboundMessages.Values.Where(x => Matches(x, query)).Select(x => x.Id).ToList();
            foreach (Guid id in ids)
            {
                s.InboundMessages.Remove(id);
                s.InboundRaw.Remove(id);
            }

            return R((long)ids.Count);
        }
    }

    public ValueTask<InboundMessage?> GetAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken)
    {
        lock (s.Gate)
        {
            return R(s.InboundMessages.TryGetValue(messageId, out InboundMessageEntity? e) && e.TenantId == tenantId ? e.ToRecord() : null);
        }
    }

    public ValueTask<byte[]?> GetRawAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken)
    {
        lock (s.Gate)
        {
            return R(s.InboundRaw.TryGetValue(messageId, out InboundMessageRawEntity? raw) && raw.TenantId == tenantId ? raw.Raw.ToArray() : null);
        }
    }

    public ValueTask<bool> DeleteAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken)
    {
        lock (s.Gate)
        {
            if (!s.InboundMessages.TryGetValue(messageId, out InboundMessageEntity? e) || e.TenantId != tenantId)
            {
                return R(false);
            }

            s.InboundMessages.Remove(messageId);
            s.InboundRaw.Remove(messageId);
            return R(true);
        }
    }

    public ValueTask<InboundRetryResult> RetryActionAsync(Guid tenantId, Guid messageId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        lock (s.Gate)
        {
            if (!s.InboundMessages.TryGetValue(messageId, out InboundMessageEntity? e) || e.TenantId != tenantId)
            {
                return R(InboundRetryResult.NotFound);
            }

            if (e.ActionKind is not (InboundActionKind.Webhook or InboundActionKind.Forward) || !e.HasRaw)
            {
                return R(InboundRetryResult.NotRetryable);
            }

            if (e.ActionState == InboundActionState.Pending)
            {
                return R(InboundRetryResult.AlreadyPending);
            }

            e.ActionState = InboundActionState.Pending;
            e.ActionAttempts = 0;
            e.RetryGeneration++;
            e.ActionNextAttemptAt = StorageTime.Normalize(now);
            e.ActionFinishedAt = null;
            e.ActionNote = null;
            e.LeaseOwner = null;
            e.LeaseUntil = InboundMapping.NoLease;
            return R(InboundRetryResult.Queued);
        }
    }

    public ValueTask<ForwardBacklog> GetForwardBacklogAsync(Guid tenantId, string sendingDomain, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string domain = sendingDomain.ToLowerInvariant();
        lock (s.Gate)
        {
            var forwards = s.Deliveries.Values.Where(d => d.TenantId == tenantId && d.Source == MessageSource.Forward).ToList();
            var ids = forwards.Select(d => d.MessageId).ToHashSet();
            long bytes = ids.Sum(id => s.Spool.TryGetValue(id, out SpoolMessageEntity? m) ? m.Size : 0);
            long inDomain = forwards.Where(d => d.SendingDomain == domain).Select(d => d.MessageId).Distinct().LongCount();
            return R(new ForwardBacklog(ids.Count, bytes, inDomain));
        }
    }

    public ValueTask<long> CountActionsAsync(InboundActionState state, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (s.Gate)
        {
            return R((long)s.InboundMessages.Values.Count(x => x.ActionState == state));
        }
    }

    public ValueTask<IReadOnlyList<ClaimedInboundAction>> ClaimActionsAsync(string owner, int max, DateTimeOffset now, TimeSpan lease, CancellationToken cancellationToken, InboundClaimLimits? limits = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(owner);
        if (max <= 0 || s.Fence.IsClosed)
        {
            return R<IReadOnlyList<ClaimedInboundAction>>([]);
        }

        DateTimeOffset at = StorageTime.Normalize(now);
        DateTimeOffset until = StorageTime.Normalize(now + lease);
        lock (s.Gate)
        {
            IEnumerable<InboundMessageEntity> eligible = s.InboundMessages.Values
                .Where(x => x.TransferSwitchId is null && x.ActionState == InboundActionState.Pending && x.ActionNextAttemptAt <= at && x.LeaseUntil <= at);
            if (limits?.ExcludeTenants is { Count: > 0 } excluded)
            {
                eligible = eligible.Where(x => !excluded.Contains(x.TenantId));
            }

            IEnumerable<InboundMessageEntity> ordered = eligible.OrderBy(x => x.ActionNextAttemptAt).ThenBy(x => InboundMapping.IdText(x.Id), StringComparer.Ordinal);
            if (limits is { MaxPerTenant: > 0 } capped)
            {
                var perTenant = new Dictionary<Guid, int>();
                ordered = ordered.Where(x =>
                {
                    int seen = perTenant.GetValueOrDefault(x.TenantId) + 1;
                    perTenant[x.TenantId] = seen;
                    return seen <= capped.AllowanceOf(x.TenantId);
                });
            }

            List<InboundMessageEntity> due = ordered.Take(max).ToList();
            var claimed = new List<ClaimedInboundAction>(due.Count);
            foreach (InboundMessageEntity e in due)
            {
                e.LeaseOwner = owner;
                e.LeaseUntil = until;
                e.ActionAttempts++;   // the claim counts the attempt: a crash in the middle of it has used it up
                e.ClaimSequence++;
                claimed.Add(new ClaimedInboundAction(e.ToRecord(), s.InboundRaw.TryGetValue(e.Id, out InboundMessageRawEntity? raw) ? raw.Raw.ToArray() : null, e.ClaimSequence));
            }

            return R<IReadOnlyList<ClaimedInboundAction>>(claimed);
        }
    }

    public ValueTask<bool> ExtendActionLeaseAsync(Guid messageId, string owner, DateTimeOffset until, CancellationToken cancellationToken)
    {
        lock (s.Gate)
        {
            if (s.InboundMessages.TryGetValue(messageId, out InboundMessageEntity? e) && e.LeaseOwner == owner)
            {
                e.LeaseUntil = StorageTime.Normalize(until);
                return R(true);
            }

            return R(false);
        }
    }

    public ValueTask<bool> CompleteActionAsync(Guid messageId, string owner, InboundActionOutcome outcome, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(outcome);
        cancellationToken.ThrowIfCancellationRequested();   // the real stores write through the token: a completion recorded with the runner's stopped token must fail here too
        if (outcome.State == InboundActionState.Pending && outcome.NextAttemptAt is null)
        {
            throw new ArgumentException("A pending outcome needs NextAttemptAt.", nameof(outcome));
        }

        DateTimeOffset at = StorageTime.Normalize(outcome.At);
        lock (s.Gate)
        {
            if (!s.InboundMessages.TryGetValue(messageId, out InboundMessageEntity? e) || e.LeaseOwner != owner || (outcome.ClaimToken is { } token && e.ClaimSequence != token))
            {
                return R(false);
            }

            e.ActionState = outcome.State;
            e.ActionNextAttemptAt = outcome.State == InboundActionState.Pending ? StorageTime.Normalize(outcome.NextAttemptAt) : null;
            e.ActionFinishedAt = outcome.State == InboundActionState.Pending ? null : at;
            e.ActionLastError = outcome.State == InboundActionState.Done ? null : InboundErrorText.Clean(outcome.Error, 1000);
            e.ActionNote = outcome.State == InboundActionState.Done ? InboundErrorText.CleanNote(outcome.Note) : null;
            e.LeaseOwner = null;
            e.LeaseUntil = InboundMapping.NoLease;
            if (outcome.ForwardMessageId is { } forward)
            {
                e.ForwardMessageId = forward;
            }

            if (outcome.FreeBody)
            {
                s.InboundRaw.Remove(messageId);
                e.HasRaw = false;
            }

            return R(true);
        }
    }

    public ValueTask<int> ReleaseOwnedActionLeasesAsync(string owner, CancellationToken cancellationToken)
    {
        lock (s.Gate)
        {
            int n = 0;
            foreach (InboundMessageEntity e in s.InboundMessages.Values.Where(x => x.LeaseOwner == owner && x.ActionState == InboundActionState.Pending))
            {
                e.ActionAttempts = Math.Max(0, e.ActionAttempts - 1);   // the attempt the claim counted was not made
                e.LeaseOwner = null;
                e.LeaseUntil = InboundMapping.NoLease;
                n++;
            }

            return R(n);
        }
    }

    public ValueTask<InboundUsage> GetUsageAsync(Guid? tenantId, Guid? domainId, CancellationToken cancellationToken)
    {
        lock (s.Gate)
        {
            List<InboundMessageEntity> rows = s.InboundMessages.Values.Where(x => (tenantId is null || x.TenantId == tenantId) && (domainId is null || x.DomainId == domainId)).ToList();
            long pending = rows.Count(x => x.ActionState == InboundActionState.Pending);
            DateTimeOffset? oldest = pending == 0 ? null : rows.Where(x => x.ActionState == InboundActionState.Pending).Min(x => (DateTimeOffset?)x.ReceivedAt);
            return R(new InboundUsage(rows.Count, rows.Where(x => x.HasRaw).Sum(x => x.Size), pending, rows.Count(x => x.ActionState == InboundActionState.Failed), oldest));
        }
    }

    /// <summary>The retention job; the same rules as <see cref="EfInboundMessageStore{TContext}.PurgeExpiredAsync"/>. Called with the state lock held.</summary>
    internal long PurgeExpired(IReadOnlyDictionary<Guid, int?> domainRetentionDays, int defaultDays, int ceilingDays, DateTimeOffset now)
    {
        long total = 0;
        foreach (InboundMessageEntity e in s.InboundMessages.Values.ToList())
        {
            int days = InboundRules.ResolveRetentionDays(domainRetentionDays.GetValueOrDefault(e.DomainId), defaultDays, ceilingDays);
            if (e.ActionState != InboundActionState.Pending && InboundRules.RetentionCutoff(now, days) is { } cutoff && e.ReceivedAt < StorageTime.Normalize(cutoff))
            {
                s.InboundMessages.Remove(e.Id);
                s.InboundRaw.Remove(e.Id);
                total++;
            }
        }

        return total;
    }
}
