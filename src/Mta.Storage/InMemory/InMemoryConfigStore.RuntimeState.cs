using Mta.Storage.Model;

namespace Mta.Storage.InMemory;

// The persisted runtime state (IRuntimeStateStore) of the in-memory config store: same semantics as EfConfigStore.RuntimeState.
internal sealed partial class InMemoryConfigStore
{
    public ValueTask<IReadOnlyList<DomainRecordCheckRecord>> GetDomainRecordChecksAsync(Guid domainId, CancellationToken ct)
    {
        lock (_gate)
        {
            return R<IReadOnlyList<DomainRecordCheckRecord>>(_domainChecks.Values.Where(x => x.DomainId == domainId).OrderBy(x => x.RecordKey, StringComparer.Ordinal).Select(x => x.ToRecord()).ToList());
        }
    }

    public ValueTask ReplaceDomainRecordChecksAsync(Guid domainId, IReadOnlyList<DomainRecordCheckRecord> checks, CancellationToken ct)
    {
        lock (_gate)
        {
            foreach (var key in _domainChecks.Keys.Where(k => k.Item1 == domainId).ToList())
            {
                _domainChecks.Remove(key);
            }

            foreach (DomainRecordCheckRecord check in checks)
            {
                var e = (check with { DomainId = domainId }).ToEntity();
                _domainChecks[(e.DomainId, e.RecordKey)] = e;
            }
        }

        return default;
    }

    public ValueTask AddTlsRptBucketsAsync(IReadOnlyList<TlsRptBucketRecord> buckets, CancellationToken ct)
    {
        lock (_gate)
        {
            foreach (TlsRptBucketRecord bucket in buckets)
            {
                var e = bucket.ToEntity();
                if (!_tlsRpt.TryAdd(e.Id, e))
                {
                    throw Conflict("tls_rpt_bucket.id");
                }
            }
        }

        return default;
    }

    public ValueTask<IReadOnlyList<TlsRptBucketRecord>> GetTlsRptBucketsAsync(int beforeDay, int max, CancellationToken ct)
    {
        lock (_gate)
        {
            return R<IReadOnlyList<TlsRptBucketRecord>>(_tlsRpt.Values.Where(x => x.Day < beforeDay)
                .OrderBy(x => x.Day).ThenBy(x => x.PolicyDomain, StringComparer.Ordinal).ThenBy(x => x.CreatedAt).ThenBy(x => x.Id).Take(Math.Max(0, max)).Select(x => x.ToRecord()).ToList());
        }
    }

    public ValueTask ReplaceTlsRptBucketsAsync(IReadOnlyCollection<Guid> removeIds, TlsRptBucketRecord? replacement, CancellationToken ct)
    {
        lock (_gate)
        {
            foreach (Guid id in removeIds)
            {
                _tlsRpt.Remove(id);
            }

            if (replacement is not null)
            {
                var e = replacement.ToEntity();
                _tlsRpt[e.Id] = e;
            }
        }

        return default;
    }

    public ValueTask<IReadOnlyList<SendingCounterRecord>> GetSendingCountersAsync(long minHourIndex, long minDayIndex, CancellationToken ct)
    {
        lock (_gate)
        {
            return R<IReadOnlyList<SendingCounterRecord>>(_counters.Values
                .Where(x => (x.WindowKind == 0 && x.WindowIndex >= minHourIndex) || (x.WindowKind == 1 && x.WindowIndex >= minDayIndex))
                .OrderBy(x => x.Scope).ThenBy(x => x.TenantId).ThenBy(x => x.Domain, StringComparer.Ordinal).ThenBy(x => x.WindowKind).ThenBy(x => x.WindowIndex).Select(x => x.ToRecord()).ToList());
        }
    }

    public ValueTask AddSendingCountersAsync(IReadOnlyList<SendingCounterRecord> deltas, long pruneBeforeHour, long pruneBeforeDay, CancellationToken ct)
    {
        lock (_gate)
        {
            foreach (SendingCounterRecord delta in deltas)
            {
                var key = (delta.Scope, delta.TenantId, delta.Domain ?? "", delta.Window, delta.WindowIndex);
                if (_counters.TryGetValue(key, out SendingCounterEntity? existing))
                {
                    existing.Count = Math.Max(0, existing.Count + delta.Count);
                }
                else if (delta.Count > 0)
                {
                    _counters[key] = delta.ToEntity();
                }
            }

            foreach (var key in _counters.Where(kv => (kv.Value.WindowKind == 0 && kv.Value.WindowIndex < pruneBeforeHour) || (kv.Value.WindowKind == 1 && kv.Value.WindowIndex < pruneBeforeDay)).Select(kv => kv.Key).ToList())
            {
                _counters.Remove(key);
            }
        }

        return default;
    }
}
