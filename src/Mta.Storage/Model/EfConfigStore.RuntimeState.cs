using Microsoft.EntityFrameworkCore;

namespace Mta.Storage.Model;

// The persisted runtime state (IRuntimeStateStore) of the EF config store. Each write is one transaction of the config writer (SQLite) or one
// advisory-locked transaction (PostgreSQL), so the read-modify-write of a counter is atomic across replicas.
public sealed partial class EfConfigStore<TContext>
{
    public async ValueTask<IReadOnlyList<DomainRecordCheckRecord>> GetDomainRecordChecksAsync(Guid domainId, CancellationToken ct) =>
        await Read<IReadOnlyList<DomainRecordCheckRecord>>(c => c.Set<DomainRecordCheckEntity>().AsNoTracking().Where(x => x.DomainId == domainId).OrderBy(x => x.RecordKey).AsEnumerable().Select(x => x.ToRecord()).ToList()).ConfigureAwait(false);

    public async ValueTask ReplaceDomainRecordChecksAsync(Guid domainId, IReadOnlyList<DomainRecordCheckRecord> checks, CancellationToken ct)
    {
        var entities = checks.Select(x => (x with { DomainId = domainId }).ToEntity()).DistinctBy(x => x.RecordKey).ToList();
        await Write(c =>
        {
            c.Set<DomainRecordCheckEntity>().Where(x => x.DomainId == domainId).ExecuteDelete();
            c.Set<DomainRecordCheckEntity>().AddRange(entities);
            c.SaveChanges();
        }, ct).ConfigureAwait(false);
    }

    public async ValueTask AddTlsRptBucketsAsync(IReadOnlyList<TlsRptBucketRecord> buckets, CancellationToken ct)
    {
        if (buckets.Count == 0)
        {
            return;
        }

        var entities = buckets.Select(x => x.ToEntity()).ToList();
        await Write(c =>
        {
            c.Set<TlsRptBucketEntity>().AddRange(entities);
            c.SaveChanges();
        }, ct).ConfigureAwait(false);
    }

    public async ValueTask<IReadOnlyList<TlsRptBucketRecord>> GetTlsRptBucketsAsync(int beforeDay, int max, CancellationToken ct) =>
        await Read<IReadOnlyList<TlsRptBucketRecord>>(c => c.Set<TlsRptBucketEntity>().AsNoTracking().Where(x => x.Day < beforeDay)
            .OrderBy(x => x.Day).ThenBy(x => x.PolicyDomain).ThenBy(x => x.CreatedAt).ThenBy(x => x.Id).Take(Math.Max(0, max)).AsEnumerable().Select(x => x.ToRecord()).ToList()).ConfigureAwait(false);

    public async ValueTask ReplaceTlsRptBucketsAsync(IReadOnlyCollection<Guid> removeIds, TlsRptBucketRecord? replacement, CancellationToken ct)
    {
        Guid[] ids = [.. removeIds];
        TlsRptBucketEntity? entity = replacement?.ToEntity();
        await Write(c =>
        {
            if (ids.Length > 0)
            {
                c.Set<TlsRptBucketEntity>().Where(x => ids.Contains(x.Id)).ExecuteDelete();
            }

            if (entity is not null)
            {
                c.Set<TlsRptBucketEntity>().Add(entity);
                c.SaveChanges();
            }
        }, ct).ConfigureAwait(false);
    }

    public async ValueTask<IReadOnlyList<SendingCounterRecord>> GetSendingCountersAsync(long minHourIndex, long minDayIndex, CancellationToken ct) =>
        await Read<IReadOnlyList<SendingCounterRecord>>(c => c.Set<SendingCounterEntity>().AsNoTracking()
            .Where(x => (x.WindowKind == 0 && x.WindowIndex >= minHourIndex) || (x.WindowKind == 1 && x.WindowIndex >= minDayIndex))
            .OrderBy(x => x.Scope).ThenBy(x => x.TenantId).ThenBy(x => x.Domain).ThenBy(x => x.WindowKind).ThenBy(x => x.WindowIndex).AsEnumerable().Select(x => x.ToRecord()).ToList()).ConfigureAwait(false);

    public async ValueTask AddSendingCountersAsync(IReadOnlyList<SendingCounterRecord> deltas, long pruneBeforeHour, long pruneBeforeDay, CancellationToken ct)
    {
        // Merge duplicates of one key first so each counter is read and written once.
        var merged = deltas
            .GroupBy(d => (d.Scope, d.TenantId, Domain: d.Domain ?? "", d.Window, d.WindowIndex))
            .Select(g => new SendingCounterRecord(g.Key.Scope, g.Key.TenantId, g.Key.Domain, g.Key.Window, g.Key.WindowIndex, g.Sum(d => d.Count)))
            .Where(d => d.Count != 0)
            .ToList();
        await Write(c =>
        {
            var set = c.Set<SendingCounterEntity>();
            foreach (SendingCounterRecord delta in merged)
            {
                SendingCounterEntity? existing = set.Find(delta.Scope, delta.TenantId, delta.Domain, delta.Window, delta.WindowIndex);
                if (existing is null)
                {
                    if (delta.Count > 0)
                    {
                        set.Add(delta.ToEntity());
                    }
                }
                else
                {
                    existing.Count = Math.Max(0, existing.Count + delta.Count);
                }
            }

            c.SaveChanges();
            set.Where(x => (x.WindowKind == 0 && x.WindowIndex < pruneBeforeHour) || (x.WindowKind == 1 && x.WindowIndex < pruneBeforeDay)).ExecuteDelete();
        }, ct).ConfigureAwait(false);
    }
}
