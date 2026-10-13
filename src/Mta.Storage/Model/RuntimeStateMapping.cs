using Mta.Storage.Logic;

namespace Mta.Storage.Model;

/// <summary>Maps the persisted runtime state (domain check results, TLS-RPT journal, sending counters) between records and entities.</summary>
public static class RuntimeStateMapping
{
    public static DomainRecordCheckEntity ToEntity(this DomainRecordCheckRecord r) => new()
    {
        DomainId = r.DomainId,
        RecordKey = r.RecordKey,
        Status = r.Status,
        Found = r.Found,
        CheckedAt = StorageTime.Normalize(r.CheckedAt),
    };

    public static DomainRecordCheckRecord ToRecord(this DomainRecordCheckEntity e) => new(e.DomainId, e.RecordKey, e.Status, e.Found, e.CheckedAt);

    public static TlsRptBucketEntity ToEntity(this TlsRptBucketRecord r) => new()
    {
        Id = r.Id,
        Day = r.Day,
        PolicyDomain = r.PolicyDomain,
        DataJson = r.DataJson,
        Attempts = r.Attempts,
        CreatedAt = StorageTime.Normalize(r.CreatedAt),
    };

    public static TlsRptBucketRecord ToRecord(this TlsRptBucketEntity e) => new(e.Id, e.Day, e.PolicyDomain, e.DataJson, e.Attempts, e.CreatedAt);

    public static SendingCounterEntity ToEntity(this SendingCounterRecord r) => new()
    {
        Scope = r.Scope,
        TenantId = r.TenantId,
        Domain = r.Domain ?? "",
        WindowKind = r.Window,
        WindowIndex = r.WindowIndex,
        Count = r.Count,
    };

    public static SendingCounterRecord ToRecord(this SendingCounterEntity e) => new(e.Scope, e.TenantId, e.Domain, e.WindowKind, e.WindowIndex, e.Count);
}
