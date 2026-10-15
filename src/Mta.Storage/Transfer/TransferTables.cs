using Microsoft.EntityFrameworkCore;
using Mta.Core;
using Mta.Storage.Model;

namespace Mta.Storage.Transfer;

/// <summary>
/// The registry of every table that moves in a backend switch (design §4.6), in import order. A table that is not listed
/// here does not move: the Data Protection key ring (the target keeps its own), leases (runtime state), the switch state
/// and the transfer progress records.
/// </summary>
public static class TransferTables
{
    /// <summary>Settings with this key prefix are the deployment's Data Protection key ring; they never move.</summary>
    public const string DataProtectionSettingPrefix = "dataprotection.key.";

    public static readonly TransferTable<TenantEntity> Tenants = new("tenant", TransferPart.Config, new()
    {
        Order = q => q.OrderBy(x => x.Id),
    });

    public static readonly TransferTable<ApiKeyEntity> ApiKeys = new("api_key", TransferPart.Config, new()
    {
        Order = q => q.OrderBy(x => x.Id),
    });

    public static readonly TransferTable<SmtpCredentialEntity> SmtpCredentials = new("smtp_credential", TransferPart.Config, new()
    {
        Order = q => q.OrderBy(x => x.Id),
    });

    public static readonly TransferTable<DashboardUserEntity> DashboardUsers = new("dashboard_user", TransferPart.Config, new()
    {
        Order = q => q.OrderBy(x => x.Id),
    });

    /// <summary>Sessions move too, so signed-in users stay signed in after the cutover (only the digest of the secret is stored).</summary>
    public static readonly TransferTable<DashboardSessionEntity> DashboardSessions = new("dashboard_session", TransferPart.Config, new()
    {
        Order = q => q.OrderBy(x => x.IdHash),
    });

    public static readonly TransferTable<DomainEntity> Domains = new("domain", TransferPart.Config, new()
    {
        Order = q => q.OrderBy(x => x.Id),
    });

    public static readonly TransferTable<DkimKeyEntity> DkimKeys = new("dkim_key", TransferPart.Config, new()
    {
        Order = q => q.OrderBy(x => x.Id),
        Secrets = [new TransferSecret<DkimKeyEntity>(nameof(DkimKeyEntity.PrivateKeyProtected), SecretPurposes.DkimKey, x => x.PrivateKeyProtected, (x, v) => x.PrivateKeyProtected = v ?? [])],
    });

    public static readonly TransferTable<SuppressionEntity> Suppressions = new("suppression", TransferPart.Config, new()
    {
        Order = q => q.OrderBy(x => x.TenantId).ThenBy(x => x.Address),
    });

    public static readonly TransferTable<WebhookEndpointEntity> WebhookEndpoints = new("webhook_endpoint", TransferPart.Config, new()
    {
        Order = q => q.OrderBy(x => x.Id),
        Secrets = [new TransferSecret<WebhookEndpointEntity>(nameof(WebhookEndpointEntity.SecretProtected), SecretPurposes.WebhookSecret, x => x.SecretProtected, (x, v) => x.SecretProtected = v ?? [])],
    });

    /// <summary>Settings, without the Data Protection key ring. Upserted: a fresh target may already hold a setting of its own.</summary>
    public static readonly TransferTable<SettingEntity> Settings = new("setting", TransferPart.Config, new()
    {
        Order = q => q.OrderBy(x => x.TenantId).ThenBy(x => x.Key),
        Scope = q => q.Where(x => !x.Key.StartsWith(DataProtectionSettingPrefix)),
        Upsert = true,
    });

    public static readonly TransferTable<TlsPolicyEntity> TlsPolicies = new("tls_policy", TransferPart.Config, new()
    {
        Order = q => q.OrderBy(x => x.Id),
    });

    public static readonly TransferTable<RelayRouteEntity> RelayRoutes = new("relay_route", TransferPart.Config, new()
    {
        Order = q => q.OrderBy(x => x.Id),
        Secrets = [new TransferSecret<RelayRouteEntity>(nameof(RelayRouteEntity.PasswordProtected), SecretPurposes.RelayPassword, x => x.PasswordProtected, (x, v) => x.PasswordProtected = v)],
    });

    public static readonly TransferTable<CertificateEntity> Certificates = new("certificate", TransferPart.Config, new()
    {
        Order = q => q.OrderBy(x => x.Id),
        Secrets = [new TransferSecret<CertificateEntity>(nameof(CertificateEntity.PrivateKeyProtected), SecretPurposes.TlsPrivateKey, x => x.PrivateKeyProtected, (x, v) => x.PrivateKeyProtected = v ?? [])],
    });

    public static readonly TransferTable<AcmeAccountEntity> AcmeAccounts = new("acme_account", TransferPart.Config, new()
    {
        Order = q => q.OrderBy(x => x.Id),
        Secrets = [new TransferSecret<AcmeAccountEntity>(nameof(AcmeAccountEntity.AccountKeyProtected), SecretPurposes.AcmeAccountKey, x => x.AccountKeyProtected, (x, v) => x.AccountKeyProtected = v ?? [])],
    });

    /// <summary>Renewal metadata moves; an in-flight DNS-01 challenge does not (the target restarts any pending order, design §4.6).</summary>
    public static readonly TransferTable<AcmeRenewalEntity> AcmeRenewals = new("acme_renewal", TransferPart.Config, new()
    {
        Order = q => q.OrderBy(x => x.CertificateName),
        PrepareExport = x => x.ChallengeStateJson = null,
        CanonicalExcludes = [nameof(AcmeRenewalEntity.ChallengeStateJson)],
    });

    /// <summary>The last DNS check result of each record of a domain: moves so a switched deployment keeps showing the real per-record state.</summary>
    public static readonly TransferTable<DomainRecordCheckEntity> DomainRecordChecks = new("domain_record_check", TransferPart.Config, new()
    {
        Order = q => q.OrderBy(x => x.DomainId).ThenBy(x => x.RecordKey),
    });

    /// <summary>Unsent TLS-RPT counters and reports move, so a switch does not lose the day's report.</summary>
    public static readonly TransferTable<TlsRptBucketEntity> TlsRptBuckets = new("tls_rpt_bucket", TransferPart.Config, new()
    {
        Order = q => q.OrderBy(x => x.Id),
    });

    /// <summary>The sending counters of the current windows move, so a switch does not reset the hourly and daily caps.</summary>
    public static readonly TransferTable<SendingCounterEntity> SendingCounters = new("sending_counter", TransferPart.Config, new()
    {
        Order = q => q.OrderBy(x => x.Scope).ThenBy(x => x.TenantId).ThenBy(x => x.Domain).ThenBy(x => x.WindowKind).ThenBy(x => x.WindowIndex),
        Upsert = true,
    });

    /// <summary>The inbound settings of each domain (decision 92).</summary>
    public static readonly TransferTable<InboundDomainSettingsEntity> InboundDomainSettings = new("inbound_domain_settings", TransferPart.Config, new()
    {
        Order = q => q.OrderBy(x => x.DomainId),
    });

    public static readonly TransferTable<InboundRouteEntity> InboundRoutes = new("inbound_route", TransferPart.Config, new()
    {
        Order = q => q.OrderBy(x => x.Id),
    });

    public static readonly TransferTable<StatAggregateEntity> StatAggregates = new("stat_aggregate", TransferPart.Stats, new()
    {
        Order = q => q.OrderBy(x => x.Daily).ThenBy(x => x.PeriodStart).ThenBy(x => x.TenantId).ThenBy(x => x.SendingDomain).ThenBy(x => x.RecipientDomain),
    });

    public static readonly TransferTable<StatMetaEntity> StatMeta = new("stat_meta", TransferPart.Stats, new()
    {
        Order = q => q.OrderBy(x => x.Key),
        Upsert = true,
    });

    /// <summary>The ring: exported oldest first; the target assigns new sequence numbers in that order.</summary>
    public static readonly TransferTable<RecentEventEntity> RecentEvents = new("recent_event", TransferPart.Stats, new()
    {
        Order = q => q.OrderBy(x => x.Seq),
        PrepareImport = x => x.Seq = 0,
        CanonicalExcludes = [nameof(RecentEventEntity.Seq)],
    });

    public static readonly TransferTable<WebhookAttemptEntity> WebhookAttempts = new("webhook_attempt", TransferPart.Stats, new()
    {
        Order = q => q.OrderBy(x => x.Seq),
        PrepareImport = x => x.Seq = 0,
        CanonicalExcludes = [nameof(WebhookAttemptEntity.Seq)],
    });

    // A row moves queued: nobody holds a lease on it in the target (the source released them when it quiesced).
    private static void ClearLease(QueuedDeliveryEntity x)
    {
        x.LeaseOwner = null;
        x.LeaseUntil = DateTimeOffset.UnixEpoch;
    }

    private static void ClearLease(WebhookOutboxEntity x)
    {
        x.LeaseOwner = null;
        x.LeaseUntil = DateTimeOffset.UnixEpoch;
    }

    private static void ClearLease(InboundMessageEntity x)
    {
        x.LeaseOwner = null;
        x.LeaseUntil = DateTimeOffset.UnixEpoch;
    }

    public static readonly TransferTable<QueuedDeliveryEntity> Deliveries = new("delivery_queue", TransferPart.Queue, new()
    {
        Order = q => q.OrderBy(x => x.Id),
        PrepareExport = ClearLease,
        PrepareImport = ClearLease,
        Hold = new TransferHold<QueuedDeliveryEntity>
        {
            Property = nameof(QueuedDeliveryEntity.TransferSwitchId),
            Set = (x, id) => x.TransferSwitchId = id,
            HoldAll = (q, id, ct) => q.Where(x => x.TransferSwitchId == null).ExecuteUpdateAsync(s => s.SetProperty(x => x.TransferSwitchId, (Guid?)id), ct),
            Release = (q, id, ct) => q.Where(x => x.TransferSwitchId == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.TransferSwitchId, (Guid?)null), ct),
            CountHeld = (q, id, ct) => q.LongCountAsync(x => x.TransferSwitchId == id, ct),
        },
    });

    public static readonly TransferTable<SpoolMessageEntity> Spool = new("message_spool", TransferPart.Queue, new()
    {
        Order = q => q.OrderBy(x => x.MessageId),
        Body = new TransferBody<SpoolMessageEntity>(nameof(SpoolMessageEntity.Raw), x => x.Raw, (x, v) => x.Raw = v),
    });

    public static readonly TransferTable<WebhookOutboxEntity> WebhookOutbox = new("webhook_outbox", TransferPart.Queue, new()
    {
        Order = q => q.OrderBy(x => x.Id),
        PrepareExport = ClearLease,
        PrepareImport = ClearLease,
        Hold = new TransferHold<WebhookOutboxEntity>
        {
            Property = nameof(WebhookOutboxEntity.TransferSwitchId),
            Set = (x, id) => x.TransferSwitchId = id,
            HoldAll = (q, id, ct) => q.Where(x => x.TransferSwitchId == null).ExecuteUpdateAsync(s => s.SetProperty(x => x.TransferSwitchId, (Guid?)id), ct),
            Release = (q, id, ct) => q.Where(x => x.TransferSwitchId == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.TransferSwitchId, (Guid?)null), ct),
            CountHeld = (q, id, ct) => q.LongCountAsync(x => x.TransferSwitchId == id, ct),
        },
    });

    /// <summary>API idempotency keys are logically configuration (they move in every switch, drain or quiesce) but live in the queue file on SQLite.</summary>
    public static readonly TransferTable<IdempotencyKeyEntity> IdempotencyKeys = new("api_idempotency_key", TransferPart.Queue, new()
    {
        Order = q => q.OrderBy(x => x.TenantId).ThenBy(x => x.IdempotencyKey),
    });

    /// <summary>Received mail and the state of its route action. Held like deliveries, so a pending action runs on exactly one side of a switch.</summary>
    public static readonly TransferTable<InboundMessageEntity> InboundMessages = new("inbound_message", TransferPart.Queue, new()
    {
        Order = q => q.OrderBy(x => x.Id),
        PrepareExport = ClearLease,
        PrepareImport = ClearLease,
        Hold = new TransferHold<InboundMessageEntity>
        {
            Property = nameof(InboundMessageEntity.TransferSwitchId),
            Set = (x, id) => x.TransferSwitchId = id,
            HoldAll = (q, id, ct) => q.Where(x => x.TransferSwitchId == null).ExecuteUpdateAsync(s => s.SetProperty(x => x.TransferSwitchId, (Guid?)id), ct),
            Release = (q, id, ct) => q.Where(x => x.TransferSwitchId == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.TransferSwitchId, (Guid?)null), ct),
            CountHeld = (q, id, ct) => q.LongCountAsync(x => x.TransferSwitchId == id, ct),
        },
    });

    /// <summary>The stored messages; the bytes travel in a body pack like the spool's.</summary>
    public static readonly TransferTable<InboundMessageRawEntity> InboundRaw = new("inbound_message_raw", TransferPart.Queue, new()
    {
        Order = q => q.OrderBy(x => x.MessageId),
        Body = new TransferBody<InboundMessageRawEntity>(nameof(InboundMessageRawEntity.Raw), x => x.Raw, (x, v) => x.Raw = v),
    });

    public static readonly TransferTable<MessageIndexEntity> MessageIndex = new("message_index", TransferPart.History, new()
    {
        Order = q => q.OrderBy(x => x.Day).ThenBy(x => x.MessageId),
        Day = x => x.Day,
    });

    public static readonly TransferTable<MessageRecipientEntity> MessageRecipients = new("message_recipient", TransferPart.History, new()
    {
        Order = q => q.OrderBy(x => x.Day).ThenBy(x => x.MessageId).ThenBy(x => x.Recipient),
        Day = x => x.Day,
    });

    public static readonly TransferTable<MessageEventEntity> MessageEvents = new("message_event", TransferPart.History, new()
    {
        Order = q => q.OrderBy(x => x.Day).ThenBy(x => x.MessageId).ThenBy(x => x.EventId),
        Day = x => x.Day,
    });

    public static readonly TransferTable<MessageContentEntity> MessageContents = new("message_content", TransferPart.History, new()
    {
        Order = q => q.OrderBy(x => x.Day).ThenBy(x => x.MessageId),
        Day = x => x.Day,
    });

    public static readonly TransferTable<RetainedRawEntity> RetainedRaw = new("message_raw_retained", TransferPart.History, new()
    {
        Order = q => q.OrderBy(x => x.Day).ThenBy(x => x.MessageId),
        Day = x => x.Day,
        Body = new TransferBody<RetainedRawEntity>(nameof(RetainedRawEntity.Raw), x => x.Raw, (x, v) => x.Raw = v),
    });

    /// <summary>Every table, in import order (config, stats, queue, history).</summary>
    public static IReadOnlyList<TransferTable> All { get; } =
    [
        Tenants, ApiKeys, SmtpCredentials, DashboardUsers, DashboardSessions, Domains, DkimKeys, Suppressions, WebhookEndpoints, Settings, TlsPolicies, RelayRoutes, Certificates, AcmeAccounts, AcmeRenewals, DomainRecordChecks, TlsRptBuckets, SendingCounters, InboundDomainSettings, InboundRoutes,
        StatAggregates, StatMeta, RecentEvents, WebhookAttempts,
        Deliveries, Spool, WebhookOutbox, IdempotencyKeys, InboundMessages, InboundRaw,
        MessageIndex, MessageRecipients, MessageEvents, MessageContents, RetainedRaw,
    ];

    public static IEnumerable<TransferTable> Of(TransferPart part) => All.Where(t => t.Part == part);

    public static TransferTable ByName(string name) =>
        All.FirstOrDefault(t => string.Equals(t.Name, name, StringComparison.Ordinal)) ?? throw new KeyNotFoundException($"'{name}' is not a transferable table.");
}
