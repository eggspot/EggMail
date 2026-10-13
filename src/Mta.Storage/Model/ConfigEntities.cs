namespace Mta.Storage.Model;

// Entities of the "config" model part (config.db on SQLite). They are the persisted shape of the records in
// Contracts.Config.cs; the mapping lives in ConfigMapping. Secrets columns hold bytes that are already protected
// with Data Protection. There are deliberately no foreign keys: references are soft so cross-file effects,
// imports (Portability) and partial restores never depend on insertion order.

public sealed class TenantEntity
{
    public Guid Id { get; set; }
    public string Name { get; set; } = "";

    /// <summary>Lower-case, unique.</summary>
    public string Slug { get; set; } = "";
    public bool Enabled { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public bool StoreAttachments { get; set; }
}

public sealed class ApiKeyEntity
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public string Name { get; set; } = "";
    public string Prefix { get; set; } = "";

    /// <summary>SHA-256 digest of the key (unique).</summary>
    public byte[] KeyHash { get; set; } = [];
    public string Scopes { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? LastUsedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
}

public sealed class SmtpCredentialEntity
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }

    /// <summary>Unique, case-sensitive.</summary>
    public string UserName { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public bool Enabled { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

public sealed class DashboardUserEntity
{
    public Guid Id { get; set; }

    /// <summary>Lower-case, unique.</summary>
    public string UserName { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public DashboardRole Role { get; set; }
    public Guid? TenantId { get; set; }
    public bool Enabled { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

public sealed class DashboardSessionEntity
{
    /// <summary>SHA-256 digest of the session secret held by the browser (primary key).</summary>
    public byte[] IdHash { get; set; } = [];
    public Guid UserId { get; set; }
    public string CsrfToken { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset LastSeenAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
}

public sealed class DomainEntity
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }

    /// <summary>Lower-case, unique.</summary>
    public string Name { get; set; } = "";
    public DomainStatus Status { get; set; }
    public string? ReturnPathHost { get; set; }
    public bool ReturnPathVerified { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? LastCheckedAt { get; set; }
    public DateTimeOffset? NextCheckAt { get; set; }
    public int ConsecutiveFailures { get; set; }
    public DateTimeOffset? TemporaryFailureSince { get; set; }
    public bool SendingPaused { get; set; }
    public string? LastError { get; set; }
}

public sealed class DkimKeyEntity
{
    public Guid Id { get; set; }
    public Guid DomainId { get; set; }
    public string Selector { get; set; } = "";
    public byte[] PrivateKeyProtected { get; set; } = [];
    public string PublicKeyBase64 { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
    public bool Active { get; set; }
    public DateTimeOffset? RetiredAt { get; set; }
}

public sealed class SuppressionEntity
{
    public Guid TenantId { get; set; }

    /// <summary>Lower-cased address (invariant culture).</summary>
    public string Address { get; set; } = "";
    public SuppressionReason Reason { get; set; }
    public string? Source { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public Guid? MessageId { get; set; }
}

public sealed class WebhookEndpointEntity
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public string Url { get; set; } = "";
    public byte[] SecretProtected { get; set; } = [];

    /// <summary>JSON array of subscribed event types; "*" subscribes to every type.</summary>
    public string EventTypesJson { get; set; } = "[]";
    public bool Enabled { get; set; }
    public string? DisabledReason { get; set; }
    public DateTimeOffset? DisabledAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? FailingSince { get; set; }
}

public sealed class SettingEntity
{
    /// <summary><see cref="Guid.Empty"/> is the global (non-tenant) scope.</summary>
    public Guid TenantId { get; set; }
    public string Key { get; set; } = "";
    public string ValueJson { get; set; } = "";
    public DateTimeOffset UpdatedAt { get; set; }
}

public sealed class TlsPolicyEntity
{
    public Guid Id { get; set; }

    /// <summary>Unique, lower-case.</summary>
    public string DomainPattern { get; set; } = "";
    public TlsLevel Level { get; set; }
}

public sealed class RelayRouteEntity
{
    public Guid Id { get; set; }
    public string Name { get; set; } = "";
    public string Host { get; set; } = "";
    public int Port { get; set; }
    public string TlsMode { get; set; } = "";
    public string? UserName { get; set; }
    public byte[]? PasswordProtected { get; set; }
    public int Priority { get; set; }
    public bool Enabled { get; set; }

    /// <summary>JSON array of recipient domains routed through this relay.</summary>
    public string DomainsJson { get; set; } = "[]";
}

public sealed class CertificateEntity
{
    public Guid Id { get; set; }

    /// <summary>Unique.</summary>
    public string Name { get; set; } = "";

    /// <summary>JSON array of subject alternative names.</summary>
    public string SubjectsJson { get; set; } = "[]";
    public DateTimeOffset NotBefore { get; set; }
    public DateTimeOffset NotAfter { get; set; }
    public string ChainPem { get; set; } = "";
    public byte[] PrivateKeyProtected { get; set; } = [];
    public string Source { get; set; } = "";
    public string Thumbprint { get; set; } = "";
    public bool Active { get; set; }

    /// <summary>Store-assigned, strictly increasing across all certificates (hot-reload poll).</summary>
    public long Version { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

public sealed class AcmeAccountEntity
{
    public Guid Id { get; set; }

    /// <summary>Unique.</summary>
    public string DirectoryUrl { get; set; } = "";
    public string Email { get; set; } = "";
    public byte[] AccountKeyProtected { get; set; } = [];
    public string? AccountUrl { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

public sealed class AcmeRenewalEntity
{
    public string CertificateName { get; set; } = "";
    public string Status { get; set; } = "";
    public DateTimeOffset? LastAttemptAt { get; set; }
    public DateTimeOffset? NextAttemptAt { get; set; }
    public int Failures { get; set; }
    public string? LastError { get; set; }
    public string? ChallengeStateJson { get; set; }
    public string? AriJson { get; set; }
}

/// <summary>The last DNS check result of one expected record of a domain (<c>domain_record_check</c>); the whole set of a domain is replaced by each check.</summary>
public sealed class DomainRecordCheckEntity
{
    public Guid DomainId { get; set; }

    /// <summary><c>TYPE|host</c>, upper-case type and lower-case host.</summary>
    public string RecordKey { get; set; } = "";

    /// <summary>The record status word of the API: ok, missing, invalid or pending.</summary>
    public string Status { get; set; } = "";
    public string? Found { get; set; }
    public DateTimeOffset CheckedAt { get; set; }
}

/// <summary>
/// One flush of the TLS-RPT collector for one policy domain and UTC day (<c>tls_rpt_bucket</c>): an append-only journal, so replicas and
/// restarts never overwrite each other. The report sender merges the rows of a completed day and deletes them once the report is sent.
/// </summary>
public sealed class TlsRptBucketEntity
{
    public Guid Id { get; set; }

    /// <summary>Days since 1970-01-01 (UTC) the sessions belong to.</summary>
    public int Day { get; set; }
    public string PolicyDomain { get; set; } = "";

    /// <summary>The aggregate of the flush (JSON of the policies with their counts and failure lines).</summary>
    public string DataJson { get; set; } = "";

    /// <summary>How many times sending the merged report has failed so far.</summary>
    public int Attempts { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>A sending counter of one scope in one hour or day window (<c>sending_counter</c>); the value is the sum of what every replica flushed.</summary>
public sealed class SendingCounterEntity
{
    /// <summary>0 global, 1 tenant, 2 sending domain.</summary>
    public byte Scope { get; set; }
    public Guid TenantId { get; set; }

    /// <summary>The sending domain for scope 2, otherwise empty (part of the key, so never null).</summary>
    public string Domain { get; set; } = "";

    /// <summary>0 hour, 1 day.</summary>
    public byte WindowKind { get; set; }

    /// <summary>Hours (or days) since the Unix epoch.</summary>
    public long WindowIndex { get; set; }
    public long Count { get; set; }
}

public sealed class LeaseEntity
{
    public string Name { get; set; } = "";
    public string Owner { get; set; } = "";
    public DateTimeOffset LeaseUntil { get; set; }

    /// <summary>Incremented every time the lease changes hands (or is re-acquired after expiry).</summary>
    public long FencingToken { get; set; }
}

public sealed class SwitchStateEntity
{
    /// <summary>Always 1: there is a single row.</summary>
    public int Id { get; set; } = 1;
    public Guid SwitchId { get; set; }
    public string Role { get; set; } = "";
    public string State { get; set; } = "";
    public DateTimeOffset UpdatedAt { get; set; }
    public string? Detail { get; set; }
}
