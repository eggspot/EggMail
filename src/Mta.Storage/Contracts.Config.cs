using Mta.Core;

namespace Mta.Storage;

public enum SuppressionReason : byte
{
    HardBounce = 0,
    Complaint,
    Manual,
    Unsubscribe,
}

/// <summary>Domain verification states (design §8).</summary>
public enum DomainStatus : byte
{
    Pending = 0,
    Verifying,
    Verified,
    TemporaryFailure,
    Failed,
}

public sealed record Tenant(Guid Id, string Name, string Slug, bool Enabled, DateTimeOffset CreatedAt, bool StoreAttachments);

public sealed record ApiKeyRecord(Guid Id, Guid TenantId, string Name, string Prefix, byte[] KeyHash, string Scopes, DateTimeOffset CreatedAt, DateTimeOffset? LastUsedAt, DateTimeOffset? RevokedAt);

public sealed record SmtpCredential(Guid Id, Guid TenantId, string UserName, string PasswordHash, bool Enabled, DateTimeOffset CreatedAt);

public sealed record DomainRecord(
    Guid Id,
    Guid TenantId,
    string Name,
    DomainStatus Status,
    string? ReturnPathHost,
    bool ReturnPathVerified,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastCheckedAt,
    DateTimeOffset? NextCheckAt,
    int ConsecutiveFailures,
    DateTimeOffset? TemporaryFailureSince,
    bool SendingPaused,
    string? LastError);

/// <summary>A DKIM key pair. The private key is protected with Data Protection; only <see cref="PrivateKeyProtected"/> is stored.</summary>
public sealed record DkimKeyRecord(
    Guid Id,
    Guid DomainId,
    string Selector,
    byte[] PrivateKeyProtected,
    string PublicKeyBase64,
    DateTimeOffset CreatedAt,
    bool Active,
    DateTimeOffset? RetiredAt);

public sealed record SuppressionRecord(Guid TenantId, string Address, SuppressionReason Reason, string? Source, DateTimeOffset CreatedAt, Guid? MessageId);

public sealed record WebhookEndpointRecord(
    Guid Id,
    Guid TenantId,
    string Url,
    byte[] SecretProtected,
    IReadOnlyList<string> EventTypes,
    bool Enabled,
    string? DisabledReason,
    DateTimeOffset? DisabledAt,
    DateTimeOffset CreatedAt,
    DateTimeOffset? FailingSince);

/// <summary>Role of a dashboard user (docs/api.md): admins see every tenant, tenant users exactly one.</summary>
public enum DashboardRole : byte
{
    Tenant = 0,
    Admin,
}

/// <summary>
/// A person who signs in to the dashboard with a password (HTTP API session cookie). <see cref="TenantId"/> is required for
/// <see cref="DashboardRole.Tenant"/> users and null for admins. User names are unique case-insensitively (stored lower-case).
/// </summary>
public sealed record DashboardUser(Guid Id, string UserName, string PasswordHash, DashboardRole Role, Guid? TenantId, bool Enabled, DateTimeOffset CreatedAt);

/// <summary>
/// A server-side dashboard session. The browser holds a random secret; only its SHA-256 digest (<see cref="IdHash"/>) is stored, so a
/// leaked database cannot be used to take over sessions. <see cref="CsrfToken"/> is the synchronizer token for cookie-authenticated mutations.
/// </summary>
public sealed record DashboardSession(byte[] IdHash, Guid UserId, string CsrfToken, DateTimeOffset CreatedAt, DateTimeOffset LastSeenAt, DateTimeOffset ExpiresAt);

/// <summary>Outcome of a guarded dashboard user write (<see cref="IConfigStore.UpdateDashboardUserGuardedAsync"/>, <see cref="IConfigStore.DeleteDashboardUserGuardedAsync"/>).</summary>
public enum DashboardUserWriteResult : byte
{
    /// <summary>The change was stored.</summary>
    Applied = 0,

    /// <summary>No user has that id.</summary>
    NotFound,

    /// <summary>Nothing was changed: it would have left the installation without an enabled administrator.</summary>
    WouldRemoveLastAdmin,
}

/// <summary>The result of <see cref="IConfigStore.UpdateDashboardUserGuardedAsync"/>: what happened and, when <see cref="DashboardUserWriteResult.Applied"/>, the stored user.</summary>
public readonly record struct DashboardUserUpdate(DashboardUserWriteResult Result, DashboardUser? User);

public sealed record SettingRecord(string Key, Guid? TenantId, string ValueJson, DateTimeOffset UpdatedAt);

public enum TlsLevel : byte
{
    None = 0,
    May,
    Encrypt,
    Verify,
}

public sealed record TlsPolicyRecord(Guid Id, string DomainPattern, TlsLevel Level);

public sealed record RelayRouteRecord(
    Guid Id,
    string Name,
    string Host,
    int Port,
    string TlsMode,
    string? UserName,
    byte[]? PasswordProtected,
    int Priority,
    bool Enabled,
    IReadOnlyList<string> Domains);

public sealed record CertificateRecord(
    Guid Id,
    string Name,
    IReadOnlyList<string> Subjects,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    string ChainPem,
    byte[] PrivateKeyProtected,
    string Source,
    string Thumbprint,
    bool Active,
    long Version,
    DateTimeOffset CreatedAt);

public sealed record AcmeAccountRecord(Guid Id, string DirectoryUrl, string Email, byte[] AccountKeyProtected, string? AccountUrl, DateTimeOffset CreatedAt);

public sealed record AcmeRenewalRecord(
    string CertificateName,
    string Status,
    DateTimeOffset? LastAttemptAt,
    DateTimeOffset? NextAttemptAt,
    int Failures,
    string? LastError,
    string? ChallengeStateJson,
    string? AriJson);

public sealed record LeaseRecord(string Name, string Owner, DateTimeOffset LeaseUntil, long FencingToken);

/// <summary>The last DNS check result of one record a domain must publish. <see cref="RecordKey"/> is <c>TYPE|host</c> (see <c>DomainCheckSnapshot.KeyOf</c>); <see cref="Status"/> is the API word (ok, missing, invalid, pending).</summary>
public sealed record DomainRecordCheckRecord(Guid DomainId, string RecordKey, string Status, string? Found, DateTimeOffset CheckedAt);

/// <summary>One flush of the TLS-RPT collector for one policy domain and UTC day, kept until the report of that day has been sent. <see cref="Day"/> is days since 1970-01-01.</summary>
public sealed record TlsRptBucketRecord(Guid Id, int Day, string PolicyDomain, string DataJson, int Attempts, DateTimeOffset CreatedAt);

/// <summary>
/// A persisted sending counter. <see cref="Scope"/> is 0 global, 1 tenant, 2 sending domain; <see cref="Window"/> is 0 hour, 1 day; <see cref="WindowIndex"/>
/// counts hours or days since the Unix epoch; <see cref="Domain"/> is empty unless the scope is a sending domain. As an argument to
/// <see cref="IRuntimeStateStore.AddSendingCountersAsync"/> <see cref="Count"/> is a delta (it can be negative); as a result it is the stored total.
/// </summary>
public sealed record SendingCounterRecord(byte Scope, Guid TenantId, string Domain, byte Window, long WindowIndex, long Count);

/// <summary>Where a backend switch stands in this store (design §4.6).</summary>
public sealed record SwitchStateRecord(Guid SwitchId, string Role, string State, DateTimeOffset UpdatedAt, string? Detail);

/// <summary>
/// State the running process would otherwise keep in memory only, persisted so a restart (or another replica) sees it: the per-record DNS check
/// results of the domain verification, the TLS-RPT counters and unsent reports, and the sending counters behind the hourly and daily caps. It sits
/// on the config store (one EF implementation for both providers, one in-memory implementation) and moves in a backend switch with the config part.
/// </summary>
public interface IRuntimeStateStore
{
    // Domain verification: the result of the last check of each record

    ValueTask<IReadOnlyList<DomainRecordCheckRecord>> GetDomainRecordChecksAsync(Guid domainId, CancellationToken ct);

    /// <summary>Replaces every stored result of the domain with <paramref name="checks"/> (an empty list clears them).</summary>
    ValueTask ReplaceDomainRecordChecksAsync(Guid domainId, IReadOnlyList<DomainRecordCheckRecord> checks, CancellationToken ct);

    // TLS-RPT: an append-only journal of collector flushes, merged and removed when the day's report is sent

    ValueTask AddTlsRptBucketsAsync(IReadOnlyList<TlsRptBucketRecord> buckets, CancellationToken ct);

    /// <summary>Buckets of days before <paramref name="beforeDay"/> (days since 1970-01-01), oldest day first, then by domain and creation; at most <paramref name="max"/>.</summary>
    ValueTask<IReadOnlyList<TlsRptBucketRecord>> GetTlsRptBucketsAsync(int beforeDay, int max, CancellationToken ct);

    /// <summary>In one transaction deletes the buckets <paramref name="removeIds"/> and inserts <paramref name="replacement"/> (null: only delete). Ids that are already gone are ignored.</summary>
    ValueTask ReplaceTlsRptBucketsAsync(IReadOnlyCollection<Guid> removeIds, TlsRptBucketRecord? replacement, CancellationToken ct);

    // Sending counters

    /// <summary>The stored totals of the hour windows from <paramref name="minHourIndex"/> and the day windows from <paramref name="minDayIndex"/> on.</summary>
    ValueTask<IReadOnlyList<SendingCounterRecord>> GetSendingCountersAsync(long minHourIndex, long minDayIndex, CancellationToken ct);

    /// <summary>
    /// Adds each record's <see cref="SendingCounterRecord.Count"/> (a delta) to the stored total, which never drops below zero, then deletes the windows older
    /// than <paramref name="pruneBeforeHour"/> and <paramref name="pruneBeforeDay"/>. Replicas add their own deltas, so the totals are the sum of all of them.
    /// </summary>
    ValueTask AddSendingCountersAsync(IReadOnlyList<SendingCounterRecord> deltas, long pruneBeforeHour, long pruneBeforeDay, CancellationToken ct);
}

/// <summary>
/// Configuration data: tenants, keys, domains, suppressions, webhook endpoints, settings, TLS state, leases.
/// One implementation over EF for both providers. Secrets arrive here already protected (Data Protection).
/// </summary>
public interface IConfigStore : IRuntimeStateStore
{
    // Tenants and credentials
    ValueTask<IReadOnlyList<Tenant>> GetTenantsAsync(CancellationToken ct);
    ValueTask<Tenant?> GetTenantAsync(Guid id, CancellationToken ct);
    ValueTask<Tenant?> GetTenantBySlugAsync(string slug, CancellationToken ct);
    ValueTask UpsertTenantAsync(Tenant tenant, CancellationToken ct);

    ValueTask<ApiKeyRecord?> FindApiKeyAsync(byte[] keyHash, CancellationToken ct);
    ValueTask<IReadOnlyList<ApiKeyRecord>> GetApiKeysAsync(Guid tenantId, CancellationToken ct);
    ValueTask AddApiKeyAsync(ApiKeyRecord key, CancellationToken ct);
    ValueTask<bool> RevokeApiKeyAsync(Guid tenantId, Guid keyId, DateTimeOffset at, CancellationToken ct);
    ValueTask TouchApiKeyAsync(Guid keyId, DateTimeOffset at, CancellationToken ct);

    ValueTask<SmtpCredential?> FindSmtpCredentialAsync(string userName, CancellationToken ct);
    ValueTask UpsertSmtpCredentialAsync(SmtpCredential credential, CancellationToken ct);
    ValueTask<IReadOnlyList<SmtpCredential>> GetSmtpCredentialsAsync(Guid tenantId, CancellationToken ct);

    /// <summary>Deletes a credential of <paramref name="tenantId"/>; false when there is none with that id for that tenant.</summary>
    ValueTask<bool> DeleteSmtpCredentialAsync(Guid tenantId, Guid credentialId, CancellationToken ct);

    // Dashboard users and sessions (HTTP API sign-in)
    ValueTask<IReadOnlyList<DashboardUser>> GetDashboardUsersAsync(CancellationToken ct);
    ValueTask<DashboardUser?> GetDashboardUserAsync(Guid id, CancellationToken ct);

    /// <summary>Finds a user by user name (case-insensitive).</summary>
    ValueTask<DashboardUser?> FindDashboardUserAsync(string userName, CancellationToken ct);

    /// <summary>Inserts or replaces a user. A user name already used by another user raises <see cref="StorageConflictException"/>.</summary>
    ValueTask UpsertDashboardUserAsync(DashboardUser user, CancellationToken ct);

    /// <summary>Deletes a user and all their sessions.</summary>
    ValueTask<bool> DeleteDashboardUserAsync(Guid id, CancellationToken ct);

    /// <summary>
    /// Applies <paramref name="change"/> to the stored user <paramref name="id"/> (read, change and write are one atomic write, so a concurrent
    /// disable cannot be overwritten by a password change made from an older copy; <paramref name="change"/> must be a pure function of its
    /// argument, it may run more than once, and it must keep the user name and id) with the last-administrator check: when the user is currently an
    /// enabled administrator, the changed user is not, and no other enabled administrator exists, nothing changes and
    /// <see cref="DashboardUserWriteResult.WouldRemoveLastAdmin"/> is returned. Two concurrent calls cannot both succeed, on any backend.
    /// With <paramref name="endSessions"/> the user's sessions are deleted in the same write, except the one whose digest is
    /// <paramref name="keepSessionHash"/>. An unknown id is <see cref="DashboardUserWriteResult.NotFound"/> (nothing is created).
    /// </summary>
    ValueTask<DashboardUserUpdate> UpdateDashboardUserGuardedAsync(Guid id, Func<DashboardUser, DashboardUser> change, bool endSessions, byte[]? keepSessionHash, CancellationToken ct);

    /// <summary>
    /// Deletes a user and the user's sessions with the same last-administrator check as <see cref="UpdateDashboardUserGuardedAsync"/>
    /// (deleting the only enabled administrator changes nothing and returns <see cref="DashboardUserWriteResult.WouldRemoveLastAdmin"/>).
    /// </summary>
    ValueTask<DashboardUserWriteResult> DeleteDashboardUserGuardedAsync(Guid id, CancellationToken ct);

    /// <summary>
    /// Adds <paramref name="session"/> only if the stored user still is the one a sign-in verified: it exists, is enabled and still has
    /// <paramref name="verified"/>'s <see cref="DashboardUser.PasswordHash"/>, <see cref="DashboardUser.Role"/> and <see cref="DashboardUser.TenantId"/>
    /// (check and insert are one write). False, and nothing added, when a password reset, a role or tenant change, a disable or a delete
    /// happened between the verification and now, so a sign-in cannot outlive the change that was meant to end the user's access.
    /// </summary>
    ValueTask<bool> TryAddDashboardSessionForVerifiedUserAsync(DashboardSession session, DashboardUser verified, CancellationToken ct);

    ValueTask AddDashboardSessionAsync(DashboardSession session, CancellationToken ct);
    ValueTask<DashboardSession?> FindDashboardSessionAsync(byte[] idHash, CancellationToken ct);

    /// <summary>Records activity (<see cref="DashboardSession.LastSeenAt"/>).</summary>
    ValueTask TouchDashboardSessionAsync(byte[] idHash, DateTimeOffset lastSeenAt, CancellationToken ct);

    ValueTask<bool> DeleteDashboardSessionAsync(byte[] idHash, CancellationToken ct);

    /// <summary>Signs a user out everywhere (password change, user disabled).</summary>
    ValueTask<int> DeleteDashboardSessionsOfUserAsync(Guid userId, CancellationToken ct);

    /// <summary>Removes sessions whose <see cref="DashboardSession.ExpiresAt"/> is not after <paramref name="now"/>.</summary>
    ValueTask<int> DeleteExpiredDashboardSessionsAsync(DateTimeOffset now, CancellationToken ct);

    // Domains and DKIM
    ValueTask<IReadOnlyList<DomainRecord>> GetDomainsAsync(Guid? tenantId, CancellationToken ct);
    ValueTask<DomainRecord?> GetDomainAsync(Guid domainId, CancellationToken ct);
    ValueTask<DomainRecord?> FindDomainByNameAsync(string name, CancellationToken ct);
    ValueTask UpsertDomainAsync(DomainRecord domain, CancellationToken ct);
    ValueTask<IReadOnlyList<DomainRecord>> GetDomainsDueForCheckAsync(DateTimeOffset now, int max, CancellationToken ct);
    ValueTask DeleteDomainAsync(Guid domainId, CancellationToken ct);

    ValueTask<IReadOnlyList<DkimKeyRecord>> GetDkimKeysAsync(Guid domainId, CancellationToken ct);
    ValueTask AddDkimKeyAsync(DkimKeyRecord key, CancellationToken ct);
    ValueTask SetActiveDkimKeyAsync(Guid domainId, Guid keyId, DateTimeOffset at, CancellationToken ct);

    /// <summary>Deletes a key that never signed (not active, never retired: a rotation that was cancelled). False for any other key or an unknown id.</summary>
    ValueTask<bool> DeletePendingDkimKeyAsync(Guid domainId, Guid keyId, CancellationToken ct);

    // Suppressions
    ValueTask<bool> IsSuppressedAsync(Guid tenantId, string address, CancellationToken ct);
    ValueTask AddSuppressionAsync(SuppressionRecord suppression, CancellationToken ct);
    ValueTask<bool> RemoveSuppressionAsync(Guid tenantId, string address, CancellationToken ct);
    ValueTask<Page<SuppressionRecord>> GetSuppressionsAsync(Guid tenantId, string? cursor, int limit, CancellationToken ct);

    // Webhook endpoints
    ValueTask<IReadOnlyList<WebhookEndpointRecord>> GetWebhookEndpointsAsync(Guid? tenantId, CancellationToken ct);
    ValueTask<WebhookEndpointRecord?> GetWebhookEndpointAsync(Guid id, CancellationToken ct);
    ValueTask UpsertWebhookEndpointAsync(WebhookEndpointRecord endpoint, CancellationToken ct);
    ValueTask DeleteWebhookEndpointAsync(Guid tenantId, Guid id, CancellationToken ct);
    ValueTask DisableWebhookEndpointAsync(Guid id, string reason, DateTimeOffset at, CancellationToken ct);

    // Settings, policies, routes
    ValueTask<IReadOnlyList<SettingRecord>> GetSettingsAsync(Guid? tenantId, CancellationToken ct);
    ValueTask SetSettingAsync(SettingRecord setting, CancellationToken ct);
    ValueTask<IReadOnlyList<TlsPolicyRecord>> GetTlsPoliciesAsync(CancellationToken ct);
    ValueTask UpsertTlsPolicyAsync(TlsPolicyRecord policy, CancellationToken ct);
    ValueTask DeleteTlsPolicyAsync(Guid id, CancellationToken ct);
    ValueTask<IReadOnlyList<RelayRouteRecord>> GetRelayRoutesAsync(CancellationToken ct);
    ValueTask UpsertRelayRouteAsync(RelayRouteRecord route, CancellationToken ct);
    ValueTask DeleteRelayRouteAsync(Guid id, CancellationToken ct);

    // Certificates and ACME (decision K)
    ValueTask<IReadOnlyList<CertificateRecord>> GetCertificatesAsync(CancellationToken ct);

    /// <summary>Highest <see cref="CertificateRecord.Version"/> across certificates (cheap poll for hot reload).</summary>
    ValueTask<long> GetCertificateVersionAsync(CancellationToken ct);

    ValueTask UpsertCertificateAsync(CertificateRecord certificate, CancellationToken ct);
    ValueTask<AcmeAccountRecord?> GetAcmeAccountAsync(string directoryUrl, CancellationToken ct);
    ValueTask UpsertAcmeAccountAsync(AcmeAccountRecord account, CancellationToken ct);
    ValueTask<IReadOnlyList<AcmeRenewalRecord>> GetAcmeRenewalsAsync(CancellationToken ct);
    ValueTask UpsertAcmeRenewalAsync(AcmeRenewalRecord renewal, CancellationToken ct);

    /// <summary>
    /// Sets only <see cref="AcmeRenewalRecord.AriJson"/> of a certificate's renewal row and touches nothing else, so a replica that stores what the CA
    /// advised cannot overwrite the status, failure count or back-off another replica wrote meanwhile. A missing row is created with status <c>issued</c>.
    /// </summary>
    ValueTask SetAcmeRenewalAdviceAsync(string certificateName, string? ariJson, CancellationToken ct);

    /// <summary>
    /// Sets only <see cref="AcmeRenewalRecord.ChallengeStateJson"/> of a certificate's renewal row (the HTTP-01 tokens of the order in flight, which every
    /// replica must be able to answer) and touches nothing else. A missing row is created with status <c>ordering</c>.
    /// </summary>
    ValueTask SetAcmeRenewalChallengeStateAsync(string certificateName, string? challengeStateJson, CancellationToken ct);

    // Leases (renewal lock, singleton jobs) and idempotency
    ValueTask<LeaseRecord?> TryAcquireLeaseAsync(string name, string owner, TimeSpan duration, DateTimeOffset now, CancellationToken ct);
    ValueTask<bool> RenewLeaseAsync(string name, string owner, long fencingToken, TimeSpan duration, DateTimeOffset now, CancellationToken ct);
    ValueTask ReleaseLeaseAsync(string name, string owner, CancellationToken ct);

    // Backend switch state (design §4.6)
    ValueTask<SwitchStateRecord?> GetSwitchStateAsync(CancellationToken ct);
    ValueTask SetSwitchStateAsync(SwitchStateRecord state, CancellationToken ct);
}
