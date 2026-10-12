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

/// <summary>Where a backend switch stands in this store (design §4.6).</summary>
public sealed record SwitchStateRecord(Guid SwitchId, string Role, string State, DateTimeOffset UpdatedAt, string? Detail);

/// <summary>
/// Configuration data: tenants, keys, domains, suppressions, webhook endpoints, settings, TLS state, leases.
/// One implementation over EF for both providers. Secrets arrive here already protected (Data Protection).
/// </summary>
public interface IConfigStore
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

    // Leases (renewal lock, singleton jobs) and idempotency
    ValueTask<LeaseRecord?> TryAcquireLeaseAsync(string name, string owner, TimeSpan duration, DateTimeOffset now, CancellationToken ct);
    ValueTask<bool> RenewLeaseAsync(string name, string owner, long fencingToken, TimeSpan duration, DateTimeOffset now, CancellationToken ct);
    ValueTask ReleaseLeaseAsync(string name, string owner, CancellationToken ct);

    // Backend switch state (design §4.6)
    ValueTask<SwitchStateRecord?> GetSwitchStateAsync(CancellationToken ct);
    ValueTask SetSwitchStateAsync(SwitchStateRecord state, CancellationToken ct);
}
