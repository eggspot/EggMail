using Mta.Storage.Logic;

namespace Mta.Storage.Model;

/// <summary>
/// Maps between the config records of the contracts and their persisted entities. Normalization (lower-casing of slugs,
/// domain names and suppression addresses; millisecond timestamps) happens here so every backend stores identical values.
/// </summary>
public static class ConfigMapping
{
    private static DateTimeOffset N(DateTimeOffset v) => StorageTime.Normalize(v);

    private static DateTimeOffset? N(DateTimeOffset? v) => StorageTime.Normalize(v);

    public static string NormalizeSlug(string slug) => slug.Trim().ToLowerInvariant();

    public static string NormalizeDomain(string name) => name.Trim().TrimEnd('.').ToLowerInvariant();

    public static string NormalizeAddress(string address) => address.Trim().ToLowerInvariant();

    public static TenantEntity ToEntity(this Tenant t) => new()
    {
        Id = t.Id,
        Name = t.Name,
        Slug = NormalizeSlug(t.Slug),
        Enabled = t.Enabled,
        CreatedAt = N(t.CreatedAt),
        StoreAttachments = t.StoreAttachments,
    };

    public static Tenant ToRecord(this TenantEntity e) => new(e.Id, e.Name, e.Slug, e.Enabled, e.CreatedAt, e.StoreAttachments);

    public static ApiKeyEntity ToEntity(this ApiKeyRecord r) => new()
    {
        Id = r.Id,
        TenantId = r.TenantId,
        Name = r.Name,
        Prefix = r.Prefix,
        KeyHash = r.KeyHash,
        Scopes = r.Scopes,
        CreatedAt = N(r.CreatedAt),
        LastUsedAt = N(r.LastUsedAt),
        RevokedAt = N(r.RevokedAt),
    };

    public static ApiKeyRecord ToRecord(this ApiKeyEntity e) => new(e.Id, e.TenantId, e.Name, e.Prefix, e.KeyHash, e.Scopes, e.CreatedAt, e.LastUsedAt, e.RevokedAt);

    public static SmtpCredentialEntity ToEntity(this SmtpCredential c) => new()
    {
        Id = c.Id,
        TenantId = c.TenantId,
        UserName = c.UserName,
        PasswordHash = c.PasswordHash,
        Enabled = c.Enabled,
        CreatedAt = N(c.CreatedAt),
    };

    public static SmtpCredential ToRecord(this SmtpCredentialEntity e) => new(e.Id, e.TenantId, e.UserName, e.PasswordHash, e.Enabled, e.CreatedAt);

    public static DomainEntity ToEntity(this DomainRecord d) => new()
    {
        Id = d.Id,
        TenantId = d.TenantId,
        Name = NormalizeDomain(d.Name),
        Status = d.Status,
        ReturnPathHost = d.ReturnPathHost,
        ReturnPathVerified = d.ReturnPathVerified,
        CreatedAt = N(d.CreatedAt),
        LastCheckedAt = N(d.LastCheckedAt),
        NextCheckAt = N(d.NextCheckAt),
        ConsecutiveFailures = d.ConsecutiveFailures,
        TemporaryFailureSince = N(d.TemporaryFailureSince),
        SendingPaused = d.SendingPaused,
        LastError = d.LastError,
    };

    public static DomainRecord ToRecord(this DomainEntity e) => new(
        e.Id, e.TenantId, e.Name, e.Status, e.ReturnPathHost, e.ReturnPathVerified, e.CreatedAt, e.LastCheckedAt, e.NextCheckAt,
        e.ConsecutiveFailures, e.TemporaryFailureSince, e.SendingPaused, e.LastError);

    public static DkimKeyEntity ToEntity(this DkimKeyRecord k) => new()
    {
        Id = k.Id,
        DomainId = k.DomainId,
        Selector = k.Selector,
        PrivateKeyProtected = k.PrivateKeyProtected,
        PublicKeyBase64 = k.PublicKeyBase64,
        CreatedAt = N(k.CreatedAt),
        Active = k.Active,
        RetiredAt = N(k.RetiredAt),
    };

    public static DkimKeyRecord ToRecord(this DkimKeyEntity e) => new(e.Id, e.DomainId, e.Selector, e.PrivateKeyProtected, e.PublicKeyBase64, e.CreatedAt, e.Active, e.RetiredAt);

    public static SuppressionEntity ToEntity(this SuppressionRecord s) => new()
    {
        TenantId = s.TenantId,
        Address = NormalizeAddress(s.Address),
        Reason = s.Reason,
        Source = s.Source,
        CreatedAt = N(s.CreatedAt),
        MessageId = s.MessageId,
    };

    public static SuppressionRecord ToRecord(this SuppressionEntity e) => new(e.TenantId, e.Address, e.Reason, e.Source, e.CreatedAt, e.MessageId);

    public static WebhookEndpointEntity ToEntity(this WebhookEndpointRecord w) => new()
    {
        Id = w.Id,
        TenantId = w.TenantId,
        Url = w.Url,
        SecretProtected = w.SecretProtected,
        EventTypesJson = StorageJson.SerializeStrings(w.EventTypes),
        Enabled = w.Enabled,
        DisabledReason = w.DisabledReason,
        DisabledAt = N(w.DisabledAt),
        CreatedAt = N(w.CreatedAt),
        FailingSince = N(w.FailingSince),
    };

    public static WebhookEndpointRecord ToRecord(this WebhookEndpointEntity e) => new(
        e.Id, e.TenantId, e.Url, e.SecretProtected, StorageJson.DeserializeStrings(e.EventTypesJson), e.Enabled, e.DisabledReason, e.DisabledAt, e.CreatedAt, e.FailingSince);

    public static SettingEntity ToEntity(this SettingRecord s) => new()
    {
        TenantId = s.TenantId ?? Guid.Empty,
        Key = s.Key,
        ValueJson = s.ValueJson,
        UpdatedAt = N(s.UpdatedAt),
    };

    public static SettingRecord ToRecord(this SettingEntity e) => new(e.Key, e.TenantId == Guid.Empty ? null : e.TenantId, e.ValueJson, e.UpdatedAt);

    public static TlsPolicyEntity ToEntity(this TlsPolicyRecord p) => new() { Id = p.Id, DomainPattern = p.DomainPattern.Trim().ToLowerInvariant(), Level = p.Level };

    public static TlsPolicyRecord ToRecord(this TlsPolicyEntity e) => new(e.Id, e.DomainPattern, e.Level);

    public static RelayRouteEntity ToEntity(this RelayRouteRecord r) => new()
    {
        Id = r.Id,
        Name = r.Name,
        Host = r.Host,
        Port = r.Port,
        TlsMode = r.TlsMode,
        UserName = r.UserName,
        PasswordProtected = r.PasswordProtected,
        Priority = r.Priority,
        Enabled = r.Enabled,
        DomainsJson = StorageJson.SerializeStrings(r.Domains),
    };

    public static RelayRouteRecord ToRecord(this RelayRouteEntity e) => new(
        e.Id, e.Name, e.Host, e.Port, e.TlsMode, e.UserName, e.PasswordProtected, e.Priority, e.Enabled, StorageJson.DeserializeStrings(e.DomainsJson));

    public static CertificateEntity ToEntity(this CertificateRecord c) => new()
    {
        Id = c.Id,
        Name = c.Name,
        SubjectsJson = StorageJson.SerializeStrings(c.Subjects),
        NotBefore = N(c.NotBefore),
        NotAfter = N(c.NotAfter),
        ChainPem = c.ChainPem,
        PrivateKeyProtected = c.PrivateKeyProtected,
        Source = c.Source,
        Thumbprint = c.Thumbprint,
        Active = c.Active,
        Version = c.Version,
        CreatedAt = N(c.CreatedAt),
    };

    public static CertificateRecord ToRecord(this CertificateEntity e) => new(
        e.Id, e.Name, StorageJson.DeserializeStrings(e.SubjectsJson), e.NotBefore, e.NotAfter, e.ChainPem, e.PrivateKeyProtected, e.Source, e.Thumbprint, e.Active, e.Version, e.CreatedAt);

    public static AcmeAccountEntity ToEntity(this AcmeAccountRecord a) => new()
    {
        Id = a.Id,
        DirectoryUrl = a.DirectoryUrl,
        Email = a.Email,
        AccountKeyProtected = a.AccountKeyProtected,
        AccountUrl = a.AccountUrl,
        CreatedAt = N(a.CreatedAt),
    };

    public static AcmeAccountRecord ToRecord(this AcmeAccountEntity e) => new(e.Id, e.DirectoryUrl, e.Email, e.AccountKeyProtected, e.AccountUrl, e.CreatedAt);

    public static AcmeRenewalEntity ToEntity(this AcmeRenewalRecord r) => new()
    {
        CertificateName = r.CertificateName,
        Status = r.Status,
        LastAttemptAt = N(r.LastAttemptAt),
        NextAttemptAt = N(r.NextAttemptAt),
        Failures = r.Failures,
        LastError = r.LastError,
        ChallengeStateJson = r.ChallengeStateJson,
        AriJson = r.AriJson,
    };

    public static AcmeRenewalRecord ToRecord(this AcmeRenewalEntity e) => new(e.CertificateName, e.Status, e.LastAttemptAt, e.NextAttemptAt, e.Failures, e.LastError, e.ChallengeStateJson, e.AriJson);

    public static LeaseRecord ToRecord(this LeaseEntity e) => new(e.Name, e.Owner, e.LeaseUntil, e.FencingToken);

    public static SwitchStateEntity ToEntity(this SwitchStateRecord s) => new()
    {
        Id = 1,
        SwitchId = s.SwitchId,
        Role = s.Role,
        State = s.State,
        UpdatedAt = N(s.UpdatedAt),
        Detail = s.Detail,
    };

    public static SwitchStateRecord ToRecord(this SwitchStateEntity e) => new(e.SwitchId, e.Role, e.State, e.UpdatedAt, e.Detail);
}
