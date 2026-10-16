using Mta.Storage.Logic;
using Mta.Storage.Model;
using Mta.Storage.Transfer;

namespace Mta.Storage.InMemory;

/// <summary>In-memory <see cref="IConfigStore"/>; same semantics as the EF implementation (normalization, uniqueness, leases).</summary>
internal sealed partial class InMemoryConfigStore : IConfigStore, IInboundConfigStore
{
    private readonly object _gate = new();
    private readonly Dictionary<Guid, TenantEntity> _tenants = [];
    private readonly Dictionary<Guid, ApiKeyEntity> _apiKeys = [];
    private readonly Dictionary<Guid, SmtpCredentialEntity> _smtp = [];
    private readonly Dictionary<Guid, DashboardUserEntity> _dashboardUsers = [];
    private readonly List<DashboardSessionEntity> _dashboardSessions = [];
    private readonly Dictionary<Guid, DomainEntity> _domains = [];
    private readonly Dictionary<Guid, DkimKeyEntity> _dkim = [];
    private readonly Dictionary<(Guid, string), SuppressionEntity> _suppressions = [];
    private readonly Dictionary<Guid, WebhookEndpointEntity> _endpoints = [];
    private readonly Dictionary<(Guid, string), SettingEntity> _settings = [];
    private readonly Dictionary<Guid, TlsPolicyEntity> _tls = [];
    private readonly Dictionary<Guid, RelayRouteEntity> _relays = [];
    private readonly Dictionary<Guid, CertificateEntity> _certs = [];
    private readonly Dictionary<Guid, AcmeAccountEntity> _acmeAccounts = [];
    private readonly Dictionary<string, AcmeRenewalEntity> _renewals = [];
    private readonly Dictionary<string, LeaseEntity> _leases = [];
    private readonly Dictionary<(Guid, string), DomainRecordCheckEntity> _domainChecks = [];
    private readonly Dictionary<Guid, TlsRptBucketEntity> _tlsRpt = [];
    private readonly Dictionary<(byte, Guid, string, byte, long), SendingCounterEntity> _counters = [];
    private SwitchStateEntity? _switch;

    private static ValueTask<T> R<T>(T value) => ValueTask.FromResult(value);

    private static StorageConflictException Conflict(string what) => new($"Unique constraint violated: {what}.");

    // Tenants and credentials

    public ValueTask<IReadOnlyList<Tenant>> GetTenantsAsync(CancellationToken ct)
    {
        lock (_gate)
        {
            return R<IReadOnlyList<Tenant>>(_tenants.Values.OrderBy(t => t.Name, StringComparer.Ordinal).ThenBy(t => t.Id).Select(t => t.ToRecord()).ToList());
        }
    }

    public ValueTask<Tenant?> GetTenantAsync(Guid id, CancellationToken ct)
    {
        lock (_gate)
        {
            return R(_tenants.TryGetValue(id, out var t) ? t.ToRecord() : null);
        }
    }

    public ValueTask<Tenant?> GetTenantBySlugAsync(string slug, CancellationToken ct)
    {
        string s = ConfigMapping.NormalizeSlug(slug);
        lock (_gate)
        {
            return R(_tenants.Values.FirstOrDefault(t => t.Slug == s)?.ToRecord());
        }
    }

    public ValueTask UpsertTenantAsync(Tenant tenant, CancellationToken ct)
    {
        var e = tenant.ToEntity();
        lock (_gate)
        {
            if (_tenants.Values.Any(t => t.Slug == e.Slug && t.Id != e.Id))
            {
                throw Conflict("tenant.slug");
            }

            _tenants[e.Id] = e;
        }

        return default;
    }

    public ValueTask<ApiKeyRecord?> FindApiKeyAsync(byte[] keyHash, CancellationToken ct)
    {
        lock (_gate)
        {
            return R(_apiKeys.Values.FirstOrDefault(k => k.KeyHash.AsSpan().SequenceEqual(keyHash))?.ToRecord());
        }
    }

    public ValueTask<IReadOnlyList<ApiKeyRecord>> GetApiKeysAsync(Guid tenantId, CancellationToken ct)
    {
        lock (_gate)
        {
            return R<IReadOnlyList<ApiKeyRecord>>(_apiKeys.Values.Where(k => k.TenantId == tenantId).OrderBy(k => k.CreatedAt).ThenBy(k => k.Id).Select(k => k.ToRecord()).ToList());
        }
    }

    public ValueTask AddApiKeyAsync(ApiKeyRecord key, CancellationToken ct)
    {
        var e = key.ToEntity();
        lock (_gate)
        {
            if (_apiKeys.ContainsKey(e.Id) || _apiKeys.Values.Any(k => k.KeyHash.AsSpan().SequenceEqual(e.KeyHash)))
            {
                throw Conflict("api_key");
            }

            _apiKeys[e.Id] = e;
        }

        return default;
    }

    public ValueTask<bool> RevokeApiKeyAsync(Guid tenantId, Guid keyId, DateTimeOffset at, CancellationToken ct)
    {
        lock (_gate)
        {
            if (_apiKeys.TryGetValue(keyId, out var k) && k.TenantId == tenantId && k.RevokedAt is null)
            {
                k.RevokedAt = StorageTime.Normalize(at);
                return R(true);
            }

            return R(false);
        }
    }

    public ValueTask TouchApiKeyAsync(Guid keyId, DateTimeOffset at, CancellationToken ct)
    {
        lock (_gate)
        {
            if (_apiKeys.TryGetValue(keyId, out var k))
            {
                k.LastUsedAt = StorageTime.Normalize(at);
            }
        }

        return default;
    }

    public ValueTask<SmtpCredential?> FindSmtpCredentialAsync(string userName, CancellationToken ct)
    {
        lock (_gate)
        {
            return R(_smtp.Values.FirstOrDefault(c => c.UserName == userName)?.ToRecord());
        }
    }

    public ValueTask UpsertSmtpCredentialAsync(SmtpCredential credential, CancellationToken ct)
    {
        var e = credential.ToEntity();
        lock (_gate)
        {
            if (_smtp.Values.Any(c => c.UserName == e.UserName && c.Id != e.Id))
            {
                throw Conflict("smtp_credential.user_name");
            }

            _smtp[e.Id] = e;
        }

        return default;
    }

    public ValueTask<IReadOnlyList<SmtpCredential>> GetSmtpCredentialsAsync(Guid tenantId, CancellationToken ct)
    {
        lock (_gate)
        {
            return R<IReadOnlyList<SmtpCredential>>(_smtp.Values.Where(c => c.TenantId == tenantId).OrderBy(c => c.UserName, StringComparer.Ordinal).Select(c => c.ToRecord()).ToList());
        }
    }

    public ValueTask<bool> DeleteSmtpCredentialAsync(Guid tenantId, Guid credentialId, CancellationToken ct)
    {
        lock (_gate)
        {
            return R(_smtp.TryGetValue(credentialId, out var c) && c.TenantId == tenantId && _smtp.Remove(credentialId));
        }
    }

    // Dashboard users and sessions

    public ValueTask<IReadOnlyList<DashboardUser>> GetDashboardUsersAsync(CancellationToken ct)
    {
        lock (_gate)
        {
            return R<IReadOnlyList<DashboardUser>>(_dashboardUsers.Values.OrderBy(u => u.UserName, StringComparer.Ordinal).Select(u => u.ToRecord()).ToList());
        }
    }

    public ValueTask<DashboardUser?> GetDashboardUserAsync(Guid id, CancellationToken ct)
    {
        lock (_gate)
        {
            return R(_dashboardUsers.TryGetValue(id, out var u) ? u.ToRecord() : null);
        }
    }

    public ValueTask<DashboardUser?> FindDashboardUserAsync(string userName, CancellationToken ct)
    {
        string n = ConfigMapping.NormalizeUserName(userName);
        lock (_gate)
        {
            return R(_dashboardUsers.Values.FirstOrDefault(u => u.UserName == n)?.ToRecord());
        }
    }

    public ValueTask UpsertDashboardUserAsync(DashboardUser user, CancellationToken ct)
    {
        var e = user.ToEntity();
        lock (_gate)
        {
            if (_dashboardUsers.Values.Any(u => u.UserName == e.UserName && u.Id != e.Id))
            {
                throw Conflict("dashboard_user.user_name");
            }

            _dashboardUsers[e.Id] = e;
        }

        return default;
    }

    public ValueTask<bool> DeleteDashboardUserAsync(Guid id, CancellationToken ct)
    {
        lock (_gate)
        {
            _dashboardSessions.RemoveAll(s => s.UserId == id);
            return R(_dashboardUsers.Remove(id));
        }
    }

    public ValueTask<DashboardUserUpdate> UpdateDashboardUserGuardedAsync(Guid id, Func<DashboardUser, DashboardUser> change, bool endSessions, byte[]? keepSessionHash, CancellationToken ct)
    {
        lock (_gate)
        {
            if (!_dashboardUsers.TryGetValue(id, out var current))
            {
                return R(new DashboardUserUpdate(DashboardUserWriteResult.NotFound, null));
            }

            var e = (change(current.ToRecord()) with { Id = id }).ToEntity();
            bool isEnabledAdmin = current.Role == DashboardRole.Admin && current.Enabled;
            bool staysEnabledAdmin = e.Role == DashboardRole.Admin && e.Enabled;
            if (isEnabledAdmin && !staysEnabledAdmin && !_dashboardUsers.Values.Any(u => u.Id != id && u.Role == DashboardRole.Admin && u.Enabled))
            {
                return R(new DashboardUserUpdate(DashboardUserWriteResult.WouldRemoveLastAdmin, null));
            }

            if (_dashboardUsers.Values.Any(u => u.UserName == e.UserName && u.Id != id))
            {
                throw Conflict("dashboard_user.user_name");
            }

            _dashboardUsers[id] = e;
            if (endSessions)
            {
                _dashboardSessions.RemoveAll(s => s.UserId == id && (keepSessionHash is null || !s.IdHash.AsSpan().SequenceEqual(keepSessionHash)));
            }

            return R(new DashboardUserUpdate(DashboardUserWriteResult.Applied, e.ToRecord()));
        }
    }

    public ValueTask<DashboardUserWriteResult> DeleteDashboardUserGuardedAsync(Guid id, CancellationToken ct)
    {
        lock (_gate)
        {
            if (!_dashboardUsers.TryGetValue(id, out var current))
            {
                return R(DashboardUserWriteResult.NotFound);
            }

            if (current.Role == DashboardRole.Admin && current.Enabled && !_dashboardUsers.Values.Any(u => u.Id != id && u.Role == DashboardRole.Admin && u.Enabled))
            {
                return R(DashboardUserWriteResult.WouldRemoveLastAdmin);
            }

            _dashboardSessions.RemoveAll(s => s.UserId == id);
            _dashboardUsers.Remove(id);
            return R(DashboardUserWriteResult.Applied);
        }
    }

    public ValueTask<bool> TryAddDashboardSessionForVerifiedUserAsync(DashboardSession session, DashboardUser verified, CancellationToken ct)
    {
        var e = session.ToEntity();
        lock (_gate)
        {
            if (!_dashboardUsers.TryGetValue(verified.Id, out var current) || !current.Enabled || current.PasswordHash != verified.PasswordHash
                || current.Role != verified.Role || current.TenantId != verified.TenantId)
            {
                return R(false);
            }

            if (_dashboardSessions.Any(s => s.IdHash.AsSpan().SequenceEqual(e.IdHash)))
            {
                throw Conflict("dashboard_session");
            }

            _dashboardSessions.Add(e);
            return R(true);
        }
    }

    public ValueTask AddDashboardSessionAsync(DashboardSession session, CancellationToken ct)
    {
        var e = session.ToEntity();
        lock (_gate)
        {
            if (_dashboardSessions.Any(s => s.IdHash.AsSpan().SequenceEqual(e.IdHash)))
            {
                throw Conflict("dashboard_session");
            }

            _dashboardSessions.Add(e);
        }

        return default;
    }

    public ValueTask<DashboardSession?> FindDashboardSessionAsync(byte[] idHash, CancellationToken ct)
    {
        lock (_gate)
        {
            return R(_dashboardSessions.FirstOrDefault(s => s.IdHash.AsSpan().SequenceEqual(idHash))?.ToRecord());
        }
    }

    public ValueTask TouchDashboardSessionAsync(byte[] idHash, DateTimeOffset lastSeenAt, CancellationToken ct)
    {
        lock (_gate)
        {
            var s = _dashboardSessions.FirstOrDefault(x => x.IdHash.AsSpan().SequenceEqual(idHash));
            if (s is not null)
            {
                s.LastSeenAt = StorageTime.Normalize(lastSeenAt);
            }
        }

        return default;
    }

    public ValueTask<bool> DeleteDashboardSessionAsync(byte[] idHash, CancellationToken ct)
    {
        lock (_gate)
        {
            return R(_dashboardSessions.RemoveAll(s => s.IdHash.AsSpan().SequenceEqual(idHash)) > 0);
        }
    }

    public ValueTask<int> DeleteDashboardSessionsOfUserAsync(Guid userId, CancellationToken ct)
    {
        lock (_gate)
        {
            return R(_dashboardSessions.RemoveAll(s => s.UserId == userId));
        }
    }

    public ValueTask<int> DeleteExpiredDashboardSessionsAsync(DateTimeOffset now, CancellationToken ct)
    {
        DateTimeOffset n = StorageTime.Normalize(now);
        lock (_gate)
        {
            return R(_dashboardSessions.RemoveAll(s => s.ExpiresAt <= n));
        }
    }

    // Domains and DKIM

    public ValueTask<IReadOnlyList<DomainRecord>> GetDomainsAsync(Guid? tenantId, CancellationToken ct)
    {
        lock (_gate)
        {
            return R<IReadOnlyList<DomainRecord>>(_domains.Values.Where(d => tenantId is null || d.TenantId == tenantId).OrderBy(d => d.Name, StringComparer.Ordinal).Select(d => d.ToRecord()).ToList());
        }
    }

    public ValueTask<DomainRecord?> GetDomainAsync(Guid domainId, CancellationToken ct)
    {
        lock (_gate)
        {
            return R(_domains.TryGetValue(domainId, out var d) ? d.ToRecord() : null);
        }
    }

    public ValueTask<DomainRecord?> FindDomainByNameAsync(string name, CancellationToken ct)
    {
        string n = ConfigMapping.NormalizeDomain(name);
        lock (_gate)
        {
            return R(_domains.Values.FirstOrDefault(d => d.Name == n)?.ToRecord());
        }
    }

    public ValueTask UpsertDomainAsync(DomainRecord domain, CancellationToken ct)
    {
        var e = domain.ToEntity();
        lock (_gate)
        {
            if (_domains.Values.Any(d => d.Name == e.Name && d.Id != e.Id))
            {
                throw Conflict("domain.name");
            }

            _domains[e.Id] = e;
        }

        return default;
    }

    public ValueTask<IReadOnlyList<DomainRecord>> GetDomainsDueForCheckAsync(DateTimeOffset now, int max, CancellationToken ct)
    {
        lock (_gate)
        {
            return R<IReadOnlyList<DomainRecord>>(_domains.Values.Where(d => d.NextCheckAt is { } n && n <= now).OrderBy(d => d.NextCheckAt).ThenBy(d => d.Name, StringComparer.Ordinal).Take(max).Select(d => d.ToRecord()).ToList());
        }
    }

    public ValueTask DeleteDomainAsync(Guid domainId, CancellationToken ct)
    {
        lock (_gate)
        {
            _domains.Remove(domainId);
            foreach (var k in _domainChecks.Keys.Where(k => k.Item1 == domainId).ToList())
            {
                _domainChecks.Remove(k);
            }

            foreach (var k in _dkim.Values.Where(k => k.DomainId == domainId).ToList())
            {
                _dkim.Remove(k.Id);
            }

            foreach (var r in _inboundRoutes.Values.Where(r => r.DomainId == domainId).ToList())
            {
                _inboundRoutes.Remove(r.Id);
            }

            _inboundSettings.Remove(domainId);
        }

        return default;
    }

    public ValueTask<IReadOnlyList<DkimKeyRecord>> GetDkimKeysAsync(Guid domainId, CancellationToken ct)
    {
        lock (_gate)
        {
            return R<IReadOnlyList<DkimKeyRecord>>(_dkim.Values.Where(k => k.DomainId == domainId).OrderBy(k => k.CreatedAt).ThenBy(k => k.Id).Select(k => k.ToRecord()).ToList());
        }
    }

    public ValueTask AddDkimKeyAsync(DkimKeyRecord key, CancellationToken ct)
    {
        var e = key.ToEntity();
        lock (_gate)
        {
            if (!_dkim.TryAdd(e.Id, e))
            {
                throw Conflict("dkim_key");
            }
        }

        return default;
    }

    public ValueTask<bool> DeletePendingDkimKeyAsync(Guid domainId, Guid keyId, CancellationToken ct)
    {
        lock (_gate)
        {
            return R(_dkim.TryGetValue(keyId, out var k) && k.DomainId == domainId && !k.Active && k.RetiredAt is null && _dkim.Remove(keyId));
        }
    }

    public ValueTask SetActiveDkimKeyAsync(Guid domainId, Guid keyId, DateTimeOffset at, CancellationToken ct)
    {
        lock (_gate)
        {
            if (!_dkim.TryGetValue(keyId, out var target) || target.DomainId != domainId)
            {
                throw new KeyNotFoundException($"DKIM key {keyId} does not belong to domain {domainId}.");
            }

            DateTimeOffset when = StorageTime.Normalize(at);
            foreach (var k in _dkim.Values.Where(k => k.DomainId == domainId && k.Id != keyId && k.Active))
            {
                k.Active = false;
                k.RetiredAt ??= when;
            }

            target.Active = true;
            target.RetiredAt = null;
        }

        return default;
    }

    // Suppressions

    public ValueTask<bool> IsSuppressedAsync(Guid tenantId, string address, CancellationToken ct)
    {
        lock (_gate)
        {
            return R(_suppressions.ContainsKey((tenantId, ConfigMapping.NormalizeAddress(address))));
        }
    }

    public ValueTask AddSuppressionAsync(SuppressionRecord suppression, CancellationToken ct)
    {
        AddSuppressionCore(suppression);
        return default;
    }

    internal void AddSuppressionCore(SuppressionRecord suppression)
    {
        var e = suppression.ToEntity();
        lock (_gate)
        {
            _suppressions[(e.TenantId, e.Address)] = e;
        }
    }

    public ValueTask<bool> RemoveSuppressionAsync(Guid tenantId, string address, CancellationToken ct)
    {
        lock (_gate)
        {
            return R(_suppressions.Remove((tenantId, ConfigMapping.NormalizeAddress(address))));
        }
    }

    public ValueTask<Page<SuppressionRecord>> GetSuppressionsAsync(Guid tenantId, string? cursor, int limit, CancellationToken ct)
    {
        limit = Math.Clamp(limit, 1, 1000);
        string? after = Cursors.TryDecode(cursor, out string c) ? c : null;
        lock (_gate)
        {
            var rows = _suppressions.Values
                .Where(s => s.TenantId == tenantId && (after is null || string.CompareOrdinal(s.Address, after) > 0))
                .OrderBy(s => s.Address, StringComparer.Ordinal)
                .Take(limit + 1)
                .ToList();
            bool more = rows.Count > limit;
            if (more)
            {
                rows.RemoveAt(rows.Count - 1);
            }

            return R(new Page<SuppressionRecord>(rows.Select(r => r.ToRecord()).ToList(), more ? Cursors.Encode(rows[^1].Address) : null));
        }
    }

    // Webhook endpoints

    public ValueTask<IReadOnlyList<WebhookEndpointRecord>> GetWebhookEndpointsAsync(Guid? tenantId, CancellationToken ct)
    {
        lock (_gate)
        {
            return R<IReadOnlyList<WebhookEndpointRecord>>(_endpoints.Values.Where(w => tenantId is null || w.TenantId == tenantId).OrderBy(w => w.CreatedAt).ThenBy(w => w.Id).Select(w => w.ToRecord()).ToList());
        }
    }

    public ValueTask<WebhookEndpointRecord?> GetWebhookEndpointAsync(Guid id, CancellationToken ct)
    {
        lock (_gate)
        {
            return R(_endpoints.TryGetValue(id, out var w) ? w.ToRecord() : null);
        }
    }

    public ValueTask UpsertWebhookEndpointAsync(WebhookEndpointRecord endpoint, CancellationToken ct)
    {
        lock (_gate)
        {
            _endpoints[endpoint.Id] = endpoint.ToEntity();
        }

        return default;
    }

    public ValueTask DeleteWebhookEndpointAsync(Guid tenantId, Guid id, CancellationToken ct)
    {
        lock (_gate)
        {
            if (_endpoints.TryGetValue(id, out var w) && w.TenantId == tenantId)
            {
                if (_inboundRoutes.Values.Any(r => r.ActionKind == InboundActionKind.Webhook && r.WebhookEndpointId == id))
                {
                    throw new StorageConflictException("The webhook endpoint is the target of inbound routes.");
                }

                _endpoints.Remove(id);
            }
        }

        return default;
    }

    public ValueTask<bool> DisableWebhookEndpointAsync(Guid id, string reason, DateTimeOffset at, CancellationToken ct)
    {
        lock (_gate)
        {
            if (_endpoints.TryGetValue(id, out var w) && w.Enabled)
            {
                w.Enabled = false;
                w.DisabledReason = reason;
                w.DisabledAt = StorageTime.Normalize(at);
                return ValueTask.FromResult(true);
            }
        }

        return ValueTask.FromResult(false);
    }

    /// <summary>Enabled endpoints of a tenant that subscribe to an event type (used by webhook fan-out).</summary>
    internal List<Guid> EndpointsFor(Guid tenantId, string eventType)
    {
        lock (_gate)
        {
            return _endpoints.Values
                .Where(w => w.TenantId == tenantId && w.Enabled && WebhookSubscriptions.Matches(StorageJson.DeserializeStrings(w.EventTypesJson), eventType))
                .OrderBy(w => w.CreatedAt).ThenBy(w => w.Id)
                .Select(w => w.Id)
                .ToList();
        }
    }

    /// <summary>Whether <see cref="EndpointsFor"/> would find an endpoint, without building the list.</summary>
    internal bool HasEndpointFor(Guid tenantId, string eventType)
    {
        lock (_gate)
        {
            foreach (var w in _endpoints.Values)
            {
                if (w.TenantId == tenantId && w.Enabled && WebhookSubscriptions.Matches(StorageJson.DeserializeStrings(w.EventTypesJson), eventType))
                {
                    return true;
                }
            }

            return false;
        }
    }

    internal bool IsEnabledEndpointOf(Guid tenantId, Guid endpointId)
    {
        lock (_gate)
        {
            return _endpoints.TryGetValue(endpointId, out var w) && w.TenantId == tenantId && w.Enabled;
        }
    }

    // Settings, policies, routes

    public ValueTask<IReadOnlyList<SettingRecord>> GetSettingsAsync(Guid? tenantId, CancellationToken ct)
    {
        Guid scope = tenantId ?? Guid.Empty;
        lock (_gate)
        {
            return R<IReadOnlyList<SettingRecord>>(_settings.Values.Where(s => s.TenantId == scope).OrderBy(s => s.Key, StringComparer.Ordinal).Select(s => s.ToRecord()).ToList());
        }
    }

    public ValueTask SetSettingAsync(SettingRecord setting, CancellationToken ct)
    {
        var e = setting.ToEntity();
        lock (_gate)
        {
            _settings[(e.TenantId, e.Key)] = e;
        }

        return default;
    }

    public ValueTask<IReadOnlyList<TlsPolicyRecord>> GetTlsPoliciesAsync(CancellationToken ct)
    {
        lock (_gate)
        {
            return R<IReadOnlyList<TlsPolicyRecord>>(_tls.Values.OrderBy(t => t.DomainPattern, StringComparer.Ordinal).Select(t => t.ToRecord()).ToList());
        }
    }

    public ValueTask UpsertTlsPolicyAsync(TlsPolicyRecord policy, CancellationToken ct)
    {
        var e = policy.ToEntity();
        lock (_gate)
        {
            if (_tls.Values.Any(t => t.DomainPattern == e.DomainPattern && t.Id != e.Id))
            {
                throw Conflict("tls_policy.domain_pattern");
            }

            _tls[e.Id] = e;
        }

        return default;
    }

    public ValueTask DeleteTlsPolicyAsync(Guid id, CancellationToken ct)
    {
        lock (_gate)
        {
            _tls.Remove(id);
        }

        return default;
    }

    public ValueTask<IReadOnlyList<RelayRouteRecord>> GetRelayRoutesAsync(CancellationToken ct)
    {
        lock (_gate)
        {
            return R<IReadOnlyList<RelayRouteRecord>>(_relays.Values.OrderBy(r => r.Priority).ThenBy(r => r.Name, StringComparer.Ordinal).ThenBy(r => r.Id).Select(r => r.ToRecord()).ToList());
        }
    }

    public ValueTask UpsertRelayRouteAsync(RelayRouteRecord route, CancellationToken ct)
    {
        lock (_gate)
        {
            _relays[route.Id] = route.ToEntity();
        }

        return default;
    }

    public ValueTask DeleteRelayRouteAsync(Guid id, CancellationToken ct)
    {
        lock (_gate)
        {
            _relays.Remove(id);
        }

        return default;
    }

    // Certificates and ACME

    public ValueTask<IReadOnlyList<CertificateRecord>> GetCertificatesAsync(CancellationToken ct)
    {
        lock (_gate)
        {
            return R<IReadOnlyList<CertificateRecord>>(_certs.Values.OrderBy(c => c.Name, StringComparer.Ordinal).Select(c => c.ToRecord()).ToList());
        }
    }

    public ValueTask<long> GetCertificateVersionAsync(CancellationToken ct)
    {
        lock (_gate)
        {
            return R(_certs.Count == 0 ? 0L : _certs.Values.Max(c => c.Version));
        }
    }

    public ValueTask UpsertCertificateAsync(CertificateRecord certificate, CancellationToken ct)
    {
        var e = certificate.ToEntity();
        lock (_gate)
        {
            if (_certs.Values.Any(c => c.Name == e.Name && c.Id != e.Id))
            {
                throw Conflict("certificate.name");
            }

            e.Version = (_certs.Count == 0 ? 0L : _certs.Values.Max(c => c.Version)) + 1;
            _certs[e.Id] = e;
        }

        return default;
    }

    public ValueTask<AcmeAccountRecord?> GetAcmeAccountAsync(string directoryUrl, CancellationToken ct)
    {
        lock (_gate)
        {
            return R(_acmeAccounts.Values.FirstOrDefault(a => a.DirectoryUrl == directoryUrl)?.ToRecord());
        }
    }

    public ValueTask UpsertAcmeAccountAsync(AcmeAccountRecord account, CancellationToken ct)
    {
        var e = account.ToEntity();
        lock (_gate)
        {
            if (_acmeAccounts.Values.Any(a => a.DirectoryUrl == e.DirectoryUrl && a.Id != e.Id))
            {
                throw Conflict("acme_account.directory_url");
            }

            _acmeAccounts[e.Id] = e;
        }

        return default;
    }

    public ValueTask<IReadOnlyList<AcmeRenewalRecord>> GetAcmeRenewalsAsync(CancellationToken ct)
    {
        lock (_gate)
        {
            return R<IReadOnlyList<AcmeRenewalRecord>>(_renewals.Values.OrderBy(r => r.CertificateName, StringComparer.Ordinal).Select(r => r.ToRecord()).ToList());
        }
    }

    public ValueTask UpsertAcmeRenewalAsync(AcmeRenewalRecord renewal, CancellationToken ct)
    {
        lock (_gate)
        {
            _renewals[renewal.CertificateName] = renewal.ToEntity();
        }

        return default;
    }

    public ValueTask SetAcmeRenewalAdviceAsync(string certificateName, string? ariJson, CancellationToken ct)
    {
        lock (_gate)
        {
            if (_renewals.TryGetValue(certificateName, out var existing))
            {
                existing.AriJson = ariJson;
            }
            else
            {
                _renewals[certificateName] = new AcmeRenewalEntity { CertificateName = certificateName, Status = "issued", AriJson = ariJson };
            }
        }

        return default;
    }

    public ValueTask SetAcmeRenewalChallengeStateAsync(string certificateName, string? challengeStateJson, CancellationToken ct)
    {
        lock (_gate)
        {
            if (_renewals.TryGetValue(certificateName, out var existing))
            {
                existing.ChallengeStateJson = challengeStateJson;
            }
            else
            {
                _renewals[certificateName] = new AcmeRenewalEntity { CertificateName = certificateName, Status = "ordering", ChallengeStateJson = challengeStateJson };
            }
        }

        return default;
    }

    // Leases

    public ValueTask<LeaseRecord?> TryAcquireLeaseAsync(string name, string owner, TimeSpan duration, DateTimeOffset now, CancellationToken ct)
    {
        lock (_gate)
        {
            _leases.TryGetValue(name, out var existing);
            var updated = LeaseRules.Acquire(existing, name, owner, duration, now);
            if (updated is null)
            {
                return R<LeaseRecord?>(null);
            }

            _leases[name] = updated;
            return R<LeaseRecord?>(updated.ToRecord());
        }
    }

    public ValueTask<bool> RenewLeaseAsync(string name, string owner, long fencingToken, TimeSpan duration, DateTimeOffset now, CancellationToken ct)
    {
        lock (_gate)
        {
            _leases.TryGetValue(name, out var existing);
            var updated = LeaseRules.Renew(existing, owner, fencingToken, duration, now);
            if (updated is null)
            {
                return R(false);
            }

            _leases[name] = updated;
            return R(true);
        }
    }

    public ValueTask ReleaseLeaseAsync(string name, string owner, CancellationToken ct)
    {
        lock (_gate)
        {
            _leases.TryGetValue(name, out var existing);
            if (LeaseRules.Release(existing, owner) is { } updated)
            {
                _leases[name] = updated;
            }
        }

        return default;
    }

    // Backend switch

    public ValueTask<SwitchStateRecord?> GetSwitchStateAsync(CancellationToken ct)
    {
        lock (_gate)
        {
            return R(_switch?.ToRecord());
        }
    }

    public ValueTask SetSwitchStateAsync(SwitchStateRecord state, CancellationToken ct)
    {
        lock (_gate)
        {
            _switch = state.ToEntity();
        }

        return default;
    }
    // Backend switch transfer (the config tables as entity rows)

    private static List<object> Snapshot<T>(IEnumerable<T> rows) where T : class => rows.Select(r => TransferTable.Clone(r)).ToList();

    /// <summary>The rows of a config table in key order (copies), without the Data Protection key ring.</summary>
    internal List<object> ReadTransferTable(string table)
    {
        lock (_gate)
        {
            return table switch
            {
                "tenant" => Snapshot(_tenants.Values.OrderBy(x => x.Id)),
                "api_key" => Snapshot(_apiKeys.Values.OrderBy(x => x.Id)),
                "smtp_credential" => Snapshot(_smtp.Values.OrderBy(x => x.Id)),
                "dashboard_user" => Snapshot(_dashboardUsers.Values.OrderBy(x => x.Id)),
                "dashboard_session" => Snapshot(_dashboardSessions.OrderBy(x => Convert.ToHexString(x.IdHash), StringComparer.Ordinal)),
                "domain" => Snapshot(_domains.Values.OrderBy(x => x.Id)),
                "dkim_key" => Snapshot(_dkim.Values.OrderBy(x => x.Id)),
                "suppression" => Snapshot(_suppressions.Values.OrderBy(x => x.TenantId).ThenBy(x => x.Address, StringComparer.Ordinal)),
                "webhook_endpoint" => Snapshot(_endpoints.Values.OrderBy(x => x.Id)),
                "setting" => Snapshot(_settings.Values.Where(x => !x.Key.StartsWith(TransferTables.DataProtectionSettingPrefix, StringComparison.Ordinal)).OrderBy(x => x.TenantId).ThenBy(x => x.Key, StringComparer.Ordinal)),
                "tls_policy" => Snapshot(_tls.Values.OrderBy(x => x.Id)),
                "relay_route" => Snapshot(_relays.Values.OrderBy(x => x.Id)),
                "certificate" => Snapshot(_certs.Values.OrderBy(x => x.Id)),
                "acme_account" => Snapshot(_acmeAccounts.Values.OrderBy(x => x.Id)),
                "acme_renewal" => Snapshot(_renewals.Values.OrderBy(x => x.CertificateName, StringComparer.Ordinal)),
                "domain_record_check" => Snapshot(_domainChecks.Values.OrderBy(x => x.DomainId).ThenBy(x => x.RecordKey, StringComparer.Ordinal)),
                "tls_rpt_bucket" => Snapshot(_tlsRpt.Values.OrderBy(x => x.Id)),
                "sending_counter" => Snapshot(_counters.Values.OrderBy(x => x.Scope).ThenBy(x => x.TenantId).ThenBy(x => x.Domain, StringComparer.Ordinal).ThenBy(x => x.WindowKind).ThenBy(x => x.WindowIndex)),
                _ => throw new ArgumentOutOfRangeException(nameof(table), table, "not a config table"),
            };
        }
    }

    /// <summary>Adds rows imported from a bundle (a row with the same key is replaced).</summary>
    internal void AddTransferRows(string table, IReadOnlyList<object> rows)
    {
        lock (_gate)
        {
            foreach (object row in rows)
            {
                switch (row)
                {
                    case TenantEntity x: _tenants[x.Id] = x; break;
                    case ApiKeyEntity x: _apiKeys[x.Id] = x; break;
                    case SmtpCredentialEntity x: _smtp[x.Id] = x; break;
                    case DashboardUserEntity x: _dashboardUsers[x.Id] = x; break;
                    case DashboardSessionEntity x:
                        _dashboardSessions.RemoveAll(s => s.IdHash.AsSpan().SequenceEqual(x.IdHash));
                        _dashboardSessions.Add(x);
                        break;
                    case DomainEntity x: _domains[x.Id] = x; break;
                    case DkimKeyEntity x: _dkim[x.Id] = x; break;
                    case SuppressionEntity x: _suppressions[(x.TenantId, x.Address)] = x; break;
                    case WebhookEndpointEntity x: _endpoints[x.Id] = x; break;
                    case SettingEntity x: _settings[(x.TenantId, x.Key)] = x; break;
                    case TlsPolicyEntity x: _tls[x.Id] = x; break;
                    case RelayRouteEntity x: _relays[x.Id] = x; break;
                    case CertificateEntity x: _certs[x.Id] = x; break;
                    case AcmeAccountEntity x: _acmeAccounts[x.Id] = x; break;
                    case AcmeRenewalEntity x: _renewals[x.CertificateName] = x; break;
                    case DomainRecordCheckEntity x: _domainChecks[(x.DomainId, x.RecordKey)] = x; break;
                    case TlsRptBucketEntity x: _tlsRpt[x.Id] = x; break;
                    case SendingCounterEntity x: _counters[(x.Scope, x.TenantId, x.Domain, x.WindowKind, x.WindowIndex)] = x; break;
                    default: throw new ArgumentOutOfRangeException(nameof(rows), table, "not a config row");
                }
            }
        }
    }

    internal bool AnyTransferRows(string table) => ReadTransferTable(table).Count > 0;

    internal void ClearTransferTable(string table)
    {
        lock (_gate)
        {
            switch (table)
            {
                case "tenant": _tenants.Clear(); break;
                case "api_key": _apiKeys.Clear(); break;
                case "smtp_credential": _smtp.Clear(); break;
                case "dashboard_user": _dashboardUsers.Clear(); break;
                case "dashboard_session": _dashboardSessions.Clear(); break;
                case "domain": _domains.Clear(); break;
                case "dkim_key": _dkim.Clear(); break;
                case "suppression": _suppressions.Clear(); break;
                case "webhook_endpoint": _endpoints.Clear(); break;
                case "setting":
                    foreach (var key in _settings.Keys.Where(k => !k.Item2.StartsWith(TransferTables.DataProtectionSettingPrefix, StringComparison.Ordinal)).ToList())
                    {
                        _settings.Remove(key);
                    }

                    break;
                case "tls_policy": _tls.Clear(); break;
                case "relay_route": _relays.Clear(); break;
                case "certificate": _certs.Clear(); break;
                case "acme_account": _acmeAccounts.Clear(); break;
                case "acme_renewal": _renewals.Clear(); break;
                case "domain_record_check": _domainChecks.Clear(); break;
                case "tls_rpt_bucket": _tlsRpt.Clear(); break;
                case "sending_counter": _counters.Clear(); break;
                default: throw new ArgumentOutOfRangeException(nameof(table), table, "not a config table");
            }
        }
    }

    internal void ClearSwitchState()
    {
        lock (_gate)
        {
            _switch = null;
        }
    }
}
