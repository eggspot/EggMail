using Mta.Storage.Model;

namespace Mta.Storage.InMemory;

// Inbound settings and routes of the in-memory config store (IInboundConfigStore): the same rules as the EF store.
internal sealed partial class InMemoryConfigStore
{
    private readonly Dictionary<Guid, InboundDomainSettingsEntity> _inboundSettings = [];
    private readonly Dictionary<Guid, InboundRouteEntity> _inboundRoutes = [];

    public ValueTask<InboundDomainSettings?> GetSettingsAsync(Guid domainId, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return R(_inboundSettings.TryGetValue(domainId, out InboundDomainSettingsEntity? s) ? s.ToRecord() : null);
        }
    }

    public ValueTask UpsertSettingsAsync(InboundDomainSettings settings, CancellationToken cancellationToken)
    {
        InboundDomainSettingsEntity entity = settings.ToEntity();
        lock (_gate)
        {
            if (!_domains.TryGetValue(entity.DomainId, out DomainEntity? domain) || domain.TenantId != entity.TenantId)
            {
                throw new StorageConflictException("The domain does not exist for this tenant.");
            }

            _inboundSettings[entity.DomainId] = entity;
        }

        return default;
    }

    public ValueTask<IReadOnlyList<InboundRouteRecord>> GetRoutesAsync(Guid domainId, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return R<IReadOnlyList<InboundRouteRecord>>(_inboundRoutes.Values.Where(r => r.DomainId == domainId).Select(r => r.ToRecord()).Order(Comparer<InboundRouteRecord>.Create(InboundMapping.CompareRoutes)).ToList());
        }
    }

    public ValueTask<InboundRouteRecord?> GetRouteAsync(Guid tenantId, Guid routeId, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return R(_inboundRoutes.TryGetValue(routeId, out InboundRouteEntity? r) && r.TenantId == tenantId ? r.ToRecord() : null);
        }
    }

    public ValueTask UpsertRouteAsync(InboundRouteRecord route, CancellationToken cancellationToken)
    {
        InboundRouteEntity entity = route.ToEntity();
        lock (_gate)
        {
            if (!_domains.TryGetValue(entity.DomainId, out DomainEntity? domain) || domain.TenantId != entity.TenantId)
            {
                throw new StorageConflictException("The domain does not exist for this tenant.");
            }

            if (entity.ActionKind == InboundActionKind.Webhook && !(entity.WebhookEndpointId is { } endpointId && _endpoints.TryGetValue(endpointId, out WebhookEndpointEntity? endpoint) && endpoint.TenantId == entity.TenantId))
            {
                throw new StorageConflictException("The webhook endpoint does not exist for this tenant.", StorageConflictReasons.WebhookEndpointMissing);
            }

            if (_inboundRoutes.TryGetValue(entity.Id, out InboundRouteEntity? existing) && (existing.TenantId != entity.TenantId || existing.DomainId != entity.DomainId))
            {
                throw new StorageConflictException("A route id belongs to one tenant and domain.");
            }

            _inboundRoutes[entity.Id] = entity;
        }

        return default;
    }

    public ValueTask<bool> DeleteRouteAsync(Guid tenantId, Guid routeId, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return R(_inboundRoutes.TryGetValue(routeId, out InboundRouteEntity? r) && r.TenantId == tenantId && _inboundRoutes.Remove(routeId));
        }
    }

    public ValueTask<IReadOnlyList<InboundRouteRecord>> GetRoutesUsingWebhookEndpointAsync(Guid endpointId, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return R<IReadOnlyList<InboundRouteRecord>>(_inboundRoutes.Values.Where(r => r.ActionKind == InboundActionKind.Webhook && r.WebhookEndpointId == endpointId)
                .OrderBy(r => InboundMapping.IdText(r.DomainId), StringComparer.Ordinal).ThenBy(r => r.SortOrder).ThenBy(r => InboundMapping.IdText(r.Id), StringComparer.Ordinal).Select(r => r.ToRecord()).ToList());
        }
    }

    public ValueTask<IReadOnlyList<InboundDomainConfiguration>> LoadEnabledDomainsAsync(CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            var list = new List<InboundDomainConfiguration>();
            foreach (InboundDomainSettingsEntity s in _inboundSettings.Values.Where(s => s.Enabled))
            {
                if (!_domains.TryGetValue(s.DomainId, out DomainEntity? domain) || !_tenants.TryGetValue(domain.TenantId, out TenantEntity? tenant))
                {
                    continue;
                }

                var routes = _inboundRoutes.Values.Where(r => r.DomainId == s.DomainId && r.Enabled).Select(r => r.ToRecord()).Order(Comparer<InboundRouteRecord>.Create(InboundMapping.CompareRoutes)).ToList();
                list.Add(new InboundDomainConfiguration(domain.Name, s.DomainId, s.TenantId, tenant.Enabled, domain.Status, s.ToRecord(), routes));
            }

            return R<IReadOnlyList<InboundDomainConfiguration>>(list.OrderBy(c => c.DomainName, StringComparer.Ordinal).ToList());
        }
    }

    /// <summary>The explicit retention setting of every domain that has a settings row (null: the server default), for the retention job.</summary>
    internal IReadOnlyDictionary<Guid, int?> InboundRetentionByDomain()
    {
        lock (_gate)
        {
            return _inboundSettings.ToDictionary(x => x.Key, x => x.Value.RetentionDays);
        }
    }
}
