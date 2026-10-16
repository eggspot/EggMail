using Microsoft.EntityFrameworkCore;
using Mta.Storage.Logic;

namespace Mta.Storage.Model;

// The inbound settings and routes (IInboundConfigStore) of the EF config store: config part, written like every other configuration.
public sealed partial class EfConfigStore<TContext>
{
    public async ValueTask<InboundDomainSettings?> GetSettingsAsync(Guid domainId, CancellationToken cancellationToken) =>
        await Read(c => c.InboundSettings.AsNoTracking().Where(x => x.DomainId == domainId).AsEnumerable().Select(x => x.ToRecord()).FirstOrDefault()).ConfigureAwait(false);

    public async ValueTask UpsertSettingsAsync(InboundDomainSettings settings, CancellationToken cancellationToken)
    {
        InboundDomainSettingsEntity entity = settings.ToEntity();
        await Write(c =>
        {
            if (!c.Domains.Any(d => d.Id == entity.DomainId && d.TenantId == entity.TenantId))
            {
                throw new StorageConflictException("The domain does not exist for this tenant.");
            }

            Upsert(c, entity, entity.DomainId);
        }, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<IReadOnlyList<InboundRouteRecord>> GetRoutesAsync(Guid domainId, CancellationToken cancellationToken) =>
        await Read<IReadOnlyList<InboundRouteRecord>>(c => c.InboundRoutes.AsNoTracking().Where(x => x.DomainId == domainId).OrderBy(x => x.SortOrder).ThenBy(x => x.Id).AsEnumerable().Select(x => x.ToRecord()).ToList()).ConfigureAwait(false);

    public async ValueTask<InboundRouteRecord?> GetRouteAsync(Guid tenantId, Guid routeId, CancellationToken cancellationToken) =>
        await Read(c => c.InboundRoutes.AsNoTracking().Where(x => x.Id == routeId && x.TenantId == tenantId).AsEnumerable().Select(x => x.ToRecord()).FirstOrDefault()).ConfigureAwait(false);

    public async ValueTask UpsertRouteAsync(InboundRouteRecord route, CancellationToken cancellationToken)
    {
        InboundRouteEntity entity = route.ToEntity();
        await Write(c =>
        {
            if (!c.Domains.Any(d => d.Id == entity.DomainId && d.TenantId == entity.TenantId))
            {
                throw new StorageConflictException("The domain does not exist for this tenant.");
            }

            // The endpoint a webhook route names must exist for this tenant, checked in this write (the schema has no foreign keys; DeleteWebhookEndpointAsync checks the other direction).
            if (entity.ActionKind == InboundActionKind.Webhook && !c.WebhookEndpoints.Any(w => w.Id == entity.WebhookEndpointId && w.TenantId == entity.TenantId))
            {
                throw new StorageConflictException("The webhook endpoint does not exist for this tenant.", StorageConflictReasons.WebhookEndpointMissing);
            }

            // A route cannot move to another tenant or domain: that would be a different route.
            if (c.InboundRoutes.Any(r => r.Id == entity.Id && (r.TenantId != entity.TenantId || r.DomainId != entity.DomainId)))
            {
                throw new StorageConflictException("A route id belongs to one tenant and domain.");
            }

            Upsert(c, entity, entity.Id);
        }, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<bool> DeleteRouteAsync(Guid tenantId, Guid routeId, CancellationToken cancellationToken) =>
        await Write(c => c.InboundRoutes.Where(x => x.Id == routeId && x.TenantId == tenantId).ExecuteDelete() > 0, cancellationToken).ConfigureAwait(false);

    public async ValueTask<IReadOnlyList<InboundRouteRecord>> GetRoutesUsingWebhookEndpointAsync(Guid endpointId, CancellationToken cancellationToken) =>
        await Read<IReadOnlyList<InboundRouteRecord>>(c => c.InboundRoutes.AsNoTracking().Where(x => x.ActionKind == InboundActionKind.Webhook && x.WebhookEndpointId == endpointId)
            .OrderBy(x => x.DomainId).ThenBy(x => x.SortOrder).ThenBy(x => x.Id).AsEnumerable().Select(x => x.ToRecord()).ToList()).ConfigureAwait(false);

    public async ValueTask<IReadOnlyList<InboundDomainConfiguration>> LoadEnabledDomainsAsync(CancellationToken cancellationToken) =>
        await Read<IReadOnlyList<InboundDomainConfiguration>>(c =>
        {
            var rows = (from s in c.InboundSettings.AsNoTracking()
                        where s.Enabled
                        join d in c.Domains.AsNoTracking() on s.DomainId equals d.Id
                        join t in c.Tenants.AsNoTracking() on d.TenantId equals t.Id
                        orderby d.Name
                        select new { Settings = s, d.Name, d.Status, TenantEnabled = t.Enabled }).ToList();
            if (rows.Count == 0)
            {
                return [];
            }

            Guid[] ids = [.. rows.Select(r => r.Settings.DomainId)];
            ILookup<Guid, InboundRouteRecord> routes = c.InboundRoutes.AsNoTracking().Where(r => r.Enabled && ids.Contains(r.DomainId))
                .OrderBy(r => r.SortOrder).ThenBy(r => r.Id).AsEnumerable().Select(r => r.ToRecord()).ToLookup(r => r.DomainId);
            return rows.Select(r => new InboundDomainConfiguration(r.Name, r.Settings.DomainId, r.Settings.TenantId, r.TenantEnabled, r.Status, r.Settings.ToRecord(), routes[r.Settings.DomainId].ToList())).ToList();
        }).ConfigureAwait(false);

    /// <summary>The explicit retention setting of every domain that has a settings row (null: the server default), for the retention job. Not part of the contract: the job runs inside the backends.</summary>
    public async ValueTask<IReadOnlyDictionary<Guid, int?>> GetInboundRetentionByDomainAsync(CancellationToken cancellationToken) =>
        await Read<IReadOnlyDictionary<Guid, int?>>(c => c.InboundSettings.AsNoTracking().Select(x => new { x.DomainId, x.RetentionDays }).ToList().ToDictionary(x => x.DomainId, x => x.RetentionDays)).ConfigureAwait(false);

    // The domain's inbound settings and routes go with the domain (called from DeleteDomainAsync inside its write).
    private static void DeleteInboundOfDomain(TContext c, Guid domainId)
    {
        c.InboundRoutes.Where(r => r.DomainId == domainId).ExecuteDelete();
        c.InboundSettings.Where(s => s.DomainId == domainId).ExecuteDelete();
    }
}
