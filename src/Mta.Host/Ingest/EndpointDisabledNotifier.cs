using Mta.Core;
using Mta.Storage;
using Mta.Webhooks;

namespace Mta.Host.Ingest;

/// <summary>
/// Tells the tenant that an endpoint was switched off after repeated failures: a warning in the log and a <c>webhook.endpoint.disabled</c>
/// event to the tenant's other endpoints that subscribe to it. The disabled endpoint itself and its reason stay visible in the dashboard.
/// </summary>
public sealed class EndpointDisabledNotifier(IStorage storage, IClock clock, IMtaLog log) : IWebhookNotifier
{
    public async ValueTask EndpointDisabledAsync(WebhookEndpointRecord endpoint, string reason, CancellationToken cancellationToken)
    {
        log.Write(MtaLogLevel.Warning, "webhooks", $"endpoint {endpoint.Id:N} of tenant {endpoint.TenantId:N} was disabled: {reason}");
        var now = clock.UtcNow;
        var draft = WebhookEventFactory.EndpointDisabledEvent(endpoint.Id, endpoint.Url, reason, now);
        await storage.Webhooks.EnqueueAsync(endpoint.TenantId, draft, now, cancellationToken).ConfigureAwait(false);
    }
}
