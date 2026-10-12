using Mta.Storage;

namespace Mta.Host.Ingest;

/// <summary>Publishes events through the storage webhook outbox, so they are retried and logged like any other delivery.</summary>
public sealed class StorageWebhookPublisher(IStorage storage) : IWebhookPublisher
{
    public async ValueTask PublishAsync(Guid tenantId, WebhookEventDraft draft, DateTimeOffset now, CancellationToken cancellationToken) =>
        await storage.Webhooks.EnqueueAsync(tenantId, draft, now, cancellationToken).ConfigureAwait(false);
}
