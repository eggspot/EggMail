namespace Mta.Storage;

/// <summary>
/// <see cref="IInboundStore"/> assembled from its two halves: the settings and routes (which live with the configuration) and the messages (which
/// live with the queue). Every backend builds its <see cref="IStorage.Inbound"/> this way, so the split is one fact in one place.
/// </summary>
public sealed class InboundStoreFacade(IInboundConfigStore config, IInboundMessageStore messages) : IInboundStore
{
    public ValueTask<InboundDomainSettings?> GetSettingsAsync(Guid domainId, CancellationToken cancellationToken) => config.GetSettingsAsync(domainId, cancellationToken);

    public ValueTask UpsertSettingsAsync(InboundDomainSettings settings, CancellationToken cancellationToken) => config.UpsertSettingsAsync(settings, cancellationToken);

    public ValueTask<IReadOnlyList<InboundRouteRecord>> GetRoutesAsync(Guid domainId, CancellationToken cancellationToken) => config.GetRoutesAsync(domainId, cancellationToken);

    public ValueTask<InboundRouteRecord?> GetRouteAsync(Guid tenantId, Guid routeId, CancellationToken cancellationToken) => config.GetRouteAsync(tenantId, routeId, cancellationToken);

    public ValueTask UpsertRouteAsync(InboundRouteRecord route, CancellationToken cancellationToken) => config.UpsertRouteAsync(route, cancellationToken);

    public ValueTask<bool> DeleteRouteAsync(Guid tenantId, Guid routeId, CancellationToken cancellationToken) => config.DeleteRouteAsync(tenantId, routeId, cancellationToken);

    public ValueTask<IReadOnlyList<InboundRouteRecord>> GetRoutesUsingWebhookEndpointAsync(Guid endpointId, CancellationToken cancellationToken) => config.GetRoutesUsingWebhookEndpointAsync(endpointId, cancellationToken);

    public ValueTask<IReadOnlyList<InboundDomainConfiguration>> LoadEnabledDomainsAsync(CancellationToken cancellationToken) => config.LoadEnabledDomainsAsync(cancellationToken);

    public ValueTask AcceptAsync(IReadOnlyList<InboundMessageDraft> drafts, CancellationToken cancellationToken) => messages.AcceptAsync(drafts, cancellationToken);

    // A filter with text that cannot be stored (NUL, an unpaired surrogate) matches nothing, on every backend (StorageText): PostgreSQL could not even be asked.
    public ValueTask<Page<InboundMessage>> SearchAsync(InboundMessageQuery query, CancellationToken cancellationToken) =>
        Storable(query) ? messages.SearchAsync(query, cancellationToken) : ValueTask.FromResult(new Page<InboundMessage>([], null));

    private static bool Storable(InboundMessageQuery q) => StorageText.IsStorable(q.Recipient) && StorageText.IsStorable(q.Sender) && StorageText.IsStorable(q.SubjectContains);

    public ValueTask<InboundMessage?> GetAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken) => messages.GetAsync(tenantId, messageId, cancellationToken);

    public ValueTask<byte[]?> GetRawAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken) => messages.GetRawAsync(tenantId, messageId, cancellationToken);

    public ValueTask<bool> DeleteAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken) => messages.DeleteAsync(tenantId, messageId, cancellationToken);

    public ValueTask<long> DeleteMatchingAsync(InboundMessageQuery query, CancellationToken cancellationToken) =>
        Storable(query) ? messages.DeleteMatchingAsync(query, cancellationToken) : ValueTask.FromResult(0L);

    public ValueTask<InboundRetryResult> RetryActionAsync(Guid tenantId, Guid messageId, DateTimeOffset now, CancellationToken cancellationToken) => messages.RetryActionAsync(tenantId, messageId, now, cancellationToken);

    public ValueTask<IReadOnlyList<ClaimedInboundAction>> ClaimActionsAsync(string owner, int max, DateTimeOffset now, TimeSpan lease, CancellationToken cancellationToken, InboundClaimLimits? limits = null) => messages.ClaimActionsAsync(owner, max, now, lease, cancellationToken, limits);

    public ValueTask<long> CountActionsAsync(InboundActionState state, CancellationToken cancellationToken) => messages.CountActionsAsync(state, cancellationToken);

    public ValueTask<ForwardBacklog> GetForwardBacklogAsync(Guid tenantId, string sendingDomain, CancellationToken cancellationToken) => messages.GetForwardBacklogAsync(tenantId, sendingDomain, cancellationToken);

    public ValueTask<bool> ExtendActionLeaseAsync(Guid messageId, string owner, DateTimeOffset until, CancellationToken cancellationToken) => messages.ExtendActionLeaseAsync(messageId, owner, until, cancellationToken);

    public ValueTask<bool> CompleteActionAsync(Guid messageId, string owner, InboundActionOutcome outcome, CancellationToken cancellationToken) => messages.CompleteActionAsync(messageId, owner, outcome, cancellationToken);

    public ValueTask<int> ReleaseOwnedActionLeasesAsync(string owner, CancellationToken cancellationToken) => messages.ReleaseOwnedActionLeasesAsync(owner, cancellationToken);

    public ValueTask<InboundUsage> GetUsageAsync(Guid? tenantId, Guid? domainId, CancellationToken cancellationToken) => messages.GetUsageAsync(tenantId, domainId, cancellationToken);
}
