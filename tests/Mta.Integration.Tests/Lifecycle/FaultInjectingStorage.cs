using Mta.Storage;

namespace Mta.Integration.Tests.Lifecycle;

/// <summary>
/// A storage that passes everything to the real one and can make the recording of a delivery attempt fail once. The failed call stands for a process that dies at that exact point: whatever the
/// engine wrote before it (a bounce message, a webhook draft) is in the database, the attempt is not.
/// </summary>
internal sealed class FaultInjectingStorage(IStorage inner) : IStorage
{
    private readonly FaultInjectingDeliveries _deliveries = new(inner.Deliveries);

    /// <summary>Called with every attempt about to be recorded; true makes that call throw (once per true answer) instead of recording.</summary>
    public Func<DeliveryAttempt, bool>? FailRecording
    {
        get => _deliveries.FailRecording;
        set => _deliveries.FailRecording = value;
    }

    public int FailedRecordings => _deliveries.Failed;

    public StorageBackend Backend => inner.Backend;

    public HistoryMode HistoryMode => inner.HistoryMode;

    public IMessageIntake Intake => inner.Intake;

    public IDeliveryStore Deliveries => _deliveries;

    public IConfigStore Config => inner.Config;

    public IStatsStore Stats => inner.Stats;

    public IHistoryStore History => inner.History;

    public IWebhookOutbox Webhooks => inner.Webhooks;

    public IStorageMaintenance Maintenance => inner.Maintenance;

    public Mta.Storage.Transfer.IStorageTransfer? Transfer => inner.Transfer;

    public IReplicaCoordination? Replicas => inner.Replicas;

    public Task InitializeAsync(CancellationToken cancellationToken) => inner.InitializeAsync(cancellationToken);

    public ValueTask DisposeAsync() => inner.DisposeAsync();

    private sealed class FaultInjectingDeliveries(IDeliveryStore inner) : IDeliveryStore
    {
        private int _failed;

        public Func<DeliveryAttempt, bool>? FailRecording { get; set; }

        public int Failed => Volatile.Read(ref _failed);

        public ValueTask<IReadOnlyList<ClaimedDelivery>> ClaimAsync(string owner, int max, DateTimeOffset now, TimeSpan lease, CancellationToken cancellationToken) =>
            inner.ClaimAsync(owner, max, now, lease, cancellationToken);

        public ValueTask<byte[]?> GetRawAsync(Guid messageId, CancellationToken cancellationToken) => inner.GetRawAsync(messageId, cancellationToken);

        public ValueTask RecordAttemptAsync(DeliveryAttempt attempt, CancellationToken cancellationToken)
        {
            if (FailRecording?.Invoke(attempt) == true)
            {
                Interlocked.Increment(ref _failed);
                // A cancellation, not an outage: the engine retries a failed recording a few times, but a cancelled one is a process going away, which is what this stands for.
                throw new OperationCanceledException("injected: the process died before the attempt was recorded");
            }

            return inner.RecordAttemptAsync(attempt, cancellationToken);
        }

        public ValueTask<bool> ExtendLeaseAsync(Guid deliveryId, string owner, DateTimeOffset until, CancellationToken cancellationToken) =>
            inner.ExtendLeaseAsync(deliveryId, owner, until, cancellationToken);

        public ValueTask<int> ReleaseExpiredLeasesAsync(DateTimeOffset now, CancellationToken cancellationToken) => inner.ReleaseExpiredLeasesAsync(now, cancellationToken);

        public ValueTask<int> ReleaseOwnedLeasesAsync(string owner, CancellationToken cancellationToken) => inner.ReleaseOwnedLeasesAsync(owner, cancellationToken);

        public ValueTask<QueueStats> GetQueueStatsAsync(CancellationToken cancellationToken) => inner.GetQueueStatsAsync(cancellationToken);

        public ValueTask<IReadOnlyList<ClaimedDelivery>> ClaimExpiredAsync(string owner, int max, DateTimeOffset now, CancellationToken cancellationToken) =>
            inner.ClaimExpiredAsync(owner, max, now, cancellationToken);

        public ValueTask<CancelResult> CancelAsync(Guid tenantId, Guid messageId, IReadOnlyList<string>? recipients, DateTimeOffset now, Func<CancelledDeliveryInfo, WebhookEventDraft?>? webhookEvent, CancellationToken cancellationToken) =>
            inner.CancelAsync(tenantId, messageId, recipients, now, webhookEvent, cancellationToken);
    }
}
