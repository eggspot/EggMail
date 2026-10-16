using Mta.Core;
using Mta.Storage.Logic;
using Mta.Storage.Model;
using Mta.Storage.Transfer;

namespace Mta.Storage.InMemory;

/// <summary>
/// A complete in-process <see cref="IStorage"/>: correct semantics, no persistence. It is the reference the SQLite (and
/// later PostgreSQL) backends are checked against by the shared conformance suite, and the storage other components use in
/// their own tests. Everything runs under one lock; performance is not a goal here.
/// </summary>
public sealed class InMemoryStorage : IStorage
{
    private readonly MemoryState _state;
    private readonly Timer? _flushTimer;
    private int _disposed;

    public InMemoryStorage(StorageOptions options, IClock? clock = null, IMtaLog? log = null, TimeSpan? statsFlushInterval = null)
    {
        StorageOptionsValidation.Validate(options);
        _state = new MemoryState(options, clock ?? SystemClock.Instance, log ?? NullMtaLog.Instance);
        var config = new InMemoryConfigStore();
        _state.Config = config;
        Intake = new MemoryIntake(_state);
        Deliveries = new MemoryDeliveries(_state);
        Config = config;
        Stats = new MemoryStats(_state);
        History = new MemoryHistory(_state);
        Webhooks = new MemoryWebhooks(_state);
        _state.InboundStore = new MemoryInbound(_state);
        Inbound = new InboundStoreFacade(config, _state.InboundStore);
        Maintenance = new MemoryMaintenance(_state);
        Transfer = new MemoryTransfer(_state);
        Replicas = new InMemoryReplicaCoordination(_state.Clock);
        TimeSpan interval = statsFlushInterval ?? TimeSpan.FromSeconds(10);
        if (interval > TimeSpan.Zero)
        {
            _flushTimer = new Timer(_ => _state.FlushStats(), null, interval, interval);
        }
    }

    public StorageBackend Backend => StorageBackend.InMemory;

    public HistoryMode HistoryMode => _state.Options.History.Mode;

    public IMessageIntake Intake { get; }

    public IDeliveryStore Deliveries { get; }

    public IConfigStore Config { get; }

    public IStatsStore Stats { get; }

    public IHistoryStore History { get; }

    public IWebhookOutbox Webhooks { get; }

    public IInboundStore Inbound { get; }

    public IStorageMaintenance Maintenance { get; }

    public IStorageTransfer Transfer { get; }

    public IReplicaCoordination? Replicas { get; }

    public Task InitializeAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            if (_flushTimer is not null)
            {
                await _flushTimer.DisposeAsync().ConfigureAwait(false);
            }

            _state.FlushStats();
        }
    }
}

internal sealed class MemoryState
{
    public readonly object Gate = new();

    /// <summary>The backend switch gate (fenced source, target not yet activated); see <see cref="SwitchGate"/>.</summary>
    public readonly SwitchGate Fence = new();
    public readonly StorageOptions Options;
    public readonly IClock Clock;
    public readonly IMtaLog Log;
    public InMemoryConfigStore Config = null!;
    public MemoryInbound InboundStore = null!;

    // Queue
    public readonly Dictionary<Guid, QueuedDeliveryEntity> Deliveries = [];
    public readonly Dictionary<Guid, SpoolMessageEntity> Spool = [];
    public readonly Dictionary<Guid, WebhookOutboxEntity> Outbox = [];
    public readonly Dictionary<(Guid Tenant, string Key), IdempotencyKeyEntity> Idempotency = [];
    public readonly Dictionary<Guid, InboundMessageEntity> InboundMessages = [];
    public readonly Dictionary<Guid, InboundMessageRawEntity> InboundRaw = [];

    // History, keyed by message id (the day is derived from the id)
    public readonly Dictionary<Guid, MessageIndexEntity> Index = [];
    public readonly Dictionary<Guid, List<string>> Recipients = [];
    public readonly Dictionary<Guid, List<MessageEventEntity>> Events = [];
    public readonly Dictionary<Guid, MessageContentEntity> Content = [];
    public readonly Dictionary<Guid, RetainedRawEntity> RetainedRaw = [];

    // Stats
    public readonly StatsAggregator Aggregator;
    public readonly StatsBucketer Bucketer;
    public readonly Dictionary<(bool Daily, DateTimeOffset Period, Guid Tenant, string Sending, string Recipient), long[]> StatRows = [];
    public int? RollupWatermarkDay;
    public readonly List<(long Seq, RecentEvent Event)> Ring = [];
    public long RingSeq;
    public readonly List<WebhookAttemptEntity> WebhookAttempts = [];
    public long AttemptSeq;

    public MemoryState(StorageOptions options, IClock clock, IMtaLog log)
    {
        Options = options;
        Clock = clock;
        Log = log;
        Aggregator = new StatsAggregator(options.Retention, options.History);
        Bucketer = new StatsBucketer(options.Retention, LoadHourSeries);
    }

    private IEnumerable<(Guid Tenant, string Sending, string Recipient)> LoadHourSeries(DateTimeOffset hour) =>
        StatRows.Keys.Where(k => !k.Daily && k.Period == hour).Select(k => (k.Tenant, k.Sending, k.Recipient)).ToList();

    public bool IsFull => Options.History.Mode == HistoryMode.Full;

    /// <summary>Drains the aggregate into the stat tables and the ring (called by FlushAsync, the timer and dispose).</summary>
    public void FlushStats()
    {
        lock (Gate)
        {
            var deltas = Aggregator.Drain(Clock.UtcNow);
            foreach (StatDelta d in Bucketer.Apply(deltas))
            {
                var key = (false, d.Key.HourStart, d.Key.TenantId, d.Key.SendingDomain, d.Key.RecipientDomain);
                if (!StatRows.TryGetValue(key, out long[]? counts))
                {
                    StatRows[key] = counts = new long[StatDelta.CounterCount];
                }

                for (int i = 0; i < counts.Length; i++)
                {
                    counts[i] += d.Counts[i];
                }
            }

            foreach (RecentEvent e in Aggregator.DrainRecent())
            {
                Ring.Add((++RingSeq, e));
            }

            int cap = Math.Max(0, Options.History.RecentEvents);
            if (Ring.Count > cap)
            {
                Ring.RemoveRange(0, Ring.Count - cap);
            }
        }
    }

    public static string IdText(Guid id) => id.ToString("D").ToUpperInvariant();
}

internal sealed class MemoryIntake(MemoryState s) : IMessageIntake
{
    public ValueTask<IntakeResult> AcceptAsync(AcceptedMessage message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);
        if (message.Recipients.Count == 0)
        {
            throw new ArgumentException("A message needs at least one recipient.", nameof(message));
        }

        if (message.MessageId.Version != 7)
        {
            throw new ArgumentException("MessageId must be a UUIDv7 (Ids.New) so the history day can be derived.", nameof(message));
        }

        s.Fence.ThrowIfClosed();
        DateTimeOffset now = s.Clock.UtcNow;
        DateTimeOffset received = StorageTime.Normalize(message.ReceivedAt);
        lock (s.Gate)
        {
            if (s.Spool.ContainsKey(message.MessageId))
            {
                throw new StorageConflictException($"Message {message.MessageId} already exists.");
            }

            if (message.IdempotencyKey is { } key)
            {
                var k = (message.TenantId, key);
                if (s.Idempotency.TryGetValue(k, out var existing) && existing.ExpiresAt > now)
                {
                    return ValueTask.FromResult(new IntakeResult(IntakeStatus.DuplicateIdempotencyKey, existing.MessageId, existing.Fingerprint));
                }

                s.Idempotency[k] = new IdempotencyKeyEntity
                {
                    TenantId = message.TenantId,
                    IdempotencyKey = key,
                    MessageId = message.MessageId,
                    CreatedAt = StorageTime.Normalize(now),
                    ExpiresAt = StorageTime.Normalize(now + (message.IdempotencyKeyLifetime ?? s.Options.Queue.IdempotencyKeyLifetime)),
                    Fingerprint = message.IdempotencyFingerprint,
                };
            }

            string from = AddressText.Format(message.EnvelopeFrom);
            s.Spool[message.MessageId] = new SpoolMessageEntity
            {
                MessageId = message.MessageId,
                TenantId = message.TenantId,
                Raw = message.Raw.ToArray(),
                Size = message.Raw.Length,
                PendingRecipients = message.Recipients.Count,
                RetainRaw = message.RetainRaw,
                ReceivedAt = received,
            };

            foreach (AcceptedRecipient r in message.Recipients)
            {
                s.Deliveries[r.DeliveryId] = new QueuedDeliveryEntity
                {
                    Id = r.DeliveryId,
                    MessageId = message.MessageId,
                    TenantId = message.TenantId,
                    EnvelopeFrom = from,
                    Recipient = AddressText.Format(r.Address),
                    RecipientDomain = r.Address.Domain,
                    SendingDomain = message.SendingDomain,
                    Source = message.Source,
                    HeadersUtf8 = message.HeadersUtf8,
                    Attempt = 0,
                    DueAt = received,
                    CreatedAt = received,
                    ExpiresAt = StorageTime.Normalize(message.ExpiresAt),
                    LeaseUntil = StorageTime.Epoch,
                };
            }

            if (s.IsFull)
            {
                RecordHistory(message, received, from);
            }

            // One count per run of recipients with the same domain (the aggregator adds equal keys together).
            string? run = null;
            int runCount = 0;
            foreach (AcceptedRecipient r in message.Recipients)
            {
                string domain = r.Address.Domain;
                if (run is not null && string.Equals(run, domain, StringComparison.Ordinal))
                {
                    runCount++;
                    continue;
                }

                if (run is not null)
                {
                    s.Aggregator.Add(new StatKey(received, message.TenantId, message.SendingDomain ?? "", run), StatCounter.Accepted, runCount);
                }

                run = domain;
                runCount = 1;
            }

            if (run is not null)
            {
                s.Aggregator.Add(new StatKey(received, message.TenantId, message.SendingDomain ?? "", run), StatCounter.Accepted, runCount);
            }
        }

        return ValueTask.FromResult(new IntakeResult(IntakeStatus.Accepted, message.MessageId));
    }

    private void RecordHistory(AcceptedMessage message, DateTimeOffset received, string from)
    {
        ContentOptions co = s.Options.Content;
        bool recordContent = ContentRules.ShouldRecord(s.Options, message);
        MessageContent? content = recordContent ? ContentRules.Prepare(s.Options, message.Content!) : null;
        string? subject = co.StoreSubject ? message.Content?.Subject : null;
        int day = StorageTime.DayNumber(message.MessageId);
        s.Index[message.MessageId] = new MessageIndexEntity
        {
            Day = day,
            MessageId = message.MessageId,
            TenantId = message.TenantId,
            ReceivedAt = received,
            Subject = subject,
            EnvelopeFrom = from,
            RecipientCount = message.Recipients.Count,
            Status = MessageStatus.Queued,
            Size = message.Raw.Length,
            ContentRecorded = recordContent,
            MessageIdHeader = MessageIdKey.Normalize(message.MessageIdHeader),
            Tags = StorageJson.SerializeTags(message.Tags),
        };
        var recipientTexts = new List<string>(message.Recipients.Count);
        HashSet<string>? seen = message.Recipients.Count > 8 ? new HashSet<string>(StringComparer.Ordinal) : null;
        foreach (AcceptedRecipient r in message.Recipients)
        {
            string text = AddressText.Format(r.Address).ToLowerInvariant();
            if (seen is null ? !recipientTexts.Contains(text) : seen.Add(text))
            {
                recipientTexts.Add(text);
            }
        }

        s.Recipients[message.MessageId] = recipientTexts;
        s.Events[message.MessageId] =
        [
            new MessageEventEntity
            {
                Day = day,
                MessageId = message.MessageId,
                EventId = EventIds.Next(received),
                TenantId = message.TenantId,
                Type = MessageEventType.Queued,
                At = received,
            },
        ];
        if (content is not null)
        {
            s.Content[message.MessageId] = new MessageContentEntity
            {
                Day = day,
                MessageId = message.MessageId,
                TenantId = message.TenantId,
                Subject = content.Subject,
                Text = content.Text,
                Html = content.Html,
                AttachmentsJson = StorageJson.SerializeAttachments(content.Attachments),
                Truncated = content.Truncated,
            };
        }
    }
}

internal sealed class MemoryDeliveries(MemoryState s) : IDeliveryStore
{
    private static readonly TimeSpan ExpiredClaimLease = TimeSpan.FromMinutes(5);

    private static readonly IComparer<QueuedDeliveryEntity> DueOrder = Comparer<QueuedDeliveryEntity>.Create(ByDue);

    private static int ByDue(QueuedDeliveryEntity a, QueuedDeliveryEntity b)
    {
        int c = a.DueAt.CompareTo(b.DueAt);
        return c != 0 ? c : CompareIdText(a.Id, b.Id);
    }

    /// <summary>The order of the upper-case "D" texts of two ids (what the SQL backends sort by), without building the texts: the big-endian bytes sort the same way.</summary>
    private static int CompareIdText(Guid x, Guid y)
    {
        Span<byte> a = stackalloc byte[16];
        Span<byte> b = stackalloc byte[16];
        x.TryWriteBytes(a, bigEndian: true, out _);
        y.TryWriteBytes(b, bigEndian: true, out _);
        return a.SequenceCompareTo(b);
    }

    public ValueTask<IReadOnlyList<ClaimedDelivery>> ClaimAsync(string owner, int max, DateTimeOffset now, TimeSpan lease, CancellationToken cancellationToken)
    {
        if (s.Fence.IsClosed)
        {
            return ValueTask.FromResult<IReadOnlyList<ClaimedDelivery>>([]);
        }

        now = StorageTime.Normalize(now);
        DateTimeOffset until = StorageTime.Normalize(now + lease);
        lock (s.Gate)
        {
            // The first `max` due rows in due order, picked in one pass over the queue (no list of every due row, no full sort).
            int take = Math.Max(0, max);
            var rows = new List<QueuedDeliveryEntity>(Math.Min(take, 64) + 1);
            if (take > 0)
            {
                foreach (var d in s.Deliveries.Values)
                {
                    if (d.TransferSwitchId is not null || d.DueAt > now || d.LeaseUntil > now || d.ExpiresAt <= now)
                    {
                        continue;
                    }

                    if (rows.Count == take && ByDue(d, rows[^1]) >= 0)
                    {
                        continue;
                    }

                    int index = rows.BinarySearch(d, DueOrder);
                    rows.Insert(index < 0 ? ~index : index, d);
                    if (rows.Count > take)
                    {
                        rows.RemoveAt(rows.Count - 1);
                    }
                }
            }

            var result = new List<ClaimedDelivery>(rows.Count);
            foreach (var d in rows)
            {
                if (d.LeaseOwner is not null)
                {
                    d.PossibleDuplicate = true;   // the previous holder never reported: it may have sent the message
                }

                d.LeaseOwner = owner;
                d.LeaseUntil = until;
                result.Add(ToClaimed(d));
            }

            return ValueTask.FromResult<IReadOnlyList<ClaimedDelivery>>(result);
        }
    }

    public ValueTask<IReadOnlyList<ClaimedDelivery>> ClaimExpiredAsync(string owner, int max, DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (s.Fence.IsClosed)
        {
            return ValueTask.FromResult<IReadOnlyList<ClaimedDelivery>>([]);
        }

        now = StorageTime.Normalize(now);
        DateTimeOffset until = StorageTime.Normalize(now + ExpiredClaimLease);
        lock (s.Gate)
        {
            var rows = s.Deliveries.Values.Where(d => d.TransferSwitchId is null && d.ExpiresAt <= now && d.LeaseUntil <= now).OrderBy(d => d.ExpiresAt).ThenBy(d => MemoryState.IdText(d.Id), StringComparer.Ordinal).Take(Math.Max(0, max)).ToList();
            foreach (var d in rows)
            {
                d.LeaseOwner = owner;
                d.LeaseUntil = until;
            }

            return ValueTask.FromResult<IReadOnlyList<ClaimedDelivery>>(rows.Select(ToClaimed).ToList());
        }
    }

    private static ClaimedDelivery ToClaimed(QueuedDeliveryEntity d) => new()
    {
        DeliveryId = d.Id,
        MessageId = d.MessageId,
        TenantId = d.TenantId,
        EnvelopeFrom = AddressText.Parse(d.EnvelopeFrom),
        Recipient = AddressText.Parse(d.Recipient),
        RecipientDomain = d.RecipientDomain,
        Attempt = d.Attempt,
        CreatedAt = d.CreatedAt,
        ExpiresAt = d.ExpiresAt,
        LeaseUntil = d.LeaseUntil,
        LastError = d.LastError,
        PossibleDuplicate = d.PossibleDuplicate,
        SendingDomain = d.SendingDomain,
        Source = d.Source,
        HeadersUtf8 = d.HeadersUtf8,
    };

    public ValueTask<byte[]?> GetRawAsync(Guid messageId, CancellationToken cancellationToken)
    {
        lock (s.Gate)
        {
            return ValueTask.FromResult(s.Spool.TryGetValue(messageId, out var m) ? (byte[])m.Raw.Clone() : null);
        }
    }

    public ValueTask RecordAttemptAsync(DeliveryAttempt attempt, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(attempt);
        lock (s.Gate)
        {
            if (!s.Deliveries.TryGetValue(attempt.DeliveryId, out var row))
            {
                return default; // already final (duplicate report): nothing to do
            }

            ApplyAttempt(row, attempt);
        }

        return default;
    }

    public ValueTask<CancelResult> CancelAsync(Guid tenantId, Guid messageId, IReadOnlyList<string>? recipients, DateTimeOffset now, Func<CancelledDeliveryInfo, WebhookEventDraft?>? webhookEvent, CancellationToken cancellationToken)
    {
        s.Fence.ThrowIfClosed();
        now = StorageTime.Normalize(now);
        lock (s.Gate)
        {
            s.Fence.ThrowIfClosed();   // again under the lock that every queue change takes
            var waiting = s.Deliveries.Values.Where(d => d.MessageId == messageId && d.TenantId == tenantId)
                .Select(d => new PendingDelivery(
                    d.Id,
                    d.Recipient,
                    d.EnvelopeFrom,
                    d.Attempt,
                    CancelPlanner.OutcomeMayBeUnknown(d.PossibleDuplicate, d.LeaseOwner is not null),
                    d.TransferSwitchId is not null ? CancelHold.TransferHeld : d.LeaseUntil > now ? CancelHold.Leased : CancelHold.None)).ToList();
            CancelSelection selection = CancelPlanner.Select(waiting, recipients);
            foreach (PendingDelivery d in selection.Cancel)
            {
                QueuedDeliveryEntity row = s.Deliveries[d.DeliveryId];
                row.PossibleDuplicate = d.PossibleDuplicate;   // the row is deleted next; the planner reads the flag from it
                ApplyAttempt(row, CancelPlanner.AttemptFor(d, messageId, tenantId, now, webhookEvent));
            }

            return ValueTask.FromResult(CancelPlanner.ResultOf(selection));
        }
    }

    /// <summary>The consequences of one attempt on a delivery row, under the state lock.</summary>
    private void ApplyAttempt(QueuedDeliveryEntity row, DeliveryAttempt attempt)
    {
        var info = new DeliveryRowInfo(row.Id, row.MessageId, row.TenantId, row.Recipient, row.RecipientDomain, row.SendingDomain, row.Source, row.Attempt, row.PossibleDuplicate);
        AttemptPlan plan = AttemptPlanner.Plan(attempt, info);
        DateTimeOffset at = StorageTime.Normalize(attempt.At);

        // 1. suppression first (a crash after this and before step 2 only means the next try bounces again)
        if (attempt.Suppress is { } reason)
        {
            s.Config.AddSuppressionCore(new SuppressionRecord(row.TenantId, row.Recipient, reason, AttemptPlanner.DescribeError(attempt) ?? "delivery", at, row.MessageId));
        }

        // 2. queue row
        switch (plan.Action)
        {
            case QueueRowAction.Complete:
                s.Deliveries.Remove(row.Id);
                break;
            case QueueRowAction.Reschedule:
                if (plan.CountAttempt)
                {
                    row.Attempt++;
                    row.LastError = plan.LastError;
                }

                row.DueAt = plan.NextAttemptAt!.Value;
                Unlease(row, plan);
                break;
            default:
                Unlease(row, plan);
                break;
        }

        // 3. webhook outbox rows (same commit as the completion)
        foreach (WebhookEventDraft draft in plan.CountAttempt ? attempt.WebhookEvents : [])
        {
            foreach (Guid endpointId in s.Config.EndpointsFor(row.TenantId, draft.EventType))
            {
                Guid id = Ids.New(at);
                s.Outbox[id] = new WebhookOutboxEntity
                {
                    Id = id,
                    EndpointId = endpointId,
                    TenantId = row.TenantId,
                    EventType = draft.EventType,
                    EventId = draft.EventId,
                    PayloadJson = draft.PayloadJson,
                    NextAttemptAt = at,
                    State = WebhookOutboxState.Pending,
                    LeaseUntil = StorageTime.Epoch,
                    CreatedAt = at,
                };
            }
        }

        // 4. spool and retained raw
        bool lastRecipient = false;
        if (plan.IsFinal && s.Spool.TryGetValue(row.MessageId, out var spool))
        {
            spool.PendingRecipients--;
            lastRecipient = spool.PendingRecipients <= 0;
            if (lastRecipient)
            {
                if (spool.RetainRaw && s.IsFull)
                {
                    s.RetainedRaw[row.MessageId] = new RetainedRawEntity
                    {
                        Day = StorageTime.DayNumber(row.MessageId),
                        MessageId = row.MessageId,
                        TenantId = row.TenantId,
                        Raw = spool.Raw,
                        RetainedAt = at,
                    };
                }

                s.Spool.Remove(row.MessageId);
            }
        }

        // 5. history events and index
        if (s.IsFull && plan.Events.Count > 0)
        {
            RecordHistory(plan, row.MessageId, row.TenantId, lastRecipient && s.RetainedRaw.ContainsKey(row.MessageId));
        }

        // 6. statistics and the ring
        DateTimeOffset hour = StorageTime.HourStart(at);
        foreach (PlannedCounter c in plan.Counters)
        {
            s.Aggregator.Add(new StatKey(hour, row.TenantId, row.SendingDomain ?? "", row.RecipientDomain), c.Counter, c.Count);
        }

        foreach (RecentEvent e in plan.Ring)
        {
            s.Aggregator.AddRecent(e);
        }
    }

    private static void Unlease(QueuedDeliveryEntity row, AttemptPlan plan)
    {
        row.LeaseOwner = null;
        row.LeaseUntil = StorageTime.Epoch;
        if (plan.SetPossibleDuplicate)
        {
            row.PossibleDuplicate = true;
        }
    }

    private void RecordHistory(AttemptPlan plan, Guid messageId, Guid tenantId, bool rawRetained)
    {
        int day = StorageTime.DayNumber(messageId);
        if (!s.Events.TryGetValue(messageId, out var events))
        {
            s.Events[messageId] = events = [];
        }

        foreach (MessageEvent e in plan.Events)
        {
            events.Add(new MessageEventEntity
            {
                Day = day,
                MessageId = messageId,
                EventId = e.EventId,
                DeliveryId = e.DeliveryId,
                TenantId = e.TenantId,
                Type = e.Type,
                At = e.At,
                Recipient = e.Recipient,
                SmtpCode = e.SmtpCode,
                EnhancedCode = e.EnhancedCode,
                Message = e.Message,
                MxHost = e.MxHost,
                Route = e.Route,
                TlsJson = StorageJson.SerializeTls(e.Tls),
            });
        }

        if (!s.Index.TryGetValue(messageId, out var index))
        {
            return;
        }

        string? finalKind = MessageStatus.FinalKind(plan.Events[0].Type);
        if (plan.IsFinal)
        {
            index.FinalCount++;
            if (plan.Delivered)
            {
                index.DeliveredCount++;
            }

            if (plan.Failed)
            {
                index.FailedCount++;
            }
        }

        if (plan.IsFinal || plan.Action == QueueRowAction.Reschedule)
        {
            index.Status = MessageStatus.Next(index.Status, index.RecipientCount, index.FinalCount, index.DeliveredCount, index.FailedCount, finalKind);
        }

        if (rawRetained)
        {
            index.RawRetained = true;
        }

        if (plan.IsFinal && index.FinalCount >= index.RecipientCount && !s.Options.Content.Retain)
        {
            s.Content.Remove(messageId);
            index.ContentRecorded = false;
        }
    }

    public ValueTask<bool> ExtendLeaseAsync(Guid deliveryId, string owner, DateTimeOffset until, CancellationToken cancellationToken)
    {
        lock (s.Gate)
        {
            if (s.Deliveries.TryGetValue(deliveryId, out var d) && d.LeaseOwner == owner)
            {
                d.LeaseUntil = StorageTime.Normalize(until);
                return ValueTask.FromResult(true);
            }

            return ValueTask.FromResult(false);
        }
    }

    public ValueTask<int> ReleaseExpiredLeasesAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        now = StorageTime.Normalize(now);
        lock (s.Gate)
        {
            int n = 0;
            foreach (var d in s.Deliveries.Values.Where(d => d.LeaseOwner is not null && d.LeaseUntil <= now))
            {
                d.PossibleDuplicate = true;       // the holder died or stalled without reporting: the message may have been sent
                d.LeaseOwner = null;
                d.LeaseUntil = StorageTime.Epoch;
                n++;
            }

            return ValueTask.FromResult(n);
        }
    }

    public ValueTask<int> ReleaseOwnedLeasesAsync(string owner, CancellationToken cancellationToken)
    {
        lock (s.Gate)
        {
            int n = 0;
            foreach (var d in s.Deliveries.Values.Where(d => d.LeaseOwner == owner))
            {
                d.LeaseOwner = null;
                d.LeaseUntil = StorageTime.Epoch;
                n++;
            }

            return ValueTask.FromResult(n);
        }
    }

    public ValueTask<QueueStats> GetQueueStatsAsync(CancellationToken cancellationToken)
    {
        DateTimeOffset now = s.Clock.UtcNow;
        lock (s.Gate)
        {
            long queued = 0, leased = 0, deferred = 0;
            DateTimeOffset? oldest = null;
            foreach (var d in s.Deliveries.Values)
            {
                if (d.LeaseUntil > now)
                {
                    leased++;
                    continue;
                }

                if (d.Attempt == 0)
                {
                    queued++;
                }
                else
                {
                    deferred++;
                }

                if (oldest is null || d.DueAt < oldest)
                {
                    oldest = d.DueAt;
                }
            }

            return ValueTask.FromResult(new QueueStats(queued, leased, deferred, oldest, s.Spool.Values.Sum(m => m.Size)));
        }
    }
}

internal sealed class MemoryStats(MemoryState s) : IStatsStore
{
    public void Add(in StatKey key, StatCounter counter, long count = 1) => s.Aggregator.Add(key, counter, count);

    public ValueTask FlushAsync(CancellationToken cancellationToken)
    {
        s.FlushStats();
        return default;
    }

    public ValueTask<IReadOnlyList<StatRow>> QueryAsync(Guid? tenantId, DateTimeOffset from, DateTimeOffset to, bool daily, CancellationToken cancellationToken)
    {
        from = StorageTime.Normalize(from);
        to = StorageTime.Normalize(to);
        lock (s.Gate)
        {
            var rows = s.StatRows
                .Where(kv => kv.Key.Daily == daily && kv.Key.Period >= from && kv.Key.Period < to && (tenantId is null || kv.Key.Tenant == tenantId))
                .OrderBy(kv => kv.Key.Period).ThenBy(kv => MemoryState.IdText(kv.Key.Tenant), StringComparer.Ordinal)
                .ThenBy(kv => kv.Key.Sending, StringComparer.Ordinal).ThenBy(kv => kv.Key.Recipient, StringComparer.Ordinal)
                .Select(kv => StatsRollup.ToRow(kv.Key.Period, daily, kv.Key.Tenant, kv.Key.Sending, kv.Key.Recipient, kv.Value))
                .ToList();
            return ValueTask.FromResult<IReadOnlyList<StatRow>>(rows);
        }
    }

    public ValueTask<IReadOnlyList<RecentEvent>> GetRecentEventsAsync(Guid? tenantId, int max, CancellationToken cancellationToken)
    {
        lock (s.Gate)
        {
            var list = s.Ring.AsEnumerable().Reverse().Select(r => r.Event).Where(e => tenantId is null || e.TenantId == tenantId).Take(Math.Max(0, max)).ToList();
            return ValueTask.FromResult<IReadOnlyList<RecentEvent>>(list);
        }
    }
}

internal sealed class MemoryHistory(MemoryState s) : IHistoryStore, IMessageRecipientLookup
{
    public ValueTask<IReadOnlyDictionary<Guid, IReadOnlyList<string>>> GetRecipientsAsync(Guid tenantId, IReadOnlyCollection<Guid> messageIds, int maxPerMessage, CancellationToken cancellationToken)
    {
        var result = new Dictionary<Guid, IReadOnlyList<string>>();
        if (!s.IsFull)
        {
            return ValueTask.FromResult<IReadOnlyDictionary<Guid, IReadOnlyList<string>>>(result);
        }

        lock (s.Gate)
        {
            foreach (Guid id in messageIds)
            {
                if (s.Index.TryGetValue(id, out var m) && m.TenantId == tenantId && s.Recipients.TryGetValue(id, out var rs))
                {
                    result[id] = rs.OrderBy(x => x, StringComparer.Ordinal).Take(Math.Max(0, maxPerMessage)).ToList();
                }
            }
        }

        return ValueTask.FromResult<IReadOnlyDictionary<Guid, IReadOnlyList<string>>>(result);
    }

    private bool IsMetadataExpired(MessageIndexEntity m, DateTimeOffset now) =>
        s.Options.Retention.MetadataDays > 0 && now >= m.ReceivedAt.AddDays(s.Options.Retention.MetadataDays);

    public ValueTask<Page<MessageSummary>> SearchAsync(MessageQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        if (!s.IsFull)
        {
            return ValueTask.FromResult(new Page<MessageSummary>([], null));
        }

        int limit = Math.Clamp(query.Limit, 1, 500);
        bool hasCursor = query.Cursor is not null;
        int cursorDay = 0;
        Guid cursorId = default;
        if (hasCursor && !Cursors.TryDecodeHistory(query.Cursor, out cursorDay, out cursorId))
        {
            throw new ArgumentException("Invalid cursor.", nameof(query));
        }

        DateTimeOffset now = s.Clock.UtcNow;
        string? recipient = query.Recipient?.Trim().ToLowerInvariant();
        string? sender = query.Sender?.Trim();
        string? status = query.Status?.Trim().ToLowerInvariant();
        lock (s.Gate)
        {
            IEnumerable<MessageIndexEntity> rows = s.Index.Values.Where(m => !IsMetadataExpired(m, now));
            if (query.TenantId is { } t)
            {
                rows = rows.Where(m => m.TenantId == t);
            }

            if (recipient is not null)
            {
                rows = rows.Where(m => s.Recipients.TryGetValue(m.MessageId, out var rs) && rs.Contains(recipient));
            }

            if (!string.IsNullOrEmpty(sender))
            {
                rows = rows.Where(m => string.Equals(m.EnvelopeFrom, sender, StringComparison.OrdinalIgnoreCase));
            }

            if (!string.IsNullOrEmpty(query.SubjectContains))
            {
                rows = rows.Where(m => m.Subject is not null && m.Subject.Contains(query.SubjectContains, StringComparison.OrdinalIgnoreCase));
            }

            if (!string.IsNullOrEmpty(status))
            {
                rows = rows.Where(m => m.Status == status);
            }

            if (!string.IsNullOrEmpty(query.Tag))
            {
                rows = rows.Where(m => StorageJson.DeserializeTags(m.Tags).Contains(query.Tag, StringComparer.Ordinal));
            }

            if (query.From is { } from)
            {
                rows = rows.Where(m => m.ReceivedAt >= StorageTime.Normalize(from));
            }

            if (query.To is { } to)
            {
                rows = rows.Where(m => m.ReceivedAt < StorageTime.Normalize(to));
            }

            var ordered = rows.OrderByDescending(m => m.Day).ThenByDescending(m => MemoryState.IdText(m.MessageId), StringComparer.Ordinal);
            IEnumerable<MessageIndexEntity> page = ordered;
            if (hasCursor)
            {
                string cursorText = MemoryState.IdText(cursorId);
                page = ordered.Where(m => m.Day < cursorDay || (m.Day == cursorDay && string.CompareOrdinal(MemoryState.IdText(m.MessageId), cursorText) < 0));
            }

            var items = page.Take(limit + 1).ToList();
            bool more = items.Count > limit;
            if (more)
            {
                items.RemoveAt(items.Count - 1);
            }

            string? next = more ? Cursors.EncodeHistory(items[^1].Day, items[^1].MessageId) : null;
            return ValueTask.FromResult(new Page<MessageSummary>(items.Select(ToSummary).ToList(), next));
        }
    }

    private static MessageSummary ToSummary(MessageIndexEntity m) =>
        new(m.MessageId, m.TenantId, m.ReceivedAt, m.Subject, m.EnvelopeFrom, m.RecipientCount, m.Status, m.Size, m.Tags is null ? null : StorageJson.DeserializeTags(m.Tags));

    public ValueTask<MessageDetail?> GetAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken)
    {
        if (!s.IsFull)
        {
            return ValueTask.FromResult<MessageDetail?>(null);
        }

        DateTimeOffset now = s.Clock.UtcNow;
        lock (s.Gate)
        {
            if (!s.Index.TryGetValue(messageId, out var m) || m.TenantId != tenantId || IsMetadataExpired(m, now))
            {
                return ValueTask.FromResult<MessageDetail?>(null);
            }

            ContentState state;
            MessageContent? content = null;
            if (!m.ContentRecorded)
            {
                state = ContentState.NotRecorded;
            }
            else if (now >= m.ReceivedAt.AddDays(s.Options.Content.RetentionDays) || !s.Content.TryGetValue(messageId, out var c))
            {
                state = ContentState.Expired;
            }
            else
            {
                state = ContentState.Available;
                content = new MessageContent(c.Subject, c.Text, c.Html, StorageJson.DeserializeAttachments(c.AttachmentsJson), c.Truncated);
            }

            bool rawRetained = m.RawRetained && s.RetainedRaw.ContainsKey(messageId) && now < m.ReceivedAt.AddDays(s.Options.Content.RetentionDays);
            var recipients = s.Recipients.TryGetValue(messageId, out var rs) ? rs.OrderBy(x => x, StringComparer.Ordinal).ToList() : [];
            return ValueTask.FromResult<MessageDetail?>(new MessageDetail(ToSummary(m), content, state, recipients, rawRetained));
        }
    }

    public ValueTask<IReadOnlyList<MessageEvent>> GetEventsAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken)
    {
        if (!s.IsFull)
        {
            return ValueTask.FromResult<IReadOnlyList<MessageEvent>>([]);
        }

        DateTimeOffset now = s.Clock.UtcNow;
        lock (s.Gate)
        {
            if (!s.Index.TryGetValue(messageId, out var m) || m.TenantId != tenantId || IsMetadataExpired(m, now) || !s.Events.TryGetValue(messageId, out var events))
            {
                return ValueTask.FromResult<IReadOnlyList<MessageEvent>>([]);
            }

            var list = events.OrderBy(e => MemoryState.IdText(e.EventId), StringComparer.Ordinal).Select(e => new MessageEvent(
                e.EventId, e.MessageId, e.DeliveryId, e.TenantId, e.Type, e.At, e.Recipient, e.SmtpCode, e.EnhancedCode, e.Message, e.MxHost, e.Route, StorageJson.DeserializeTls(e.TlsJson))).ToList();
            return ValueTask.FromResult<IReadOnlyList<MessageEvent>>(list);
        }
    }

    public ValueTask<Guid?> AttachReportAsync(Guid tenantId, string messageIdHeader, AsyncReport report, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(report);
        string? key = MessageIdKey.Normalize(messageIdHeader);
        if (!s.IsFull || key is null)
        {
            return ValueTask.FromResult<Guid?>(null);
        }

        DateTimeOffset now = s.Clock.UtcNow;
        lock (s.Gate)
        {
            var m = s.Index.Values
                .Where(x => x.TenantId == tenantId && x.MessageIdHeader == key && !IsMetadataExpired(x, now))
                .OrderByDescending(x => x.Day).ThenByDescending(x => MemoryState.IdText(x.MessageId), StringComparer.Ordinal).FirstOrDefault();
            if (m is null)
            {
                return ValueTask.FromResult<Guid?>(null);
            }

            if (!s.Events.TryGetValue(m.MessageId, out var events))
            {
                s.Events[m.MessageId] = events = [];
            }

            events.Add(new MessageEventEntity
            {
                Day = m.Day,
                MessageId = m.MessageId,
                EventId = EventIds.Next(report.At),
                TenantId = tenantId,
                Type = report.Type,
                At = StorageTime.Normalize(report.At),
                Recipient = report.Recipient,
                SmtpCode = report.SmtpCode,
                EnhancedCode = report.EnhancedCode,
                Message = report.Message,
            });
            m.Status = MessageStatus.AfterReport(m.Status, m.RecipientCount, report.Type);
            return ValueTask.FromResult<Guid?>(m.MessageId);
        }
    }

    public ValueTask<byte[]?> GetRetainedRawAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken)
    {
        if (!s.IsFull)
        {
            return ValueTask.FromResult<byte[]?>(null);
        }

        DateTimeOffset now = s.Clock.UtcNow;
        lock (s.Gate)
        {
            if (s.RetainedRaw.TryGetValue(messageId, out var raw) && raw.TenantId == tenantId
                && s.Index.TryGetValue(messageId, out var m) && now < m.ReceivedAt.AddDays(s.Options.Content.RetentionDays))
            {
                return ValueTask.FromResult<byte[]?>((byte[])raw.Raw.Clone());
            }

            return ValueTask.FromResult<byte[]?>(null);
        }
    }
}

internal sealed class MemoryWebhooks(MemoryState s) : IWebhookOutbox
{
    public bool MayHaveSubscribers(Guid tenantId, string eventType) => s.Config.HasEndpointFor(tenantId, eventType);

    public ValueTask<IReadOnlyList<WebhookOutboxItem>> ClaimDueAsync(string owner, int max, DateTimeOffset now, TimeSpan lease, CancellationToken cancellationToken)
    {
        if (s.Fence.IsClosed)
        {
            return ValueTask.FromResult<IReadOnlyList<WebhookOutboxItem>>([]);
        }

        now = StorageTime.Normalize(now);
        DateTimeOffset until = StorageTime.Normalize(now + lease);
        lock (s.Gate)
        {
            var rows = s.Outbox.Values.Where(o => o.TransferSwitchId is null && o.State == WebhookOutboxState.Pending && o.NextAttemptAt <= now && o.LeaseUntil <= now)
                .OrderBy(o => o.NextAttemptAt).ThenBy(o => MemoryState.IdText(o.Id), StringComparer.Ordinal).Take(Math.Max(0, max)).ToList();
            foreach (var o in rows)
            {
                o.LeaseOwner = owner;
                o.LeaseUntil = until;
            }

            return ValueTask.FromResult<IReadOnlyList<WebhookOutboxItem>>(rows.Select(o => new WebhookOutboxItem
            {
                Id = o.Id,
                EndpointId = o.EndpointId,
                TenantId = o.TenantId,
                EventType = o.EventType,
                EventId = o.EventId,
                PayloadJson = o.PayloadJson,
                Attempt = o.Attempt,
                NextAttemptAt = o.NextAttemptAt,
                CreatedAt = o.CreatedAt,
            }).ToList());
        }
    }

    public ValueTask CompleteAsync(Guid outboxId, WebhookAttemptRecord attempt, WebhookOutboxState newState, DateTimeOffset? nextAttemptAt, CancellationToken cancellationToken)
    {
        if (newState == WebhookOutboxState.Pending && nextAttemptAt is null)
        {
            throw new ArgumentException("A pending outbox item needs nextAttemptAt.", nameof(nextAttemptAt));
        }

        lock (s.Gate)
        {
            if (!s.Outbox.TryGetValue(outboxId, out var o))
            {
                return default;
            }

            o.Attempt++;
            o.State = newState;
            o.LeaseOwner = null;
            o.LeaseUntil = StorageTime.Epoch;
            if (newState == WebhookOutboxState.Pending)
            {
                o.NextAttemptAt = StorageTime.Normalize(nextAttemptAt!.Value);
                o.FinishedAt = null;
            }
            else
            {
                o.FinishedAt = StorageTime.Normalize(attempt.At);
            }

            s.WebhookAttempts.Add(new WebhookAttemptEntity
            {
                Seq = ++s.AttemptSeq,
                OutboxId = outboxId,
                EndpointId = o.EndpointId,
                TenantId = o.TenantId,
                At = StorageTime.Normalize(attempt.At),
                StatusCode = attempt.StatusCode,
                DurationMs = (long)attempt.Duration.TotalMilliseconds,
                ErrorClass = attempt.ErrorClass,
                ResponseSnippet = attempt.ResponseSnippet,
            });
        }

        return default;
    }

    public ValueTask<IReadOnlyList<WebhookAttemptRecord>> GetAttemptsAsync(Guid tenantId, Guid endpointId, int max, CancellationToken cancellationToken)
    {
        lock (s.Gate)
        {
            var list = s.WebhookAttempts.Where(a => a.TenantId == tenantId && a.EndpointId == endpointId).OrderByDescending(a => a.Seq).Take(Math.Max(0, max))
                .Select(a => new WebhookAttemptRecord(a.OutboxId, a.At, a.StatusCode, TimeSpan.FromMilliseconds(a.DurationMs), a.ErrorClass, a.ResponseSnippet)).ToList();
            return ValueTask.FromResult<IReadOnlyList<WebhookAttemptRecord>>(list);
        }
    }

    public ValueTask<int> EnqueueAsync(Guid tenantId, WebhookEventDraft draft, DateTimeOffset now, CancellationToken cancellationToken)
    {
        DateTimeOffset at = StorageTime.Normalize(now);
        lock (s.Gate)
        {
            int count = 0;
            foreach (Guid endpointId in s.Config.EndpointsFor(tenantId, draft.EventType))
            {
                Guid id = Ids.New(at);
                s.Outbox[id] = new WebhookOutboxEntity
                {
                    Id = id,
                    EndpointId = endpointId,
                    TenantId = tenantId,
                    EventType = draft.EventType,
                    EventId = draft.EventId,
                    PayloadJson = draft.PayloadJson,
                    NextAttemptAt = at,
                    State = WebhookOutboxState.Pending,
                    LeaseUntil = StorageTime.Epoch,
                    CreatedAt = at,
                };
                count++;
            }

            return ValueTask.FromResult(count);
        }
    }

    public ValueTask<Guid?> EnqueueForEndpointAsync(Guid tenantId, Guid endpointId, WebhookEventDraft draft, DateTimeOffset now, CancellationToken cancellationToken)
    {
        DateTimeOffset at = StorageTime.Normalize(now);
        lock (s.Gate)
        {
            if (!s.Config.IsEnabledEndpointOf(tenantId, endpointId))
            {
                return ValueTask.FromResult<Guid?>(null);
            }

            Guid id = Ids.New(at);
            s.Outbox[id] = new WebhookOutboxEntity
            {
                Id = id,
                EndpointId = endpointId,
                TenantId = tenantId,
                EventType = draft.EventType,
                EventId = draft.EventId,
                PayloadJson = draft.PayloadJson,
                NextAttemptAt = at,
                State = WebhookOutboxState.Pending,
                LeaseUntil = StorageTime.Epoch,
                CreatedAt = at,
            };
            return ValueTask.FromResult<Guid?>(id);
        }
    }

    public ValueTask<bool> ReplayAsync(Guid tenantId, Guid outboxId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        lock (s.Gate)
        {
            if (s.Outbox.TryGetValue(outboxId, out var o) && o.TenantId == tenantId && o.State != WebhookOutboxState.Pending)
            {
                o.State = WebhookOutboxState.Pending;
                o.Attempt = 0;
                o.NextAttemptAt = StorageTime.Normalize(now);
                o.LeaseOwner = null;
                o.LeaseUntil = StorageTime.Epoch;
                o.FinishedAt = null;
                return ValueTask.FromResult(true);
            }

            return ValueTask.FromResult(false);
        }
    }
}

internal sealed class MemoryMaintenance(MemoryState s) : IStorageMaintenance
{
    public ValueTask<IReadOnlyList<MaintenanceReport>> RunAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (s.Fence.IsClosed)
        {
            // A fenced source stays untouched until the switch is finalized or rolled back; a target is not live yet.
            return ValueTask.FromResult<IReadOnlyList<MaintenanceReport>>([]);
        }

        now = StorageTime.Normalize(now);
        var reports = new List<MaintenanceReport>();
        s.FlushStats();
        IReadOnlyDictionary<Guid, int?> inboundRetention = s.Config.InboundRetentionByDomain();
        lock (s.Gate)
        {
            RetentionOptions r = s.Options.Retention;

            long events = 0;
            if (RetentionCutoffs.DayKeyCutoff(now, r.MetadataDays) is { } metaDay)
            {
                foreach (Guid id in s.Index.Values.Where(m => m.Day < metaDay).Select(m => m.MessageId).ToList())
                {
                    events += (s.Events.TryGetValue(id, out var e) ? e.Count : 0) + 1;
                    s.Index.Remove(id);
                    s.Recipients.Remove(id);
                    s.Events.Remove(id);
                }
            }

            reports.Add(new MaintenanceReport("retention.metadata", TimeSpan.Zero, events, null));

            long content = 0;
            if (RetentionCutoffs.DayKeyCutoff(now, s.Options.Content.RetentionDays) is { } contentDay)
            {
                foreach (Guid id in s.Content.Where(kv => kv.Value.Day < contentDay).Select(kv => kv.Key).ToList())
                {
                    s.Content.Remove(id);
                    content++;
                }

                foreach (Guid id in s.RetainedRaw.Where(kv => kv.Value.Day < contentDay).Select(kv => kv.Key).ToList())
                {
                    s.RetainedRaw.Remove(id);
                    content++;
                }
            }

            reports.Add(new MaintenanceReport("retention.content", TimeSpan.Zero, content, null));

            long outbox = 0;
            if (RetentionCutoffs.InstantCutoff(now, r.WebhookOutboxDays) is { } outboxCutoff)
            {
                foreach (Guid id in s.Outbox.Values.Where(o => o.FinishedAt is { } f && f < outboxCutoff).Select(o => o.Id).ToList())
                {
                    s.Outbox.Remove(id);
                    outbox++;
                }
            }

            reports.Add(new MaintenanceReport("retention.webhook_outbox", TimeSpan.Zero, outbox, null));

            long attempts = 0;
            if (RetentionCutoffs.InstantCutoff(now, r.WebhookAttemptLogDays) is { } attemptCutoff)
            {
                attempts = s.WebhookAttempts.RemoveAll(a => a.At < attemptCutoff);
            }

            reports.Add(new MaintenanceReport("retention.webhook_attempts", TimeSpan.Zero, attempts, null));

            long rolled = Rollup(now);
            reports.Add(new MaintenanceReport("stats.rollup", TimeSpan.Zero, rolled, null));

            long statsDeleted = 0;
            if (RetentionCutoffs.StatsCutoff(now, r.StatsHourlyDays) is { } hourlyCutoff)
            {
                foreach (var k in s.StatRows.Keys.Where(k => !k.Daily && k.Period < hourlyCutoff).ToList())
                {
                    s.StatRows.Remove(k);
                    statsDeleted++;
                }
            }

            if (RetentionCutoffs.StatsCutoff(now, r.StatsDailyDays) is { } dailyCutoff)
            {
                foreach (var k in s.StatRows.Keys.Where(k => k.Daily && k.Period < dailyCutoff).ToList())
                {
                    s.StatRows.Remove(k);
                    statsDeleted++;
                }
            }

            reports.Add(new MaintenanceReport("stats.retention", TimeSpan.Zero, statsDeleted, null));

            int idem = 0;
            foreach (var k in s.Idempotency.Where(kv => kv.Value.ExpiresAt <= now).Select(kv => kv.Key).ToList())
            {
                s.Idempotency.Remove(k);
                idem++;
            }

            reports.Add(new MaintenanceReport("idempotency.expired", TimeSpan.Zero, idem, null));

            reports.Add(new MaintenanceReport("inbound_retention", TimeSpan.Zero, s.InboundStore.PurgeExpired(inboundRetention, s.Options.Inbound.RetentionDays, s.Options.Inbound.MaxRetentionDays, now), null));
        }

        return ValueTask.FromResult<IReadOnlyList<MaintenanceReport>>(reports);
    }

    private long Rollup(DateTimeOffset now)
    {
        int? first = s.StatRows.Keys.Where(k => !k.Daily).Select(k => (int?)StorageTime.DayNumber(k.Period)).Min();
        var (firstDay, lastDay) = StatsRollup.DaysToRoll(now, s.RollupWatermarkDay, first);
        long written = 0;
        for (int day = firstDay; day <= lastDay; day++)
        {
            DateTimeOffset start = StorageTime.DayStart(day);
            DateTimeOffset end = StorageTime.DayStart(day + 1);
            var hourly = s.StatRows.Where(kv => !kv.Key.Daily && kv.Key.Period >= start && kv.Key.Period < end)
                .Select(kv => StatsRollup.ToRow(kv.Key.Period, false, kv.Key.Tenant, kv.Key.Sending, kv.Key.Recipient, kv.Value)).ToList();
            if (hourly.Count == 0)
            {
                continue;
            }

            foreach (var k in s.StatRows.Keys.Where(k => k.Daily && k.Period == start).ToList())
            {
                s.StatRows.Remove(k);
            }

            foreach (StatRow row in StatsRollup.RollUpDay(hourly, start, s.Options.Retention.RecipientDomainTopNDaily))
            {
                var counts = new long[StatDelta.CounterCount];
                StatsRollup.Accumulate(counts, row);
                s.StatRows[(true, start, row.TenantId, row.SendingDomain, row.RecipientDomain)] = counts;
                written++;
            }
        }

        if (lastDay >= firstDay)
        {
            s.RollupWatermarkDay = lastDay;
        }

        return written;
    }

    public ValueTask<StorageHealth> GetHealthAsync(CancellationToken cancellationToken)
    {
        var warnings = new List<string>();
        foreach (string knob in StorageOptionsValidation.UnlimitedRetentionKnobs(s.Options))
        {
            warnings.Add("retention_unlimited:" + knob);
        }

        var details = new Dictionary<string, string>
        {
            ["backend"] = "inmemory",
            ["history_mode"] = s.Options.History.Mode.ToString(),
        };
        return ValueTask.FromResult(new StorageHealth(true, warnings, details));
    }

    /// <summary>Backups are not supported by the in-memory backend (returns null).</summary>
    public ValueTask<string?> BackupAsync(string directory, CancellationToken cancellationToken) => ValueTask.FromResult<string?>(null);
}
