using System.Runtime.CompilerServices;
using Mta.Storage.Logic;
using Mta.Storage.Model;
using Mta.Storage.Transfer;

namespace Mta.Storage.InMemory;

/// <summary>
/// <see cref="IStorageTransfer"/> for the in-memory backend: it hands out and takes in the same provider-neutral entity rows
/// as the relational providers, straight from and into the dictionaries of <see cref="MemoryState"/>.
/// </summary>
internal sealed class MemoryTransfer(MemoryState s) : IStorageTransfer
{
    private readonly Dictionary<(Guid Switch, string Chunk), TransferChunkRecord> _chunks = [];

    public SwitchGate Gate => s.Fence;

    public bool HasPart(TransferPart part) => part != TransferPart.History || s.IsFull;

    private void Require(TransferPart part)
    {
        if (!HasPart(part))
        {
            throw new StorageTransferException("This store has no history part (History:Mode=StatsOnly).");
        }
    }

    private static List<object> Copies<T>(IEnumerable<T> rows) where T : class => rows.Select(r => TransferTable.Clone(r)).ToList();

    private static bool InRange(int day, TransferRange r) => (r.FromDay is null || day >= r.FromDay) && (r.ToDay is null || day <= r.ToDay);

    private List<object> Rows(TransferTable table, TransferRange range)
    {
        switch (table.Part)
        {
            case TransferPart.Config:
                return s.Config.ReadTransferTable(table.Name);
            case TransferPart.Stats:
                lock (s.Gate)
                {
                    return table.Name switch
                    {
                        "stat_aggregate" => s.StatRows
                            .OrderBy(kv => kv.Key.Daily).ThenBy(kv => kv.Key.Period).ThenBy(kv => MemoryState.IdText(kv.Key.Tenant), StringComparer.Ordinal)
                            .ThenBy(kv => kv.Key.Sending, StringComparer.Ordinal).ThenBy(kv => kv.Key.Recipient, StringComparer.Ordinal)
                            .Select(kv => (object)ToAggregate(kv.Key, kv.Value)).ToList(),
                        "stat_meta" => s.RollupWatermarkDay is { } d ? [new StatMetaEntity { Key = "rollup_watermark", Value = d }] : [],
                        "recent_event" => s.Ring.Select(r => (object)new RecentEventEntity
                        {
                            Seq = r.Seq, At = r.Event.At, TenantId = r.Event.TenantId, EventType = r.Event.EventType, RecipientDomain = r.Event.RecipientDomain, Detail = r.Event.Detail,
                        }).ToList(),
                        "webhook_attempt" => Copies(s.WebhookAttempts.OrderBy(a => a.Seq)),
                        _ => throw new ArgumentOutOfRangeException(nameof(table), table.Name, "not a stats table"),
                    };
                }

            case TransferPart.Queue:
                lock (s.Gate)
                {
                    return table.Name switch
                    {
                        "delivery_queue" => Copies(s.Deliveries.Values.OrderBy(x => MemoryState.IdText(x.Id), StringComparer.Ordinal)),
                        "message_spool" => Copies(s.Spool.Values.OrderBy(x => MemoryState.IdText(x.MessageId), StringComparer.Ordinal)),
                        "webhook_outbox" => Copies(s.Outbox.Values.OrderBy(x => MemoryState.IdText(x.Id), StringComparer.Ordinal)),
                        "inbound_message" => Copies(s.InboundMessages.Values.OrderBy(x => MemoryState.IdText(x.Id), StringComparer.Ordinal)),
                        "inbound_message_raw" => Copies(s.InboundRaw.Values.OrderBy(x => MemoryState.IdText(x.MessageId), StringComparer.Ordinal)),
                        "api_idempotency_key" => Copies(s.Idempotency.Values.OrderBy(x => MemoryState.IdText(x.TenantId), StringComparer.Ordinal).ThenBy(x => x.IdempotencyKey, StringComparer.Ordinal)),
                        _ => throw new ArgumentOutOfRangeException(nameof(table), table.Name, "not a queue table"),
                    };
                }

            default:
                Require(TransferPart.History);
                lock (s.Gate)
                {
                    return table.Name switch
                    {
                        "message_index" => Copies(s.Index.Values.Where(x => InRange(x.Day, range)).OrderBy(x => x.Day).ThenBy(x => MemoryState.IdText(x.MessageId), StringComparer.Ordinal)),
                        "message_recipient" => s.Index.Values.Where(x => InRange(x.Day, range)).OrderBy(x => x.Day).ThenBy(x => MemoryState.IdText(x.MessageId), StringComparer.Ordinal)
                            .SelectMany(x => (s.Recipients.TryGetValue(x.MessageId, out var rs) ? rs : []).Order(StringComparer.Ordinal).Select(r => (object)new MessageRecipientEntity { Day = x.Day, MessageId = x.MessageId, Recipient = r })).ToList(),
                        "message_event" => s.Events.Values.SelectMany(e => e).Where(e => InRange(e.Day, range)).OrderBy(e => e.Day).ThenBy(e => MemoryState.IdText(e.MessageId), StringComparer.Ordinal).ThenBy(e => MemoryState.IdText(e.EventId), StringComparer.Ordinal)
                            .Select(e => TransferTable.Clone(e)).ToList(),
                        "message_content" => Copies(s.Content.Values.Where(x => InRange(x.Day, range)).OrderBy(x => x.Day).ThenBy(x => MemoryState.IdText(x.MessageId), StringComparer.Ordinal)),
                        "message_raw_retained" => Copies(s.RetainedRaw.Values.Where(x => InRange(x.Day, range)).OrderBy(x => x.Day).ThenBy(x => MemoryState.IdText(x.MessageId), StringComparer.Ordinal)),
                        _ => throw new ArgumentOutOfRangeException(nameof(table), table.Name, "not a history table"),
                    };
                }
        }
    }

    private static StatAggregateEntity ToAggregate((bool Daily, DateTimeOffset Period, Guid Tenant, string Sending, string Recipient) k, long[] c) => new()
    {
        Daily = k.Daily,
        PeriodStart = k.Period,
        TenantId = k.Tenant,
        SendingDomain = k.Sending,
        RecipientDomain = k.Recipient,
        Accepted = c[(int)StatCounter.Accepted],
        Delivered = c[(int)StatCounter.Delivered],
        Deferred = c[(int)StatCounter.Deferred],
        HardBounce = c[(int)StatCounter.HardBounce],
        SoftBounce = c[(int)StatCounter.SoftBounce],
        Expired = c[(int)StatCounter.Expired],
        Complained = c[(int)StatCounter.Complained],
        Rejected = c[(int)StatCounter.Rejected],
        Suppressed = c[(int)StatCounter.Suppressed],
    };

    public async IAsyncEnumerable<object> ReadAsync(TransferTable table, TransferRange range, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        Require(table.Part);
        foreach (object row in Rows(table, range))
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return row;
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    public ValueTask<long> CountAsync(TransferTable table, TransferRange range, CancellationToken cancellationToken)
    {
        Require(table.Part);
        return ValueTask.FromResult((long)Rows(table, range).Count);
    }

    public ValueTask<IReadOnlyList<int>> GetHistoryDaysAsync(CancellationToken cancellationToken)
    {
        if (!s.IsFull)
        {
            return ValueTask.FromResult<IReadOnlyList<int>>([]);
        }

        lock (s.Gate)
        {
            var days = s.Index.Values.Select(x => x.Day)
                .Concat(s.Content.Values.Select(x => x.Day)).Concat(s.RetainedRaw.Values.Select(x => x.Day)).Concat(s.Events.Values.SelectMany(e => e).Select(e => e.Day))
                .Distinct().Order().ToList();
            return ValueTask.FromResult<IReadOnlyList<int>>(days);
        }
    }

    public ValueTask<IReadOnlyList<string>> GetNonEmptyTablesAsync(CancellationToken cancellationToken)
    {
        var result = new List<string>();
        foreach (TransferTable table in TransferTables.All.Where(t => HasPart(t.Part)))
        {
            if (Rows(table, TransferRange.All).Count > 0)
            {
                result.Add(table.Name);
            }
        }

        return ValueTask.FromResult<IReadOnlyList<string>>(result);
    }

    public ValueTask<ChunkApplyOutcome> ApplyChunkAsync(TransferChunk chunk, IReadOnlyList<object> rows, CancellationToken cancellationToken)
    {
        Require(chunk.Table.Part);
        lock (s.Gate)
        {
            if (_chunks.TryGetValue((chunk.SwitchId, chunk.ChunkId), out TransferChunkRecord? existing))
            {
                if (!string.Equals(existing.Checksum, chunk.Checksum, StringComparison.OrdinalIgnoreCase))
                {
                    throw new StorageTransferException($"Chunk {chunk.ChunkId} was applied before with a different checksum ({existing.Checksum}, now {chunk.Checksum}); the bundle changed after the import started.");
                }

                return ValueTask.FromResult(ChunkApplyOutcome.AlreadyApplied);
            }

            Guid? hold = chunk.HoldRows ? chunk.SwitchId : null;
            switch (chunk.Table.Part)
            {
                case TransferPart.Config:
                    s.Config.AddTransferRows(chunk.Table.Name, rows);
                    break;
                case TransferPart.Stats:
                    AddStats(chunk.Table.Name, rows);
                    break;
                case TransferPart.Queue:
                    AddQueue(chunk.Table.Name, rows, hold);
                    break;
                default:
                    AddHistory(rows);
                    break;
            }

            _chunks[(chunk.SwitchId, chunk.ChunkId)] = new TransferChunkRecord(chunk.SwitchId, chunk.ChunkId, chunk.Table.Name, rows.Count, chunk.Checksum, StorageTime.Normalize(s.Clock.UtcNow));
        }

        return ValueTask.FromResult(ChunkApplyOutcome.Applied);
    }

    private void AddStats(string table, IReadOnlyList<object> rows)
    {
        foreach (object row in rows)
        {
            switch (row)
            {
                case StatAggregateEntity a:
                    var counts = new long[StatDelta.CounterCount];
                    counts[(int)StatCounter.Accepted] = a.Accepted;
                    counts[(int)StatCounter.Delivered] = a.Delivered;
                    counts[(int)StatCounter.Deferred] = a.Deferred;
                    counts[(int)StatCounter.HardBounce] = a.HardBounce;
                    counts[(int)StatCounter.SoftBounce] = a.SoftBounce;
                    counts[(int)StatCounter.Expired] = a.Expired;
                    counts[(int)StatCounter.Complained] = a.Complained;
                    counts[(int)StatCounter.Rejected] = a.Rejected;
                    counts[(int)StatCounter.Suppressed] = a.Suppressed;
                    s.StatRows[(a.Daily, a.PeriodStart, a.TenantId, a.SendingDomain, a.RecipientDomain)] = counts;
                    break;
                case StatMetaEntity m:
                    if (m.Key == "rollup_watermark")
                    {
                        s.RollupWatermarkDay = (int)m.Value;
                    }

                    break;
                case RecentEventEntity r:
                    s.Ring.Add((++s.RingSeq, new RecentEvent(r.At, r.TenantId, r.EventType, r.RecipientDomain, r.Detail)));
                    break;
                case WebhookAttemptEntity w:
                    w.Seq = ++s.AttemptSeq;
                    s.WebhookAttempts.Add(w);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(rows), table, "not a stats row");
            }
        }
    }

    private void AddQueue(string table, IReadOnlyList<object> rows, Guid? hold)
    {
        foreach (object row in rows)
        {
            switch (row)
            {
                case QueuedDeliveryEntity d:
                    d.TransferSwitchId = hold;
                    s.Deliveries[d.Id] = d;
                    break;
                case SpoolMessageEntity m:
                    s.Spool[m.MessageId] = m;
                    break;
                case WebhookOutboxEntity o:
                    o.TransferSwitchId = hold;
                    s.Outbox[o.Id] = o;
                    break;
                case IdempotencyKeyEntity k:
                    s.Idempotency[(k.TenantId, k.IdempotencyKey)] = k;
                    break;
                case InboundMessageEntity m:
                    m.TransferSwitchId = hold;
                    s.InboundMessages[m.Id] = m;
                    break;
                case InboundMessageRawEntity raw:
                    s.InboundRaw[raw.MessageId] = raw;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(rows), table, "not a queue row");
            }
        }
    }

    private void AddHistory(IReadOnlyList<object> rows)
    {
        foreach (object row in rows)
        {
            switch (row)
            {
                case MessageIndexEntity i:
                    s.Index[i.MessageId] = i;
                    break;
                case MessageRecipientEntity r:
                    if (!s.Recipients.TryGetValue(r.MessageId, out List<string>? list))
                    {
                        s.Recipients[r.MessageId] = list = [];
                    }

                    list.Add(r.Recipient);
                    break;
                case MessageEventEntity e:
                    if (!s.Events.TryGetValue(e.MessageId, out List<MessageEventEntity>? events))
                    {
                        s.Events[e.MessageId] = events = [];
                    }

                    events.Add(e);
                    break;
                case MessageContentEntity c:
                    s.Content[c.MessageId] = c;
                    break;
                case RetainedRawEntity raw:
                    s.RetainedRaw[raw.MessageId] = raw;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(rows), "not a history row");
            }
        }
    }

    public ValueTask<IReadOnlyList<TransferChunkRecord>> GetAppliedChunksAsync(Guid switchId, TransferPart part, CancellationToken cancellationToken)
    {
        lock (s.Gate)
        {
            var list = _chunks.Values.Where(c => c.SwitchId == switchId && TransferTables.ByName(c.Table).Part == part).OrderBy(c => c.ChunkId, StringComparer.Ordinal).ToList();
            return ValueTask.FromResult<IReadOnlyList<TransferChunkRecord>>(list);
        }
    }

    public ValueTask DiscardImportedAsync(Guid switchId, CancellationToken cancellationToken)
    {
        lock (s.Gate)
        {
            foreach (TransferTable t in TransferTables.Of(TransferPart.Config))
            {
                s.Config.ClearTransferTable(t.Name);
            }

            s.StatRows.Clear();
            s.RollupWatermarkDay = null;
            s.Ring.Clear();
            s.WebhookAttempts.Clear();
            s.Deliveries.Clear();
            s.Spool.Clear();
            s.Outbox.Clear();
            s.Idempotency.Clear();
            s.InboundMessages.Clear();
            s.InboundRaw.Clear();
            s.Index.Clear();
            s.Recipients.Clear();
            s.Events.Clear();
            s.Content.Clear();
            s.RetainedRaw.Clear();
            foreach (var key in _chunks.Keys.Where(k => k.Switch == switchId).ToList())
            {
                _chunks.Remove(key);
            }
        }

        return default;
    }

    public ValueTask<SwitchStateRecord?> GetStateAsync(CancellationToken cancellationToken) => s.Config.GetSwitchStateAsync(cancellationToken);

    public async ValueTask SetStateAsync(SwitchStateRecord state, CancellationToken cancellationToken)
    {
        await s.Config.SetSwitchStateAsync(state, cancellationToken).ConfigureAwait(false);
        s.Fence.Apply(state);
    }

    public ValueTask ClearStateAsync(CancellationToken cancellationToken)
    {
        s.Config.ClearSwitchState();
        s.Fence.Apply(null);
        return default;
    }

    public ValueTask<long> MarkQueueTransferredAsync(Guid switchId, CancellationToken cancellationToken)
    {
        lock (s.Gate)
        {
            long n = 0;
            foreach (QueuedDeliveryEntity d in s.Deliveries.Values.Where(d => d.TransferSwitchId is null))
            {
                d.TransferSwitchId = switchId;
                n++;
            }

            foreach (WebhookOutboxEntity o in s.Outbox.Values.Where(o => o.TransferSwitchId is null))
            {
                o.TransferSwitchId = switchId;
                n++;
            }

            foreach (InboundMessageEntity m in s.InboundMessages.Values.Where(m => m.TransferSwitchId is null))
            {
                m.TransferSwitchId = switchId;
                n++;
            }

            return ValueTask.FromResult(n);
        }
    }

    public ValueTask<long> ReleaseQueueAsync(Guid switchId, CancellationToken cancellationToken)
    {
        lock (s.Gate)
        {
            long n = 0;
            foreach (QueuedDeliveryEntity d in s.Deliveries.Values.Where(d => d.TransferSwitchId == switchId))
            {
                d.TransferSwitchId = null;
                n++;
            }

            foreach (WebhookOutboxEntity o in s.Outbox.Values.Where(o => o.TransferSwitchId == switchId))
            {
                o.TransferSwitchId = null;
                n++;
            }

            foreach (InboundMessageEntity m in s.InboundMessages.Values.Where(m => m.TransferSwitchId == switchId))
            {
                m.TransferSwitchId = null;
                n++;
            }

            return ValueTask.FromResult(n);
        }
    }

    public ValueTask<long> CountHeldQueueRowsAsync(Guid switchId, CancellationToken cancellationToken)
    {
        lock (s.Gate)
        {
            return ValueTask.FromResult((long)(s.Deliveries.Values.Count(d => d.TransferSwitchId == switchId) + s.Outbox.Values.Count(o => o.TransferSwitchId == switchId) + s.InboundMessages.Values.Count(m => m.TransferSwitchId == switchId)));
        }
    }
}
