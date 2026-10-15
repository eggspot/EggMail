using System.Runtime.InteropServices;
using Microsoft.Data.Sqlite;
using Mta.Core;
using Mta.Storage.Logic;

namespace Mta.Storage.Sqlite;

internal static class QueueSql
{
    public static readonly Stmt IdempotencyUpsert = new(
        "INSERT INTO api_idempotency_key (tenant_id, idempotency_key, message_id, created_at, expires_at, fingerprint) VALUES (@t, @k, @m, @c, @e, @f) " +
        "ON CONFLICT (tenant_id, idempotency_key) DO UPDATE SET message_id = excluded.message_id, created_at = excluded.created_at, expires_at = excluded.expires_at, fingerprint = excluded.fingerprint " +
        "WHERE api_idempotency_key.expires_at <= @now",
        "@t", "@k", "@m", "@c", "@e", "@f", "@now");

    public static readonly Stmt IdempotencyGet = new(
        "SELECT message_id, fingerprint FROM api_idempotency_key WHERE tenant_id = @t AND idempotency_key = @k",
        "@t", "@k");

    public static readonly Stmt SpoolInsert = new(
        "INSERT INTO message_spool (message_id, tenant_id, raw, size, pending_recipients, retain_raw, awaiting_retention, received_at) VALUES (@m, @t, @raw, @size, @n, @retain, 0, @rcv)",
        "@m", "@t", "@raw", "@size", "@n", "@retain", "@rcv");

    public static readonly Stmt DeliveryInsert = new(
        "INSERT INTO delivery_queue (id, message_id, tenant_id, envelope_from, recipient, recipient_domain, sending_domain, source, attempt, due_at, created_at, expires_at, lease_owner, lease_until, last_error, possible_duplicate, headers_utf8) " +
        "VALUES (@id, @m, @t, @from, @rcpt, @dom, @sd, @src, 0, @due, @due, @exp, NULL, 0, NULL, 0, @utf8)",
        "@id", "@m", "@t", "@from", "@rcpt", "@dom", "@sd", "@src", "@due", "@exp", "@utf8");

    private const string ClaimColumns =
        "id, message_id, tenant_id, envelope_from, recipient, recipient_domain, attempt, created_at, expires_at, lease_until, last_error, possible_duplicate, sending_domain, source, due_at, headers_utf8";

    public static readonly Stmt Claim = new(
        "UPDATE delivery_queue SET lease_owner = @owner, lease_until = @until, possible_duplicate = CASE WHEN lease_owner IS NOT NULL THEN 1 ELSE possible_duplicate END WHERE id IN (" +
        "SELECT id FROM delivery_queue WHERE transfer_switch_id IS NULL AND due_at <= @now AND lease_until <= @now AND expires_at > @now ORDER BY due_at, id LIMIT @max) " +
        "RETURNING " + ClaimColumns,
        "@owner", "@until", "@now", "@max");

    public static readonly Stmt ClaimExpired = new(
        "UPDATE delivery_queue SET lease_owner = @owner, lease_until = @until, possible_duplicate = CASE WHEN lease_owner IS NOT NULL THEN 1 ELSE possible_duplicate END WHERE id IN (" +
        "SELECT id FROM delivery_queue WHERE transfer_switch_id IS NULL AND expires_at <= @now AND lease_until <= @now ORDER BY expires_at, id LIMIT @max) " +
        "RETURNING " + ClaimColumns,
        "@owner", "@until", "@now", "@max");

    public static readonly Stmt DeliverySelect = new(
        "SELECT message_id, tenant_id, recipient, recipient_domain, sending_domain, source, attempt, possible_duplicate FROM delivery_queue WHERE id = @id",
        "@id");

    public static readonly Stmt CancelRows = new(
        "SELECT id, recipient, recipient_domain, sending_domain, source, attempt, lease_until, transfer_switch_id, lease_owner, possible_duplicate, envelope_from FROM delivery_queue WHERE message_id = @m AND tenant_id = @t",
        "@m", "@t");

    public static readonly Stmt DeliveryDelete = new("DELETE FROM delivery_queue WHERE id = @id", "@id");

    public static readonly Stmt DeliveryReschedule = new(
        "UPDATE delivery_queue SET attempt = attempt + 1, due_at = @due, lease_owner = NULL, lease_until = 0, last_error = @err, " +
        "possible_duplicate = CASE WHEN @dup = 1 THEN 1 ELSE possible_duplicate END WHERE id = @id",
        "@id", "@due", "@err", "@dup");

    public static readonly Stmt DeliveryHold = new(
        "UPDATE delivery_queue SET due_at = @due, lease_owner = NULL, lease_until = 0 WHERE id = @id", "@id", "@due");

    public static readonly Stmt DeliveryRequeue = new(
        "UPDATE delivery_queue SET lease_owner = NULL, lease_until = 0, possible_duplicate = CASE WHEN @dup = 1 THEN 1 ELSE possible_duplicate END WHERE id = @id",
        "@id", "@dup");

    public static readonly Stmt SpoolDecrement = new(
        "UPDATE message_spool SET pending_recipients = pending_recipients - 1 WHERE message_id = @m RETURNING pending_recipients, retain_raw",
        "@m");

    public static readonly Stmt SpoolAwaitRetention = new("UPDATE message_spool SET awaiting_retention = 1 WHERE message_id = @m", "@m");

    public static readonly Stmt SpoolDelete = new("DELETE FROM message_spool WHERE message_id = @m", "@m");

    public static readonly Stmt SpoolDeleteAllAwaiting = new("DELETE FROM message_spool WHERE awaiting_retention = 1");

    public static readonly Stmt SpoolDeleteIfAwaiting = new("DELETE FROM message_spool WHERE message_id = @m AND awaiting_retention = 1", "@m");

    public static readonly Stmt OutboxInsert = new(
        "INSERT INTO webhook_outbox (id, endpoint_id, tenant_id, event_type, event_id, payload_json, attempt, next_attempt_at, state, lease_owner, lease_until, created_at, finished_at) " +
        "VALUES (@id, @ep, @t, @type, @eid, @payload, 0, @at, 0, NULL, 0, @at, NULL)",
        "@id", "@ep", "@t", "@type", "@eid", "@payload", "@at");

    public static readonly Stmt ExtendLease = new("UPDATE delivery_queue SET lease_until = @until WHERE id = @id AND lease_owner = @owner", "@id", "@owner", "@until");

    public static readonly Stmt ReleaseExpired = new(
        "UPDATE delivery_queue SET lease_owner = NULL, lease_until = 0, possible_duplicate = 1 WHERE lease_owner IS NOT NULL AND lease_until <= @now", "@now");

    public static readonly Stmt ReleaseOwned = new("UPDATE delivery_queue SET lease_owner = NULL, lease_until = 0 WHERE lease_owner = @owner", "@owner");

    public static readonly Stmt ClearDeliveryLeases = new(
        "UPDATE delivery_queue SET possible_duplicate = CASE WHEN lease_owner IS NOT NULL THEN 1 ELSE possible_duplicate END, lease_owner = NULL, lease_until = 0 WHERE lease_owner IS NOT NULL OR lease_until <> 0");

    public static readonly Stmt ClearOutboxLeases = new(
        "UPDATE webhook_outbox SET lease_owner = NULL, lease_until = 0 WHERE lease_owner IS NOT NULL OR lease_until <> 0");

    public static readonly Stmt ClearInboundLeases = new(
        "UPDATE inbound_message SET lease_owner = NULL, lease_until = 0 WHERE lease_owner IS NOT NULL OR lease_until <> 0");

    public static readonly Stmt OutboxClaim = new(
        "UPDATE webhook_outbox SET lease_owner = @owner, lease_until = @until WHERE id IN (" +
        "SELECT id FROM webhook_outbox WHERE transfer_switch_id IS NULL AND state = 0 AND next_attempt_at <= @now AND lease_until <= @now ORDER BY next_attempt_at, id LIMIT @max) " +
        "RETURNING id, endpoint_id, tenant_id, event_type, event_id, payload_json, attempt, next_attempt_at, created_at",
        "@owner", "@until", "@now", "@max");

    public static readonly Stmt OutboxComplete = new(
        "UPDATE webhook_outbox SET attempt = attempt + 1, state = @state, next_attempt_at = COALESCE(@next, next_attempt_at), lease_owner = NULL, lease_until = 0, finished_at = @fin " +
        "WHERE id = @id RETURNING endpoint_id, tenant_id",
        "@id", "@state", "@next", "@fin");

    public static readonly Stmt OutboxReplay = new(
        "UPDATE webhook_outbox SET state = 0, attempt = 0, next_attempt_at = @now, lease_owner = NULL, lease_until = 0, finished_at = NULL WHERE id = @id AND tenant_id = @t AND state <> 0",
        "@id", "@t", "@now");

    public static readonly Stmt SpoolAwaitingList = new("SELECT message_id, tenant_id, received_at FROM message_spool WHERE awaiting_retention = 1 LIMIT @max", "@max");
}

internal readonly record struct AcceptState(AcceptedMessage Message, long NowMs, long KeyExpiresMs);

internal readonly record struct ClaimState(string Owner, int Max, long NowMs, long UntilMs);

internal readonly record struct AttemptState(DeliveryAttempt Attempt, WebhookTarget[] Targets, bool Full);

internal readonly record struct AttemptOutcome(bool Found, DeliveryRowInfo Row, AttemptPlan? Plan, bool NeedsRetention);

/// <summary>Intake, delivery queue and webhook outbox on queue.db (one writer; reads on short connections).</summary>
internal sealed class SqliteQueueStore(SqliteRuntime rt, SqliteHistoryStore history) : IMessageIntake, IDeliveryStore, IWebhookOutbox
{
    private static readonly TimeSpan ExpiredClaimLease = TimeSpan.FromMinutes(5);

    public bool MayHaveSubscribers(Guid tenantId, string eventType) => rt.AnyWebhookSubscriber(tenantId, eventType) ?? true;

    // Intake

    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
    public async ValueTask<IntakeResult> AcceptAsync(AcceptedMessage message, CancellationToken cancellationToken)
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

        rt.Fence.ThrowIfClosed();
        DateTimeOffset now = rt.Clock.UtcNow;
        var state = new AcceptState(message, StorageTime.ToUnixMs(now), StorageTime.ToUnixMs(now + rt.Options.Queue.IdempotencyKeyLifetime));
        IntakeResult result;
        try
        {
            result = await rt.QueueWriter.SubmitAsync(state, AcceptCommand, cancellationToken).ConfigureAwait(false);
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            throw new StorageConflictException($"Message {message.MessageId} or one of its deliveries already exists.", ex);
        }

        if (result.Status != IntakeStatus.Accepted)
        {
            return result;
        }

        // The message is queued and acknowledged-safe at this point. History is written after it (a crash in between leaves a
        // message without a history entry, never a history entry without a message).
        if (rt.IsFull)
        {
            try
            {
                await history.RecordAcceptedAsync(message, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                rt.Log.Write(MtaLogLevel.Error, "storage.sqlite", $"History entry for accepted message {message.MessageId} could not be written; the message is queued regardless.", ex);
            }
        }

        CountAccepted(message);
        return result;
    }

    private void CountAccepted(AcceptedMessage message)
    {
        DateTimeOffset hour = StorageTime.HourStart(message.ReceivedAt);
        string sending = message.SendingDomain ?? "";
        string? run = null;
        int count = 0;
        IReadOnlyList<AcceptedRecipient> recipients = message.Recipients;
        for (int i = 0; i < recipients.Count; i++)
        {
            string domain = recipients[i].Address.Domain;
            if (run is not null && string.Equals(run, domain, StringComparison.Ordinal))
            {
                count++;
                continue;
            }

            if (run is not null)
            {
                rt.Aggregator.Add(new StatKey(hour, message.TenantId, sending, run), StatCounter.Accepted, count);
            }

            run = domain;
            count = 1;
        }

        if (run is not null)
        {
            rt.Aggregator.Add(new StatKey(hour, message.TenantId, sending, run), StatCounter.Accepted, count);
        }
    }

    private static readonly Func<WriterContext, AcceptState, IntakeResult> AcceptCommand = static (ctx, s) =>
    {
        AcceptedMessage m = s.Message;
        if (m.IdempotencyKey is { } key)
        {
            int changed = ctx.Command(QueueSql.IdempotencyUpsert)
                .Set(0, m.TenantId).Set(1, key).Set(2, m.MessageId).Set(3, s.NowMs).Set(4, s.KeyExpiresMs).Set(5, m.IdempotencyFingerprint).Set(6, s.NowMs)
                .ExecuteNonQuery();
            if (changed == 0)
            {
                using RawReader r = ctx.Command(QueueSql.IdempotencyGet).Set(0, m.TenantId).Set(1, key).ExecuteReader();
                if (r.Read())
                {
                    return new IntakeResult(IntakeStatus.DuplicateIdempotencyKey, r.GetGuid(0), r.GetNullableString(1));
                }
            }
        }

        long received = StorageTime.ToUnixMs(m.ReceivedAt);
        ctx.Command(QueueSql.SpoolInsert)
            .Set(0, m.MessageId).Set(1, m.TenantId).Set(2, RawBytes(m.Raw)).Set(3, (long)m.Raw.Length)
            .Set(4, m.Recipients.Count).Set(5, m.RetainRaw ? 1 : 0).Set(6, received)
            .ExecuteNonQuery();

        long expires = StorageTime.ToUnixMs(m.ExpiresAt);
        PreparedCommand insert = ctx.Command(QueueSql.DeliveryInsert);
        IReadOnlyList<AcceptedRecipient> recipients = m.Recipients;
        for (int i = 0; i < recipients.Count; i++)
        {
            AcceptedRecipient r = recipients[i];
            insert.Set(0, r.DeliveryId).Set(1, m.MessageId).Set(2, m.TenantId).SetAddress(3, m.EnvelopeFrom)
                .SetAddress(4, r.Address).Set(5, r.Address.Domain).Set(6, m.SendingDomain)
                .Set(7, (long)m.Source).Set(8, received).Set(9, expires).Set(10, m.HeadersUtf8 ? 1 : 0)
                .ExecuteNonQuery();
        }

        return new IntakeResult(IntakeStatus.Accepted, m.MessageId);
    };

    /// <summary>The raw bytes as an array: the backing array itself when the memory covers it entirely, otherwise a copy.</summary>
    internal static byte[] RawBytes(ReadOnlyMemory<byte> raw) =>
        MemoryMarshal.TryGetArray(raw, out ArraySegment<byte> seg) && seg.Offset == 0 && seg.Count == seg.Array!.Length ? seg.Array : raw.ToArray();

    // Claiming

    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
    public async ValueTask<IReadOnlyList<ClaimedDelivery>> ClaimAsync(string owner, int max, DateTimeOffset now, TimeSpan lease, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(owner);
        if (max <= 0 || rt.Fence.IsClosed)
        {
            return [];
        }

        var state = new ClaimState(owner, max, StorageTime.ToUnixMs(now), StorageTime.ToUnixMs(now + lease));
        return await rt.QueueWriter.SubmitAsync(state, ClaimNormal, cancellationToken).ConfigureAwait(false);
    }

    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
    public async ValueTask<IReadOnlyList<ClaimedDelivery>> ClaimExpiredAsync(string owner, int max, DateTimeOffset now, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(owner);
        if (max <= 0 || rt.Fence.IsClosed)
        {
            return [];
        }

        var state = new ClaimState(owner, max, StorageTime.ToUnixMs(now), StorageTime.ToUnixMs(now + ExpiredClaimLease));
        return await rt.QueueWriter.SubmitAsync(state, ClaimExpiredCommand, cancellationToken).ConfigureAwait(false);
    }

    private static readonly Func<WriterContext, ClaimState, IReadOnlyList<ClaimedDelivery>> ClaimNormal = (ctx, s) => RunClaim(ctx, s, QueueSql.Claim);

    private static readonly Func<WriterContext, ClaimState, IReadOnlyList<ClaimedDelivery>> ClaimExpiredCommand = (ctx, s) => RunClaim(ctx, s, QueueSql.ClaimExpired);

    private static IReadOnlyList<ClaimedDelivery> RunClaim(WriterContext ctx, ClaimState s, Stmt stmt)
    {
        using RawReader r = ctx.Command(stmt).Set(0, s.Owner).Set(1, s.UntilMs).Set(2, s.NowMs).Set(3, (long)s.Max).ExecuteReader();
        var rows = new List<(long Due, ClaimedDelivery Delivery)>();
        // A batch is mostly one sender to a few domains: the text that repeats from one row to the next is made (and parsed) once.
        string? lastFrom = null, lastDomain = null, lastSending = null;
        EmailAddress lastFromAddress = default;
        while (r.Read())
        {
            string? fromBefore = lastFrom;
            string from = r.GetStringReusing(3, ref lastFrom);
            if (!ReferenceEquals(fromBefore, lastFrom) || fromBefore is null)
            {
                lastFromAddress = AddressText.Parse(from);
            }

            rows.Add((r.GetInt64(14), new ClaimedDelivery
            {
                DeliveryId = r.GetGuid(0),
                MessageId = r.GetGuid(1),
                TenantId = r.GetGuid(2),
                EnvelopeFrom = lastFromAddress,
                Recipient = AddressText.Parse(r.GetString(4)),
                RecipientDomain = r.GetStringReusing(5, ref lastDomain),
                Attempt = r.GetInt32(6),
                CreatedAt = r.GetInstant(7),
                ExpiresAt = r.GetInstant(8),
                LeaseUntil = r.GetInstant(9),
                LastError = r.GetNullableString(10),
                PossibleDuplicate = r.GetFlag(11),
                SendingDomain = r.GetNullableStringReusing(12, ref lastSending),
                Source = (MessageSource)r.GetInt32(13),
                HeadersUtf8 = r.GetFlag(15),
            }));
        }

        // RETURNING does not promise an order: due time, then the id's text (compared as its big-endian bytes, which sort the same way).
        rows.Sort(static (a, b) => a.Due != b.Due ? a.Due.CompareTo(b.Due) : CompareIdText(a.Delivery.DeliveryId, b.Delivery.DeliveryId));
        var claimed = new ClaimedDelivery[rows.Count];
        for (int i = 0; i < claimed.Length; i++)
        {
            claimed[i] = rows[i].Delivery;
        }

        return claimed;
    }

    private static int CompareIdText(Guid x, Guid y)
    {
        Span<byte> a = stackalloc byte[16];
        Span<byte> b = stackalloc byte[16];
        x.TryWriteBytes(a, bigEndian: true, out _);
        y.TryWriteBytes(b, bigEndian: true, out _);
        return a.SequenceCompareTo(b);
    }

    private static readonly Stmt SpoolRaw = new("SELECT raw FROM message_spool WHERE message_id = @m", "@m");

    public ValueTask<byte[]?> GetRawAsync(Guid messageId, CancellationToken cancellationToken)
    {
        if (rt.Queue.IsMemory)
        {
            // The in-memory queue has one connection, owned by its writer: the read runs there.
            return rt.QueueWriter.SubmitAsync(messageId, static (ctx, id) =>
            {
                using RawReader r = ctx.Command(SpoolRaw).Set(0, id).ExecuteReader();
                return r.Read() ? r.GetBytes(0) : null;
            }, cancellationToken);
        }

        using ReadLease lease = rt.Queue.ReadSessions.Rent();
        using RawReader row = lease.Session.Command(SpoolRaw).Set(0, messageId).ExecuteReader();
        return ValueTask.FromResult(row.Read() ? row.GetBytes(0) : null);
    }

    // Recording attempts

    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder))]
    public async ValueTask RecordAttemptAsync(DeliveryAttempt attempt, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(attempt);
        DateTimeOffset at = StorageTime.Normalize(attempt.At);

        // 1. Suppression first, in config.db. If the process dies after this and before the queue commit, the delivery is
        //    retried, bounces again, and this idempotent upsert is harmless.
        if (attempt.Suppress is { } reason)
        {
            (Guid tenant, string recipient, Guid messageId)? row = await ReadDeliveryKeyAsync(attempt.DeliveryId).ConfigureAwait(false);
            if (row is null)
            {
                return; // already final
            }

            await rt.ConfigStore.AddSuppressionAsync(
                new SuppressionRecord(row.Value.tenant, row.Value.recipient, reason, AttemptPlanner.DescribeError(attempt) ?? "delivery", at, row.Value.messageId),
                cancellationToken).ConfigureAwait(false);
        }

        WebhookTarget[] targets = attempt.WebhookEvents.Count == 0 ? [] : await rt.GetWebhookTargetsAsync(cancellationToken).ConfigureAwait(false);

        // 2. The queue transaction: row, spool counter, webhook outbox rows.
        AttemptOutcome outcome = await rt.QueueWriter.SubmitAsync(new AttemptState(attempt, targets, rt.IsFull), RecordAttemptCommand, cancellationToken).ConfigureAwait(false);
        if (!outcome.Found)
        {
            return;
        }

        AttemptPlan plan = outcome.Plan!;
        DeliveryRowInfo row2 = outcome.Row;

        // 3. Retained raw goes to history.db before the spool row is deleted (a crash between leaves both; reconcile removes the spool row).
        bool rawRetained = false;
        if (outcome.NeedsRetention)
        {
            rawRetained = await RetainAndFreeSpoolAsync(row2.MessageId, row2.TenantId, at, cancellationToken).ConfigureAwait(false);
        }

        // 4. History events, status, content lifecycle.
        if (rt.IsFull && plan.Events.Count > 0)
        {
            try
            {
                await history.ApplyAttemptAsync(plan, row2.MessageId, row2.TenantId, rawRetained, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                rt.Log.Write(MtaLogLevel.Error, "storage.sqlite", $"History events for delivery {row2.DeliveryId} could not be written.", ex);
            }
        }

        // 5. Statistics and the ring (in memory, flushed to stats.db).
        DateTimeOffset hour = StorageTime.HourStart(at);
        foreach (PlannedCounter c in plan.Counters)
        {
            rt.Aggregator.Add(new StatKey(hour, row2.TenantId, row2.SendingDomain ?? "", row2.RecipientDomain), c.Counter, c.Count);
        }

        foreach (RecentEvent e in plan.Ring)
        {
            rt.Aggregator.AddRecent(e);
        }
    }

    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
    private async ValueTask<(Guid Tenant, string Recipient, Guid MessageId)?> ReadDeliveryKeyAsync(Guid deliveryId) =>
        await rt.ReadAsync(rt.Queue, rt.QueueWriter, deliveryId, static (c, id) =>
        {
            using SqliteCommand cmd = c.CreateCommand();
            cmd.CommandText = "SELECT tenant_id, recipient, message_id FROM delivery_queue WHERE id = @id";
            cmd.Parameters.AddWithValue("@id", id);
            using SqliteDataReader r = cmd.ExecuteReader();
            return r.Read() ? ((Guid, string, Guid)?)(r.GetGuid(0), r.GetString(1), r.GetGuid(2)) : null;
        }).ConfigureAwait(false);

    private static readonly Func<WriterContext, AttemptState, AttemptOutcome> RecordAttemptCommand = static (ctx, s) =>
    {
        DeliveryAttempt a = s.Attempt;
        DeliveryRowInfo row;
        using (RawReader r = ctx.Command(QueueSql.DeliverySelect).Set(0, a.DeliveryId).ExecuteReader())
        {
            if (!r.Read())
            {
                return new AttemptOutcome(false, default, null, false);
            }

            row = new DeliveryRowInfo(a.DeliveryId, r.GetGuid(0), r.GetGuid(1), r.GetString(2), r.GetString(3), r.GetNullableString(4), (MessageSource)r.GetInt32(5), r.GetInt32(6), r.GetInt32(7) != 0);
        }

        AttemptPlan plan = AttemptPlanner.Plan(a, row);
        switch (plan.Action)
        {
            case QueueRowAction.Complete:
                ctx.Command(QueueSql.DeliveryDelete).Set(0, a.DeliveryId).ExecuteNonQuery();
                break;
            case QueueRowAction.Reschedule when !plan.CountAttempt:
                ctx.Command(QueueSql.DeliveryHold).Set(0, a.DeliveryId).Set(1, StorageTime.ToUnixMs(plan.NextAttemptAt!.Value)).ExecuteNonQuery();
                break;
            case QueueRowAction.Reschedule:
                ctx.Command(QueueSql.DeliveryReschedule)
                    .Set(0, a.DeliveryId).Set(1, StorageTime.ToUnixMs(plan.NextAttemptAt!.Value)).Set(2, plan.LastError).Set(3, plan.SetPossibleDuplicate ? 1 : 0)
                    .ExecuteNonQuery();
                break;
            default:
                ctx.Command(QueueSql.DeliveryRequeue).Set(0, a.DeliveryId).Set(1, plan.SetPossibleDuplicate ? 1 : 0).ExecuteNonQuery();
                break;
        }

        // Webhook fan-out in the same transaction as the completion: a crash cannot lose an event whose outcome is durable.
        if (plan.CountAttempt && a.WebhookEvents.Count > 0 && s.Targets.Length > 0)
        {
            FanOut(ctx, a.WebhookEvents, s.Targets, row.TenantId, a.At);
        }

        bool needsRetention = plan.IsFinal && FreeSpoolIfLast(ctx, row.MessageId, s.Full);

        return new AttemptOutcome(true, row, plan, needsRetention);
    };

    /// <summary>Writes one outbox row per (draft, enabled endpoint of the tenant that subscribes to its type), inside the caller's queue transaction.</summary>
    private static void FanOut(WriterContext ctx, IReadOnlyList<WebhookEventDraft> drafts, WebhookTarget[] targets, Guid tenantId, DateTimeOffset at)
    {
        long atMs = StorageTime.ToUnixMs(at);
        PreparedCommand insert = ctx.Command(QueueSql.OutboxInsert);
        foreach (WebhookEventDraft draft in drafts)
        {
            foreach (WebhookTarget target in targets)
            {
                if (target.TenantId != tenantId || !WebhookSubscriptions.Matches(target.EventTypes, draft.EventType))
                {
                    continue;
                }

                insert.Set(0, Ids.New(at)).Set(1, target.EndpointId).Set(2, tenantId).Set(3, draft.EventType).Set(4, draft.EventId).Set(5, draft.PayloadJson).Set(6, atMs)
                    .ExecuteNonQuery();
            }
        }
    }

    /// <summary>Counts one recipient of the message as final; with the last one, deletes the spool row (or marks it for the move of the raw message to history). True when the raw message must be retained.</summary>
    private static bool FreeSpoolIfLast(WriterContext ctx, Guid messageId, bool full)
    {
        int pending = 1;
        bool retain = false;
        using (RawReader r = ctx.Command(QueueSql.SpoolDecrement).Set(0, messageId).ExecuteReader())
        {
            if (r.Read())
            {
                pending = r.GetInt32(0);
                retain = r.GetFlag(1);
            }
        }

        if (pending > 0)
        {
            return false;
        }

        if (retain && full)
        {
            ctx.Command(QueueSql.SpoolAwaitRetention).Set(0, messageId).ExecuteNonQuery();
            return true;
        }

        ctx.Command(QueueSql.SpoolDelete).Set(0, messageId).ExecuteNonQuery();
        return false;
    }

    // Cancelling (decision 86)

    private readonly record struct CancelState(Guid Tenant, Guid Message, IReadOnlyList<string>? Recipients, long NowMs, DateTimeOffset Now, bool Full, Mta.Storage.Transfer.SwitchGate Fence, Func<CancelledDeliveryInfo, WebhookEventDraft?>? WebhookEvent, WebhookTarget[] Targets);

    private readonly record struct CancelledDelivery(DeliveryRowInfo Row, AttemptPlan Plan, bool NeedsRetention);

    private sealed record CancelOutcome(CancelResult Result, List<CancelledDelivery> Done);

    public async ValueTask<CancelResult> CancelAsync(Guid tenantId, Guid messageId, IReadOnlyList<string>? recipients, DateTimeOffset now, Func<CancelledDeliveryInfo, WebhookEventDraft?>? webhookEvent, CancellationToken cancellationToken)
    {
        rt.Fence.ThrowIfClosed();
        now = StorageTime.Normalize(now);
        WebhookTarget[] targets = webhookEvent is null ? [] : await rt.GetWebhookTargetsAsync(cancellationToken).ConfigureAwait(false);
        CancelOutcome outcome = await rt.QueueWriter.SubmitAsync(
            new CancelState(tenantId, messageId, recipients, StorageTime.ToUnixMs(now), now, rt.IsFull, rt.Fence, webhookEvent, targets), CancelCommand, cancellationToken).ConfigureAwait(false);

        // The queue rows are final and committed; the rest is what follows a recorded attempt (steps 3 to 5 of RecordAttemptAsync). History lives in another
        // file, so, exactly as for RecordAttemptAsync, a crash between the two leaves the queue right and the history without the event.
        foreach (CancelledDelivery done in outcome.Done)
        {
            bool rawRetained = false;
            if (done.NeedsRetention)
            {
                rawRetained = await RetainAndFreeSpoolAsync(done.Row.MessageId, done.Row.TenantId, now, cancellationToken).ConfigureAwait(false);
            }

            if (rt.IsFull)
            {
                try
                {
                    await history.ApplyAttemptAsync(done.Plan, done.Row.MessageId, done.Row.TenantId, rawRetained, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    rt.Log.Write(MtaLogLevel.Error, "storage.sqlite", $"History events for cancelled delivery {done.Row.DeliveryId} could not be written.", ex);
                }
            }

            foreach (RecentEvent e in done.Plan.Ring)
            {
                rt.Aggregator.AddRecent(e);
            }
        }

        return outcome.Result;
    }

    private static readonly Func<WriterContext, CancelState, CancelOutcome> CancelCommand = static (ctx, s) =>
    {
        s.Fence.ThrowIfClosed();   // again inside the writer, the one place that orders this against claims and recorded attempts
        var waiting = new List<PendingDelivery>();
        var rows = new Dictionary<Guid, (string Domain, string? SendingDomain, MessageSource Source)>();
        using (RawReader r = ctx.Command(QueueSql.CancelRows).Set(0, s.Message).Set(1, s.Tenant).ExecuteReader())
        {
            while (r.Read())
            {
                Guid id = r.GetGuid(0);
                CancelHold hold = !r.IsDBNull(7) ? CancelHold.TransferHeld : r.GetInt64(6) > s.NowMs ? CancelHold.Leased : CancelHold.None;
                waiting.Add(new PendingDelivery(id, r.GetString(1), r.GetString(10), r.GetInt32(5), CancelPlanner.OutcomeMayBeUnknown(r.GetFlag(9), !r.IsDBNull(8)), hold));
                rows[id] = (r.GetString(2), r.GetNullableString(3), (MessageSource)r.GetInt32(4));
            }
        }

        CancelSelection selection = CancelPlanner.Select(waiting, s.Recipients);
        var done = new List<CancelledDelivery>(selection.Cancel.Count);
        foreach (PendingDelivery d in selection.Cancel)
        {
            var (domain, sendingDomain, source) = rows[d.DeliveryId];
            var row = new DeliveryRowInfo(d.DeliveryId, s.Message, s.Tenant, d.Recipient, domain, sendingDomain, source, d.Attempt, d.PossibleDuplicate);
            DeliveryAttempt attempt = CancelPlanner.AttemptFor(d, s.Message, s.Tenant, s.Now, s.WebhookEvent);
            AttemptPlan plan = AttemptPlanner.Plan(attempt, row);
            ctx.Command(QueueSql.DeliveryDelete).Set(0, d.DeliveryId).ExecuteNonQuery();
            if (attempt.WebhookEvents.Count > 0 && s.Targets.Length > 0)
            {
                FanOut(ctx, attempt.WebhookEvents, s.Targets, s.Tenant, s.Now);
            }

            done.Add(new CancelledDelivery(row, plan, FreeSpoolIfLast(ctx, s.Message, s.Full)));
        }

        return new CancelOutcome(CancelPlanner.ResultOf(selection), done);
    };

    /// <summary>Copies the spool's raw message to retained storage, then deletes the spool row. Returns whether the copy exists.</summary>
    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
    internal async ValueTask<bool> RetainAndFreeSpoolAsync(Guid messageId, Guid tenantId, DateTimeOffset at, CancellationToken cancellationToken)
    {
        byte[]? raw = await GetRawAsync(messageId, cancellationToken).ConfigureAwait(false);
        if (raw is null)
        {
            return false;
        }

        await history.RetainRawAsync(messageId, tenantId, raw, at, cancellationToken).ConfigureAwait(false);
        await rt.QueueWriter.SubmitAsync(messageId, static (ctx, id) => ctx.Command(QueueSql.SpoolDeleteIfAwaiting).Set(0, id).ExecuteNonQuery(), cancellationToken).ConfigureAwait(false);
        return true;
    }

    // Leases

    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
    public async ValueTask<bool> ExtendLeaseAsync(Guid deliveryId, string owner, DateTimeOffset until, CancellationToken cancellationToken) =>
        await rt.QueueWriter.SubmitAsync((deliveryId, owner, StorageTime.ToUnixMs(until)), static (ctx, s) =>
            ctx.Command(QueueSql.ExtendLease).Set(0, s.deliveryId).Set(1, s.owner).Set(2, s.Item3).ExecuteNonQuery() > 0, cancellationToken).ConfigureAwait(false);

    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
    public async ValueTask<int> ReleaseExpiredLeasesAsync(DateTimeOffset now, CancellationToken cancellationToken) =>
        await rt.QueueWriter.SubmitAsync(StorageTime.ToUnixMs(now), static (ctx, ms) => ctx.Command(QueueSql.ReleaseExpired).Set(0, ms).ExecuteNonQuery(), cancellationToken).ConfigureAwait(false);

    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
    public async ValueTask<int> ReleaseOwnedLeasesAsync(string owner, CancellationToken cancellationToken) =>
        await rt.QueueWriter.SubmitAsync(owner, static (ctx, o) => ctx.Command(QueueSql.ReleaseOwned).Set(0, o).ExecuteNonQuery(), cancellationToken).ConfigureAwait(false);

    /// <summary>Startup: nothing can be in flight in a single-process backend, so every lease is cleared (delivery is at-least-once).</summary>
    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder))]
    internal async ValueTask ClearAllLeasesAsync(CancellationToken cancellationToken) =>
        await rt.QueueWriter.SubmitAsync(0, static (ctx, _) =>
        {
            ctx.Command(QueueSql.ClearDeliveryLeases).ExecuteNonQuery();
            ctx.Command(QueueSql.ClearInboundLeases).ExecuteNonQuery();
            return ctx.Command(QueueSql.ClearOutboxLeases).ExecuteNonQuery();
        }, cancellationToken).ConfigureAwait(false);

    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
    public async ValueTask<QueueStats> GetQueueStatsAsync(CancellationToken cancellationToken)
    {
        long nowMs = StorageTime.ToUnixMs(rt.Clock.UtcNow);
        return await rt.ReadAsync(rt.Queue, rt.QueueWriter, nowMs, static (c, now) =>
        {
            long queued, leased, deferred;
            long? oldest;
            using (SqliteCommand cmd = c.CreateCommand())
            {
                cmd.CommandText =
                    "SELECT COALESCE(SUM(CASE WHEN lease_until <= @now AND attempt = 0 THEN 1 ELSE 0 END), 0), " +
                    "COALESCE(SUM(CASE WHEN lease_until > @now THEN 1 ELSE 0 END), 0), " +
                    "COALESCE(SUM(CASE WHEN lease_until <= @now AND attempt > 0 THEN 1 ELSE 0 END), 0), " +
                    "MIN(CASE WHEN lease_until <= @now THEN due_at END) FROM delivery_queue";
                cmd.Parameters.AddWithValue("@now", now);
                using SqliteDataReader r = cmd.ExecuteReader();
                r.Read();
                queued = r.GetInt64(0);
                leased = r.GetInt64(1);
                deferred = r.GetInt64(2);
                oldest = r.IsDBNull(3) ? null : r.GetInt64(3);
            }

            long spool;
            using (SqliteCommand cmd = c.CreateCommand())
            {
                cmd.CommandText = "SELECT COALESCE(SUM(size), 0) FROM message_spool";
                spool = Convert.ToInt64(cmd.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
            }

            return new QueueStats(queued, leased, deferred, oldest is { } o ? StorageTime.FromUnixMs(o) : null, spool);
        }).ConfigureAwait(false);
    }

    // Webhook outbox

    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
    public async ValueTask<IReadOnlyList<WebhookOutboxItem>> ClaimDueAsync(string owner, int max, DateTimeOffset now, TimeSpan lease, CancellationToken cancellationToken)
    {
        if (max <= 0 || rt.Fence.IsClosed)
        {
            return [];
        }

        var state = new ClaimState(owner, max, StorageTime.ToUnixMs(now), StorageTime.ToUnixMs(now + lease));
        return await rt.QueueWriter.SubmitAsync(state, static (ctx, s) =>
        {
            using RawReader r = ctx.Command(QueueSql.OutboxClaim).Set(0, s.Owner).Set(1, s.UntilMs).Set(2, s.NowMs).Set(3, (long)s.Max).ExecuteReader();
            var rows = new List<WebhookOutboxItem>();
            while (r.Read())
            {
                rows.Add(new WebhookOutboxItem
                {
                    Id = r.GetGuid(0),
                    EndpointId = r.GetGuid(1),
                    TenantId = r.GetGuid(2),
                    EventType = r.GetString(3),
                    EventId = r.GetGuid(4),
                    PayloadJson = r.GetString(5),
                    Attempt = r.GetInt32(6),
                    NextAttemptAt = r.GetInstant(7),
                    CreatedAt = r.GetInstant(8),
                });
            }

            rows.Sort(static (a, b) => a.NextAttemptAt != b.NextAttemptAt ? a.NextAttemptAt.CompareTo(b.NextAttemptAt) : string.CompareOrdinal(a.Id.ToString(), b.Id.ToString()));
            return (IReadOnlyList<WebhookOutboxItem>)rows;
        }, cancellationToken).ConfigureAwait(false);
    }

    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder))]
    public async ValueTask CompleteAsync(Guid outboxId, WebhookAttemptRecord attempt, WebhookOutboxState newState, DateTimeOffset? nextAttemptAt, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(attempt);
        if (newState == WebhookOutboxState.Pending && nextAttemptAt is null)
        {
            throw new ArgumentException("A pending outbox item needs nextAttemptAt.", nameof(nextAttemptAt));
        }

        long? next = nextAttemptAt is { } n ? StorageTime.ToUnixMs(n) : null;
        long? finished = newState == WebhookOutboxState.Pending ? null : StorageTime.ToUnixMs(attempt.At);
        (Guid Endpoint, Guid Tenant)? owner = await rt.QueueWriter.SubmitAsync((outboxId, newState, next, finished), static (ctx, s) =>
        {
            using RawReader r = ctx.Command(QueueSql.OutboxComplete).Set(0, s.outboxId).Set(1, (long)s.newState).Set(2, s.next).Set(3, s.finished).ExecuteReader();
            return r.Read() ? ((Guid, Guid)?)(r.GetGuid(0), r.GetGuid(1)) : null;
        }, cancellationToken).ConfigureAwait(false);

        if (owner is null)
        {
            return;
        }

        // The attempt log lives in stats.db; losing a few rows in a crash is acceptable (design §6).
        await rt.StatsWriter.SubmitAsync((outboxId, owner.Value.Endpoint, owner.Value.Tenant, attempt), SqliteStatsStore.InsertWebhookAttempt, cancellationToken).ConfigureAwait(false);
    }

    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
    public async ValueTask<IReadOnlyList<WebhookAttemptRecord>> GetAttemptsAsync(Guid tenantId, Guid endpointId, int max, CancellationToken cancellationToken) =>
        await rt.ReadAsync(rt.Stats, rt.StatsWriter, (tenantId, endpointId, max), static (c, s) =>
        {
            using SqliteCommand cmd = c.CreateCommand();
            cmd.CommandText =
                "SELECT outbox_id, at, status_code, duration_ms, error_class, response_snippet FROM webhook_attempt " +
                "WHERE tenant_id = @t AND endpoint_id = @e ORDER BY seq DESC LIMIT @n";
            cmd.Parameters.AddWithValue("@t", s.tenantId);
            cmd.Parameters.AddWithValue("@e", s.endpointId);
            cmd.Parameters.AddWithValue("@n", (long)Math.Max(0, s.max));
            using SqliteDataReader r = cmd.ExecuteReader();
            var list = new List<WebhookAttemptRecord>();
            while (r.Read())
            {
                list.Add(new WebhookAttemptRecord(r.GetGuid(0), r.GetInstant(1), r.GetNullableInt(2), TimeSpan.FromMilliseconds(r.GetInt64(3)), r.GetNullableString(4), r.GetNullableString(5)));
            }

            return (IReadOnlyList<WebhookAttemptRecord>)list;
        }).ConfigureAwait(false);

    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
    public async ValueTask<int> EnqueueAsync(Guid tenantId, WebhookEventDraft draft, DateTimeOffset now, CancellationToken cancellationToken)
    {
        WebhookTarget[] targets = (await rt.GetWebhookTargetsAsync(cancellationToken).ConfigureAwait(false))
            .Where(t => t.TenantId == tenantId && WebhookSubscriptions.Matches(t.EventTypes, draft.EventType)).ToArray();
        if (targets.Length == 0)
        {
            return 0;
        }

        return await rt.QueueWriter.SubmitAsync((targets, draft, tenantId, now), static (ctx, s) =>
        {
            long atMs = StorageTime.ToUnixMs(s.now);
            PreparedCommand insert = ctx.Command(QueueSql.OutboxInsert);
            foreach (WebhookTarget target in s.targets)
            {
                insert.Set(0, Ids.New(s.now)).Set(1, target.EndpointId).Set(2, s.tenantId).Set(3, s.draft.EventType).Set(4, s.draft.EventId).Set(5, s.draft.PayloadJson).Set(6, atMs)
                    .ExecuteNonQuery();
            }

            return s.targets.Length;
        }, cancellationToken).ConfigureAwait(false);
    }

    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
    public async ValueTask<Guid?> EnqueueForEndpointAsync(Guid tenantId, Guid endpointId, WebhookEventDraft draft, DateTimeOffset now, CancellationToken cancellationToken)
    {
        bool known = (await rt.GetWebhookTargetsAsync(cancellationToken).ConfigureAwait(false)).Any(t => t.TenantId == tenantId && t.EndpointId == endpointId);
        if (!known)
        {
            return null;
        }

        return await rt.QueueWriter.SubmitAsync((endpointId, draft, tenantId, now), static (ctx, s) =>
        {
            Guid id = Ids.New(s.now);
            ctx.Command(QueueSql.OutboxInsert).Set(0, id).Set(1, s.endpointId).Set(2, s.tenantId).Set(3, s.draft.EventType).Set(4, s.draft.EventId).Set(5, s.draft.PayloadJson).Set(6, StorageTime.ToUnixMs(s.now))
                .ExecuteNonQuery();
            return (Guid?)id;
        }, cancellationToken).ConfigureAwait(false);
    }

    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
    public async ValueTask<bool> ReplayAsync(Guid tenantId, Guid outboxId, DateTimeOffset now, CancellationToken cancellationToken) =>
        await rt.QueueWriter.SubmitAsync((outboxId, tenantId, StorageTime.ToUnixMs(now)), static (ctx, s) =>
            ctx.Command(QueueSql.OutboxReplay).Set(0, s.outboxId).Set(1, s.tenantId).Set(2, s.Item3).ExecuteNonQuery() > 0, cancellationToken).ConfigureAwait(false);

    // Reconciliation (design §4.4): finish interrupted retained-raw hand-overs.

    /// <summary>
    /// A crash between "mark spool row awaiting retention" and "delete spool row" leaves a spool row whose raw message may or
    /// may not have reached history.db. This copies it (idempotently) and deletes the spool row. Returns rows reconciled.
    /// </summary>
    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
    internal async ValueTask<int> ReconcileSpoolAsync(CancellationToken cancellationToken)
    {
        if (!rt.IsFull)
        {
            // Without history there is nowhere to retain to; free the rows.
            return await rt.QueueWriter.SubmitAsync(0, static (ctx, _) => ctx.Command(QueueSql.SpoolDeleteAllAwaiting).ExecuteNonQuery(), cancellationToken).ConfigureAwait(false);
        }

        var pending = await rt.QueueWriter.SubmitAsync(1000, static (ctx, max) =>
        {
            using RawReader r = ctx.Command(QueueSql.SpoolAwaitingList).Set(0, (long)max).ExecuteReader();
            var list = new List<(Guid, Guid, DateTimeOffset)>();
            while (r.Read())
            {
                list.Add((r.GetGuid(0), r.GetGuid(1), r.GetInstant(2)));
            }

            return list;
        }, cancellationToken).ConfigureAwait(false);

        int done = 0;
        foreach ((Guid messageId, Guid tenantId, DateTimeOffset receivedAt) in pending)
        {
            if (await RetainAndFreeSpoolAsync(messageId, tenantId, rt.Clock.UtcNow, cancellationToken).ConfigureAwait(false))
            {
                done++;
            }
        }

        return done;
    }
}
