using System.Globalization;
using Mta.Core;
using Mta.Storage.Logic;
using Mta.Storage.Model;
using Npgsql;

namespace Mta.Storage.Postgres;

/// <summary>
/// Intake, delivery queue and webhook outbox on PostgreSQL. Every state change is one transaction that spans the queue, the
/// webhook outbox, the history tables and the suppression list (design §4.2), so none of the cross-file crash windows of the
/// SQLite backend exists here. Hot paths use hand-written SQL on Npgsql with positional parameters and <see cref="NpgsqlBatch"/>
/// (several statements, one round trip, one implicit transaction); EF is used only for configuration.
/// <para><b>Claim</b> is a single statement, <c>UPDATE … WHERE id IN (SELECT … FOR UPDATE SKIP LOCKED) RETURNING</c>, so any
/// number of workers on any number of replicas take disjoint rows without waiting for each other.</para>
/// <para><b>Failures.</b> A connectivity failure becomes <see cref="StorageUnavailableException"/> (the SMTP layer answers 451);
/// a uniqueness violation on intake becomes <see cref="StorageConflictException"/>, like on SQLite.</para>
/// </summary>
internal sealed class PostgresQueueStore(PostgresRuntime rt, PostgresHistoryStore history) : IMessageIntake, IDeliveryStore, IWebhookOutbox
{
    private static readonly TimeSpan ExpiredClaimLease = TimeSpan.FromMinutes(5);

    private const string ClaimColumns =
        "id, message_id, tenant_id, envelope_from, recipient, recipient_domain, attempt, created_at, expires_at, lease_until, last_error, possible_duplicate, sending_domain, source, due_at, headers_utf8";

    private const string ClaimSql =
        "UPDATE delivery_queue SET lease_owner = $1, lease_until = $2, possible_duplicate = possible_duplicate OR lease_owner IS NOT NULL WHERE id IN (" +
        "SELECT id FROM delivery_queue WHERE transfer_switch_id IS NULL AND due_at <= $3 AND lease_until <= $3 AND expires_at > $3 ORDER BY due_at, id LIMIT $4 FOR UPDATE SKIP LOCKED) " +
        "RETURNING " + ClaimColumns;

    private const string ClaimExpiredSql =
        "UPDATE delivery_queue SET lease_owner = $1, lease_until = $2, possible_duplicate = possible_duplicate OR lease_owner IS NOT NULL WHERE id IN (" +
        "SELECT id FROM delivery_queue WHERE transfer_switch_id IS NULL AND expires_at <= $3 AND lease_until <= $3 ORDER BY expires_at, id LIMIT $4 FOR UPDATE SKIP LOCKED) " +
        "RETURNING " + ClaimColumns;

    private const string OutboxInsertSql =
        "INSERT INTO webhook_outbox (id, endpoint_id, tenant_id, event_type, event_id, payload_json, attempt, next_attempt_at, state, lease_owner, lease_until, created_at, finished_at) " +
        "SELECT d.id, d.ep, $1, d.type, d.eid, d.payload, 0, $2, 0, NULL, 'epoch'::timestamptz, $2, NULL FROM unnest($3, $4, $5, $6, $7) AS d(id, ep, type, eid, payload)";

    public bool MayHaveSubscribers(Guid tenantId, string eventType) => rt.AnyWebhookSubscriber(tenantId, eventType) ?? true;

    // Intake

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
        int day = StorageTime.DayNumber(message.MessageId);
        bool writeHistory = rt.IsFull && history.MetadataWritable(day, now);
        MessageContent? content = writeHistory && ContentRules.ShouldRecord(rt.Options, message) ? ContentRules.Prepare(rt.Options, message.Content!) : null;
        string? subject = rt.Options.Content.StoreSubject ? message.Content?.Subject : null;
        bool storeContent = content is not null && history.ContentWritable(day, now);
        Guid eventId = EventIds.Next(message.ReceivedAt);

        IntakeResult result;
        try
        {
            result = await WithPartitionRetryAsync(async () =>
            {
                if (writeHistory)
                {
                    await rt.Partitions.EnsureDayAsync(day, force: false, cancellationToken).ConfigureAwait(false);
                }

                return await AcceptCoreAsync(message, now, day, writeHistory, content, storeContent, subject, eventId, cancellationToken).ConfigureAwait(false);
            }, () => writeHistory ? day : null, cancellationToken).ConfigureAwait(false);
        }
        catch (PostgresException ex) when (ex.SqlState == PostgresErrors.UniqueViolation)
        {
            throw new StorageConflictException($"Message {message.MessageId} or one of its deliveries already exists.", ex);
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex))
        {
            throw rt.Unavailable(ex);
        }

        if (result.Status == IntakeStatus.Accepted)
        {
            CountAccepted(message);
        }

        return result;
    }

    /// <summary>
    /// A write that hits a missing partition (dropped by another replica, or never created for this day) creates it and tries
    /// once more. The failed attempt has already given its connection and transaction back, so the partition is created while
    /// this caller holds no pooled connection: nothing here ever waits for a second connection while holding the first.
    /// </summary>
    private async Task<T> WithPartitionRetryAsync<T>(Func<Task<T>> body, Func<int?> missingDay, CancellationToken ct)
    {
        try
        {
            return await body().ConfigureAwait(false);
        }
        catch (PostgresException ex) when (ex.SqlState == PostgresErrors.CheckViolation && ex.MessageText.Contains("no partition", StringComparison.Ordinal))
        {
            rt.Partitions.ForgetAll();
            if (missingDay() is { } day)
            {
                await rt.Partitions.EnsureDayAsync(day, force: true, ct).ConfigureAwait(false);
            }

            return await body().ConfigureAwait(false);
        }
    }

    private async Task<IntakeResult> AcceptCoreAsync(AcceptedMessage m, DateTimeOffset now, int day, bool writeHistory, MessageContent? content, bool storeContent, string? subject, Guid eventId, CancellationToken ct)
    {
        await using NpgsqlConnection connection = await rt.Data.OpenConnectionAsync(ct).ConfigureAwait(false);
        NpgsqlTransaction? tx = null;
        try
        {
            if (m.IdempotencyKey is { } key)
            {
                // The key check needs its own result, so this path uses an explicit transaction. A concurrent insert of the same
                // key waits here for the first transaction to finish, then sees the row and falls through to the lookup.
                tx = await connection.BeginTransactionAsync(ct).ConfigureAwait(false);
                for (int attempt = 0; ; attempt++)
                {
                    await using var upsert = new NpgsqlCommand(
                        "INSERT INTO api_idempotency_key (tenant_id, idempotency_key, message_id, created_at, expires_at, fingerprint) VALUES ($1, $2, $3, $4, $5, $6) " +
                        "ON CONFLICT (tenant_id, idempotency_key) DO UPDATE SET message_id = excluded.message_id, created_at = excluded.created_at, expires_at = excluded.expires_at, fingerprint = excluded.fingerprint " +
                        "WHERE api_idempotency_key.expires_at <= $7", connection, tx);
                    upsert.Parameters.Uuid(m.TenantId).Text(key).Uuid(m.MessageId).Time(now).Time(now + rt.Options.Queue.IdempotencyKeyLifetime).Text(m.IdempotencyFingerprint).Time(now);
                    if (await upsert.ExecuteNonQueryAsync(ct).ConfigureAwait(false) > 0)
                    {
                        break; // the key is ours
                    }

                    await using var get = new NpgsqlCommand("SELECT message_id, fingerprint FROM api_idempotency_key WHERE tenant_id = $1 AND idempotency_key = $2", connection, tx);
                    get.Parameters.Uuid(m.TenantId).Text(key);
                    await using (NpgsqlDataReader found = await get.ExecuteReaderAsync(ct).ConfigureAwait(false))
                    {
                        if (await found.ReadAsync(ct).ConfigureAwait(false))
                        {
                            Guid existing = found.GetGuid(0);
                            string? fingerprint = found.IsDBNull(1) ? null : found.GetString(1);
                            await found.CloseAsync().ConfigureAwait(false);
                            await tx.RollbackAsync(ct).ConfigureAwait(false);
                            return new IntakeResult(IntakeStatus.DuplicateIdempotencyKey, existing, fingerprint);
                        }
                    }

                    if (attempt >= 2)
                    {
                        throw new StorageConflictException($"The idempotency key of message {m.MessageId} is being changed concurrently.");
                    }
                }
            }

            await using var batch = new NpgsqlBatch(connection, tx);

            NpgsqlBatchCommand spool = batch.CreateBatchCommand();
            spool.CommandText =
                "INSERT INTO message_spool (message_id, tenant_id, raw, size, pending_recipients, retain_raw, awaiting_retention, received_at) VALUES ($1, $2, $3, $4, $5, $6, false, $7)";
            spool.Parameters.Uuid(m.MessageId).Uuid(m.TenantId).Bytes(m.Raw).Long(m.Raw.Length).Int(m.Recipients.Count).Bool(m.RetainRaw).Time(m.ReceivedAt);
            batch.BatchCommands.Add(spool);

            NpgsqlBatchCommand deliveries = batch.CreateBatchCommand();
            deliveries.CommandText =
                "INSERT INTO delivery_queue (id, message_id, tenant_id, envelope_from, recipient, recipient_domain, sending_domain, source, attempt, due_at, created_at, expires_at, lease_owner, lease_until, last_error, possible_duplicate, headers_utf8) " +
                "SELECT d.id, $2, $3, $4, d.rcpt, d.dom, $5, $6, 0, $7, $7, $8, NULL, 'epoch'::timestamptz, NULL, false, $11 FROM unnest($1, $9, $10) AS d(id, rcpt, dom)";
            deliveries.Parameters.UuidArray(m.Recipients.Select(r => r.DeliveryId).ToArray()).Uuid(m.MessageId).Uuid(m.TenantId)
                .Text(AddressText.Format(m.EnvelopeFrom)).Text(m.SendingDomain).Small((int)m.Source).Time(m.ReceivedAt).Time(m.ExpiresAt)
                .TextArray(m.Recipients.Select(r => AddressText.Format(r.Address)).ToArray())
                .TextArray(m.Recipients.Select(r => r.Address.Domain).ToArray())
                .Bool(m.HeadersUtf8);
            batch.BatchCommands.Add(deliveries);

            if (writeHistory)
            {
                history.AppendAccepted(batch, m, day, content, storeContent, subject, eventId);
            }

            await batch.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            if (tx is not null)
            {
                await tx.CommitAsync(ct).ConfigureAwait(false);
            }

            return new IntakeResult(IntakeStatus.Accepted, m.MessageId);
        }
        finally
        {
            if (tx is not null)
            {
                await tx.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private void CountAccepted(AcceptedMessage message)
    {
        DateTimeOffset hour = StorageTime.HourStart(message.ReceivedAt);
        string sending = message.SendingDomain ?? "";
        string? run = null;
        int count = 0;
        foreach (AcceptedRecipient r in message.Recipients)
        {
            string domain = r.Address.Domain;
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

    // Claiming

    public async ValueTask<IReadOnlyList<ClaimedDelivery>> ClaimAsync(string owner, int max, DateTimeOffset now, TimeSpan lease, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(owner);
        return max <= 0 || rt.Fence.IsClosed ? [] : await RunClaimAsync(ClaimSql, owner, max, now, lease, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<IReadOnlyList<ClaimedDelivery>> ClaimExpiredAsync(string owner, int max, DateTimeOffset now, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(owner);
        return max <= 0 || rt.Fence.IsClosed ? [] : await RunClaimAsync(ClaimExpiredSql, owner, max, now, ExpiredClaimLease, cancellationToken).ConfigureAwait(false);
    }

    private async Task<IReadOnlyList<ClaimedDelivery>> RunClaimAsync(string sql, string owner, int max, DateTimeOffset now, TimeSpan lease, CancellationToken ct)
    {
        try
        {
            await using NpgsqlConnection connection = await rt.Data.OpenConnectionAsync(ct).ConfigureAwait(false);
            await using var cmd = new NpgsqlCommand(sql, connection);
            cmd.Parameters.Text(owner).Time(now + lease).Time(now).Long(max);
            var rows = new List<(DateTimeOffset Due, ClaimedDelivery Delivery)>();
            await using NpgsqlDataReader r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await r.ReadAsync(ct).ConfigureAwait(false))
            {
                rows.Add((r.GetInstant(14), new ClaimedDelivery
                {
                    DeliveryId = r.GetGuid(0),
                    MessageId = r.GetGuid(1),
                    TenantId = r.GetGuid(2),
                    EnvelopeFrom = AddressText.Parse(r.GetString(3)),
                    Recipient = AddressText.Parse(r.GetString(4)),
                    RecipientDomain = r.GetString(5),
                    Attempt = r.GetInt32(6),
                    CreatedAt = r.GetInstant(7),
                    ExpiresAt = r.GetInstant(8),
                    LeaseUntil = r.GetInstant(9),
                    LastError = r.GetNullableString(10),
                    PossibleDuplicate = r.GetBoolean(11),
                    SendingDomain = r.GetNullableString(12),
                    Source = (MessageSource)r.GetInt16(13),
                    HeadersUtf8 = r.GetBoolean(15),
                }));
            }

            // RETURNING does not promise an order; the byte order of a uuid equals the order of its canonical text.
            rows.Sort(static (a, b) => a.Due != b.Due ? a.Due.CompareTo(b.Due) : string.CompareOrdinal(a.Delivery.DeliveryId.ToString(), b.Delivery.DeliveryId.ToString()));
            return rows.Select(x => x.Delivery).ToList();
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex))
        {
            throw rt.Unavailable(ex);
        }
    }

    public async ValueTask<byte[]?> GetRawAsync(Guid messageId, CancellationToken cancellationToken)
    {
        try
        {
            await using NpgsqlConnection connection = await rt.Data.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var cmd = new NpgsqlCommand("SELECT raw FROM message_spool WHERE message_id = $1", connection);
            cmd.Parameters.Uuid(messageId);
            await using NpgsqlDataReader r = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            return await r.ReadAsync(cancellationToken).ConfigureAwait(false) ? r.GetFieldValue<byte[]>(0) : null;
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex))
        {
            throw rt.Unavailable(ex);
        }
    }

    // Recording attempts

    private readonly record struct AttemptResult(bool Found, DeliveryRowInfo Row, AttemptPlan? Plan);

    public async ValueTask RecordAttemptAsync(DeliveryAttempt attempt, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(attempt);
        AttemptResult result;
        try
        {
            WebhookTarget[] targets = attempt.WebhookEvents.Count == 0 ? [] : await rt.GetWebhookTargetsAsync(cancellationToken).ConfigureAwait(false);
            int? historyDay = null;
            result = await WithPartitionRetryAsync(() => RecordAttemptCoreAsync(attempt, targets, d => historyDay = d, cancellationToken), () => historyDay, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex))
        {
            throw rt.Unavailable(ex);
        }

        if (!result.Found)
        {
            return;
        }

        // Statistics and the ring are in memory and flushed about every 10 s (a crash loses at most that window).
        AttemptPlan plan = result.Plan!;
        DateTimeOffset hour = StorageTime.HourStart(StorageTime.Normalize(attempt.At));
        foreach (PlannedCounter c in plan.Counters)
        {
            rt.Aggregator.Add(new StatKey(hour, result.Row.TenantId, result.Row.SendingDomain ?? "", result.Row.RecipientDomain), c.Counter, c.Count);
        }

        foreach (RecentEvent e in plan.Ring)
        {
            rt.Aggregator.AddRecent(e);
        }
    }

    private async Task<AttemptResult> RecordAttemptCoreAsync(DeliveryAttempt a, WebhookTarget[] targets, Action<int?> historyDayWritten, CancellationToken ct)
    {
        DateTimeOffset at = StorageTime.Normalize(a.At);
        await using NpgsqlConnection connection = await rt.Data.OpenConnectionAsync(ct).ConfigureAwait(false);
        await using NpgsqlTransaction tx = await connection.BeginTransactionAsync(ct).ConfigureAwait(false);

        // 1. Lock the delivery row. A repeated report of the same attempt waits here and then finds the row gone.
        DeliveryRowInfo row;
        await using (var select = new NpgsqlCommand(
            "SELECT message_id, tenant_id, recipient, recipient_domain, sending_domain, source, attempt FROM delivery_queue WHERE id = $1 FOR UPDATE", connection, tx))
        {
            select.Parameters.Uuid(a.DeliveryId);
            await using NpgsqlDataReader r = await select.ExecuteReaderAsync(ct).ConfigureAwait(false);
            if (!await r.ReadAsync(ct).ConfigureAwait(false))
            {
                return new AttemptResult(false, default, null);
            }

            row = new DeliveryRowInfo(a.DeliveryId, r.GetGuid(0), r.GetGuid(1), r.GetString(2), r.GetString(3), r.GetNullableString(4), (MessageSource)r.GetInt16(5), r.GetInt32(6));
        }

        AttemptResult result = await ApplyAttemptLockedAsync(connection, tx, row, a, targets, historyDayWritten, ct).ConfigureAwait(false);
        await tx.CommitAsync(ct).ConfigureAwait(false);
        return result;
    }

    /// <summary>Everything a recorded attempt does once its delivery row is locked in the open transaction; the caller commits.</summary>
    private async Task<AttemptResult> ApplyAttemptLockedAsync(NpgsqlConnection connection, NpgsqlTransaction tx, DeliveryRowInfo row, DeliveryAttempt a, WebhookTarget[] targets, Action<int?> historyDayWritten, CancellationToken ct)
    {
        DateTimeOffset at = StorageTime.Normalize(a.At);
        AttemptPlan plan = AttemptPlanner.Plan(a, row);
        int day = StorageTime.DayNumber(row.MessageId);
        DateTimeOffset now = rt.Clock.UtcNow;
        bool writeHistory = rt.IsFull && plan.Events.Count > 0 && history.MetadataWritable(day, now);
        // The day's partitions were created when the message was accepted; if they are not there (another replica dropped them, or the
        // message was accepted before history was on) the first write fails with "no partition", the transaction is rolled back and
        // WithPartitionRetryAsync creates them with no connection held. Nothing is created here, inside the transaction.
        historyDayWritten(writeHistory ? day : null);

        // 2. The spool counter first (RETURNING is read below), then suppression, the queue row and the webhook fan-out: one round trip.
        await using var batch = new NpgsqlBatch(connection, tx);
        if (plan.IsFinal)
        {
            NpgsqlBatchCommand dec = batch.CreateBatchCommand();
            dec.CommandText = "UPDATE message_spool SET pending_recipients = pending_recipients - 1 WHERE message_id = $1 RETURNING pending_recipients, retain_raw";
            dec.Parameters.Uuid(row.MessageId);
            batch.BatchCommands.Add(dec);
        }

        if (a.Suppress is { } reason)
        {
            // Suppression belongs to the same transaction as the completion: both or neither.
            SuppressionEntity s = new SuppressionRecord(row.TenantId, row.Recipient, reason, AttemptPlanner.DescribeError(a) ?? "delivery", at, row.MessageId).ToEntity();
            NpgsqlBatchCommand sup = batch.CreateBatchCommand();
            sup.CommandText =
                "INSERT INTO suppression (tenant_id, address, reason, source, created_at, message_id) VALUES ($1, $2, $3, $4, $5, $6) " +
                "ON CONFLICT (tenant_id, address) DO UPDATE SET reason = excluded.reason, source = excluded.source, created_at = excluded.created_at, message_id = excluded.message_id";
            sup.Parameters.Uuid(s.TenantId).Text(s.Address).Small((int)s.Reason).Text(s.Source).Time(s.CreatedAt).Uuid(s.MessageId);
            batch.BatchCommands.Add(sup);
        }

        NpgsqlBatchCommand rowCommand = batch.CreateBatchCommand();
        switch (plan.Action)
        {
            case QueueRowAction.Complete:
                rowCommand.CommandText = "DELETE FROM delivery_queue WHERE id = $1";
                rowCommand.Parameters.Uuid(a.DeliveryId);
                break;
            case QueueRowAction.Reschedule when !plan.CountAttempt:
                rowCommand.CommandText = "UPDATE delivery_queue SET due_at = $2, lease_owner = NULL, lease_until = 'epoch'::timestamptz WHERE id = $1";
                rowCommand.Parameters.Uuid(a.DeliveryId).Time(plan.NextAttemptAt!.Value);
                break;
            case QueueRowAction.Reschedule:
                rowCommand.CommandText =
                    "UPDATE delivery_queue SET attempt = attempt + 1, due_at = $2, lease_owner = NULL, lease_until = 'epoch'::timestamptz, last_error = $3, possible_duplicate = possible_duplicate OR $4 WHERE id = $1";
                rowCommand.Parameters.Uuid(a.DeliveryId).Time(plan.NextAttemptAt!.Value).Text(plan.LastError).Bool(plan.SetPossibleDuplicate);
                break;
            default:
                rowCommand.CommandText = "UPDATE delivery_queue SET lease_owner = NULL, lease_until = 'epoch'::timestamptz, possible_duplicate = possible_duplicate OR $2 WHERE id = $1";
                rowCommand.Parameters.Uuid(a.DeliveryId).Bool(plan.SetPossibleDuplicate);
                break;
        }

        batch.BatchCommands.Add(rowCommand);

        // Webhook fan-out in the same transaction as the completion: an event whose outcome is durable cannot be lost.
        if (plan.CountAttempt && a.WebhookEvents.Count > 0 && targets.Length > 0)
        {
            AppendOutboxFanOut(batch, a.WebhookEvents, targets.Where(t => t.TenantId == row.TenantId).ToArray(), row.TenantId, a.At);
        }

        int pending = 1;
        bool retain = false;
        await using (NpgsqlDataReader r = await batch.ExecuteReaderAsync(ct).ConfigureAwait(false))
        {
            if (plan.IsFinal && await r.ReadAsync(ct).ConfigureAwait(false))
            {
                pending = r.GetInt32(0);
                retain = r.GetBoolean(1);
            }
        }

        // 3. Free the spool with the last recipient; move the raw message to retention in the same transaction when requested.
        bool rawRetained = false;
        if (plan.IsFinal && pending <= 0)
        {
            await using var free = new NpgsqlBatch(connection, tx);
            bool move = retain && rt.IsFull && history.MetadataWritable(day, now) && history.ContentWritable(day, now);
            if (move)
            {
                history.AppendRetainRaw(free, row.MessageId, day, at);
                rawRetained = true;
            }

            NpgsqlBatchCommand del = free.CreateBatchCommand();
            del.CommandText = "DELETE FROM message_spool WHERE message_id = $1";
            del.Parameters.Uuid(row.MessageId);
            free.BatchCommands.Add(del);
            await free.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        // 4. History events, status, content lifecycle.
        if (writeHistory)
        {
            await history.ApplyAttemptAsync(connection, tx, plan, row.MessageId, rawRetained, ct).ConfigureAwait(false);
        }

        return new AttemptResult(true, row, plan);
    }

    // Cancelling (decision 80)

    public async ValueTask<CancelResult> CancelAsync(Guid tenantId, Guid messageId, IReadOnlyList<string>? recipients, DateTimeOffset now, CancellationToken cancellationToken)
    {
        rt.Fence.ThrowIfClosed();
        now = StorageTime.Normalize(now);
        List<AttemptResult> done;
        CancelResult result;
        try
        {
            int? historyDay = null;
            (result, done) = await WithPartitionRetryAsync(() => CancelCoreAsync(tenantId, messageId, recipients, now, d => historyDay = d, cancellationToken), () => historyDay, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex))
        {
            throw rt.Unavailable(ex);
        }

        // Statistics and the ring are in memory and flushed about every 10 s, as after a recorded attempt.
        foreach (AttemptResult r in done)
        {
            foreach (PlannedCounter c in r.Plan!.Counters)
            {
                rt.Aggregator.Add(new StatKey(StorageTime.HourStart(now), r.Row.TenantId, r.Row.SendingDomain ?? "", r.Row.RecipientDomain), c.Counter, c.Count);
            }

            foreach (RecentEvent e in r.Plan.Ring)
            {
                rt.Aggregator.AddRecent(e);
            }
        }

        return result;
    }

    private async Task<(CancelResult Result, List<AttemptResult> Done)> CancelCoreAsync(Guid tenantId, Guid messageId, IReadOnlyList<string>? recipients, DateTimeOffset now, Action<int?> historyDayWritten, CancellationToken ct)
    {
        await using NpgsqlConnection connection = await rt.Data.OpenConnectionAsync(ct).ConfigureAwait(false);
        await using NpgsqlTransaction tx = await connection.BeginTransactionAsync(ct).ConfigureAwait(false);

        // Lock every pending row of the message in id order. A claim skips locked rows and never waits (no deadlock); a recorded attempt or another
        // cancel holding a row makes this wait, and the lease column read afterwards is the committed one. A row that a claim committed first has a
        // lease in the future and is reported as in flight, so cancel and claim cannot both win a row.
        var pending = new List<PendingDelivery>();
        var rows = new Dictionary<Guid, DeliveryRowInfo>();
        await using (var select = new NpgsqlCommand(
            "SELECT id, recipient, recipient_domain, sending_domain, source, attempt, lease_until, transfer_switch_id FROM delivery_queue WHERE message_id = $1 AND tenant_id = $2 ORDER BY id FOR UPDATE", connection, tx))
        {
            select.Parameters.Uuid(messageId).Uuid(tenantId);
            await using NpgsqlDataReader r = await select.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await r.ReadAsync(ct).ConfigureAwait(false))
            {
                Guid id = r.GetGuid(0);
                string recipient = r.GetString(1);
                bool locked = r.GetInstant(6) > now || !r.IsDBNull(7);
                pending.Add(new PendingDelivery(id, recipient, locked));
                rows[id] = new DeliveryRowInfo(id, messageId, tenantId, recipient, r.GetString(2), r.GetNullableString(3), (MessageSource)r.GetInt16(4), r.GetInt32(5));
            }
        }

        CancelSelection selection = CancelPlanner.Select(pending, recipients);
        var done = new List<AttemptResult>(selection.Cancel.Count);
        foreach (PendingDelivery d in selection.Cancel)
        {
            done.Add(await ApplyAttemptLockedAsync(connection, tx, rows[d.DeliveryId], CancelPlanner.AttemptFor(d.DeliveryId, now), [], historyDayWritten, ct).ConfigureAwait(false));
        }

        await tx.CommitAsync(ct).ConfigureAwait(false);
        return (CancelPlanner.ResultOf(selection), done);
    }

    private static void AppendOutboxFanOut(NpgsqlBatch batch, IReadOnlyList<WebhookEventDraft> drafts, WebhookTarget[] targets, Guid tenantId, DateTimeOffset at)
    {
        var ids = new List<Guid>();
        var endpoints = new List<Guid>();
        var types = new List<string?>();
        var eventIds = new List<Guid>();
        var payloads = new List<string?>();
        foreach (WebhookEventDraft draft in drafts)
        {
            foreach (WebhookTarget target in targets)
            {
                if (!WebhookSubscriptions.Matches(target.EventTypes, draft.EventType))
                {
                    continue;
                }

                ids.Add(Ids.New(at));
                endpoints.Add(target.EndpointId);
                types.Add(draft.EventType);
                eventIds.Add(draft.EventId);
                payloads.Add(draft.PayloadJson);
            }
        }

        if (ids.Count == 0)
        {
            return;
        }

        NpgsqlBatchCommand insert = batch.CreateBatchCommand();
        insert.CommandText = OutboxInsertSql;
        insert.Parameters.Uuid(tenantId).Time(at).UuidArray([.. ids]).UuidArray([.. endpoints]).TextArray([.. types]).UuidArray([.. eventIds]).TextArray([.. payloads]);
        batch.BatchCommands.Add(insert);
    }

    // Leases

    public async ValueTask<bool> ExtendLeaseAsync(Guid deliveryId, string owner, DateTimeOffset until, CancellationToken cancellationToken) =>
        await ExecuteAsync("UPDATE delivery_queue SET lease_until = $3 WHERE id = $1 AND lease_owner = $2", p => p.Uuid(deliveryId).Text(owner).Time(until), cancellationToken).ConfigureAwait(false) > 0;

    public async ValueTask<int> ReleaseExpiredLeasesAsync(DateTimeOffset now, CancellationToken cancellationToken) =>
        await ExecuteAsync("UPDATE delivery_queue SET lease_owner = NULL, lease_until = 'epoch'::timestamptz, possible_duplicate = true WHERE lease_owner IS NOT NULL AND lease_until <= $1", p => p.Time(now), cancellationToken).ConfigureAwait(false);

    public async ValueTask<int> ReleaseOwnedLeasesAsync(string owner, CancellationToken cancellationToken) =>
        await ExecuteAsync("UPDATE delivery_queue SET lease_owner = NULL, lease_until = 'epoch'::timestamptz WHERE lease_owner = $1", p => p.Text(owner), cancellationToken).ConfigureAwait(false);

    private async Task<int> ExecuteAsync(string sql, Action<NpgsqlParameterCollection> bind, CancellationToken ct)
    {
        try
        {
            await using NpgsqlConnection connection = await rt.Data.OpenConnectionAsync(ct).ConfigureAwait(false);
            await using var cmd = new NpgsqlCommand(sql, connection);
            bind(cmd.Parameters);
            return await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex))
        {
            throw rt.Unavailable(ex);
        }
    }

    public async ValueTask<QueueStats> GetQueueStatsAsync(CancellationToken cancellationToken)
    {
        DateTimeOffset now = rt.Clock.UtcNow;
        try
        {
            await using NpgsqlConnection connection = await rt.Data.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            long queued, leased, deferred;
            DateTimeOffset? oldest;
            await using (var cmd = new NpgsqlCommand(
                "SELECT COALESCE(SUM(CASE WHEN lease_until <= $1 AND attempt = 0 THEN 1 ELSE 0 END), 0)::bigint, " +
                "COALESCE(SUM(CASE WHEN lease_until > $1 THEN 1 ELSE 0 END), 0)::bigint, " +
                "COALESCE(SUM(CASE WHEN lease_until <= $1 AND attempt > 0 THEN 1 ELSE 0 END), 0)::bigint, " +
                "MIN(CASE WHEN lease_until <= $1 THEN due_at END) FROM delivery_queue", connection))
            {
                cmd.Parameters.Time(now);
                await using NpgsqlDataReader r = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
                await r.ReadAsync(cancellationToken).ConfigureAwait(false);
                queued = r.GetInt64(0);
                leased = r.GetInt64(1);
                deferred = r.GetInt64(2);
                oldest = r.GetNullableInstant(3);
            }

            long spool;
            await using (var cmd = new NpgsqlCommand("SELECT COALESCE(SUM(size), 0)::bigint FROM message_spool", connection))
            {
                spool = Convert.ToInt64(await cmd.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture);
            }

            return new QueueStats(queued, leased, deferred, oldest, spool);
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex))
        {
            throw rt.Unavailable(ex);
        }
    }

    // Webhook outbox

    public async ValueTask<IReadOnlyList<WebhookOutboxItem>> ClaimDueAsync(string owner, int max, DateTimeOffset now, TimeSpan lease, CancellationToken cancellationToken)
    {
        if (max <= 0 || rt.Fence.IsClosed)
        {
            return [];
        }

        try
        {
            await using NpgsqlConnection connection = await rt.Data.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var cmd = new NpgsqlCommand(
                "UPDATE webhook_outbox SET lease_owner = $1, lease_until = $2 WHERE id IN (" +
                "SELECT id FROM webhook_outbox WHERE transfer_switch_id IS NULL AND state = 0 AND next_attempt_at <= $3 AND lease_until <= $3 ORDER BY next_attempt_at, id LIMIT $4 FOR UPDATE SKIP LOCKED) " +
                "RETURNING id, endpoint_id, tenant_id, event_type, event_id, payload_json, attempt, next_attempt_at, created_at", connection);
            cmd.Parameters.Text(owner).Time(now + lease).Time(now).Long(max);
            var rows = new List<WebhookOutboxItem>();
            await using NpgsqlDataReader r = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await r.ReadAsync(cancellationToken).ConfigureAwait(false))
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
            return rows;
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex))
        {
            throw rt.Unavailable(ex);
        }
    }

    public async ValueTask CompleteAsync(Guid outboxId, WebhookAttemptRecord attempt, WebhookOutboxState newState, DateTimeOffset? nextAttemptAt, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(attempt);
        if (newState == WebhookOutboxState.Pending && nextAttemptAt is null)
        {
            throw new ArgumentException("A pending outbox item needs nextAttemptAt.", nameof(nextAttemptAt));
        }

        DateTimeOffset? finished = newState == WebhookOutboxState.Pending ? null : StorageTime.Normalize(attempt.At);

        // One statement: the state change and the attempt-log row commit together (an unknown item writes nothing).
        await ExecuteAsync(
            "WITH upd AS (UPDATE webhook_outbox SET attempt = attempt + 1, state = $2, next_attempt_at = COALESCE($3, next_attempt_at), lease_owner = NULL, lease_until = 'epoch'::timestamptz, finished_at = $4 " +
            "WHERE id = $1 RETURNING endpoint_id, tenant_id) " +
            "INSERT INTO webhook_attempt (outbox_id, endpoint_id, tenant_id, at, status_code, duration_ms, error_class, response_snippet) " +
            "SELECT $1, endpoint_id, tenant_id, $5, $6, $7, $8, $9 FROM upd",
            p => p.Uuid(outboxId).Small((int)newState).Time(nextAttemptAt).Time(finished).Time(attempt.At).Int(attempt.StatusCode)
                .Long((long)attempt.Duration.TotalMilliseconds).Text(attempt.ErrorClass).Text(attempt.ResponseSnippet),
            cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<IReadOnlyList<WebhookAttemptRecord>> GetAttemptsAsync(Guid tenantId, Guid endpointId, int max, CancellationToken cancellationToken)
    {
        try
        {
            await using NpgsqlConnection connection = await rt.Data.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var cmd = new NpgsqlCommand(
                "SELECT outbox_id, at, status_code, duration_ms, error_class, response_snippet FROM webhook_attempt WHERE tenant_id = $1 AND endpoint_id = $2 ORDER BY seq DESC LIMIT $3", connection);
            cmd.Parameters.Uuid(tenantId).Uuid(endpointId).Long(Math.Max(0, max));
            var list = new List<WebhookAttemptRecord>();
            await using NpgsqlDataReader r = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await r.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                list.Add(new WebhookAttemptRecord(r.GetGuid(0), r.GetInstant(1), r.GetNullableInt(2), TimeSpan.FromMilliseconds(r.GetInt64(3)), r.GetNullableString(4), r.GetNullableString(5)));
            }

            return list;
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex))
        {
            throw rt.Unavailable(ex);
        }
    }

    public async ValueTask<int> EnqueueAsync(Guid tenantId, WebhookEventDraft draft, DateTimeOffset now, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(draft);
        try
        {
            WebhookTarget[] targets = (await rt.GetWebhookTargetsAsync(cancellationToken).ConfigureAwait(false))
                .Where(t => t.TenantId == tenantId && WebhookSubscriptions.Matches(t.EventTypes, draft.EventType)).ToArray();
            if (targets.Length == 0)
            {
                return 0;
            }

            await using NpgsqlConnection connection = await rt.Data.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var batch = new NpgsqlBatch(connection);
            AppendOutboxFanOut(batch, [draft], targets, tenantId, now);
            return await batch.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex))
        {
            throw rt.Unavailable(ex);
        }
    }

    public async ValueTask<Guid?> EnqueueForEndpointAsync(Guid tenantId, Guid endpointId, WebhookEventDraft draft, DateTimeOffset now, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(draft);
        try
        {
            bool known = (await rt.GetWebhookTargetsAsync(cancellationToken).ConfigureAwait(false)).Any(t => t.TenantId == tenantId && t.EndpointId == endpointId);
            if (!known)
            {
                return null;
            }

            Guid id = Ids.New(now);
            await using NpgsqlConnection connection = await rt.Data.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var cmd = new NpgsqlCommand(
                "INSERT INTO webhook_outbox (id, endpoint_id, tenant_id, event_type, event_id, payload_json, attempt, next_attempt_at, state, lease_owner, lease_until, created_at, finished_at) " +
                "VALUES ($1, $2, $3, $4, $5, $6, 0, $7, 0, NULL, 'epoch'::timestamptz, $7, NULL)", connection);
            cmd.Parameters.Uuid(id).Uuid(endpointId).Uuid(tenantId).Text(draft.EventType).Uuid(draft.EventId).Text(draft.PayloadJson).Time(now);
            await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            return id;
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex))
        {
            throw rt.Unavailable(ex);
        }
    }

    public async ValueTask<bool> ReplayAsync(Guid tenantId, Guid outboxId, DateTimeOffset now, CancellationToken cancellationToken) =>
        await ExecuteAsync(
            "UPDATE webhook_outbox SET state = 0, attempt = 0, next_attempt_at = $3, lease_owner = NULL, lease_until = 'epoch'::timestamptz, finished_at = NULL WHERE id = $1 AND tenant_id = $2 AND state <> 0",
            p => p.Uuid(outboxId).Uuid(tenantId).Time(now), cancellationToken).ConfigureAwait(false) > 0;
}
