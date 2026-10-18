using System.Text;
using Mta.Storage.Logic;
using Npgsql;

namespace Mta.Storage.Postgres;

/// <summary>
/// Per-message history on the day-partitioned tables (<see cref="HistoryMode.Full"/> only). Unlike SQLite, history is written
/// in the <b>same transaction</b> as the queue change (design §4.2: one transaction across all tables), so a message is never
/// acknowledged without its history row and an event never exists without its delivery outcome. Reads mirror the SQLite
/// provider statement for statement; only the dialect differs.
/// </summary>
internal sealed class PostgresHistoryStore(PostgresRuntime rt) : IHistoryStore, IMessageRecipientLookup
{
    public async ValueTask<IReadOnlyDictionary<Guid, IReadOnlyList<string>>> GetRecipientsAsync(Guid tenantId, IReadOnlyCollection<Guid> messageIds, int maxPerMessage, CancellationToken cancellationToken)
    {
        var result = new Dictionary<Guid, IReadOnlyList<string>>();
        if (!rt.IsFull || messageIds.Count == 0)
        {
            return result;
        }

        try
        {
            await using NpgsqlConnection c = await rt.Reader.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var cmd = new NpgsqlCommand(
                "SELECT r.message_id, r.recipient FROM message_recipient r JOIN message_index m ON m.day = r.day AND m.message_id = r.message_id " +
                "WHERE r.day = $1 AND r.message_id = $2 AND m.tenant_id = $3 ORDER BY r.recipient LIMIT $4", c);
            foreach (Guid messageId in messageIds)
            {
                cmd.Parameters.Clear();
                cmd.Parameters.Int(StorageTime.DayNumber(messageId)).Uuid(messageId).Uuid(tenantId).Long(Math.Max(0, maxPerMessage));
                var list = new List<string>();
                await using (NpgsqlDataReader r = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
                {
                    while (await r.ReadAsync(cancellationToken).ConfigureAwait(false))
                    {
                        list.Add(r.GetString(1));
                    }
                }

                if (list.Count > 0)
                {
                    result[messageId] = list;
                }
            }

            return result;
        }
        catch (Exception ex) when (PostgresErrors.IsStatementTimeout(ex, cancellationToken))
        {
            throw new StorageQueryTimeoutException("The read-only query ran past statement_timeout (Postgres:ReadOnlyStatementTimeoutSeconds).", ex);
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex))
        {
            throw rt.Unavailable(ex);
        }
    }

    // Writes (called by PostgresQueueStore inside its transaction)

    private const string IndexInsert =
        "INSERT INTO message_index (day, message_id, tenant_id, received_at, subject, envelope_from, recipient_count, final_count, delivered_count, failed_count, status, size, content_recorded, raw_retained, message_id_header, tags) " +
        "VALUES ($1, $2, $3, $4, $5, $6, $7, 0, 0, 0, 'queued', $8, $9, false, $10, $11)";

    private const string RecipientInsert =
        "INSERT INTO message_recipient (day, message_id, recipient) SELECT $1, $2, r FROM unnest($3) AS r ON CONFLICT DO NOTHING";

    private const string ContentInsert =
        "INSERT INTO message_content (day, message_id, tenant_id, subject, text, html, attachments_json, truncated) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";

    private const string EventInsert =
        "INSERT INTO message_event (day, message_id, event_id, delivery_id, tenant_id, type, at, recipient, smtp_code, enhanced_code, message, mx_host, route, tls_json) " +
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)";

    private const string IndexCounts =
        "UPDATE message_index SET final_count = final_count + $1, delivered_count = delivered_count + $2, failed_count = failed_count + $3 " +
        "WHERE day = $4 AND message_id = $5 RETURNING recipient_count, final_count, delivered_count, failed_count, status";

    private const string RetainedInsert =
        "INSERT INTO message_raw_retained (day, message_id, tenant_id, raw, retained_at) SELECT $1, message_id, tenant_id, raw, $3 FROM message_spool WHERE message_id = $2 " +
        "ON CONFLICT (day, message_id) DO UPDATE SET raw = excluded.raw, retained_at = excluded.retained_at";

    /// <summary>Whether history rows of this day are still inside the metadata retention (older ones would be dropped at once, so they are not written).</summary>
    internal bool MetadataWritable(int day, DateTimeOffset now) =>
        RetentionCutoffs.DayKeyCutoff(now, rt.Options.Retention.MetadataDays) is not { } cutoff || day >= cutoff;

    internal bool ContentWritable(int day, DateTimeOffset now) =>
        day >= RetentionCutoffs.DayKeyCutoff(now, rt.Options.Content.RetentionDays)!.Value;

    /// <summary>Appends the commands that record an accepted message: index row, recipients, content and the "queued" event.</summary>
    internal void AppendAccepted(NpgsqlBatch batch, AcceptedMessage m, int day, MessageContent? content, bool storeContent, string? subject, Guid eventId)
    {
        NpgsqlBatchCommand index = batch.CreateBatchCommand();
        index.CommandText = IndexInsert;
        index.Parameters.Int(day).Uuid(m.MessageId).Uuid(m.TenantId).Time(m.ReceivedAt).Text(subject).Text(AddressText.Format(m.EnvelopeFrom))
            .Int(m.Recipients.Count).Long(m.Raw.Length).Bool(content is not null).Text(MessageIdKey.Normalize(m.MessageIdHeader)).Text(StorageJson.SerializeTags(m.Tags));
        batch.BatchCommands.Add(index);

        NpgsqlBatchCommand recipients = batch.CreateBatchCommand();
        recipients.CommandText = RecipientInsert;
        recipients.Parameters.Int(day).Uuid(m.MessageId).TextArray(m.Recipients.Select(r => AddressText.Format(r.Address).ToLowerInvariant()).Distinct(StringComparer.Ordinal).ToArray());
        batch.BatchCommands.Add(recipients);

        if (content is not null && storeContent)
        {
            NpgsqlBatchCommand c = batch.CreateBatchCommand();
            c.CommandText = ContentInsert;
            c.Parameters.Int(day).Uuid(m.MessageId).Uuid(m.TenantId).Text(content.Subject).Text(content.Text).Text(content.Html)
                .Text(StorageJson.SerializeAttachments(content.Attachments)).Bool(content.Truncated);
            batch.BatchCommands.Add(c);
        }

        NpgsqlBatchCommand ev = batch.CreateBatchCommand();
        ev.CommandText = EventInsert;
        ev.Parameters.Int(day).Uuid(m.MessageId).Uuid(eventId).Uuid((Guid?)null).Uuid(m.TenantId).Small((int)MessageEventType.Queued).Time(m.ReceivedAt)
            .Text(null).Int((int?)null).Text(null).Text(null).Text(null).Text(null).Text(null);
        batch.BatchCommands.Add(ev);
    }

    /// <summary>Appends the INSERT that copies the spool's raw message to retained storage (same transaction as the spool delete).</summary>
    internal void AppendRetainRaw(NpgsqlBatch batch, Guid messageId, int day, DateTimeOffset at)
    {
        NpgsqlBatchCommand retain = batch.CreateBatchCommand();
        retain.CommandText = RetainedInsert;
        retain.Parameters.Int(day).Uuid(messageId).Time(at);
        batch.BatchCommands.Add(retain);
    }

    /// <summary>Events, message status and content lifecycle for one recorded attempt (<paramref name="connection"/> is inside the caller's transaction).</summary>
    internal async Task ApplyAttemptAsync(NpgsqlConnection connection, NpgsqlTransaction tx, AttemptPlan plan, Guid messageId, bool rawRetained, CancellationToken ct)
    {
        int day = StorageTime.DayNumber(messageId);
        await using var batch = new NpgsqlBatch(connection, tx);
        foreach (MessageEvent e in plan.Events)
        {
            NpgsqlBatchCommand ev = batch.CreateBatchCommand();
            ev.CommandText = EventInsert;
            ev.Parameters.Int(day).Uuid(messageId).Uuid(e.EventId).Uuid(e.DeliveryId).Uuid(e.TenantId).Small((int)e.Type).Time(e.At)
                .Text(e.Recipient).Int(e.SmtpCode).Text(e.EnhancedCode).Text(e.Message).Text(e.MxHost).Text(e.Route).Text(StorageJson.SerializeTls(e.Tls));
            batch.BatchCommands.Add(ev);
        }

        bool counts = plan.IsFinal || plan.Action == QueueRowAction.Reschedule;
        if (counts)
        {
            NpgsqlBatchCommand c = batch.CreateBatchCommand();
            c.CommandText = IndexCounts;
            c.Parameters.Int(plan.IsFinal ? 1 : 0).Int(plan.Delivered ? 1 : 0).Int(plan.Failed ? 1 : 0).Int(day).Uuid(messageId);
            batch.BatchCommands.Add(c);
        }

        int recipients = 0, final = 0, delivered = 0, failed = 0;
        string status = "";
        bool haveIndex = false;
        await using (NpgsqlDataReader r = await batch.ExecuteReaderAsync(ct).ConfigureAwait(false))
        {
            if (counts)
            {
                // Only the UPDATE … RETURNING produces a result set; the event inserts do not.
                if (await r.ReadAsync(ct).ConfigureAwait(false))
                {
                    haveIndex = true;
                    recipients = r.GetInt32(0);
                    final = r.GetInt32(1);
                    delivered = r.GetInt32(2);
                    failed = r.GetInt32(3);
                    status = r.GetString(4);
                }
            }
        }

        if (counts && !haveIndex)
        {
            return; // no index row (history was not written for this message): the events above stand alone
        }

        var follow = new NpgsqlBatch(connection, tx);
        await using (follow.ConfigureAwait(false))
        {
            if (counts)
            {
                string next = MessageStatus.Next(status, recipients, final, delivered, failed, MessageStatus.FinalKind(plan.Events[0].Type));
                if (!string.Equals(next, status, StringComparison.Ordinal))
                {
                    NpgsqlBatchCommand s = follow.CreateBatchCommand();
                    s.CommandText = "UPDATE message_index SET status = $1 WHERE day = $2 AND message_id = $3";
                    s.Parameters.Text(next).Int(day).Uuid(messageId);
                    follow.BatchCommands.Add(s);
                }

                if (plan.IsFinal && final >= recipients && !rt.Options.Content.Retain)
                {
                    NpgsqlBatchCommand del = follow.CreateBatchCommand();
                    del.CommandText = "DELETE FROM message_content WHERE day = $1 AND message_id = $2";
                    del.Parameters.Int(day).Uuid(messageId);
                    follow.BatchCommands.Add(del);
                    NpgsqlBatchCommand clear = follow.CreateBatchCommand();
                    clear.CommandText = "UPDATE message_index SET content_recorded = false WHERE day = $1 AND message_id = $2";
                    clear.Parameters.Int(day).Uuid(messageId);
                    follow.BatchCommands.Add(clear);
                }
            }

            if (rawRetained)
            {
                NpgsqlBatchCommand set = follow.CreateBatchCommand();
                set.CommandText = "UPDATE message_index SET raw_retained = true WHERE day = $1 AND message_id = $2";
                set.Parameters.Int(day).Uuid(messageId);
                follow.BatchCommands.Add(set);
            }

            if (follow.BatchCommands.Count > 0)
            {
                await follow.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            }
        }
    }

    private static IReadOnlyList<string>? TagsOf(string? json) => json is null ? null : StorageJson.DeserializeTags(json);

    public async ValueTask<Guid?> AttachReportAsync(Guid tenantId, string messageIdHeader, AsyncReport report, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(report);
        string? key = MessageIdKey.Normalize(messageIdHeader);
        if (!rt.IsFull || key is null)
        {
            return null;
        }

        DateTimeOffset? floor = MetadataFloor(rt.Clock.UtcNow);
        try
        {
            await using NpgsqlConnection c = await rt.Data.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using NpgsqlTransaction tx = await c.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
            int day;
            Guid messageId;
            int recipients;
            string status;
            await using (var find = new NpgsqlCommand(
                "SELECT day, message_id, recipient_count, status FROM message_index WHERE tenant_id = $1 AND message_id_header = $2 AND ($3::timestamptz IS NULL OR received_at > $3) " +
                "ORDER BY day DESC, message_id DESC LIMIT 1 FOR UPDATE", c, tx))
            {
                find.Parameters.Uuid(tenantId).Text(key).Time(floor);
                await using NpgsqlDataReader r = await find.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
                if (!await r.ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    return null;
                }

                day = r.GetInt32(0);
                messageId = r.GetGuid(1);
                recipients = r.GetInt32(2);
                status = r.GetString(3);
            }

            await using (var insert = new NpgsqlCommand(EventInsert, c, tx))
            {
                insert.Parameters.Int(day).Uuid(messageId).Uuid(EventIds.Next(report.At)).Uuid((Guid?)null).Uuid(tenantId).Small((int)report.Type).Time(report.At)
                    .Text(report.Recipient).Int(report.SmtpCode).Text(report.EnhancedCode).Text(report.Message).Text(null).Text(null).Text(null);
                await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            string next = MessageStatus.AfterReport(status, recipients, report.Type);
            if (!string.Equals(next, status, StringComparison.Ordinal))
            {
                await using var update = new NpgsqlCommand("UPDATE message_index SET status = $1 WHERE day = $2 AND message_id = $3", c, tx);
                update.Parameters.Text(next).Int(day).Uuid(messageId);
                await update.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
            return messageId;
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex))
        {
            throw rt.Unavailable(ex);
        }
    }

    // Reads

    private DateTimeOffset? MetadataFloor(DateTimeOffset now) => rt.Options.Retention.MetadataDays > 0 ? StorageTime.Normalize(now.AddDays(-rt.Options.Retention.MetadataDays)) : null;

    private DateTimeOffset ContentFloor(DateTimeOffset now) => StorageTime.Normalize(now.AddDays(-rt.Options.Content.RetentionDays));

    public async ValueTask<Page<MessageSummary>> SearchAsync(MessageQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        if (!rt.IsFull || !StorageText.IsStorable(query))
        {
            return new Page<MessageSummary>([], null);   // a filter that cannot be stored matches nothing (and is never cleaned into one that does)
        }

        int limit = Math.Clamp(query.Limit, 1, 500);
        int cursorDay = 0;
        Guid cursorId = default;
        bool hasCursor = query.Cursor is not null;
        if (hasCursor && !Cursors.TryDecodeHistory(query.Cursor, out cursorDay, out cursorId))
        {
            throw new ArgumentException("Invalid cursor.", nameof(query));
        }

        DateTimeOffset now = rt.Clock.UtcNow;
        string? recipient = string.IsNullOrWhiteSpace(query.Recipient) ? null : query.Recipient.Trim().ToLowerInvariant();
        var sql = new StringBuilder("SELECT m.day, m.message_id, m.tenant_id, m.received_at, m.subject, m.envelope_from, m.recipient_count, m.status, m.size, m.tags FROM ");
        sql.Append(recipient is null ? "message_index m" : "message_recipient r JOIN message_index m ON m.day = r.day AND m.message_id = r.message_id");
        sql.Append(" WHERE true");
        using var cmd = new NpgsqlCommand();
        void Arg(string text, Action<NpgsqlParameterCollection> add)
        {
            add(cmd.Parameters);
            sql.Append(" AND ").Append(text.Replace("$$", "$" + cmd.Parameters.Count.ToString(System.Globalization.CultureInfo.InvariantCulture), StringComparison.Ordinal));
        }

        if (recipient is not null)
        {
            Arg("r.recipient = $$", p => p.TextExact(recipient));
        }

        if (MetadataFloor(now) is { } floor)
        {
            Arg("m.received_at > $$", p => p.Time(floor));
        }

        if (query.TenantId is { } tenant)
        {
            Arg("m.tenant_id = $$", p => p.Uuid(tenant));
        }

        if (!string.IsNullOrWhiteSpace(query.Sender))
        {
            // SQLite compares with COLLATE NOCASE (ASCII case folding); lower() under the "C" collation folds ASCII only too.
            Arg("lower(m.envelope_from) = lower($$)", p => p.TextExact(query.Sender.Trim()));
        }

        if (!string.IsNullOrEmpty(query.SubjectContains))
        {
            string escaped = query.SubjectContains.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("%", "\\%", StringComparison.Ordinal).Replace("_", "\\_", StringComparison.Ordinal);
            Arg("m.subject ILIKE $$ ESCAPE '\\'", p => p.TextExact("%" + escaped + "%"));
        }

        if (!string.IsNullOrWhiteSpace(query.Status))
        {
            Arg("m.status = $$", p => p.TextExact(query.Status.Trim().ToLowerInvariant()));
        }

        if (!string.IsNullOrEmpty(query.Tag))
        {
            Arg("m.tags IS NOT NULL AND jsonb_exists(m.tags::jsonb, $$)", p => p.TextExact(query.Tag));
        }

        if (query.From is { } from)
        {
            Arg("m.received_at >= $$", p => p.Time(from));
            Arg("m.day >= $$", p => p.Int(StorageTime.DayNumber(from)));
        }

        if (query.To is { } to)
        {
            Arg("m.received_at < $$", p => p.Time(to));
            Arg("m.day <= $$", p => p.Int(StorageTime.DayNumber(to)));
        }

        if (hasCursor)
        {
            cmd.Parameters.Int(cursorDay).Uuid(cursorId);
            int n = cmd.Parameters.Count;
            sql.Append(" AND (m.day < $").Append(n - 1).Append(" OR (m.day = $").Append(n - 1).Append(" AND m.message_id < $").Append(n).Append("))");
        }

        cmd.Parameters.Long(limit + 1L);
        sql.Append(" ORDER BY m.day DESC, m.message_id DESC LIMIT $").Append(cmd.Parameters.Count);
        cmd.CommandText = sql.ToString();

        var items = new List<MessageSummary>();
        var keys = new List<(int Day, Guid Id)>();
        try
        {
            await using NpgsqlConnection connection = await rt.Reader.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            cmd.Connection = connection;
            await using NpgsqlDataReader r = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await r.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                keys.Add((r.GetInt32(0), r.GetGuid(1)));
                items.Add(new MessageSummary(r.GetGuid(1), r.GetGuid(2), r.GetInstant(3), r.GetNullableString(4), r.GetString(5), r.GetInt32(6), r.GetString(7), r.GetInt64(8), TagsOf(r.GetNullableString(9))));
            }
        }
        catch (Exception ex) when (PostgresErrors.IsStatementTimeout(ex, cancellationToken))
        {
            throw new StorageQueryTimeoutException("The read-only query ran past statement_timeout (Postgres:ReadOnlyStatementTimeoutSeconds).", ex);
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex))
        {
            throw rt.Unavailable(ex);
        }

        string? next = null;
        if (items.Count > limit)
        {
            items.RemoveAt(items.Count - 1);
            keys.RemoveAt(keys.Count - 1);
            next = Cursors.EncodeHistory(keys[^1].Day, keys[^1].Id);
        }

        return new Page<MessageSummary>(items, next);
    }

    public async ValueTask<MessageDetail?> GetAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken)
    {
        if (!rt.IsFull)
        {
            return null;
        }

        DateTimeOffset now = rt.Clock.UtcNow;
        int day = StorageTime.DayNumber(messageId);
        try
        {
            await using NpgsqlConnection c = await rt.Reader.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

            MessageSummary summary;
            bool contentRecorded, rawRetained;
            DateTimeOffset received;
            await using (var cmd = new NpgsqlCommand(
                "SELECT message_id, tenant_id, received_at, subject, envelope_from, recipient_count, status, size, content_recorded, raw_retained, tags FROM message_index " +
                "WHERE day = $1 AND message_id = $2 AND tenant_id = $3 AND ($4::timestamptz IS NULL OR received_at > $4)", c))
            {
                cmd.Parameters.Int(day).Uuid(messageId).Uuid(tenantId).Time(MetadataFloor(now));
                await using NpgsqlDataReader r = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
                if (!await r.ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    return null;
                }

                received = r.GetInstant(2);
                summary = new MessageSummary(r.GetGuid(0), r.GetGuid(1), received, r.GetNullableString(3), r.GetString(4), r.GetInt32(5), r.GetString(6), r.GetInt64(7), TagsOf(r.GetNullableString(10)));
                contentRecorded = r.GetBoolean(8);
                rawRetained = r.GetBoolean(9);
            }

            bool contentInRetention = received > ContentFloor(now);
            ContentState state = ContentState.NotRecorded;
            MessageContent? content = null;
            if (contentRecorded)
            {
                state = ContentState.Expired;
                if (contentInRetention)
                {
                    await using var cmd = new NpgsqlCommand("SELECT subject, text, html, attachments_json, truncated FROM message_content WHERE day = $1 AND message_id = $2", c);
                    cmd.Parameters.Int(day).Uuid(messageId);
                    await using NpgsqlDataReader r = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
                    if (await r.ReadAsync(cancellationToken).ConfigureAwait(false))
                    {
                        state = ContentState.Available;
                        content = new MessageContent(r.GetNullableString(0), r.GetNullableString(1), r.GetNullableString(2), StorageJson.DeserializeAttachments(r.GetString(3)), r.GetBoolean(4));
                    }
                }
            }

            var recipients = new List<string>();
            await using (var cmd = new NpgsqlCommand("SELECT recipient FROM message_recipient WHERE day = $1 AND message_id = $2 ORDER BY recipient", c))
            {
                cmd.Parameters.Int(day).Uuid(messageId);
                await using NpgsqlDataReader r = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
                while (await r.ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    recipients.Add(r.GetString(0));
                }
            }

            return new MessageDetail(summary, content, state, recipients, rawRetained && contentInRetention);
        }
        catch (Exception ex) when (PostgresErrors.IsStatementTimeout(ex, cancellationToken))
        {
            throw new StorageQueryTimeoutException("The read-only query ran past statement_timeout (Postgres:ReadOnlyStatementTimeoutSeconds).", ex);
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex))
        {
            throw rt.Unavailable(ex);
        }
    }

    public async ValueTask<IReadOnlyList<MessageEvent>> GetEventsAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken)
    {
        if (!rt.IsFull)
        {
            return [];
        }

        DateTimeOffset now = rt.Clock.UtcNow;
        try
        {
            await using NpgsqlConnection c = await rt.Reader.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var cmd = new NpgsqlCommand(
                "SELECT e.event_id, e.delivery_id, e.tenant_id, e.type, e.at, e.recipient, e.smtp_code, e.enhanced_code, e.message, e.mx_host, e.route, e.tls_json " +
                "FROM message_event e WHERE e.day = $1 AND e.message_id = $2 AND EXISTS (" +
                "SELECT 1 FROM message_index i WHERE i.day = e.day AND i.message_id = e.message_id AND i.tenant_id = $3 AND ($4::timestamptz IS NULL OR i.received_at > $4)) " +
                "ORDER BY e.event_id", c);
            cmd.Parameters.Int(StorageTime.DayNumber(messageId)).Uuid(messageId).Uuid(tenantId).Time(MetadataFloor(now));
            var list = new List<MessageEvent>();
            await using NpgsqlDataReader r = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await r.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                list.Add(new MessageEvent(
                    r.GetGuid(0), messageId, r.GetNullableGuid(1), r.GetGuid(2), (MessageEventType)r.GetInt16(3), r.GetInstant(4), r.GetNullableString(5),
                    r.GetNullableInt(6), r.GetNullableString(7), r.GetNullableString(8), r.GetNullableString(9), r.GetNullableString(10), StorageJson.DeserializeTls(r.GetNullableString(11))));
            }

            return list;
        }
        catch (Exception ex) when (PostgresErrors.IsStatementTimeout(ex, cancellationToken))
        {
            throw new StorageQueryTimeoutException("The read-only query ran past statement_timeout (Postgres:ReadOnlyStatementTimeoutSeconds).", ex);
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex))
        {
            throw rt.Unavailable(ex);
        }
    }

    public async ValueTask<byte[]?> GetRetainedRawAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken)
    {
        if (!rt.IsFull)
        {
            return null;
        }

        DateTimeOffset now = rt.Clock.UtcNow;
        try
        {
            await using NpgsqlConnection c = await rt.Reader.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var cmd = new NpgsqlCommand(
                "SELECT r.raw FROM message_raw_retained r JOIN message_index i ON i.day = r.day AND i.message_id = r.message_id " +
                "WHERE r.day = $1 AND r.message_id = $2 AND r.tenant_id = $3 AND i.received_at > $4", c);
            cmd.Parameters.Int(StorageTime.DayNumber(messageId)).Uuid(messageId).Uuid(tenantId).Time(ContentFloor(now));
            await using NpgsqlDataReader r = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            return await r.ReadAsync(cancellationToken).ConfigureAwait(false) ? r.GetFieldValue<byte[]>(0) : null;
        }
        catch (Exception ex) when (PostgresErrors.IsStatementTimeout(ex, cancellationToken))
        {
            throw new StorageQueryTimeoutException("The read-only query ran past statement_timeout (Postgres:ReadOnlyStatementTimeoutSeconds).", ex);
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex))
        {
            throw rt.Unavailable(ex);
        }
    }
}
