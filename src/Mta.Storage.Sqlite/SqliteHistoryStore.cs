using System.Text;
using Microsoft.Data.Sqlite;
using Mta.Storage.Logic;

namespace Mta.Storage.Sqlite;

internal static class HistorySql
{
    public static readonly Stmt IndexInsert = new(
        "INSERT INTO message_index (day, message_id, tenant_id, received_at, subject, envelope_from, recipient_count, final_count, delivered_count, failed_count, status, size, content_recorded, raw_retained, message_id_header, tags) " +
        "VALUES (@day, @m, @t, @rcv, @subj, @from, @n, 0, 0, 0, 'queued', @size, @cr, 0, @mih, @tags)",
        "@day", "@m", "@t", "@rcv", "@subj", "@from", "@n", "@size", "@cr", "@mih", "@tags");

    public static readonly Stmt RecipientInsert = new(
        "INSERT OR IGNORE INTO message_recipient (day, message_id, recipient) VALUES (@day, @m, @r)", "@day", "@m", "@r");

    public static readonly Stmt ContentInsert = new(
        "INSERT INTO message_content (day, message_id, tenant_id, subject, \"text\", html, attachments_json, truncated) VALUES (@day, @m, @t, @subj, @text, @html, @att, @trunc)",
        "@day", "@m", "@t", "@subj", "@text", "@html", "@att", "@trunc");

    public static readonly Stmt EventInsert = new(
        "INSERT INTO message_event (day, message_id, event_id, delivery_id, tenant_id, \"type\", \"at\", recipient, smtp_code, enhanced_code, \"message\", mx_host, route, tls_json) " +
        "VALUES (@day, @m, @eid, @did, @t, @type, @at, @rcpt, @code, @enh, @msg, @mx, @route, @tls)",
        "@day", "@m", "@eid", "@did", "@t", "@type", "@at", "@rcpt", "@code", "@enh", "@msg", "@mx", "@route", "@tls");

    public static readonly Stmt IndexCounts = new(
        "UPDATE message_index SET final_count = final_count + @f, delivered_count = delivered_count + @d, failed_count = failed_count + @x " +
        "WHERE day = @day AND message_id = @m RETURNING recipient_count, final_count, delivered_count, failed_count, status",
        "@f", "@d", "@x", "@day", "@m");

    public static readonly Stmt IndexStatus = new("UPDATE message_index SET status = @s WHERE day = @day AND message_id = @m", "@s", "@day", "@m");

    public static readonly Stmt ContentDelete = new("DELETE FROM message_content WHERE day = @day AND message_id = @m", "@day", "@m");

    public static readonly Stmt IndexClearContent = new("UPDATE message_index SET content_recorded = 0 WHERE day = @day AND message_id = @m", "@day", "@m");

    public static readonly Stmt RetainedInsert = new(
        "INSERT OR REPLACE INTO message_raw_retained (day, message_id, tenant_id, raw, retained_at) VALUES (@day, @m, @t, @raw, @at)",
        "@day", "@m", "@t", "@raw", "@at");

    public static readonly Stmt IndexFindByHeader = new(
        "SELECT day, message_id, recipient_count, status FROM message_index WHERE tenant_id = @t AND message_id_header = @h AND received_at > @floor ORDER BY day DESC, message_id DESC LIMIT 1",
        "@t", "@h", "@floor");

    public static readonly Stmt IndexSetRetained = new("UPDATE message_index SET raw_retained = 1 WHERE day = @day AND message_id = @m", "@day", "@m");
}

internal readonly record struct ApplyAttemptState(AttemptPlan Plan, Guid MessageId, Guid TenantId, bool RawRetained, bool KeepContent);

internal readonly record struct AcceptHistoryState(AcceptedMessage Message, MessageContent? Content, string? Subject, Guid EventId);

/// <summary>Per-message history on history.db (present only with <see cref="HistoryMode.Full"/>).</summary>
internal sealed class SqliteHistoryStore(SqliteRuntime rt) : IHistoryStore, IMessageRecipientLookup
{
    public ValueTask<IReadOnlyDictionary<Guid, IReadOnlyList<string>>> GetRecipientsAsync(Guid tenantId, IReadOnlyCollection<Guid> messageIds, int maxPerMessage, CancellationToken cancellationToken)
    {
        var result = new Dictionary<Guid, IReadOnlyList<string>>();
        if (!rt.IsFull || messageIds.Count == 0)
        {
            return ValueTask.FromResult<IReadOnlyDictionary<Guid, IReadOnlyList<string>>>(result);
        }

        using SqliteConnection c = rt.History!.OpenReader();
        using SqliteCommand cmd = c.CreateCommand();
        cmd.CommandText =
            "SELECT r.recipient FROM message_recipient r JOIN message_index m ON m.day = r.day AND m.message_id = r.message_id " +
            "WHERE r.day = @day AND r.message_id = @m AND m.tenant_id = @t ORDER BY r.recipient LIMIT @n";
        SqliteParameter day = cmd.Parameters.Add("@day", SqliteType.Integer);
        SqliteParameter id = cmd.Parameters.Add("@m", SqliteType.Text);
        cmd.Parameters.AddWithValue("@t", tenantId);
        cmd.Parameters.AddWithValue("@n", (long)Math.Max(0, maxPerMessage));
        foreach (Guid messageId in messageIds)
        {
            day.Value = StorageTime.DayNumber(messageId);
            id.Value = messageId;
            var list = new List<string>();
            using (SqliteDataReader r = cmd.ExecuteReader())
            {
                while (r.Read())
                {
                    list.Add(r.GetString(0));
                }
            }

            if (list.Count > 0)
            {
                result[messageId] = list;
            }
        }

        return ValueTask.FromResult<IReadOnlyDictionary<Guid, IReadOnlyList<string>>>(result);
    }

    // Writes

    internal async ValueTask RecordAcceptedAsync(AcceptedMessage message, CancellationToken cancellationToken)
    {
        MessageContent? content = ContentRules.ShouldRecord(rt.Options, message) ? ContentRules.Prepare(rt.Options, message.Content!) : null;
        string? subject = rt.Options.Content.StoreSubject ? message.Content?.Subject : null;
        await rt.HistoryWriter!.SubmitAsync(new AcceptHistoryState(message, content, subject, EventIds.Next(message.ReceivedAt)), RecordAccepted, cancellationToken).ConfigureAwait(false);
    }

    private static readonly Func<WriterContext, AcceptHistoryState, int> RecordAccepted = static (ctx, s) =>
    {
        AcceptedMessage m = s.Message;
        int day = StorageTime.DayNumber(m.MessageId);
        long received = StorageTime.ToUnixMs(m.ReceivedAt);
        ctx.Command(HistorySql.IndexInsert)
            .Set(0, day).Set(1, m.MessageId).Set(2, m.TenantId).Set(3, received).Set(4, s.Subject).Set(5, AddressText.Format(m.EnvelopeFrom))
            .Set(6, m.Recipients.Count).Set(7, (long)m.Raw.Length).Set(8, s.Content is null ? 0 : 1)
            .Set(9, MessageIdKey.Normalize(m.MessageIdHeader)).Set(10, StorageJson.SerializeTags(m.Tags))
            .ExecuteNonQuery();

        SqliteCommand rcpt = ctx.Command(HistorySql.RecipientInsert).Set(0, day).Set(1, m.MessageId);
        foreach (AcceptedRecipient r in m.Recipients)
        {
            rcpt.Set(2, AddressText.Format(r.Address).ToLowerInvariant()).ExecuteNonQuery();
        }

        if (s.Content is { } c)
        {
            ctx.Command(HistorySql.ContentInsert)
                .Set(0, day).Set(1, m.MessageId).Set(2, m.TenantId).Set(3, c.Subject).Set(4, c.Text).Set(5, c.Html)
                .Set(6, StorageJson.SerializeAttachments(c.Attachments)).Set(7, c.Truncated ? 1 : 0)
                .ExecuteNonQuery();
        }

        ctx.Command(HistorySql.EventInsert)
            .Set(0, day).Set(1, m.MessageId).Set(2, s.EventId).Set(3, null).Set(4, m.TenantId).Set(5, (long)MessageEventType.Queued).Set(6, received)
            .Set(7, null).Set(8, null).Set(9, null).Set(10, null).Set(11, null).Set(12, null).Set(13, null)
            .ExecuteNonQuery();
        return 0;
    };

    internal async ValueTask ApplyAttemptAsync(AttemptPlan plan, Guid messageId, Guid tenantId, bool rawRetained, CancellationToken cancellationToken) =>
        await rt.HistoryWriter!.SubmitAsync(new ApplyAttemptState(plan, messageId, tenantId, rawRetained, rt.Options.Content.Retain), ApplyAttempt, cancellationToken).ConfigureAwait(false);

    private static readonly Func<WriterContext, ApplyAttemptState, int> ApplyAttempt = static (ctx, s) =>
    {
        int day = StorageTime.DayNumber(s.MessageId);
        AttemptPlan plan = s.Plan;
        SqliteCommand insert = ctx.Command(HistorySql.EventInsert);
        foreach (MessageEvent e in plan.Events)
        {
            insert.Set(0, day).Set(1, s.MessageId).Set(2, e.EventId).Set(3, e.DeliveryId).Set(4, e.TenantId).Set(5, (long)e.Type).Set(6, StorageTime.ToUnixMs(e.At))
                .Set(7, e.Recipient).Set(8, e.SmtpCode).Set(9, e.EnhancedCode).Set(10, e.Message).Set(11, e.MxHost).Set(12, e.Route).Set(13, StorageJson.SerializeTls(e.Tls))
                .ExecuteNonQuery();
        }

        if (plan.IsFinal || plan.Action == QueueRowAction.Reschedule)
        {
            int recipients, final, delivered, failed;
            string status;
            using (SqliteDataReader r = ctx.Command(HistorySql.IndexCounts)
                .Set(0, plan.IsFinal ? 1 : 0).Set(1, plan.Delivered ? 1 : 0).Set(2, plan.Failed ? 1 : 0).Set(3, day).Set(4, s.MessageId).ExecuteReader())
            {
                if (!r.Read())
                {
                    return 0; // no index row (history was not written for this message): the events above stand alone
                }

                recipients = r.GetInt32(0);
                final = r.GetInt32(1);
                delivered = r.GetInt32(2);
                failed = r.GetInt32(3);
                status = r.GetString(4);
            }

            string next = MessageStatus.Next(status, recipients, final, delivered, failed, MessageStatus.FinalKind(plan.Events[0].Type));
            if (!string.Equals(next, status, StringComparison.Ordinal))
            {
                ctx.Command(HistorySql.IndexStatus).Set(0, next).Set(1, day).Set(2, s.MessageId).ExecuteNonQuery();
            }

            if (plan.IsFinal && final >= recipients && !s.KeepContent)
            {
                ctx.Command(HistorySql.ContentDelete).Set(0, day).Set(1, s.MessageId).ExecuteNonQuery();
                ctx.Command(HistorySql.IndexClearContent).Set(0, day).Set(1, s.MessageId).ExecuteNonQuery();
            }
        }

        if (s.RawRetained)
        {
            ctx.Command(HistorySql.IndexSetRetained).Set(0, day).Set(1, s.MessageId).ExecuteNonQuery();
        }

        return 0;
    };

    internal async ValueTask RetainRawAsync(Guid messageId, Guid tenantId, byte[] raw, DateTimeOffset at, CancellationToken cancellationToken) =>
        await rt.HistoryWriter!.SubmitAsync((messageId, tenantId, raw, StorageTime.ToUnixMs(at)), static (ctx, s) =>
        {
            int day = StorageTime.DayNumber(s.messageId);
            ctx.Command(HistorySql.RetainedInsert).Set(0, day).Set(1, s.messageId).Set(2, s.tenantId).Set(3, s.raw).Set(4, s.Item4).ExecuteNonQuery();
            return ctx.Command(HistorySql.IndexSetRetained).Set(0, day).Set(1, s.messageId).ExecuteNonQuery();
        }, cancellationToken).ConfigureAwait(false);

    private static IReadOnlyList<string>? TagsOf(string? json) => json is null ? null : StorageJson.DeserializeTags(json);

    public async ValueTask<Guid?> AttachReportAsync(Guid tenantId, string messageIdHeader, AsyncReport report, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(report);
        string? key = MessageIdKey.Normalize(messageIdHeader);
        if (!rt.IsFull || key is null)
        {
            return null;
        }

        long floor = MetadataFloorMs(rt.Clock.UtcNow) ?? long.MinValue;
        Guid eventId = EventIds.Next(report.At);
        return await rt.HistoryWriter!.SubmitAsync((tenantId, key, report, eventId, floor), AttachReport, cancellationToken).ConfigureAwait(false);
    }

    private static readonly Func<WriterContext, (Guid Tenant, string Key, AsyncReport Report, Guid EventId, long Floor), Guid?> AttachReport = static (ctx, s) =>
    {
        int day;
        Guid messageId;
        int recipients;
        string status;
        using (SqliteDataReader r = ctx.Command(HistorySql.IndexFindByHeader).Set(0, s.Tenant).Set(1, s.Key).Set(2, s.Floor).ExecuteReader())
        {
            if (!r.Read())
            {
                return null;
            }

            day = r.GetInt32(0);
            messageId = r.GetGuid(1);
            recipients = r.GetInt32(2);
            status = r.GetString(3);
        }

        AsyncReport e = s.Report;
        ctx.Command(HistorySql.EventInsert)
            .Set(0, day).Set(1, messageId).Set(2, s.EventId).Set(3, null).Set(4, s.Tenant).Set(5, (long)e.Type).Set(6, StorageTime.ToUnixMs(e.At))
            .Set(7, e.Recipient).Set(8, e.SmtpCode).Set(9, e.EnhancedCode).Set(10, e.Message).Set(11, null).Set(12, null).Set(13, null)
            .ExecuteNonQuery();
        string next = MessageStatus.AfterReport(status, recipients, e.Type);
        if (!string.Equals(next, status, StringComparison.Ordinal))
        {
            ctx.Command(HistorySql.IndexStatus).Set(0, next).Set(1, day).Set(2, messageId).ExecuteNonQuery();
        }

        return messageId;
    };

    // Reads

    private long? MetadataFloorMs(DateTimeOffset now) => rt.Options.Retention.MetadataDays > 0 ? StorageTime.ToUnixMs(now.AddDays(-rt.Options.Retention.MetadataDays)) : null;

    private long ContentFloorMs(DateTimeOffset now) => StorageTime.ToUnixMs(now.AddDays(-rt.Options.Content.RetentionDays));

    public ValueTask<Page<MessageSummary>> SearchAsync(MessageQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        if (!rt.IsFull)
        {
            return ValueTask.FromResult(new Page<MessageSummary>([], null));
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
        sql.Append(" WHERE 1 = 1");
        var args = new List<(string, object)>();
        void Arg(string text, string name, object value)
        {
            sql.Append(" AND ").Append(text);
            args.Add((name, value));
        }

        if (recipient is not null)
        {
            Arg("r.recipient = @rcpt", "@rcpt", recipient);
        }

        if (MetadataFloorMs(now) is { } floor)
        {
            Arg("m.received_at > @floor", "@floor", floor);
        }

        if (query.TenantId is { } tenant)
        {
            Arg("m.tenant_id = @tenant", "@tenant", tenant);
        }

        if (!string.IsNullOrWhiteSpace(query.Sender))
        {
            Arg("m.envelope_from = @sender COLLATE NOCASE", "@sender", query.Sender.Trim());
        }

        if (!string.IsNullOrEmpty(query.SubjectContains))
        {
            string escaped = query.SubjectContains.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("%", "\\%", StringComparison.Ordinal).Replace("_", "\\_", StringComparison.Ordinal);
            Arg("m.subject LIKE @subject ESCAPE '\\'", "@subject", "%" + escaped + "%");
        }

        if (!string.IsNullOrWhiteSpace(query.Status))
        {
            Arg("m.status = @status", "@status", query.Status.Trim().ToLowerInvariant());
        }

        if (!string.IsNullOrEmpty(query.Tag))
        {
            Arg("m.tags IS NOT NULL AND EXISTS (SELECT 1 FROM json_each(m.tags) WHERE json_each.value = @tag)", "@tag", query.Tag);
        }

        if (query.From is { } from)
        {
            Arg("m.received_at >= @from", "@from", StorageTime.ToUnixMs(from));
            Arg("m.day >= @fromDay", "@fromDay", (long)StorageTime.DayNumber(from));
        }

        if (query.To is { } to)
        {
            Arg("m.received_at < @to", "@to", StorageTime.ToUnixMs(to));
            Arg("m.day <= @toDay", "@toDay", (long)StorageTime.DayNumber(to));
        }

        if (hasCursor)
        {
            sql.Append(" AND (m.day < @cday OR (m.day = @cday AND m.message_id < @cid))");
            args.Add(("@cday", (long)cursorDay));
            args.Add(("@cid", cursorId));
        }

        sql.Append(" ORDER BY m.day DESC, m.message_id DESC LIMIT @limit");
        args.Add(("@limit", (long)limit + 1));
        string text = sql.ToString();

        using SqliteConnection connection = rt.History!.OpenReader();
        using SqliteCommand cmd = connection.CreateCommand();
        cmd.CommandText = text;
        foreach ((string name, object value) in args)
        {
            cmd.Parameters.AddWithValue(name, value);
        }

        var items = new List<MessageSummary>();
        var keys = new List<(int Day, Guid Id)>();
        using (SqliteDataReader r = cmd.ExecuteReader())
        {
            while (r.Read())
            {
                keys.Add((r.GetInt32(0), r.GetGuid(1)));
                items.Add(new MessageSummary(r.GetGuid(1), r.GetGuid(2), r.GetInstant(3), r.GetNullableString(4), r.GetString(5), r.GetInt32(6), r.GetString(7), r.GetInt64(8), TagsOf(r.GetNullableString(9))));
            }
        }

        string? next = null;
        if (items.Count > limit)
        {
            items.RemoveAt(items.Count - 1);
            keys.RemoveAt(keys.Count - 1);
            next = Cursors.EncodeHistory(keys[^1].Day, keys[^1].Id);
        }

        return ValueTask.FromResult(new Page<MessageSummary>(items, next));
    }

    public ValueTask<MessageDetail?> GetAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken)
    {
        if (!rt.IsFull)
        {
            return ValueTask.FromResult<MessageDetail?>(null);
        }

        DateTimeOffset now = rt.Clock.UtcNow;
        int day = StorageTime.DayNumber(messageId);
        using SqliteConnection c = rt.History!.OpenReader();

        MessageSummary summary;
        bool contentRecorded, rawRetained;
        long receivedMs;
        using (SqliteCommand cmd = c.CreateCommand())
        {
            cmd.CommandText = "SELECT message_id, tenant_id, received_at, subject, envelope_from, recipient_count, status, size, content_recorded, raw_retained, tags FROM message_index " +
                "WHERE day = @day AND message_id = @m AND tenant_id = @t" + (MetadataFloorMs(now) is null ? "" : " AND received_at > @floor");
            cmd.Parameters.AddWithValue("@day", day);
            cmd.Parameters.AddWithValue("@m", messageId);
            cmd.Parameters.AddWithValue("@t", tenantId);
            if (MetadataFloorMs(now) is { } floor)
            {
                cmd.Parameters.AddWithValue("@floor", floor);
            }

            using SqliteDataReader r = cmd.ExecuteReader();
            if (!r.Read())
            {
                return ValueTask.FromResult<MessageDetail?>(null);
            }

            receivedMs = r.GetInt64(2);
            summary = new MessageSummary(r.GetGuid(0), r.GetGuid(1), StorageTime.FromUnixMs(receivedMs), r.GetNullableString(3), r.GetString(4), r.GetInt32(5), r.GetString(6), r.GetInt64(7), TagsOf(r.GetNullableString(10)));
            contentRecorded = r.GetFlag(8);
            rawRetained = r.GetFlag(9);
        }

        bool contentInRetention = receivedMs > ContentFloorMs(now);
        ContentState state = ContentState.NotRecorded;
        MessageContent? content = null;
        if (contentRecorded)
        {
            state = ContentState.Expired;
            if (contentInRetention)
            {
                using SqliteCommand cmd = c.CreateCommand();
                cmd.CommandText = "SELECT subject, \"text\", html, attachments_json, truncated FROM message_content WHERE day = @day AND message_id = @m";
                cmd.Parameters.AddWithValue("@day", day);
                cmd.Parameters.AddWithValue("@m", messageId);
                using SqliteDataReader r = cmd.ExecuteReader();
                if (r.Read())
                {
                    state = ContentState.Available;
                    content = new MessageContent(r.GetNullableString(0), r.GetNullableString(1), r.GetNullableString(2), StorageJson.DeserializeAttachments(r.GetString(3)), r.GetFlag(4));
                }
            }
        }

        var recipients = new List<string>();
        using (SqliteCommand cmd = c.CreateCommand())
        {
            cmd.CommandText = "SELECT recipient FROM message_recipient WHERE day = @day AND message_id = @m ORDER BY recipient";
            cmd.Parameters.AddWithValue("@day", day);
            cmd.Parameters.AddWithValue("@m", messageId);
            using SqliteDataReader r = cmd.ExecuteReader();
            while (r.Read())
            {
                recipients.Add(r.GetString(0));
            }
        }

        return ValueTask.FromResult<MessageDetail?>(new MessageDetail(summary, content, state, recipients, rawRetained && contentInRetention));
    }

    public ValueTask<IReadOnlyList<MessageEvent>> GetEventsAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken)
    {
        if (!rt.IsFull)
        {
            return ValueTask.FromResult<IReadOnlyList<MessageEvent>>([]);
        }

        DateTimeOffset now = rt.Clock.UtcNow;
        int day = StorageTime.DayNumber(messageId);
        using SqliteConnection c = rt.History!.OpenReader();
        using SqliteCommand cmd = c.CreateCommand();
        cmd.CommandText =
            "SELECT e.event_id, e.delivery_id, e.tenant_id, e.\"type\", e.\"at\", e.recipient, e.smtp_code, e.enhanced_code, e.\"message\", e.mx_host, e.route, e.tls_json " +
            "FROM message_event e WHERE e.day = @day AND e.message_id = @m AND EXISTS (" +
            "SELECT 1 FROM message_index i WHERE i.day = e.day AND i.message_id = e.message_id AND i.tenant_id = @t" + (MetadataFloorMs(now) is null ? "" : " AND i.received_at > @floor") + ") " +
            "ORDER BY e.event_id";
        cmd.Parameters.AddWithValue("@day", day);
        cmd.Parameters.AddWithValue("@m", messageId);
        cmd.Parameters.AddWithValue("@t", tenantId);
        if (MetadataFloorMs(now) is { } floor)
        {
            cmd.Parameters.AddWithValue("@floor", floor);
        }

        var list = new List<MessageEvent>();
        using SqliteDataReader r = cmd.ExecuteReader();
        while (r.Read())
        {
            list.Add(new MessageEvent(
                r.GetGuid(0), messageId, r.GetNullableGuid(1), r.GetGuid(2), (MessageEventType)r.GetInt32(3), r.GetInstant(4), r.GetNullableString(5),
                r.GetNullableInt(6), r.GetNullableString(7), r.GetNullableString(8), r.GetNullableString(9), r.GetNullableString(10), StorageJson.DeserializeTls(r.GetNullableString(11))));
        }

        return ValueTask.FromResult<IReadOnlyList<MessageEvent>>(list);
    }

    public ValueTask<byte[]?> GetRetainedRawAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken)
    {
        if (!rt.IsFull)
        {
            return ValueTask.FromResult<byte[]?>(null);
        }

        DateTimeOffset now = rt.Clock.UtcNow;
        using SqliteConnection c = rt.History!.OpenReader();
        using SqliteCommand cmd = c.CreateCommand();
        cmd.CommandText =
            "SELECT r.raw FROM message_raw_retained r JOIN message_index i ON i.day = r.day AND i.message_id = r.message_id " +
            "WHERE r.day = @day AND r.message_id = @m AND r.tenant_id = @t AND i.received_at > @floor";
        cmd.Parameters.AddWithValue("@day", StorageTime.DayNumber(messageId));
        cmd.Parameters.AddWithValue("@m", messageId);
        cmd.Parameters.AddWithValue("@t", tenantId);
        cmd.Parameters.AddWithValue("@floor", ContentFloorMs(now));
        using SqliteDataReader r = cmd.ExecuteReader();
        return ValueTask.FromResult<byte[]?>(r.Read() ? r.GetFieldValue<byte[]>(0) : null);
    }
}
