using System.Text.Json;
using Mta.Storage.Logic;

namespace Mta.Storage.Model;

/// <summary>
/// Maps the inbound records of <c>Contracts.Inbound.cs</c> to their persisted entities and back. Normalization (lower-case local parts and
/// addresses, millisecond timestamps, bounded text) happens here so every backend stores identical values.
/// </summary>
public static class InboundMapping
{
    private static DateTimeOffset N(DateTimeOffset v) => StorageTime.Normalize(v);

    private static DateTimeOffset? N(DateTimeOffset? v) => StorageTime.Normalize(v);

    /// <summary>The epoch, the stored value of "not leased".</summary>
    public static DateTimeOffset NoLease => DateTimeOffset.UnixEpoch;

    public static InboundDomainSettingsEntity ToEntity(this InboundDomainSettings s) => new()
    {
        DomainId = s.DomainId,
        TenantId = s.TenantId,
        Enabled = s.Enabled,
        DmarcAction = s.DmarcAction,
        MaxMessageBytes = s.MaxMessageBytes,
        MaxMessagesPerMinute = s.MaxMessagesPerMinute,
        MaxMessagesPerMinutePerRemote = s.MaxMessagesPerMinutePerRemote,
        MaxStoredBytes = s.MaxStoredBytes,
        RetentionDays = s.RetentionDays,
        UpdatedAt = N(s.UpdatedAt),
    };

    public static InboundDomainSettings ToRecord(this InboundDomainSettingsEntity e) =>
        new(e.DomainId, e.TenantId, e.Enabled, e.DmarcAction, e.MaxMessageBytes, e.MaxMessagesPerMinute, e.MaxMessagesPerMinutePerRemote, e.MaxStoredBytes, e.RetentionDays, e.UpdatedAt);

    public static InboundRouteEntity ToEntity(this InboundRouteRecord r) => new()
    {
        Id = r.Id,
        TenantId = r.TenantId,
        DomainId = r.DomainId,
        Name = r.Name,
        SortOrder = r.Order,
        Enabled = r.Enabled,
        MatchKind = r.MatchKind,
        LocalPart = r.MatchKind == InboundMatchKind.CatchAll ? null : r.LocalPart?.ToLowerInvariant(),
        PlusAddressing = r.PlusAddressing,
        ActionKind = r.ActionKind,
        WebhookEndpointId = r.ActionKind == InboundActionKind.Webhook ? r.WebhookEndpointId : null,
        WebhookFormat = r.WebhookFormat,
        ForwardToJson = r.ActionKind == InboundActionKind.Forward ? JsonSerializer.Serialize(r.ForwardTo.Select(a => a.Trim()).ToArray()) : "[]",
        CreatedAt = N(r.CreatedAt),
        UpdatedAt = N(r.UpdatedAt),
    };

    public static InboundRouteRecord ToRecord(this InboundRouteEntity e) =>
        new(e.Id, e.TenantId, e.DomainId, e.Name, e.SortOrder, e.Enabled, e.MatchKind, e.LocalPart, e.PlusAddressing, e.ActionKind, e.WebhookEndpointId, e.WebhookFormat,
            JsonSerializer.Deserialize<string[]>(e.ForwardToJson) ?? [], e.CreatedAt, e.UpdatedAt);

    /// <summary>The evaluation order of routes (the order the receive path matches in).</summary>
    public static int CompareRoutes(InboundRouteRecord a, InboundRouteRecord b) =>
        a.Order != b.Order ? a.Order.CompareTo(b.Order) : string.CompareOrdinal(IdText(a.Id), IdText(b.Id));

    /// <summary>The canonical text of an id: the order Guids sort in on every backend (upper-case TEXT on SQLite, byte order of a uuid on PostgreSQL).</summary>
    public static string IdText(Guid id) => id.ToString("D").ToUpperInvariant();

    /// <summary>
    /// Lower-case for ASCII letters only. SQLite's <c>lower()</c> and PostgreSQL's under the <c>"C"</c> collation change nothing else, so the subject search
    /// (which lowers the column in SQL) answers alike on every backend when the term is lowered the same way.
    /// </summary>
    public static string AsciiLower(string text) => string.Create(text.Length, text, static (span, source) =>
    {
        for (int i = 0; i < span.Length; i++)
        {
            char c = source[i];
            span[i] = c is >= 'A' and <= 'Z' ? (char)(c + 32) : c;
        }
    });

    /// <summary>
    /// The subject for display and search: line breaks and tabs become one space, other control characters are removed, and the length is bounded
    /// (<see cref="InboundRules.MaxSubjectLength"/>). Null when nothing is left.
    /// </summary>
    public static string? CleanSubject(string? subject)
    {
        if (string.IsNullOrEmpty(subject))
        {
            return null;
        }

        Span<char> buffer = stackalloc char[InboundRules.MaxSubjectLength];
        int n = 0;
        foreach (char c in subject)
        {
            if (n == buffer.Length)
            {
                break;
            }

            if (c is '\r' or '\n' or '\t')
            {
                if (n > 0 && buffer[n - 1] != ' ')
                {
                    buffer[n++] = ' ';
                }
            }
            else if (!char.IsControl(c))
            {
                buffer[n++] = c;
            }
        }

        // A bound that falls inside a surrogate pair would leave a lone surrogate.
        if (n > 0 && char.IsHighSurrogate(buffer[n - 1]))
        {
            n--;
        }

        string text = new string(buffer[..n]).Trim();
        return text.Length == 0 ? null : text;
    }

    /// <summary>The entity of a new message (state derived from the action kind, see <see cref="InboundRules.InitialActionState"/>).</summary>
    public static InboundMessageEntity ToEntity(this InboundMessageDraft d)
    {
        InboundActionState state = InboundRules.InitialActionState(d.ActionKind);
        DateTimeOffset received = N(d.ReceivedAt);
        return new InboundMessageEntity
        {
            Id = d.Id,
            TenantId = d.TenantId,
            DomainId = d.DomainId,
            Domain = d.Domain.ToLowerInvariant(),
            ReceivedAt = received,
            RemoteAddress = d.RemoteAddress,
            Helo = d.Helo,
            TlsUsed = d.TlsUsed,
            EnvelopeFrom = d.EnvelopeFrom.ToLowerInvariant(),
            EnvelopeTo = d.EnvelopeTo.ToLowerInvariant(),
            Subject = CleanSubject(d.Subject),
            Size = d.Raw.Length,
            Spf = d.Auth.Spf,
            SpfDomain = d.Auth.SpfDomain,
            Dkim = d.Auth.Dkim,
            DkimDomain = d.Auth.DkimDomain,
            Dmarc = d.Auth.Dmarc,
            DmarcPolicy = d.Auth.DmarcPolicy,
            Arc = d.Auth.Arc,
            Disposition = d.Disposition,
            RouteId = d.RouteId,
            ActionKind = d.ActionKind,
            ActionState = state,
            ActionAttempts = 0,
            ActionNextAttemptAt = state == InboundActionState.Pending ? received : null,
            ActionFinishedAt = state == InboundActionState.Done ? received : null,
            HasRaw = InboundRules.StoresBody(d.ActionKind),
            LeaseUntil = NoLease,
        };
    }

    public static InboundMessage ToRecord(this InboundMessageEntity e) => new(
        e.Id, e.TenantId, e.DomainId, e.Domain, e.ReceivedAt, e.RemoteAddress, e.Helo, e.TlsUsed, e.EnvelopeFrom, e.EnvelopeTo, e.Subject, e.Size,
        new InboundAuthResults(e.Spf, e.SpfDomain, e.Dkim, e.DkimDomain, e.Dmarc, e.DmarcPolicy, e.Arc),
        e.Disposition, e.RouteId, e.ActionKind, e.ActionState, e.ActionAttempts, e.ActionNextAttemptAt, e.ActionFinishedAt, e.ActionLastError, e.ForwardMessageId, e.HasRaw);
}
