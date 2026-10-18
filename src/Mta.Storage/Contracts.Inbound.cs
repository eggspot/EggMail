namespace Mta.Storage;

// Contracts of inbound mail (design section 11, decision 95). Three kinds of data, one interface:
//   - per-domain inbound settings and the routes of a domain: configuration (the config part), read at RCPT time through a cache;
//   - inbound messages: the received mail with its verification results and the state of the route action (the queue part, so a
//     forward can join the outbound queue in the same file and the switch holds them like deliveries);
//   - retention: the "inbound_retention" job of IStorageMaintenance.RunAsync.
// Every method behaves identically on every backend (decision E).

/// <summary>What the receiver does when DMARC evaluation says the message fails and the sender's policy asks for quarantine or rejection. Nothing is ever quarantined (moved aside): a failing message is accepted and flagged, or refused.</summary>
public enum InboundDmarcAction : byte
{
    /// <summary>Accept and record the DMARC verdict; never act on the sender's policy (the default).</summary>
    RecordOnly = 0,

    /// <summary>Accept; when the sender's policy is quarantine or reject and the message fails DMARC, flag the stored message (<see cref="InboundDmarcDisposition.Flagged"/>) and add <c>X-EggMail-Dmarc: flagged</c>.</summary>
    Flag = 1,

    /// <summary>Honor the sender's policy: a message that fails DMARC under <c>p=reject</c> is refused at the end of DATA with <c>550 5.7.1</c>; a <c>p=quarantine</c> failure is flagged as with <see cref="Flag"/>. A transaction with several recipients is refused only when <b>every</b> accepted recipient's domain asks for rejection (design section 11.5); otherwise it is accepted and the rejecting domains' copies are flagged.</summary>
    Reject = 2,
}

/// <summary>What was done to a stored message because of DMARC. A refused message is never stored, so there is no value for it.</summary>
public enum InboundDmarcDisposition : byte
{
    None = 0,
    Flagged = 1,
}

/// <summary>Result of one verification mechanism. Wire names (API, headers) are the lower-case names; <see cref="SoftFail"/> is <c>softfail</c>.</summary>
public enum InboundVerdict : byte
{
    None = 0,
    Pass = 1,
    Fail = 2,
    SoftFail = 3,
    Neutral = 4,
    TempError = 5,
    PermError = 6,
    Policy = 7,
}

/// <summary>The verification results of one received message: SPF (on MAIL FROM, or on HELO when the reverse-path is null; HELO is evaluated and recorded too), DKIM (the best signature: pass when any passes), DMARC and ARC.</summary>
/// <param name="Spf">SPF verdict.</param>
/// <param name="SpfDomain">The domain the SPF verdict is for: the MAIL FROM domain, or the HELO name when the reverse-path is null.</param>
/// <param name="SpfHelo">SPF verdict for the HELO/EHLO name (RFC 7208 section 2.3), evaluated even when MAIL FROM is present; <see cref="InboundVerdict.None"/> when the name is not a domain.</param>
/// <param name="Dkim">DKIM verdict: <see cref="InboundVerdict.Pass"/> when any signature passed, else the strongest failure, <see cref="InboundVerdict.None"/> without signatures.</param>
/// <param name="DkimDomain">The <c>d=</c> of the signature that decided <paramref name="Dkim"/>.</param>
/// <param name="Dmarc">DMARC verdict for the RFC 5322 From domain.</param>
/// <param name="DmarcPolicy">The policy the sender published (<c>none</c>, <c>quarantine</c>, <c>reject</c>, the subdomain policy when it applied); null without a DMARC record.</param>
/// <param name="Arc">ARC chain validation (<see cref="InboundVerdict.None"/> without a chain, <see cref="InboundVerdict.Pass"/> or <see cref="InboundVerdict.Fail"/>).</param>
public sealed record InboundAuthResults(
    InboundVerdict Spf,
    string? SpfDomain,
    InboundVerdict SpfHelo,
    InboundVerdict Dkim,
    string? DkimDomain,
    InboundVerdict Dmarc,
    string? DmarcPolicy,
    InboundVerdict Arc)
{
    public static InboundAuthResults NotChecked { get; } = new(InboundVerdict.None, null, InboundVerdict.None, InboundVerdict.None, null, InboundVerdict.None, null, InboundVerdict.None);
}

/// <summary>What a route does with a matching message. Stored as a byte: the numbers never change.</summary>
public enum InboundActionKind : byte
{
    /// <summary>POST to a webhook endpoint of the tenant (Standard Webhooks signing); see <see cref="InboundWebhookFormat"/>.</summary>
    Webhook = 0,

    /// <summary>Send to other addresses through the outbound queue, with an SRS envelope sender.</summary>
    Forward = 1,

    /// <summary>Keep the message for retrieval through the API and the dashboard until the retention ends.</summary>
    Store = 2,

    /// <summary>Accept and drop: only the metadata row is kept (so the dashboard can show that it arrived), never the body.</summary>
    Discard = 3,
}

public enum InboundWebhookFormat : byte
{
    /// <summary>The body is a JSON document with the envelope, verification results, headers, text and HTML (bounded) and attachments by reference.</summary>
    Json = 0,

    /// <summary>The body is the received RFC 5322 message as is (<c>Content-Type: message/rfc822</c>); the envelope and verdicts travel in <c>EggMail-*</c> headers.</summary>
    RawMime = 1,
}

/// <summary>How a route chooses the recipients it handles.</summary>
public enum InboundMatchKind : byte
{
    /// <summary>Every local part of the domain.</summary>
    CatchAll = 0,

    /// <summary>One local part, compared ignoring case (and the <c>+tag</c> when <see cref="InboundRouteRecord.PlusAddressing"/> is set).</summary>
    Address = 1,

    /// <summary>A local part pattern in which <c>*</c> matches any run of characters (including none), for example <c>billing-*</c>.</summary>
    Wildcard = 2,
}

/// <summary>State of the action of a message. Store and discard messages are <see cref="Done"/> from the start.</summary>
public enum InboundActionState : byte
{
    /// <summary>Waiting for an attempt (new, or scheduled for a retry). The only state the claim picks up.</summary>
    Pending = 0,

    Done = 1,

    /// <summary>Gave up (attempts used up, route gone, or a permanent failure). <c>retry</c> puts it back to <see cref="Pending"/>.</summary>
    Failed = 2,
}

/// <summary>
/// Inbound settings of one domain of a tenant. A domain with no stored settings is not inbound-enabled. The nullable members mean "use the
/// server default" (<c>Inbound:*</c>); <see cref="RetentionDays"/> 0 means keep forever, like every retention knob (design section 5.1).
/// </summary>
/// <param name="DomainId">The domain these settings belong to (one row per domain, deleted with the domain).</param>
/// <param name="TenantId">The owning tenant (of the domain).</param>
/// <param name="Enabled">Whether the server accepts mail for the domain. Needs a verified domain (design section 11.3).</param>
/// <param name="DmarcAction">What to do with a DMARC failure.</param>
/// <param name="MaxMessageBytes">Largest accepted message; capped by the server limit. Null: the server limit.</param>
/// <param name="MaxMessagesPerMinute">Messages per minute accepted for the domain. Null: the server default.</param>
/// <param name="MaxMessagesPerMinutePerRemote">Messages per minute accepted from one remote address for the domain. Null: the server default.</param>
/// <param name="MaxStoredBytes">Total body bytes kept for the domain; at the limit new mail is refused with <c>452 4.2.2</c>. 0: unlimited. Null: the server default.</param>
/// <param name="RetentionDays">Days a message (row and body) is kept, counted from receipt. 0: keep forever. Null: the server default.</param>
/// <param name="UpdatedAt">When the settings were last written.</param>
public sealed record InboundDomainSettings(
    Guid DomainId,
    Guid TenantId,
    bool Enabled,
    InboundDmarcAction DmarcAction,
    long? MaxMessageBytes,
    int? MaxMessagesPerMinute,
    int? MaxMessagesPerMinutePerRemote,
    long? MaxStoredBytes,
    int? RetentionDays,
    DateTimeOffset UpdatedAt)
{
    /// <summary>The settings of a domain that was never configured: inbound off, everything else default.</summary>
    public static InboundDomainSettings Disabled(Guid domainId, Guid tenantId, DateTimeOffset now) =>
        new(domainId, tenantId, false, InboundDmarcAction.RecordOnly, null, null, null, null, null, now);
}

/// <summary>
/// A route of a domain: which recipients it handles and what happens to their mail. The first enabled route (lowest <see cref="Order"/>,
/// then lowest <see cref="Id"/>) that matches wins; there is no other precedence, so a catch-all belongs last.
/// </summary>
/// <param name="Id">Route id (UUIDv7).</param>
/// <param name="TenantId">The owning tenant.</param>
/// <param name="DomainId">The domain the route belongs to (deleted with the domain).</param>
/// <param name="Name">A label for people; may be empty.</param>
/// <param name="Order">Evaluation order, ascending.</param>
/// <param name="Enabled">A disabled route is skipped (mail it would have handled is refused at RCPT unless another route matches).</param>
/// <param name="MatchKind">How <paramref name="LocalPart"/> is used.</param>
/// <param name="LocalPart">The local part (<see cref="InboundMatchKind.Address"/>) or pattern (<see cref="InboundMatchKind.Wildcard"/>); null for <see cref="InboundMatchKind.CatchAll"/>. Stored lower-case.</param>
/// <param name="PlusAddressing">Compare the local part without its <c>+tag</c> as well (<c>support+billing</c> reaches the route for <c>support</c>).</param>
/// <param name="ActionKind">What to do.</param>
/// <param name="WebhookEndpointId">The webhook endpoint of the tenant for <see cref="InboundActionKind.Webhook"/>; null otherwise.</param>
/// <param name="WebhookFormat">The body format for <see cref="InboundActionKind.Webhook"/>.</param>
/// <param name="ForwardTo">The addresses for <see cref="InboundActionKind.Forward"/> (at most <see cref="InboundRules.MaxForwardTargets"/>); empty otherwise.</param>
/// <param name="CreatedAt">Creation time.</param>
/// <param name="UpdatedAt">Time of the last change.</param>
public sealed record InboundRouteRecord(
    Guid Id,
    Guid TenantId,
    Guid DomainId,
    string Name,
    int Order,
    bool Enabled,
    InboundMatchKind MatchKind,
    string? LocalPart,
    bool PlusAddressing,
    InboundActionKind ActionKind,
    Guid? WebhookEndpointId,
    InboundWebhookFormat WebhookFormat,
    IReadOnlyList<string> ForwardTo,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt)
{
    // A record compares its members by value, but a list by reference: two routes with the same forward targets are equal.
    public bool Equals(InboundRouteRecord? other) =>
        other is not null && Id == other.Id && TenantId == other.TenantId && DomainId == other.DomainId && Name == other.Name && Order == other.Order && Enabled == other.Enabled
        && MatchKind == other.MatchKind && LocalPart == other.LocalPart && PlusAddressing == other.PlusAddressing && ActionKind == other.ActionKind && WebhookEndpointId == other.WebhookEndpointId
        && WebhookFormat == other.WebhookFormat && ForwardTo.SequenceEqual(other.ForwardTo) && CreatedAt == other.CreatedAt && UpdatedAt == other.UpdatedAt;

    public override int GetHashCode() => HashCode.Combine(Id, DomainId, Name, Order, MatchKind, LocalPart, ActionKind, ForwardTo.Count);
}

/// <summary>
/// What the receive path needs to know about one inbound-enabled domain, in one object, so it can keep a cache and decide RCPT without a
/// round trip. <see cref="Routes"/> holds the enabled routes only, in evaluation order.
/// </summary>
public sealed record InboundDomainConfiguration(
    string DomainName,
    Guid DomainId,
    Guid TenantId,
    bool TenantEnabled,
    DomainStatus DomainStatus,
    InboundDomainSettings Settings,
    IReadOnlyList<InboundRouteRecord> Routes)
{
    /// <summary>
    /// A fingerprint of everything in this object (domain, status, tenant state, settings and the enabled routes with their targets): it changes exactly when the receive path's view of
    /// the domain changes. The receive path compares it after each refresh to rebuild its derived structures (compiled route lists, limiter configuration) only for the domains that changed.
    /// It is computed from the content, so it needs no storage support and is identical on every backend and replica.
    /// </summary>
    public string ETag
    {
        get
        {
            var sb = new System.Text.StringBuilder(256);
            sb.Append(DomainName).Append('|').Append(DomainId).Append('|').Append(TenantId).Append('|').Append(TenantEnabled).Append('|').Append((int)DomainStatus);
            InboundDomainSettings s = Settings;
            sb.Append('|').Append(s.Enabled).Append('|').Append((int)s.DmarcAction).Append('|').Append(s.MaxMessageBytes).Append('|').Append(s.MaxMessagesPerMinute)
                .Append('|').Append(s.MaxMessagesPerMinutePerRemote).Append('|').Append(s.MaxStoredBytes).Append('|').Append(s.RetentionDays).Append('|').Append(s.UpdatedAt.UtcTicks);
            foreach (InboundRouteRecord r in Routes)
            {
                sb.Append('#').Append(r.Id).Append('|').Append(r.Order).Append('|').Append(r.Enabled).Append('|').Append((int)r.MatchKind).Append('|').Append(r.LocalPart).Append('|').Append(r.PlusAddressing)
                    .Append('|').Append((int)r.ActionKind).Append('|').Append(r.WebhookEndpointId).Append('|').Append((int)r.WebhookFormat).Append('|').Append(r.UpdatedAt.UtcTicks);
                foreach (string target in r.ForwardTo)
                {
                    sb.Append('>').Append(target);
                }
            }

            return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(sb.ToString())))[..24];
        }
    }
}

/// <summary>One received message for one recipient (a transaction with several recipients stores one row, and one body, per recipient: tenants never share a stored copy).</summary>
/// <param name="Id">Message id (UUIDv7; the retention clock reads the day from it).</param>
/// <param name="TenantId">The tenant that owns the recipient domain.</param>
/// <param name="DomainId">The recipient domain.</param>
/// <param name="Domain">The recipient domain name at receipt.</param>
/// <param name="ReceivedAt">Time of acceptance.</param>
/// <param name="RemoteAddress">The client IP address, text form.</param>
/// <param name="Helo">The name the client gave in HELO/EHLO.</param>
/// <param name="TlsUsed">The session was encrypted.</param>
/// <param name="EnvelopeFrom">MAIL FROM as <c>local@domain</c>; empty for the null reverse-path.</param>
/// <param name="EnvelopeTo">The recipient as <c>local@domain</c>, lower-cased.</param>
/// <param name="Subject">The Subject header (decoded, at most 256 characters); null when there is none.</param>
/// <param name="Size">Bytes of the stored message (with the added headers).</param>
/// <param name="Auth">The verification results.</param>
/// <param name="Disposition">What DMARC caused.</param>
/// <param name="RouteId">The route that matched at receipt.</param>
/// <param name="ActionKind">What that route did at receipt (the action that runs is the route's current one, design section 11.7).</param>
/// <param name="ActionState">Where the action stands.</param>
/// <param name="ActionAttempts">Attempts made.</param>
/// <param name="ActionNextAttemptAt">When the next attempt is due; null when not pending.</param>
/// <param name="ActionFinishedAt">When the action became <see cref="InboundActionState.Done"/> or <see cref="InboundActionState.Failed"/>.</param>
/// <param name="ActionLastError">The last failure, a short sentence without secrets.</param>
/// <param name="ForwardMessageId">For a forward, the id of the outbound message that carries it.</param>
/// <param name="HasRaw">The body is stored (false for discard, after a completed forward, or when it was deleted).</param>
/// <param name="RetryGeneration">How often the action was put back with <see cref="IInboundMessageStore.RetryActionAsync"/>; part of the webhook id, so a manual retry is a new event for the receiver.</param>
/// <param name="ActionNote">Set when the action finished <see cref="InboundActionState.Done"/> but something happened that the tenant should know (a short code such as <c>all_targets_suppressed</c> or <c>route_is_now_store</c>); null otherwise. Cleared by a retry.</param>
public sealed record InboundMessage(
    Guid Id,
    Guid TenantId,
    Guid DomainId,
    string Domain,
    DateTimeOffset ReceivedAt,
    string RemoteAddress,
    string? Helo,
    bool TlsUsed,
    string EnvelopeFrom,
    string EnvelopeTo,
    string? Subject,
    long Size,
    InboundAuthResults Auth,
    InboundDmarcDisposition Disposition,
    Guid? RouteId,
    InboundActionKind ActionKind,
    InboundActionState ActionState,
    int ActionAttempts,
    DateTimeOffset? ActionNextAttemptAt,
    DateTimeOffset? ActionFinishedAt,
    string? ActionLastError,
    Guid? ForwardMessageId,
    bool HasRaw,
    int RetryGeneration = 0,
    string? ActionNote = null);

/// <summary>
/// A message to store, built by the receive path after verification and route matching. The state is derived, not given: webhook and forward
/// start <see cref="InboundActionState.Pending"/> and due at <see cref="ReceivedAt"/>, store starts <see cref="InboundActionState.Done"/> with the body, discard
/// starts <see cref="InboundActionState.Done"/> without it (<see cref="Raw"/> is not stored).
/// </summary>
public sealed class InboundMessageDraft
{
    public required Guid Id { get; set; }
    public required Guid TenantId { get; set; }
    public required Guid DomainId { get; set; }
    public required string Domain { get; set; }
    public required DateTimeOffset ReceivedAt { get; set; }
    public required string RemoteAddress { get; set; }
    public string? Helo { get; set; }
    public bool TlsUsed { get; set; }
    public required string EnvelopeFrom { get; set; }
    public required string EnvelopeTo { get; set; }
    public string? Subject { get; set; }
    public required InboundAuthResults Auth { get; set; }
    public InboundDmarcDisposition Disposition { get; set; }
    /// <summary>The route that matched; null for the implicit <c>postmaster</c> delivery (RFC 5321 section 4.5.1, design section 11.4), which is stored.</summary>
    public Guid? RouteId { get; set; }
    public required InboundActionKind ActionKind { get; set; }

    /// <summary>The stored message: the received bytes with the headers the server added (Received, Authentication-Results, ...), CRLF lines.</summary>
    public required ReadOnlyMemory<byte> Raw { get; set; }
}

/// <summary>
/// A search of one tenant's received mail. The tenant is required: there is no all-tenants search in the contract (an administrator acts as a tenant, with <c>X-Tenant-Id</c>),
/// so a missing filter can never leak another tenant's mail.
/// </summary>
public sealed record InboundMessageQuery(
    Guid TenantId,
    Guid? DomainId = null,
    string? Recipient = null,
    string? Sender = null,
    string? SubjectContains = null,
    Guid? RouteId = null,
    InboundActionKind? ActionKind = null,
    InboundActionState? ActionState = null,
    InboundVerdict? Dmarc = null,
    bool? DmarcFlagged = null,
    DateTimeOffset? From = null,
    DateTimeOffset? To = null,
    int Limit = 50,
    string? Cursor = null);

/// <summary>
/// An action claimed for an attempt, with the body (null when it is gone, which the runner records as a permanent failure). <c>Message.ActionAttempts</c> already includes this attempt
/// (1 for the first). <paramref name="ClaimToken"/> identifies this claim: it grows with every claim of the row, never goes back down (a release or a manual retry do not touch it), and is
/// passed back as <see cref="InboundActionOutcome.ClaimToken"/>.
/// </summary>
public sealed record ClaimedInboundAction(InboundMessage Message, byte[]? Raw, long ClaimToken = 0);

/// <summary>
/// The result of one attempt. <see cref="InboundActionState.Pending"/> with a <paramref name="NextAttemptAt"/> schedules a retry; <see cref="InboundActionState.Done"/>
/// and <see cref="InboundActionState.Failed"/> are final. The attempt counter is counted at claim time, not here.
/// </summary>
/// <param name="State">The new state.</param>
/// <param name="At">The time of the attempt (becomes <see cref="InboundMessage.ActionFinishedAt"/> when final).</param>
/// <param name="NextAttemptAt">Required for <see cref="InboundActionState.Pending"/>.</param>
/// <param name="Error">What failed (kept as <see cref="InboundMessage.ActionLastError"/>; cleared by a success).</param>
/// <param name="ForwardMessageId">The outbound message id of a forward.</param>
/// <param name="Note">Only for <see cref="InboundActionState.Done"/>: a short code (letters, digits, <c>_</c>) for a completion the tenant should know about, kept as <see cref="InboundMessage.ActionNote"/>. Known codes: <c>all_targets_suppressed</c> (every forward target is on the tenant's suppression list: nothing was queued), <c>route_is_now_store</c> and <c>route_is_now_discard</c> (the route was changed to an action without delivery while the message waited; the body is kept until retention).</param>
/// <param name="ClaimToken">The <see cref="ClaimedInboundAction.ClaimToken"/> the claim returned; the completion is refused when the row has been claimed again since, whatever happened to the attempt count in between (a release, a retry). Null: not checked.</param>
/// <param name="FreeBody">Delete the stored body: the runner sets it for a completed forward, whose copy now lives in the outbound queue. A completed webhook keeps the body for the attachment references until retention.</param>
public sealed record InboundActionOutcome(InboundActionState State, DateTimeOffset At, DateTimeOffset? NextAttemptAt, string? Error, Guid? ForwardMessageId = null, bool FreeBody = false, string? Note = null, long? ClaimToken = null);

public enum InboundRetryResult : byte
{
    /// <summary>The action is pending again, due now, with its attempts reset.</summary>
    Queued = 0,

    /// <summary>No such message for the tenant.</summary>
    NotFound,

    /// <summary>Store and discard have no action to repeat, and a message whose body is gone cannot be sent again.</summary>
    NotRetryable,

    /// <summary>The action is pending already (waiting or being attempted).</summary>
    AlreadyPending,
}

/// <summary>What an inbound-enabled domain (or a tenant, or the server) holds. <see cref="Pending"/> and <see cref="Failed"/> count actions.</summary>
public sealed record InboundUsage(long Messages, long BodyBytes, long Pending, long Failed, DateTimeOffset? OldestPendingAt);

/// <summary>
/// The operator's server-wide limits (<c>Inbound:*</c>, design section 11.6): what a domain's own settings may be at most. A tenant can only lower a limit, never raise it, and a domain
/// that sets nothing gets the ceiling itself (rates, sizes) or the default (retention, see <c>StorageOptions.Inbound</c>). <c>0</c> is unlimited for the stored-bytes limits and means
/// "no ceiling" for <see cref="MaxRetentionDays"/>.
/// </summary>
/// <param name="MaxMessageBytes">Largest inbound message.</param>
/// <param name="MaxMessagesPerMinute">Messages per minute for one domain.</param>
/// <param name="MaxMessagesPerMinutePerRemote">Messages per minute from one client address (an IPv6 /64) for one domain.</param>
/// <param name="MaxStoredBytesPerDomain">Body bytes kept for one domain; 0 unlimited.</param>
/// <param name="MaxStoredBytesPerTenant">Body bytes kept for all domains of one tenant together; 0 unlimited. Enforced by the receive path.</param>
/// <param name="MaxRetentionDays">The longest retention a domain may choose; 0: none (a domain may keep forever).</param>
public sealed record InboundCeilings(long MaxMessageBytes, int MaxMessagesPerMinute, int MaxMessagesPerMinutePerRemote, long MaxStoredBytesPerDomain, long MaxStoredBytesPerTenant, int MaxRetentionDays);

/// <summary>Per-domain inbound settings and routes (the config part).</summary>
public interface IInboundConfigStore
{
    /// <summary>The settings of a domain, or null when it was never configured (inbound off).</summary>
    ValueTask<InboundDomainSettings?> GetSettingsAsync(Guid domainId, CancellationToken cancellationToken);

    /// <summary>Inserts or replaces the settings of <see cref="InboundDomainSettings.DomainId"/>. The domain must exist (an unknown one is a <see cref="StorageConflictException"/>) and belong to <see cref="InboundDomainSettings.TenantId"/>.</summary>
    ValueTask UpsertSettingsAsync(InboundDomainSettings settings, CancellationToken cancellationToken);

    /// <summary>The routes of a domain, enabled or not, in evaluation order (<see cref="InboundRouteRecord.Order"/>, then <see cref="InboundRouteRecord.Id"/>).</summary>
    ValueTask<IReadOnlyList<InboundRouteRecord>> GetRoutesAsync(Guid domainId, CancellationToken cancellationToken);

    /// <summary>One route of the tenant; null when unknown or another tenant's.</summary>
    ValueTask<InboundRouteRecord?> GetRouteAsync(Guid tenantId, Guid routeId, CancellationToken cancellationToken);

    /// <summary>
    /// Inserts or replaces a route (validated by <see cref="Logic.InboundRules.ValidateRoute"/> before the call). The domain must exist and belong to the route's tenant, and a webhook route's
    /// endpoint must exist and belong to the same tenant: both are checked inside the same write as the insert (<see cref="StorageConflictException"/> otherwise), so an endpoint deleted at the same moment
    /// cannot be left behind a route. The schema has no foreign keys by design; this and <see cref="IConfigStore.DeleteWebhookEndpointAsync"/> are the integrity rule.
    /// </summary>
    ValueTask UpsertRouteAsync(InboundRouteRecord route, CancellationToken cancellationToken);

    /// <summary>Deletes a route of the tenant; false when there is none. Messages that referenced it keep their row (their action then fails with <c>route_deleted</c> if still pending).</summary>
    ValueTask<bool> DeleteRouteAsync(Guid tenantId, Guid routeId, CancellationToken cancellationToken);

    /// <summary>The routes (any domain) whose webhook action targets <paramref name="endpointId"/>, so deleting an endpoint can be refused while a route needs it.</summary>
    ValueTask<IReadOnlyList<InboundRouteRecord>> GetRoutesUsingWebhookEndpointAsync(Guid endpointId, CancellationToken cancellationToken);

    /// <summary>Every domain with <see cref="InboundDomainSettings.Enabled"/>, with its enabled routes: what the receive path caches.</summary>
    ValueTask<IReadOnlyList<InboundDomainConfiguration>> LoadEnabledDomainsAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Received messages and the state of their route actions (the queue part). While a backend switch closes the store only the operations that start new work are fenced:
/// <see cref="AcceptAsync"/> throws <see cref="StorageFencedException"/> and <see cref="ClaimActionsAsync"/> returns nothing; completing, extending, releasing, retrying and deleting are allowed
/// (a completion finishes the attempt in flight that the quiesce waits for, the others act on data that stays in the source until the switch is finalized).
/// </summary>
public interface IInboundMessageStore
{
    /// <summary>
    /// Stores the drafts of one SMTP transaction (one per accepted recipient) in one atomic step, returns after the data is committed according to the
    /// configured sync mode (the same promise as <see cref="IMessageIntake.AcceptAsync"/>: the caller sends <c>250</c> after it returns). The caller reuses the
    /// drafts once the task completes, so nothing may still read them and the objects must not be kept.
    /// </summary>
    ValueTask AcceptAsync(IReadOnlyList<InboundMessageDraft> drafts, CancellationToken cancellationToken);

    /// <summary>One page, newest first. <see cref="InboundMessageQuery.Limit"/> is clamped to 1 to <see cref="Logic.InboundRules.MaxPageSize"/> (200) on every backend.</summary>
    ValueTask<Page<InboundMessage>> SearchAsync(InboundMessageQuery query, CancellationToken cancellationToken);

    /// <summary>One message of the tenant; null when unknown, another tenant's, or already deleted by retention.</summary>
    ValueTask<InboundMessage?> GetAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken);

    /// <summary>The stored body; null when there is none (discard, a completed forward, deleted) or the message is unknown or foreign.</summary>
    ValueTask<byte[]?> GetRawAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken);

    /// <summary>Deletes the message and its body, whatever its action state; false when there is none for the tenant. An attempt in flight finishes harmlessly (its completion returns false).</summary>
    ValueTask<bool> DeleteAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken);

    /// <summary>
    /// Deletes every message (and body) of <paramref name="query"/>'s tenant that matches its filters, whatever its action state (erasure of one sender's or recipient's mail, a
    /// domain's mail). At least one filter besides the tenant is required (<see cref="ArgumentException"/> otherwise), so it can never empty a tenant by accident; the
    /// paging members are ignored. Returns the number of messages deleted. Done in batches; an attempt in flight finishes harmlessly.
    /// </summary>
    ValueTask<long> DeleteMatchingAsync(InboundMessageQuery query, CancellationToken cancellationToken);

    /// <summary>Puts a <see cref="InboundActionState.Failed"/> or <see cref="InboundActionState.Done"/> webhook or forward action back to pending (due at <paramref name="now"/>, attempts reset, <see cref="InboundMessage.RetryGeneration"/> + 1). A forward whose body was freed is <see cref="InboundRetryResult.NotRetryable"/>.</summary>
    ValueTask<InboundRetryResult> RetryActionAsync(Guid tenantId, Guid messageId, DateTimeOffset now, CancellationToken cancellationToken);

    /// <summary>
    /// Leases up to <paramref name="max"/> pending actions due at <paramref name="now"/> (webhook and forward) to <paramref name="owner"/> for <paramref name="lease"/>
    /// (a row whose lease ran out is claimable again). PostgreSQL: <c>FOR UPDATE SKIP LOCKED</c>; SQLite: the queue writer. Oldest due first.
    /// <b>The claim counts the attempt</b>: <see cref="InboundMessage.ActionAttempts"/> goes up by one when the row is claimed (the returned message shows the new value, so the first attempt is 1),
    /// not when it is completed. A runner that crashes in the middle of an attempt has therefore used it up, and a message that crashes its runner every time (a poison pill) reaches the end of
    /// the ladder instead of being claimed for ever; the runner fails an action whose attempt number is past the last rung. A graceful release gives the attempt back
    /// (<see cref="ReleaseOwnedActionLeasesAsync"/>).
    /// </summary>
    ValueTask<IReadOnlyList<ClaimedInboundAction>> ClaimActionsAsync(string owner, int max, DateTimeOffset now, TimeSpan lease, CancellationToken cancellationToken);

    /// <summary>Extends the lease of a long attempt; false when <paramref name="owner"/> no longer holds it.</summary>
    ValueTask<bool> ExtendActionLeaseAsync(Guid messageId, string owner, DateTimeOffset until, CancellationToken cancellationToken);

    /// <summary>
    /// Records the result of an attempt made under the lease of <paramref name="owner"/>; false (nothing changed) when the lease was lost, the message was deleted or it is not leased
    /// by <paramref name="owner"/>. <b>Lost includes re-claimed by the same owner</b>: pass <see cref="ClaimedInboundAction.ClaimToken"/> as
    /// <see cref="InboundActionOutcome.ClaimToken"/> and a completion from an earlier claim (the lease ran out or was released, the row was claimed again, even under the same owner name) is refused, because
    /// the token grows with every claim and never goes back down. Without <c>ClaimToken</c> only the owner is checked, so a runner that cannot pass it must use a distinct owner name per claim. A completion after the
    /// lease ran out is accepted while nobody has claimed the row since (the work was done; refusing it would only repeat it). The attempt count is not changed by completing.
    /// <see cref="InboundActionOutcome.FreeBody"/> deletes the body (<see cref="InboundMessage.HasRaw"/> becomes false); an <see cref="InboundActionState.Pending"/> outcome needs <see cref="InboundActionOutcome.NextAttemptAt"/> (<see cref="ArgumentException"/> otherwise).
    /// </summary>
    ValueTask<bool> CompleteActionAsync(Guid messageId, string owner, InboundActionOutcome outcome, CancellationToken cancellationToken);

    /// <summary>Releases the leases held by <paramref name="owner"/> and gives back the attempt each claim counted (graceful shutdown, quiesce: the attempt was not made); the claim token is not given back.</summary>
    ValueTask<int> ReleaseOwnedActionLeasesAsync(string owner, CancellationToken cancellationToken);

    /// <summary>
    /// What is held: <paramref name="tenantId"/> and/or <paramref name="domainId"/> narrow the count (both null: the whole server). Cheap enough to poll every few seconds
    /// (indexed counts); the receive path caches it for the stored-bytes limit and the metrics read it.
    /// </summary>
    ValueTask<InboundUsage> GetUsageAsync(Guid? tenantId, Guid? domainId, CancellationToken cancellationToken);
}

/// <summary>Inbound mail storage: <see cref="IStorage.Inbound"/>. Retention runs inside <see cref="IStorageMaintenance.RunAsync"/> (job <c>inbound_retention</c>).</summary>
public interface IInboundStore : IInboundConfigStore, IInboundMessageStore
{
}
