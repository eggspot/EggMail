namespace Mta.Storage;

// Contracts of inbound mail (design section 11, decision 92). Three kinds of data, one interface:
//   - per-domain inbound settings and the routes of a domain: configuration (the config part), read at RCPT time through a cache;
//   - inbound messages: the received mail with its verification results and the state of the route action (the queue part, so a
//     forward can join the outbound queue in the same file and the switch holds them like deliveries);
//   - retention: the "inbound_retention" job of IStorageMaintenance.RunAsync.
// Every method behaves identically on every backend (decision E).

/// <summary>What the receiver does when DMARC evaluation says the message fails and the sender's policy asks for quarantine or rejection.</summary>
public enum InboundDmarcAction : byte
{
    /// <summary>Accept and record the DMARC verdict; never act on the sender's policy (the default).</summary>
    RecordOnly = 0,

    /// <summary>Accept; when the sender's policy is quarantine or reject and the message fails DMARC, flag the stored message (<see cref="InboundDmarcDisposition.QuarantineFlagged"/>) and add <c>X-EggMail-Quarantine: dmarc</c>.</summary>
    QuarantineFlag = 1,

    /// <summary>Honor the sender's policy: a message that fails DMARC under <c>p=reject</c> is refused at the end of DATA with <c>550 5.7.1</c>; a <c>p=quarantine</c> failure is flagged as with <see cref="QuarantineFlag"/>.</summary>
    Reject = 2,
}

/// <summary>What was done to a stored message because of DMARC. A refused message is never stored, so there is no value for it.</summary>
public enum InboundDmarcDisposition : byte
{
    None = 0,
    QuarantineFlagged = 1,
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

/// <summary>The verification results of one received message: SPF (on MAIL FROM, HELO when the reverse-path is null), DKIM (the best signature: pass when any passes), DMARC and ARC.</summary>
/// <param name="Spf">SPF verdict.</param>
/// <param name="SpfDomain">The domain SPF was evaluated for.</param>
/// <param name="Dkim">DKIM verdict: <see cref="InboundVerdict.Pass"/> when any signature passed, else the strongest failure, <see cref="InboundVerdict.None"/> without signatures.</param>
/// <param name="DkimDomain">The <c>d=</c> of the signature that decided <paramref name="Dkim"/>.</param>
/// <param name="Dmarc">DMARC verdict for the RFC 5322 From domain.</param>
/// <param name="DmarcPolicy">The policy the sender published (<c>none</c>, <c>quarantine</c>, <c>reject</c>, the subdomain policy when it applied); null without a DMARC record.</param>
/// <param name="Arc">ARC chain validation (<see cref="InboundVerdict.None"/> without a chain, <see cref="InboundVerdict.Pass"/> or <see cref="InboundVerdict.Fail"/>).</param>
public sealed record InboundAuthResults(
    InboundVerdict Spf,
    string? SpfDomain,
    InboundVerdict Dkim,
    string? DkimDomain,
    InboundVerdict Dmarc,
    string? DmarcPolicy,
    InboundVerdict Arc)
{
    public static InboundAuthResults NotChecked { get; } = new(InboundVerdict.None, null, InboundVerdict.None, null, InboundVerdict.None, null, InboundVerdict.None);
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
    IReadOnlyList<InboundRouteRecord> Routes);

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
    bool HasRaw);

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
    public required Guid RouteId { get; set; }
    public required InboundActionKind ActionKind { get; set; }

    /// <summary>The stored message: the received bytes with the headers the server added (Received, Authentication-Results, ...), CRLF lines.</summary>
    public required ReadOnlyMemory<byte> Raw { get; set; }
}

public sealed record InboundMessageQuery(
    Guid? TenantId = null,
    Guid? DomainId = null,
    string? Recipient = null,
    string? Sender = null,
    string? SubjectContains = null,
    Guid? RouteId = null,
    InboundActionKind? ActionKind = null,
    InboundActionState? ActionState = null,
    InboundVerdict? Dmarc = null,
    bool? Quarantined = null,
    DateTimeOffset? From = null,
    DateTimeOffset? To = null,
    int Limit = 50,
    string? Cursor = null);

/// <summary>An action claimed for an attempt, with the body (null when it is gone, which the runner records as a permanent failure).</summary>
public sealed record ClaimedInboundAction(InboundMessage Message, byte[]? Raw);

/// <summary>
/// The result of one attempt. <see cref="InboundActionState.Pending"/> with a <paramref name="NextAttemptAt"/> schedules a retry; <see cref="InboundActionState.Done"/>
/// and <see cref="InboundActionState.Failed"/> are final. The attempt counter always goes up by one.
/// </summary>
/// <param name="State">The new state.</param>
/// <param name="At">The time of the attempt (becomes <see cref="InboundMessage.ActionFinishedAt"/> when final).</param>
/// <param name="NextAttemptAt">Required for <see cref="InboundActionState.Pending"/>.</param>
/// <param name="Error">What failed (kept as <see cref="InboundMessage.ActionLastError"/>; cleared by a success).</param>
/// <param name="ForwardMessageId">The outbound message id of a forward.</param>
/// <param name="FreeBody">Delete the stored body: the runner sets it for a completed forward, whose copy now lives in the outbound queue. A completed webhook keeps the body for the attachment references until retention.</param>
public sealed record InboundActionOutcome(InboundActionState State, DateTimeOffset At, DateTimeOffset? NextAttemptAt, string? Error, Guid? ForwardMessageId = null, bool FreeBody = false);

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

    /// <summary>Inserts or replaces a route. The domain must exist and belong to the route's tenant (<see cref="StorageConflictException"/> otherwise).</summary>
    ValueTask UpsertRouteAsync(InboundRouteRecord route, CancellationToken cancellationToken);

    /// <summary>Deletes a route of the tenant; false when there is none. Messages that referenced it keep their row (their action then fails with <c>route_deleted</c> if still pending).</summary>
    ValueTask<bool> DeleteRouteAsync(Guid tenantId, Guid routeId, CancellationToken cancellationToken);

    /// <summary>The routes (any domain) whose webhook action targets <paramref name="endpointId"/>, so deleting an endpoint can be refused while a route needs it.</summary>
    ValueTask<IReadOnlyList<InboundRouteRecord>> GetRoutesUsingWebhookEndpointAsync(Guid endpointId, CancellationToken cancellationToken);

    /// <summary>Every domain with <see cref="InboundDomainSettings.Enabled"/>, with its enabled routes: what the receive path caches.</summary>
    ValueTask<IReadOnlyList<InboundDomainConfiguration>> LoadEnabledDomainsAsync(CancellationToken cancellationToken);
}

/// <summary>Received messages and the state of their route actions (the queue part).</summary>
public interface IInboundMessageStore
{
    /// <summary>
    /// Stores the drafts of one SMTP transaction (one per accepted recipient) in one atomic step, returns after the data is committed according to the
    /// configured sync mode (the same promise as <see cref="IMessageIntake.AcceptAsync"/>: the caller sends <c>250</c> after it returns). The caller reuses the
    /// drafts once the task completes, so nothing may still read them and the objects must not be kept.
    /// </summary>
    ValueTask AcceptAsync(IReadOnlyList<InboundMessageDraft> drafts, CancellationToken cancellationToken);

    ValueTask<Page<InboundMessage>> SearchAsync(InboundMessageQuery query, CancellationToken cancellationToken);

    /// <summary>One message of the tenant; null when unknown, another tenant's, or already deleted by retention.</summary>
    ValueTask<InboundMessage?> GetAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken);

    /// <summary>The stored body; null when there is none (discard, a completed forward, deleted) or the message is unknown or foreign.</summary>
    ValueTask<byte[]?> GetRawAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken);

    /// <summary>Deletes the message and its body, whatever its action state; false when there is none for the tenant. An attempt in flight finishes harmlessly (its completion returns false).</summary>
    ValueTask<bool> DeleteAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken);

    /// <summary>Puts a <see cref="InboundActionState.Failed"/> or <see cref="InboundActionState.Done"/> webhook or forward action back to pending (due at <paramref name="now"/>, attempts reset). A forward whose body was freed is <see cref="InboundRetryResult.NotRetryable"/>.</summary>
    ValueTask<InboundRetryResult> RetryActionAsync(Guid tenantId, Guid messageId, DateTimeOffset now, CancellationToken cancellationToken);

    /// <summary>
    /// Leases up to <paramref name="max"/> pending actions due at <paramref name="now"/> (webhook and forward) to <paramref name="owner"/> for <paramref name="lease"/>
    /// (a row whose lease ran out is claimable again). PostgreSQL: <c>FOR UPDATE SKIP LOCKED</c>; SQLite: the queue writer. Oldest due first.
    /// </summary>
    ValueTask<IReadOnlyList<ClaimedInboundAction>> ClaimActionsAsync(string owner, int max, DateTimeOffset now, TimeSpan lease, CancellationToken cancellationToken);

    /// <summary>Extends the lease of a long attempt; false when <paramref name="owner"/> no longer holds it.</summary>
    ValueTask<bool> ExtendActionLeaseAsync(Guid messageId, string owner, DateTimeOffset until, CancellationToken cancellationToken);

    /// <summary>
    /// Records the result of an attempt made under the lease of <paramref name="owner"/>; false (nothing changed) when the lease was lost, the message was deleted or it is not leased
    /// by <paramref name="owner"/>. <see cref="InboundActionOutcome.FreeBody"/> deletes the body (<see cref="InboundMessage.HasRaw"/> becomes false); an <see cref="InboundActionState.Pending"/> outcome needs <see cref="InboundActionOutcome.NextAttemptAt"/> (<see cref="ArgumentException"/> otherwise).
    /// </summary>
    ValueTask<bool> CompleteActionAsync(Guid messageId, string owner, InboundActionOutcome outcome, CancellationToken cancellationToken);

    /// <summary>Releases the leases held by <paramref name="owner"/> without counting an attempt (graceful shutdown, quiesce).</summary>
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
