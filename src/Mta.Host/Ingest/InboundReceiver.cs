using System.Collections.Concurrent;
using System.Net;
using System.Text;
using Mta.Core;
using Mta.Dsn;
using Mta.Smtp.Protocol;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Storage.Logic;

namespace Mta.Host.Ingest;

/// <summary>How the bounce side of the port-25 listener classifies a recipient (see <see cref="IBounceNamespace"/>).</summary>
public enum BounceRecipientClass : byte
{
    /// <summary>Not an address in the bounce namespace: the inbound classification goes on.</summary>
    NotBounce = 0,

    /// <summary>A signed bounce address (or <c>postmaster</c>/<c>abuse</c> at the shared bounce domain): accepted as a bounce recipient.</summary>
    Accepted,

    /// <summary>An address in the bounce namespace that is none of those (an invalid token, any other local part): <c>550 5.1.1</c>, never an inbound recipient.</summary>
    Refused,
}

/// <summary>The bounce half of the port-25 listener, as the receive path sees it. Implemented by <see cref="IngestHandler"/>, which owns the bounce address rules.</summary>
public interface IBounceNamespace
{
    /// <param name="recipient">The recipient.</param>
    /// <param name="clientKey">The client network (<see cref="NetworkKey.Remote"/>): uncached lookups are budgeted per client.</param>
    /// <param name="cancellationToken">Cancels the lookup.</param>
    ValueTask<BounceRecipientClass> ClassifyAsync(EmailAddress recipient, string clientKey, CancellationToken cancellationToken);

    ValueTask<SmtpReply> HandleMessageAsync(SmtpMessage message, CancellationToken cancellationToken);
}

/// <summary>
/// The MX receiver for the domains tenants enabled for inbound mail (design section 11, decision 95), behind the port-25 listener of role <see cref="ListenerRole.Inbound"/>. It decides at RCPT
/// time (nothing is accepted and bounced later: no backscatter; an address no route handles is never accepted: no open relay), enforces size, budget, rate and slot limits, verifies the
/// message, and hands one copy per recipient to the inbound store in one atomic write. The route actions run later, by their own worker; this class only stores the message as pending.
/// <para>Classification order of a recipient: a signed bounce address (or <c>postmaster</c>/<c>abuse</c> at the shared bounce domain, or a token at a verified return-path host), an SRS address,
/// an inbound-enabled domain with a matching enabled route (or the implicit <c>postmaster</c>), and everything else is refused. A transaction has one kind (bounce, SRS or inbound).</para>
/// </summary>
public sealed class InboundReceiver
{
    private static readonly SmtpReply RelayDenied = SmtpReply.Constant(550, "5.7.1", "Relaying denied");
    private static readonly SmtpReply UnknownMailbox = SmtpReply.Constant(550, "5.1.1", "Mailbox unavailable");
    private static readonly SmtpReply NoSuchUser = SmtpReply.Constant(550, "5.1.1", "No such user here");
    private static readonly SmtpReply MailboxDisabled = SmtpReply.Constant(450, "4.2.1", "Mailbox disabled, try again later");
    private static readonly SmtpReply TooManyMessages = SmtpReply.Constant(450, "4.7.1", "Too many messages, try again later");
    private static readonly SmtpReply TooManyRecipients = SmtpReply.Constant(452, "4.5.3", "Too many recipients");
    private static readonly SmtpReply TooManyRecipientsForSize = SmtpReply.Constant(452, "4.5.3", "Too many recipients for this size");
    private static readonly SmtpReply MixedKinds = SmtpReply.Constant(452, "4.5.3", "Cannot mix these recipients in one transaction, send them separately");
    private static readonly SmtpReply MailboxFull = SmtpReply.Constant(452, "4.2.2", "Mailbox full, try again later");
    private static readonly SmtpReply MessageTooBig = SmtpReply.Constant(552, "5.3.4", "Message too big");
    private static readonly SmtpReply Busy = SmtpReply.Constant(451, "4.7.0", "Server busy, try again later");
    private static readonly SmtpReply AuthTryLater = SmtpReply.Constant(451, "4.7.0", "Temporary authentication failure, try again later");
    private static readonly SmtpReply TooManyHops = SmtpReply.Constant(554, "5.4.6", "Too many hops");
    private static readonly SmtpReply HeadersTooLarge = SmtpReply.Constant(554, "5.6.0", "Header section too large");
    private static readonly SmtpReply MalformedStart = SmtpReply.Constant(554, "5.6.0", "Malformed message: it starts with white space");
    private static readonly SmtpReply NoUsableFromAddress = SmtpReply.Constant(554, "5.6.0", "No usable From address");
    private static readonly SmtpReply TooManyFromAddresses = SmtpReply.Constant(554, "5.6.0", "Too many From addresses");
    private static readonly SmtpReply Unavailable = SmtpReply.Constant(451, "4.3.0", "Temporary problem accepting the message, try again later");
    private static readonly SmtpReply StorageFull = SmtpReply.Constant(452, "4.3.1", "Insufficient system storage, try again later");
    private static readonly SmtpReply Accepted = SmtpReply.Constant(250, "2.0.0", "Accepted");

    private long _lastInternalAddressWarning = long.MinValue;   // per receiver: one warning an hour for the listener, however many senders
    private static readonly long WarningIntervalTicks = (long)(TimeSpan.FromHours(1).TotalSeconds * System.Diagnostics.Stopwatch.Frequency);

    private enum Kind : byte
    {
        None,
        Bounce,
        Srs,
        Inbound,
    }

    private sealed record AcceptedRecipient(InboundDomainView Domain, InboundRouteRecord? Route, string Address);

    private sealed class State
    {
        public required IPAddress Client { get; init; }
        public Kind Kind;
        public List<AcceptedRecipient> Recipients { get; } = [];
        public long? DeclaredSize;
        public long MinLimit = long.MaxValue;
        public bool DnsblChecked;
        public HashSet<Guid> CountedDomains { get; } = [];
        public string? DnsblZone;

        public void Reset()
        {
            Kind = Kind.None;
            Recipients.Clear();
            CountedDomains.Clear();
            DeclaredSize = null;
            MinLimit = long.MaxValue;
        }
    }

    private readonly IBounceNamespace _bounces;
    private readonly IInboundStore _store;
    private readonly InboundConfigurationCache _config;
    private readonly InboundVerifier _verifier;
    private readonly VerificationSlots _slots;
    private readonly InboundRateLimiter _limiter;
    private readonly DnsblChecker _dnsbl;
    private readonly SrsCodec? _srs;
    private readonly ForwardHopMarker? _hops;
    private readonly InboundReceiveOptions _options;
    private readonly IClock _clock;
    private readonly IMtaLog _log;
    private readonly Func<SmtpSessionContext, IPAddress> _clientAddress;
    private readonly Action? _onAccepted;
    private readonly string[] _ownAuthservIds;
    private readonly ConcurrentDictionary<Guid, (long ExpiresAt, InboundUsage Usage)> _usage = new();

    public InboundReceiver(
        IBounceNamespace bounces, IInboundStore store, InboundConfigurationCache config, InboundVerifier verifier, VerificationSlots slots, InboundRateLimiter limiter, DnsblChecker dnsbl,
        SrsCodec? srs, ForwardHopMarker? hops, InboundReceiveOptions options, string hostname, IClock clock, IMtaLog? log = null, Func<SmtpSessionContext, IPAddress>? clientAddress = null, Action? onAccepted = null)
    {
        _bounces = bounces;
        _store = store;
        _config = config;
        _verifier = verifier;
        _slots = slots;
        _limiter = limiter;
        _dnsbl = dnsbl;
        _srs = srs;
        _hops = hops;
        _options = options;
        _clock = clock;
        _log = log ?? NullMtaLog.Instance;
        _clientAddress = clientAddress ?? (static ctx => NetworkKey.Normalize(ctx.RemoteEndPoint.Address));
        _onAccepted = onAccepted;
        _ownAuthservIds = string.Equals(verifier.AuthservId, hostname, StringComparison.OrdinalIgnoreCase) ? [verifier.AuthservId] : [verifier.AuthservId, hostname];
        InboundMetrics.Attach(() => config.AgeSeconds, () => (limiter.DomainEntries, limiter.RemoteEntries));
    }

    // ---------------------------------------------------------------- connection and sender

    public ValueTask<SmtpReply?> OnConnectedAsync(SmtpSessionContext session)
    {
        IPAddress client = NetworkKey.Normalize(_clientAddress(session));
        session.HandlerState = new State { Client = client };
        if (NetworkKey.IsInternal(client) && !IPAddress.IsLoopback(session.LocalEndPoint.Address))
        {
            // Behind source NAT (a Docker bridge or userland proxy, a Service with externalTrafficPolicy Cluster) every sender looks like this address.
            long now = System.Diagnostics.Stopwatch.GetTimestamp();
            long last = Volatile.Read(ref _lastInternalAddressWarning);
            if ((last == long.MinValue || now - last > WarningIntervalTicks) && Interlocked.CompareExchange(ref _lastInternalAddressWarning, now, last) == last)
            {
                _log.Write(MtaLogLevel.Warning, "inbound", "client addresses look internal (an inbound connection came from a private, loopback or link-local address); SPF and per-address limits are not meaningful behind NAT, see the Inbound mail section of the operations guide");
            }
        }

        return ValueTask.FromResult<SmtpReply?>(null);
    }

    public ValueTask<SmtpReply> OnMailFromAsync(SmtpSessionContext session, MailFromInfo mail)
    {
        State state = StateOf(session);
        state.Reset();
        state.DeclaredSize = mail.Parameters.Size;
        // An unauthenticated MAIL FROM of a local domain is an external sender claiming a local identity: accepted like any other, verified (SPF fails unless the sender is authorized),
        // and neither authenticated nor relayed. Inbound sessions have no AUTH.
        return ValueTask.FromResult(SmtpReplies.SenderOk);
    }

    private static State StateOf(SmtpSessionContext session) => session.HandlerState as State ?? throw new InvalidOperationException("The inbound session has no state.");

    // ---------------------------------------------------------------- recipients

    public async ValueTask<SmtpReply> OnRcptToAsync(SmtpSessionContext session, MailFromInfo mail, EmailAddress recipient, CancellationToken ct)
    {
        State state = StateOf(session);
        try
        {
            return await ClassifyAsync(session, state, mail, recipient, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Write(MtaLogLevel.Warning, "inbound", "a recipient could not be checked", ex);
            InboundMetrics.Recipient("unavailable");
            return Unavailable;
        }
    }

    private async ValueTask<SmtpReply> ClassifyAsync(SmtpSessionContext session, State state, MailFromInfo mail, EmailAddress recipient, CancellationToken ct)
    {
        // 1. A bounce recipient, exactly what the bounce listener accepts (decision 92).
        switch (await _bounces.ClassifyAsync(recipient, NetworkKey.Remote(state.Client), ct).ConfigureAwait(false))
        {
            case BounceRecipientClass.Accepted:
                if (state.Kind is not (Kind.None or Kind.Bounce))
                {
                    return Mixed();
                }

                state.Kind = Kind.Bounce;
                LimitBounceClassMessage(session, mail);
                InboundMetrics.Recipient("bounce");
                return SmtpReplies.RecipientOk;

            case BounceRecipientClass.Refused:
                InboundMetrics.Recipient("unknown_mailbox");
                return NoSuchUser;
        }

        if (!_config.IsAvailable)
        {
            // Never "unknown domain" for a configuration that is not there.
            InboundMetrics.Recipient("unavailable");
            return Unavailable;
        }

        InboundDomainView? view = _config.Find(recipient.Domain);
        if (view is null)
        {
            InboundMetrics.Recipient("relay_denied");
            return RelayDenied;
        }

        string local = recipient.LocalPart;

        // 2. An SRS address: only from the null sender, only with a valid hash and age; the bounce is dropped.
        if (SrsCodec.HasSrsPrefix(local))
        {
            if (!mail.Sender.IsNull || _srs is null || !_srs.TryVerify(local, _clock.UtcNow))
            {
                InboundMetrics.Recipient("unknown_mailbox");
                return UnknownMailbox;
            }

            if (state.Kind is not (Kind.None or Kind.Srs))
            {
                return Mixed();
            }

            state.Kind = Kind.Srs;
            LimitBounceClassMessage(session, mail);
            InboundMetrics.Recipient("srs_bounce");
            return SmtpReplies.RecipientOk;
        }

        // 3. An inbound recipient.
        if (state.Kind is not (Kind.None or Kind.Inbound))
        {
            return Mixed();
        }

        if (!view.Serving)
        {
            InboundMetrics.Recipient(view.Configuration.TenantEnabled ? "domain_unverified" : "tenant_disabled");
            return MailboxDisabled;
        }

        InboundRouteRecord? route = InboundRules.MatchRoute(view.Configuration.Routes, local);
        bool postmaster = route is null && InboundRules.IsPostmaster(local);
        if (route is null && !postmaster)
        {
            InboundMetrics.Recipient("unknown_mailbox");
            return UnknownMailbox;
        }

        if (state.Recipients.Count >= _options.MaxRecipients)
        {
            InboundMetrics.Recipient("too_many");
            return TooManyRecipients;
        }

        DateTimeOffset now = _clock.UtcNow;
        InboundEffectiveLimits limits = view.Limits;
        // A message is counted once per domain, however many of its recipients are in that domain (the limit is on messages per minute).
        if (!state.CountedDomains.Contains(view.DomainId) && !_limiter.Allows(view.DomainId, state.Client, limits.MaxMessagesPerMinute, limits.MaxMessagesPerMinutePerRemote, now))
        {
            InboundMetrics.Recipient("rate_limited");
            return TooManyMessages;
        }

        long limit = Math.Min(state.MinLimit, limits.MaxMessageBytes);
        if (state.DeclaredSize is { } declared && declared > limit)
        {
            InboundMetrics.Recipient("message_too_large");
            return MessageTooBig;
        }

        long assumed = state.DeclaredSize ?? InboundReceiveOptions.AssumedMessageSize;
        if (assumed > _options.MaxTransactionBytes / (state.Recipients.Count + 1))
        {
            InboundMetrics.Recipient("budget");
            InboundMetrics.Refused("budget");
            return TooManyRecipientsForSize;
        }

        if (!state.DnsblChecked)
        {
            // Once per connection, at the first recipient that classifies as inbound; a connection that carries only bounce or SRS recipients is never looked up.
            state.DnsblChecked = true;
            if (_dnsbl.Enabled && !NetworkKey.IsInternal(state.Client))   // an internal address says nothing to a list and need not be disclosed to it
            {
                state.DnsblZone = await _dnsbl.FindListingAsync(state.Client, ct).ConfigureAwait(false);
            }
        }

        if (state.DnsblZone is { } zone && _options.DnsblReject)
        {
            InboundMetrics.Recipient("dnsbl_rejected");
            return SmtpReply.Create(554, "5.7.1", "Listed by " + SafeText(zone));
        }

        if (await QuotaReachedAsync(view, limits, ct).ConfigureAwait(false))
        {
            InboundMetrics.Recipient("mailbox_full");
            return MailboxFull;
        }

        if (state.CountedDomains.Add(view.DomainId))
        {
            _limiter.Count(view.DomainId, state.Client, now);
        }

        state.Kind = Kind.Inbound;
        state.Recipients.Add(new AcceptedRecipient(view, route, recipient.LocalPart.ToLowerInvariant() + "@" + InboundRules.ALabel(view.DomainName)));
        state.MinLimit = limit;
        session.TransactionMaxMessageSize = limit;
        InboundMetrics.Recipient(postmaster ? "postmaster" : "accepted");
        return SmtpReplies.RecipientOk;
    }

    // A report from the null sender may be large (some servers return the whole original) and is accepted up to the normal limit: only its head is read. A message to a bounce address from anybody else is
    // not a report, and the anonymous port does not take more than a mebibyte of it.
    private static void LimitBounceClassMessage(SmtpSessionContext session, MailFromInfo mail)
    {
        if (!mail.Sender.IsNull)
        {
            session.TransactionMaxMessageSize = session.TransactionMaxMessageSize is { } existing ? Math.Min(existing, InboundReceiveOptions.BounceMessageLimit) : InboundReceiveOptions.BounceMessageLimit;
        }
    }

    private static SmtpReply Mixed()
    {
        InboundMetrics.Recipient("mixed_kinds");
        InboundMetrics.Refused("mixed_kinds");
        return MixedKinds;
    }

    private async ValueTask<bool> QuotaReachedAsync(InboundDomainView view, InboundEffectiveLimits limits, CancellationToken ct)
    {
        if (limits.MaxStoredBytes > 0 && (await UsageAsync(view.TenantId, view.DomainId, ct).ConfigureAwait(false)).BodyBytes >= limits.MaxStoredBytes)
        {
            return true;
        }

        long tenantLimit = _options.Ceilings.MaxStoredBytesPerTenant;
        return tenantLimit > 0 && (await UsageAsync(view.TenantId, null, ct).ConfigureAwait(false)).BodyBytes >= tenantLimit;
    }

    // The stored-bytes figures are an indexed aggregate, cached for a few seconds: the limit is a guard against filling the disk, not an exact quota (design section 11.4).
    private async ValueTask<InboundUsage> UsageAsync(Guid tenantId, Guid? domainId, CancellationToken ct)
    {
        Guid key = domainId ?? tenantId;
        long now = _clock.Timestamp;
        if (_usage.TryGetValue(key, out var cached) && now < cached.ExpiresAt)
        {
            return cached.Usage;
        }

        InboundUsage usage = await _store.GetUsageAsync(domainId is null ? tenantId : null, domainId, ct).ConfigureAwait(false);
        _usage[key] = (now + (long)(_options.UsageCacheLifetime.TotalSeconds * System.Diagnostics.Stopwatch.Frequency), usage);
        return usage;
    }

    // ---------------------------------------------------------------- start of data

    public ValueTask<SmtpReply?> OnDataStartAsync(SmtpSessionContext session)
    {
        State state = StateOf(session);
        if (state.Kind == Kind.Inbound && !_slots.HasFreeSlotFor(state.Client))
        {
            // A look, nothing reserved: the slot is taken after the end of DATA. Refusing here spares receiving a body that would be refused anyway.
            InboundMetrics.Refused("no_verification_slot");
            InboundMetrics.Message("rejected_busy");
            return ValueTask.FromResult<SmtpReply?>(Busy);
        }

        return ValueTask.FromResult<SmtpReply?>(null);
    }

    /// <summary>The server refused the body itself (too large, or the in-flight budget): the handler never sees such a message, so it is counted here.</summary>
    public void OnMessageRefused(SmtpSessionContext session, SmtpReply reply)
    {
        if (session.HandlerState is State { Kind: Kind.Inbound })
        {
            InboundMetrics.Message(reply.Code == 552 ? "rejected_size" : "rejected_other");
        }
    }

    // ---------------------------------------------------------------- the message

    public async ValueTask<SmtpReply> OnMessageAsync(SmtpMessage message, CancellationToken ct)
    {
        State state = StateOf(message.Session);
        switch (state.Kind)
        {
            case Kind.Bounce:
                return await _bounces.HandleMessageAsync(message, ct).ConfigureAwait(false);

            case Kind.Srs:
                // Verified at RCPT (hash, age, null sender), size-limited by the session; dropped, never relayed and never answered with a message (design section 11.7).
                _log.Write(MtaLogLevel.Debug, "inbound", $"SRS bounce dropped ({message.Size} bytes)");
                return Accepted;

            case Kind.Inbound:
                try
                {
                    return await ReceiveAsync(message, state, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (StorageFullException ex)
                {
                    _log.Write(MtaLogLevel.Error, "inbound", "message could not be stored: the disk is full", ex);
                    InboundMetrics.Message("rejected_other");
                    return StorageFull;
                }
                catch (Exception ex)
                {
                    _log.Write(MtaLogLevel.Error, "inbound", "message could not be stored", ex);
                    InboundMetrics.Message("rejected_other");
                    return Unavailable;
                }
        }

        return Unavailable;
    }

    private async ValueTask<SmtpReply> ReceiveAsync(SmtpMessage message, State state, CancellationToken ct)
    {
        // The session already stopped reading at the lowest limit of the accepted recipients; the check here is the same rule, applied to what really arrived.
        long size = message.Body.Length;
        if (size > state.MinLimit)
        {
            InboundMetrics.Message("rejected_size");
            return MessageTooBig;
        }

        // The budget again, with the actual size: a client can declare a small SIZE (or none) and send a large body.
        int copies = state.Recipients.Select(r => r.Address).Distinct(StringComparer.Ordinal).Count();
        if (size > _options.MaxTransactionBytes / Math.Max(1, copies))
        {
            InboundMetrics.Refused("budget");
            InboundMetrics.Message("rejected_size");
            return TooManyRecipientsForSize;
        }

        // The copies this handler makes are memory too: reserve them from the same budget the message bytes were counted in before making them, so a flood of large messages cannot multiply its footprint.
        if (!message.Body.IsSingleSegment && !message.Session.TryReserveMemory(size))
        {
            InboundMetrics.Message("rejected_other");
            return StorageFull;
        }

        ReadOnlyMemory<byte> original = message.Body.IsSingleSegment ? message.Body.First : message.ToArray();
        InboundHeaderAnalysis headers = InboundHeaderAnalysis.Analyze(original, _ownAuthservIds, _hops);
        if (headers.StartsWithWhiteSpace)
        {
            InboundMetrics.Message("rejected_other");
            return MalformedStart;
        }

        if (headers.Oversized)
        {
            InboundMetrics.Message("rejected_other");
            return HeadersTooLarge;
        }

        if (headers.TooManyFromDomains)
        {
            InboundMetrics.Message("rejected_other");
            return TooManyFromAddresses;
        }

        if (headers.ReceivedCount > InboundReceiveOptions.MaxReceivedHeaders)
        {
            InboundMetrics.Message("rejected_other");
            return TooManyHops;
        }

        IPAddress client = state.Client;
        string mailFrom = message.Sender.IsNull ? string.Empty : message.Sender.LocalPart + "@" + message.Sender.Domain;
        InboundVerification verification;
        VerificationSlots.Lease? lease = _slots.TryAcquire(client);
        if (lease is null)
        {
            InboundMetrics.Refused("no_verification_slot");
            InboundMetrics.Message("rejected_busy");
            return Busy;
        }

        try
        {
            verification = await _verifier.VerifyAsync(client, message.Session.HeloName, mailFrom, original, headers.Headers, headers.FromDomains, !headers.FromUnusable, ct).ConfigureAwait(false);
        }
        finally
        {
            lease.Dispose();   // held for the verification only, not while the message is stored
        }

        InboundDmarcOutcome decision = InboundDmarcDecision.Decide(verification, state.Recipients.Select(r => r.Domain.Configuration.Settings.DmarcAction).ToArray());
        switch (decision.Refusal)
        {
            case InboundDmarcRefusal.Reject:
                InboundMetrics.Refused("dmarc");
                InboundMetrics.Message("rejected_dmarc");
                return SmtpReply.Create(550, "5.7.1", "Rejected by the DMARC policy of " + SafeText(verification.Dmarc?.FromDomain ?? "the sender"));

            case InboundDmarcRefusal.NoUsableFrom:
                InboundMetrics.Refused("dmarc");
                InboundMetrics.Message("rejected_dmarc");
                return NoUsableFromAddress;

            case InboundDmarcRefusal.TryLater:
                InboundMetrics.Refused("verification_temperror");
                InboundMetrics.Message("rejected_verification");
                return AuthTryLater;
        }

        // One stamped copy per distinct state (flagged or not), each as large as the message plus the headers we add (known now: the Received field, our Authentication-Results and the markers).
        // The buffer and the contiguous copy were counted when they were made; only the extra copies are reserved here, so one message is not counted three times.
        int variants = decision.Flagged.Distinct().Count();
        long stamped = message.ReceivedHeader.Length + Encoding.UTF8.GetByteCount(verification.AuthenticationResultsHeader) + 256;
        if (!message.Session.TryReserveMemory(variants * (size + stamped)))
        {
            InboundMetrics.Message("rejected_other");
            return StorageFull;
        }

        IReadOnlyList<InboundMessageDraft> drafts = BuildDrafts(message, state, headers, verification, decision);
        await _store.AcceptAsync(drafts, ct).ConfigureAwait(false);

        InboundMetrics.Message("accepted");
        InboundMetrics.Bytes.Add(size);
        if (_log.IsEnabled(MtaLogLevel.Debug))
        {
            _log.Write(MtaLogLevel.Debug, "inbound", $"message accepted from {client}: {drafts.Count} recipient(s), {size} bytes, spf={InboundNames.Of(verification.Auth.Spf)} dkim={InboundNames.Of(verification.Auth.Dkim)} dmarc={InboundNames.Of(verification.Auth.Dmarc)}");
        }

        _onAccepted?.Invoke();
        return Accepted;
    }

    private List<InboundMessageDraft> BuildDrafts(SmtpMessage message, State state, InboundHeaderAnalysis headers, InboundVerification verification, InboundDmarcOutcome decision)
    {
        // The headers we add, on top of the received bytes: Received, Authentication-Results, then the X-EggMail-* markers (the namespace is ours).
        byte[] received = message.ReceivedHeader.ToArray();
        byte[] authenticationResults = Encoding.UTF8.GetBytes(verification.AuthenticationResultsHeader);
        string reputation = state.DnsblZone is { } zone && !_options.DnsblReject ? "X-EggMail-Reputation: dnsbl=" + SafeText(zone) + "\r\n" : string.Empty;
        byte[]? plain = null, flaggedCopy = null;

        byte[] Stored(bool flagged)
        {
            if (flagged ? flaggedCopy is not null : plain is not null)
            {
                return flagged ? flaggedCopy! : plain!;
            }

            string extras = (flagged ? "X-EggMail-Dmarc: flagged\r\n" : string.Empty) + reputation;
            byte[] prefix = [.. received, .. authenticationResults, .. Encoding.ASCII.GetBytes(extras)];
            byte[] copy = headers.Compose(prefix);
            if (flagged)
            {
                flaggedCopy = copy;
            }
            else
            {
                plain = copy;
            }

            return copy;
        }

        DateTimeOffset receivedAt = message.ReceivedAt;
        SmtpSessionContext session = message.Session;
        string remote = Clean(state.Client.ToString(), 255);
        string? helo = session.HeloName is { } h ? Clean(h, 255) : null;
        string envelopeFrom = message.Sender.IsNull ? string.Empty : (message.Sender.LocalPart + "@" + message.Sender.Domain).ToLowerInvariant();
        InboundAuthResults auth = Sanitized(verification.Auth);
        var drafts = new List<InboundMessageDraft>(state.Recipients.Count);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 0; i < state.Recipients.Count; i++)
        {
            AcceptedRecipient recipient = state.Recipients[i];
            if (!seen.Add(recipient.Address))
            {
                continue;   // the same address named twice is one delivery
            }

            bool flagged = decision.Flagged[i];
            byte[] raw = Stored(flagged);
            drafts.Add(new InboundMessageDraft
            {
                Id = Ids.New(receivedAt),
                TenantId = recipient.Domain.TenantId,
                DomainId = recipient.Domain.DomainId,
                Domain = recipient.Domain.DomainName,
                ReceivedAt = receivedAt,
                RemoteAddress = remote,
                Helo = helo,
                TlsUsed = session.TlsActive,
                EnvelopeFrom = envelopeFrom,
                EnvelopeTo = recipient.Address,
                Subject = headers.Subject,
                Auth = auth,
                Disposition = flagged ? InboundDmarcDisposition.Flagged : InboundDmarcDisposition.None,
                RouteId = recipient.Route?.Id,
                ActionKind = recipient.Route?.ActionKind ?? InboundActionKind.Store,
                Raw = raw,
            });
        }

        return drafts;
    }

    private static InboundAuthResults Sanitized(InboundAuthResults auth) => auth with
    {
        SpfDomain = auth.SpfDomain is null ? null : Clean(auth.SpfDomain, 255),
        DkimDomain = auth.DkimDomain is null ? null : Clean(auth.DkimDomain, 255),
        DmarcPolicy = auth.DmarcPolicy is null ? null : Clean(auth.DmarcPolicy, 255),
    };

    // Client-supplied text reaches the dashboard and the webhook: no control characters, cut at 255.
    private static string Clean(string text, int max)
    {
        var sb = new StringBuilder(Math.Min(text.Length, max));
        foreach (char c in text)
        {
            if (sb.Length >= max)
            {
                break;
            }

            sb.Append(char.IsControl(c) ? '?' : c);
        }

        return sb.ToString();
    }

    // Text that goes into a reply line or a header we write from outside data: letters, digits, dot and hyphen only.
    private static string SafeText(string text)
    {
        var sb = new StringBuilder(Math.Min(text.Length, 100));
        foreach (char c in text)
        {
            if (sb.Length >= 100)
            {
                break;
            }

            sb.Append(char.IsAsciiLetterOrDigit(c) || c is '.' or '-' ? c : '_');
        }

        return sb.ToString();
    }
}
