using System.Collections.Concurrent;
using System.Security.Cryptography;
using Mta.Auth.Arc;
using Mta.Auth.Domains;
using Mta.Core;
using Mta.Dsn;
using Mta.Mime;
using Mta.Storage;
using Mta.Storage.Logic;

namespace Mta.Host.Inbound;

/// <summary>Supplies the ARC sealer of a sending domain (its active DKIM key); null when the domain has no usable key (the forward then goes out unsealed).</summary>
public interface IForwardArcSealerProvider
{
    /// <summary>The sealer of <paramref name="domain"/> when that domain belongs to <paramref name="tenantId"/>; null otherwise.</summary>
    ValueTask<ArcSealer?> GetSealerAsync(Guid tenantId, string domain, CancellationToken cancellationToken);
}

/// <summary>Looks the domain's newest active DKIM key up in the configuration store and builds an <see cref="ArcSealer"/> with it (RSA keys only), cached briefly like the DKIM signer.</summary>
public sealed class ConfigArcSealerProvider(IConfigStore config, ISecretProtector protector, IClock clock, TimeSpan? cacheTtl = null) : IForwardArcSealerProvider, IDisposable
{
    private sealed record Entry(ArcSealer? Sealer, long ExpiresAt);

    private readonly TimeSpan _ttl = cacheTtl ?? TimeSpan.FromMinutes(1);
    private readonly ConcurrentDictionary<string, Entry> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<Guid, (ArcSealer Sealer, RSA Key)> _sealers = new();

    public async ValueTask<ArcSealer?> GetSealerAsync(Guid tenantId, string domain, CancellationToken cancellationToken)
    {
        string name = domain.Trim().TrimEnd('.').ToLowerInvariant();
        string cacheKey = tenantId.ToString("N") + "/" + name;
        long now = clock.Timestamp;
        if (_cache.TryGetValue(cacheKey, out Entry? cached) && now < cached.ExpiresAt)
        {
            return cached.Sealer;
        }

        ArcSealer? sealer = null;
        DomainRecord? record = await config.FindDomainByNameAsync(name, cancellationToken).ConfigureAwait(false);
        // Exactly the route's domain, and the tenant's own: a parent's key would put another domain's name on the seal, and another tenant's key must never sign this tenant's mail.
        if (record is not null && record.TenantId == tenantId && string.Equals(record.Name, name, StringComparison.OrdinalIgnoreCase))
        {
            DkimKeyRecord? key = (await config.GetDkimKeysAsync(record.Id, cancellationToken).ConfigureAwait(false))
                .Where(k => k.Active && k.RetiredAt is null).OrderByDescending(k => k.CreatedAt).FirstOrDefault();
            if (key is not null)
            {
                sealer = SealerOf(record.Name, key);
            }
        }

        _cache[cacheKey] = new Entry(sealer, now + (long)(_ttl.TotalSeconds * System.Diagnostics.Stopwatch.Frequency));
        return sealer;
    }

    private ArcSealer SealerOf(string domain, DkimKeyRecord key)
    {
        if (_sealers.TryGetValue(key.Id, out var existing))
        {
            return existing.Sealer;
        }

        // Two callers can get here together: the loser disposes the key it made instead of leaking it.
        (ArcSealer Sealer, RSA Key) made = Create(domain, key);
        if (_sealers.TryAdd(key.Id, made))
        {
            return made.Sealer;
        }

        made.Sealer.Dispose();
        made.Key.Dispose();
        return _sealers[key.Id].Sealer;
    }

    private (ArcSealer, RSA) Create(string domain, DkimKeyRecord key)
    {
        byte[] der = protector.Unprotect(key.PrivateKeyProtected, SecretPurposes.DkimKey);
        try
        {
            var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(der, out _);
            return (new ArcSealer(new ArcSealerOptions { Domain = domain, Selector = key.Selector, Clock = clock }, rsa), rsa);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(der);
        }
    }

    public void Dispose()
    {
        foreach ((ArcSealer sealer, RSA key) in _sealers.Values)
        {
            sealer.Dispose();
            key.Dispose();
        }

        _sealers.Clear();
        _cache.Clear();
    }
}

/// <summary>Settings of the forward action.</summary>
public sealed record InboundForwarderOptions
{
    /// <summary>The authserv-id written to the ARC set when the stored message has no Authentication-Results of ours (the host name).</summary>
    public string AuthenticationResultsId { get; init; } = "localhost";

    /// <summary>The shared bounce domain: never a forward target.</summary>
    public string? BounceDomain { get; init; }

    /// <summary>How long the queued copy may wait (<c>Queue:MaxLifetime</c>).</summary>
    public TimeSpan QueueLifetime { get; init; } = TimeSpan.FromDays(5);

    /// <summary>How long the set of domains this server receives for is cached.</summary>
    public TimeSpan LocalDomainsCacheTime { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Forwarded messages of a tenant that may wait in the outbound queue (<c>Inbound:Forward:MaxQueuedMessagesPerTenant</c>); 0: no cap.</summary>
    public int MaxQueuedMessagesPerTenant { get; init; } = 5000;

    /// <summary>Bytes of the forwarded messages of a tenant that may wait in the outbound queue (<c>Inbound:Forward:MaxQueuedBytesPerTenant</c>); 0: no cap.</summary>
    public long MaxQueuedBytesPerTenant { get; init; } = 1024L * 1024 * 1024;

    /// <summary>Forwarded messages sent from one domain that may wait in the outbound queue (<c>Inbound:Forward:MaxQueuedMessagesPerDomain</c>); 0: no cap.</summary>
    public int MaxQueuedMessagesPerDomain { get; init; } = 1000;

    /// <summary>The longest the chain of ARC sets is validated (DNS lookups for the keys of other domains included); a chain not validated in time is sealed over as <c>cv=fail</c>.</summary>
    public TimeSpan ArcValidationTimeout { get; init; } = TimeSpan.FromSeconds(5);
}

/// <summary>
/// The forward action (design section 11.7): queues a copy of a received message for the route's targets through the outbound queue as source <see cref="MessageSource.Forward"/>.
/// <list type="bullet">
/// <item>The targets are fixed in the route (never taken from the message) and none may be in a domain this server receives for or in the bounce domain, whatever the route said when it was written (a loop closed at run time too).</item>
/// <item>The signed hop marker stops loops: a message that has been forwarded <see cref="InboundRules.MaxForwardHops"/> times is not forwarded (<c>loop_detected</c>); the copy carries one marker with the count plus one.</item>
/// <item>The suppression list is consulted here for every target (suppressed targets are left out; all of them: nothing is queued, the action is <c>done</c> with the note <c>all_targets_suppressed</c>).</item>
/// <item>The envelope sender is an SRS0 address at the route's domain, or the null reverse-path when the message arrived with one.</item>
/// <item>The copy is the stored message with headers added on top only (hop marker, ARC set), so the original DKIM signatures stay valid. The ARC set is sealed with the route domain's key; <c>cv=fail</c> when the chain does not validate, <c>cv=none</c> without a chain, <c>cv=pass</c> with a valid one. No key: unsealed.</item>
/// <item>A message from a domain of the route's own organization that did not pass DMARC is not forwarded (<c>unauthenticated_local_sender</c>): the SRS envelope and our signature would otherwise make a spoof of the tenant's own domain pass SPF and DMARC at the final receiver.</item>
/// <item>The idempotency key is <c>inbound:&lt;id&gt;</c>, remembered 30 days with no request fingerprint, so a retry after a crash (or after the targets were edited) returns the copy that exists. The prefix is reserved: the public API refuses it, and a key that already belongs to something else is a failure (<c>forward_key_conflict</c>), never a silent success.</item>
/// <item>What a tenant may have waiting in the outbound queue is capped (<c>Inbound:Forward:*</c>): over a cap the forward waits on its ladder as <c>forward_backlog_full</c> and the message stays in the inbound store, where the inbound quotas keep applying.</item>
/// <item>Our own internal headers (<c>X-EggMail-Dmarc</c>, <c>X-EggMail-Reputation</c>) are not passed on.</item>
/// </list>
/// </summary>
public sealed class InboundForwarder : IInboundForwarder
{
    private readonly IStorage _storage;
    private readonly SrsCodec _srs;
    private readonly ForwardHopMarker _hops;
    private readonly ArcValidator? _arcValidator;
    private readonly IForwardArcSealerProvider? _sealers;
    private readonly InboundForwarderOptions _options;
    private readonly IClock _clock;
    private readonly IMtaLog _log;
    private readonly Action? _onQueued;
    private long _localDomainsAt;
    private HashSet<string>? _localDomains;

    public InboundForwarder(
        IStorage storage, SrsCodec srs, ForwardHopMarker hops, ArcValidator? arcValidator, IForwardArcSealerProvider? sealers, InboundForwarderOptions options, IClock clock, IMtaLog log, Action? onQueued = null)
    {
        _storage = storage;
        _srs = srs;
        _hops = hops;
        _arcValidator = arcValidator;
        _sealers = sealers;
        _options = options;
        _clock = clock;
        _log = log;
        _onQueued = onQueued;
    }

    public async ValueTask<InboundActionResult> ForwardAsync(InboundMessage message, InboundRouteRecord route, byte[] raw, CancellationToken cancellationToken)
    {
        // Targets: valid, and not somewhere this server would receive them again.
        var targets = new List<EmailAddress>(route.ForwardTo.Count);
        HashSet<string> local = await LocalDomainsAsync(cancellationToken).ConfigureAwait(false);
        foreach (string text in route.ForwardTo)
        {
            if (!EmailAddress.TryParse(text, allowUtf8: true, out EmailAddress target) || target.IsNull || target.IsAddressLiteral)
            {
                return Refused("invalid_forward_target");
            }

            string domain = target.Domain.ToLowerInvariant();
            if (domain == message.Domain.ToLowerInvariant() || local.Contains(domain) || string.Equals(domain, _options.BounceDomain, StringComparison.OrdinalIgnoreCase))
            {
                return Refused("forward_target_is_local");
            }

            if (!targets.Contains(target))
            {
                targets.Add(target);
            }
        }

        if (targets.Count == 0)
        {
            return Refused("invalid_forward_target");
        }

        int hops = _hops.ReadValidHops(raw);
        if (hops >= InboundRules.MaxForwardHops)
        {
            InboundActionMetrics.ForwardLoops.Add(1);
            return InboundActionResult.Failed("loop_detected");
        }

        switch (CheckSender(message, raw))
        {
            case SenderCheck.Refused:
                return Refused("unauthenticated_local_sender");
            case SenderCheck.Unsettled:
                // DMARC could not be settled at receipt (a DNS error): the message is not shown to be foreign, and not shown to be a spoof either. The verdict is the one stored at receipt and is not
                // evaluated again here, so waiting does not change it: the action runs its ladder (about 27 hours) and ends failed with dmarc_unsettled. It is a retry, not a refusal, only so that the
                // tenant sees that nothing was decided about the message; it is not forwarded.
                return InboundActionResult.Retry("dmarc_unsettled");
        }

        var remaining = new List<EmailAddress>(targets.Count);
        foreach (EmailAddress target in targets)
        {
            if (!await _storage.Config.IsSuppressedAsync(message.TenantId, target.ToString(), cancellationToken).ConfigureAwait(false))
            {
                remaining.Add(target);
            }
        }

        if (remaining.Count == 0)
        {
            // Nothing is queued and the body stays (a retry after the tenant removed a suppression can still forward it).
            return InboundActionResult.Done(note: "all_targets_suppressed");
        }

        // The copy leaves the inbound store when it is queued, so what may wait in the outbound queue is capped here (the inbound quotas no longer see it).
        ForwardBacklog backlog = await _storage.Inbound.GetForwardBacklogAsync(message.TenantId, message.Domain, cancellationToken).ConfigureAwait(false);
        if ((_options.MaxQueuedMessagesPerTenant > 0 && backlog.TenantMessages >= _options.MaxQueuedMessagesPerTenant)
            || (_options.MaxQueuedBytesPerTenant > 0 && backlog.TenantBytes + raw.Length > _options.MaxQueuedBytesPerTenant)
            || (_options.MaxQueuedMessagesPerDomain > 0 && backlog.DomainMessages >= _options.MaxQueuedMessagesPerDomain))
        {
            InboundActionMetrics.ForwardRefused.Add(1, new KeyValuePair<string, object?>("reason", "forward_backlog_full"));
            return InboundActionResult.Retry("forward_backlog_full");
        }

        DateTimeOffset now = _clock.UtcNow;
        if (!TryEnvelopeFrom(message, now, out EmailAddress envelopeFrom))
        {
            return Refused("srs_failed");
        }

        // Added on top and nothing else changed, except that what this server wrote for its own use does not leave with the copy.
        byte[] marked = new MessageHeaderEditor(_hops.Apply(raw, hops + 1)).Remove("X-EggMail-Dmarc").Remove("X-EggMail-Reputation").ToArray();
        byte[] final = await SealAsync(message, marked, cancellationToken).ConfigureAwait(false);

        var accepted = new AcceptedMessage
        {
            MessageId = Ids.New(now),
            TenantId = message.TenantId,
            Source = MessageSource.Forward,
            EnvelopeFrom = envelopeFrom,
            Recipients = remaining.Select(a => new AcceptedRecipient(Ids.New(now), a)).ToList(),
            Raw = final,
            ReceivedAt = now,
            ExpiresAt = now + _options.QueueLifetime,
            IdempotencyKey = InboundRules.ForwardKey(message.Id),
            IdempotencyKeyLifetime = InboundRules.ForwardKeyLifetime,
            HeadersUtf8 = MessageInspector.HasValidUtf8Headers(final),
            SendingDomain = message.Domain.ToLowerInvariant(),   // the route's domain: the DKIM key and the sending limits of a forward are always its, never the From domain's
        };

        IntakeResult result = await _storage.Intake.AcceptAsync(accepted, cancellationToken).ConfigureAwait(false);
        if (result.Status == IntakeStatus.DuplicateIdempotencyKey && !await IsOurForwardAsync(message, result.MessageId, cancellationToken).ConfigureAwait(false))
        {
            // The key of this forward belongs to some other message (it was registered before the prefix was reserved): nothing was queued, and the body must not be freed as if it had been.
            _log.Write(MtaLogLevel.Warning, "inbound", $"inbound message {message.Id:N}: the idempotency key of its forward belongs to another message; not forwarded");
            return Refused("forward_key_conflict");
        }

        _onQueued?.Invoke();
        return InboundActionResult.Done(forwardMessageId: result.MessageId, freeBody: true);
    }

    private static InboundActionResult Refused(string code)
    {
        InboundActionMetrics.ForwardRefused.Add(1, new KeyValuePair<string, object?>("reason", code));
        return InboundActionResult.Failed(code);
    }

    /// <summary>
    /// Whether the message the idempotency key points at is a forward of this tenant's route: its envelope sender is the null one or an SRS0 address at the route's domain. Where history keeps no
    /// summary (statistics-only mode, or already aged out) nothing can be told and the key is taken as ours: the public API cannot register this prefix any more.
    /// </summary>
    private async ValueTask<bool> IsOurForwardAsync(InboundMessage message, Guid existing, CancellationToken ct)
    {
        MessageDetail? detail = await _storage.History.GetAsync(message.TenantId, existing, ct).ConfigureAwait(false);
        if (detail is null)
        {
            return true;
        }

        string from = detail.Summary.EnvelopeFrom;
        return from.Length == 0
            || (from.StartsWith(SrsCodec.Prefix, StringComparison.OrdinalIgnoreCase) && from.EndsWith("@" + message.Domain, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>The null reverse-path stays null (a bounce is never turned into a message from us); any other sender becomes an SRS0 address at the route's domain. False when that cannot be made.</summary>
    private bool TryEnvelopeFrom(InboundMessage message, DateTimeOffset now, out EmailAddress from)
    {
        from = EmailAddress.Null;
        if (string.IsNullOrEmpty(message.EnvelopeFrom))
        {
            return true;
        }

        if (!EmailAddress.TryParse(message.EnvelopeFrom, allowUtf8: true, out EmailAddress original))
        {
            _log.Write(MtaLogLevel.Warning, "inbound", $"inbound message {message.Id:N}: the stored envelope sender cannot be read; not forwarded (a forward must never go out with a null sender instead)");
            return false;
        }

        if (original.IsNull)
        {
            return true;
        }

        try
        {
            string local = _srs.CreateLocalPart(original.Domain, original.LocalPart, now);
            if (EmailAddress.TryParse(local + "@" + message.Domain, allowUtf8: true, out from))
            {
                return true;
            }
        }
        catch (ArgumentException ex)
        {
            _log.Write(MtaLogLevel.Warning, "inbound", $"inbound message {message.Id:N}: no SRS address could be made for the envelope sender; not forwarded", ex);
            return false;
        }

        _log.Write(MtaLogLevel.Warning, "inbound", $"inbound message {message.Id:N}: the SRS address made for the envelope sender is not valid at the route's domain; not forwarded");
        from = EmailAddress.Null;
        return false;
    }

    private async ValueTask<byte[]> SealAsync(InboundMessage message, byte[] marked, CancellationToken ct)
    {
        if (_sealers is null || _arcValidator is null)
        {
            return marked;
        }

        try
        {
            ArcSealer? sealer = await _sealers.GetSealerAsync(message.TenantId, message.Domain, ct).ConfigureAwait(false);
            if (sealer is null)
            {
                return marked;   // no key for the route's domain: unsealed rather than sealed with anything else
            }

            // The chain as it stands now: Pass only when it validates; anything else we could not validate says cv=fail (RFC 8617 section 5.1.1), no chain says cv=none. The chain is the sender's,
            // so the work it can cause (a key lookup for every seal) is bounded by the validator's own limits and by a time limit here: a runner slot is never held for a hostile chain.
            ArcChainResult chain;
            using (var limit = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                limit.CancelAfter(_options.ArcValidationTimeout);
                try
                {
                    chain = await _arcValidator.ValidateAsync(marked, limit.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    chain = new ArcChainResult(ArcChainStatus.Fail, "the chain could not be validated in time", ArcFailure.InternalError);
                }
            }

            ArcSealResult sealed1 = sealer.Seal(marked, AuthenticationResultsOf(message, marked), chain);
            if (!sealed1.IsSealed)
            {
                return marked;
            }

            var withSeal = new byte[sealed1.HeaderBytes.Length + marked.Length];
            sealed1.HeaderBytes.CopyTo(withSeal);
            Buffer.BlockCopy(marked, 0, withSeal, sealed1.HeaderBytes.Length, marked.Length);
            return withSeal;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // A message the sealer cannot take (too many headers) is forwarded unsealed: the original signatures still carry it.
            _log.Write(MtaLogLevel.Warning, "inbound", $"inbound message {message.Id:N}: ARC sealing failed, forwarding unsealed", ex);
            return marked;
        }
    }

    /// <summary>The results this hop recorded: the body of our own Authentication-Results header of the stored message, else a line built from the verdicts.</summary>
    private string AuthenticationResultsOf(InboundMessage message, byte[] raw)
    {
        string id = _options.AuthenticationResultsId;
        try
        {
            MimeMessage parsed = MimeMessage.Parse(raw, MimeLimits.Default);
            foreach (MimeHeader header in parsed.Headers)
            {
                if (header.Name.Equals("Authentication-Results", StringComparison.OrdinalIgnoreCase) && header.Value.TrimStart().StartsWith(id + ";", StringComparison.OrdinalIgnoreCase))
                {
                    return string.Join(' ', header.Value.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries).Select(l => l.Trim()));
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Write(MtaLogLevel.Debug, "inbound", "could not read the stored Authentication-Results; building the ARC results from the verdicts", ex);
        }

        InboundAuthResults a = message.Auth;
        return $"{id}; spf={InboundNames.Of(a.Spf)}; dkim={InboundNames.Of(a.Dkim)}; dmarc={InboundNames.Of(a.Dmarc)}";
    }

    private enum SenderCheck
    {
        Allowed,

        /// <summary>From is in the route's own organizational domain (or cannot be shown not to be) and DMARC did not pass.</summary>
        Refused,

        /// <summary>The same, but DMARC could not be settled at receipt (a temporary error): not a verdict, so not a permanent refusal.</summary>
        Unsettled,
    }

    /// <summary>Whether the message may be forwarded: a From in the route's own organizational domain needs a DMARC pass (the SRS envelope and our signature would otherwise launder a spoof of it).</summary>
    private static SenderCheck CheckSender(InboundMessage message, byte[] raw)
    {
        if (message.Auth.Dmarc == InboundVerdict.Pass)
        {
            return SenderCheck.Allowed;
        }

        SenderCheck refusal = message.Auth.Dmarc == InboundVerdict.TempError ? SenderCheck.Unsettled : SenderCheck.Refused;
        try
        {
            MimeMessage parsed = MimeMessage.Parse(raw, MimeLimits.Default);
            // Every From header counts, not only the first: with two of them (which DMARC treats as an error) a mail client may show the second, and the verdict recorded at receipt is not the whole story.
            foreach (MimeHeader from in parsed.Headers)
            {
                if (!from.Name.Equals("From", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                foreach (Mailbox mailbox in AddressList.Parse(from).Mailboxes)
                {
                    // An address that does not parse could still be read as ours by a client: it cannot be shown to be foreign.
                    if (!mailbox.IsValid || (mailbox.Domain is { } domain && PublicSuffixList.Default.HaveSameOrganizationalDomain(domain, message.Domain)))
                    {
                        return refusal;
                    }
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return refusal;   // a From we cannot read cannot be shown to be foreign
        }

        return SenderCheck.Allowed;
    }

    private async ValueTask<HashSet<string>> LocalDomainsAsync(CancellationToken ct)
    {
        long now = _clock.Timestamp;
        if (_localDomains is { } cached && _clock.GetElapsedTime(_localDomainsAt) < _options.LocalDomainsCacheTime)
        {
            return cached;
        }

        IReadOnlyList<InboundDomainConfiguration> enabled = await _storage.Inbound.LoadEnabledDomainsAsync(ct).ConfigureAwait(false);
        var set = new HashSet<string>(enabled.Select(d => d.DomainName.ToLowerInvariant()), StringComparer.Ordinal);
        _localDomains = set;
        _localDomainsAt = now;
        return set;
    }
}
