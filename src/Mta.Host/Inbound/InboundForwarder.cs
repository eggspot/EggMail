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
    ValueTask<ArcSealer?> GetSealerAsync(string domain, CancellationToken cancellationToken);
}

/// <summary>Looks the domain's newest active DKIM key up in the configuration store and builds an <see cref="ArcSealer"/> with it (RSA keys only), cached briefly like the DKIM signer.</summary>
public sealed class ConfigArcSealerProvider(IConfigStore config, ISecretProtector protector, IClock clock, TimeSpan? cacheTtl = null) : IForwardArcSealerProvider, IDisposable
{
    private sealed record Entry(ArcSealer? Sealer, long ExpiresAt);

    private readonly TimeSpan _ttl = cacheTtl ?? TimeSpan.FromMinutes(1);
    private readonly ConcurrentDictionary<string, Entry> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<Guid, (ArcSealer Sealer, RSA Key)> _sealers = new();

    public async ValueTask<ArcSealer?> GetSealerAsync(string domain, CancellationToken cancellationToken)
    {
        string name = domain.Trim().TrimEnd('.').ToLowerInvariant();
        long now = clock.Timestamp;
        if (_cache.TryGetValue(name, out Entry? cached) && now < cached.ExpiresAt)
        {
            return cached.Sealer;
        }

        ArcSealer? sealer = null;
        DomainRecord? record = await config.FindDomainByNameAsync(name, cancellationToken).ConfigureAwait(false);
        if (record is not null && string.Equals(record.Name, name, StringComparison.OrdinalIgnoreCase))
        {
            // Exactly the route's domain: a parent's key would put another domain's name on the seal.
            DkimKeyRecord? key = (await config.GetDkimKeysAsync(record.Id, cancellationToken).ConfigureAwait(false))
                .Where(k => k.Active && k.RetiredAt is null).OrderByDescending(k => k.CreatedAt).FirstOrDefault();
            if (key is not null)
            {
                sealer = _sealers.GetOrAdd(key.Id, _ => Create(record.Name, key)).Sealer;
            }
        }

        _cache[name] = new Entry(sealer, now + (long)(_ttl.TotalSeconds * System.Diagnostics.Stopwatch.Frequency));
        return sealer;
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
/// <item>The idempotency key is <c>inbound:&lt;id&gt;</c>, remembered a year with no request fingerprint, so a retry after a crash (or after the targets were edited) returns the copy that exists.</item>
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
                return InboundActionResult.Failed("invalid_forward_target");
            }

            string domain = target.Domain.ToLowerInvariant();
            if (domain == message.Domain.ToLowerInvariant() || local.Contains(domain) || string.Equals(domain, _options.BounceDomain, StringComparison.OrdinalIgnoreCase))
            {
                return InboundActionResult.Failed("forward_target_is_local");
            }

            if (!targets.Contains(target))
            {
                targets.Add(target);
            }
        }

        if (targets.Count == 0)
        {
            return InboundActionResult.Failed("invalid_forward_target");
        }

        int hops = _hops.ReadValidHops(raw);
        if (hops >= InboundRules.MaxForwardHops)
        {
            InboundActionMetrics.ForwardLoops.Add(1);
            return InboundActionResult.Failed("loop_detected");
        }

        if (!SenderMayBeForwarded(message, raw))
        {
            return InboundActionResult.Failed("unauthenticated_local_sender");
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

        DateTimeOffset now = _clock.UtcNow;
        byte[] marked = _hops.Apply(raw, hops + 1);
        byte[] final = await SealAsync(message, marked, cancellationToken).ConfigureAwait(false);
        EmailAddress envelopeFrom = EnvelopeFrom(message, now);

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
        _onQueued?.Invoke();
        return InboundActionResult.Done(forwardMessageId: result.MessageId, freeBody: true);
    }

    private EmailAddress EnvelopeFrom(InboundMessage message, DateTimeOffset now)
    {
        // A bounce is never turned into a message from us and never gets an SRS address.
        if (string.IsNullOrEmpty(message.EnvelopeFrom) || !EmailAddress.TryParse(message.EnvelopeFrom, allowUtf8: true, out EmailAddress original) || original.IsNull)
        {
            return EmailAddress.Null;
        }

        string local = _srs.CreateLocalPart(original.Domain, original.LocalPart, now);
        return EmailAddress.TryParse(local + "@" + message.Domain, allowUtf8: true, out EmailAddress srs) ? srs : EmailAddress.Null;
    }

    private async ValueTask<byte[]> SealAsync(InboundMessage message, byte[] marked, CancellationToken ct)
    {
        if (_sealers is null || _arcValidator is null)
        {
            return marked;
        }

        try
        {
            ArcSealer? sealer = await _sealers.GetSealerAsync(message.Domain, ct).ConfigureAwait(false);
            if (sealer is null)
            {
                return marked;   // no key for the route's domain: unsealed rather than sealed with anything else
            }

            // The chain as it stands now: Pass only when it validates; anything else we could not validate says cv=fail (RFC 8617 section 5.1.1), no chain says cv=none.
            ArcChainResult chain = await _arcValidator.ValidateAsync(marked, ct).ConfigureAwait(false);
            if (chain.Status == ArcChainStatus.Fail && chain.IsTransient)
            {
                chain = new ArcChainResult(ArcChainStatus.Fail, "chain could not be validated", chain.Failure);
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

    /// <summary>False for a message whose From is in the route's own organizational domain and did not pass DMARC.</summary>
    private static bool SenderMayBeForwarded(InboundMessage message, byte[] raw)
    {
        if (message.Auth.Dmarc == InboundVerdict.Pass)
        {
            return true;
        }

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
                        return false;
                    }
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return false;   // a From we cannot read cannot be shown to be foreign
        }

        return true;
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
