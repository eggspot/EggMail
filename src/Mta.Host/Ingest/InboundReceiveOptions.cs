using Mta.Host.Configuration;
using Mta.Storage;

namespace Mta.Host.Ingest;

/// <summary>
/// What the inbound receive path needs from the configuration (<c>Inbound:*</c>, design sections 11.6 and 11.13), in one object. The operator's limits are both the default and the
/// ceiling of the matching domain setting (<see cref="Ceilings"/>); <see cref="Mta.Storage.Logic.InboundRules.Effective"/> combines them with a domain's own values.
/// </summary>
public sealed class InboundReceiveOptions
{
    /// <summary>A chain of more ARC sets than this is <c>arc=fail</c> (reason <c>too_long</c>) without further work.</summary>
    public const int MaxArcInstances = 10;

    /// <summary>The size assumed for the transaction budget when the client declares none (design section 11.4).</summary>
    public const long AssumedMessageSize = 1L << 20;

    /// <summary>A message with more <c>Received</c> headers than this is refused at the end of DATA with <c>554 5.4.6</c>.</summary>
    public const int MaxReceivedHeaders = 25;

    /// <summary>A message to a bounce or SRS address is at most this big (a DSN is headers and a piece of the original; the port is anonymous).</summary>
    public const long BounceMessageLimit = 1L << 20;

    /// <summary><c>Inbound:Enabled</c>: the master switch. Off, the port-25 listener is the bounce listener it always was.</summary>
    public bool Enabled { get; init; }

    /// <summary>The operator's limits: the ceiling and default of the per-domain settings.</summary>
    public InboundCeilings Ceilings { get; init; } = new(25L * 1024 * 1024, 600, 60, 2L << 30, 10L << 30, 0);

    /// <summary><c>Inbound:RetentionDays</c>: the server default retention (for <see cref="Mta.Storage.Logic.InboundRules.Effective"/>).</summary>
    public int ServerRetentionDays { get; init; } = 7;

    /// <summary><c>Inbound:MaxRecipients</c>: recipients per transaction.</summary>
    public int MaxRecipients { get; init; } = 20;

    /// <summary><c>Inbound:MaxTransactionBytes</c>: the most one transaction may store (size times recipients).</summary>
    public long MaxTransactionBytes { get; init; } = 256L << 20;

    /// <summary><c>Inbound:AuthenticationResultsId</c>: the authserv-id of the header we add; null or empty: the host name.</summary>
    public string? AuthenticationResultsId { get; init; }

    /// <summary><c>Inbound:Verification:Timeout</c>: the total time for SPF, DKIM, DMARC and ARC of one message.</summary>
    public TimeSpan VerificationTimeout { get; init; } = TimeSpan.FromSeconds(20);

    /// <summary><c>Inbound:Verification:MaxConcurrency</c>.</summary>
    public int VerificationMaxConcurrency { get; init; } = 32;

    /// <summary><c>Inbound:Verification:MaxConcurrencyPerRemote</c>, per IPv4 /24 and IPv6 /64.</summary>
    public int VerificationMaxConcurrencyPerRemote { get; init; } = 4;

    /// <summary><c>Inbound:Arc:TrustedSealers</c>: the <c>d=</c> of ARC sealers whose last seal may override a DMARC failure. Empty: nothing is trusted.</summary>
    public IReadOnlyList<string> TrustedArcSealers { get; init; } = [];

    /// <summary><c>Inbound:Dnsbl:Zones</c>: empty means off.</summary>
    public IReadOnlyList<string> DnsblZones { get; init; } = [];

    /// <summary><c>Inbound:Dnsbl:Action</c> is <c>Reject</c>: a listed address is refused at its first inbound recipient. Otherwise (<c>Flag</c>) the message carries <c>X-EggMail-Reputation</c>.</summary>
    public bool DnsblReject { get; init; }

    /// <summary><c>Inbound:Dnsbl:Timeout</c>.</summary>
    public TimeSpan DnsblTimeout { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary><c>Inbound:CheckSpfForInternalClients</c>: check SPF for clients with a private, loopback or link-local address (lab setups and networks that really send from them). Off, SPF is not checked for them: behind source NAT the address is the NAT's.</summary>
    public bool CheckSpfForInternalClients { get; init; }

    /// <summary>
    /// What one message of the largest size takes from the in-flight budget, in multiples of its size: the buffer it is received into, the contiguous copy the checks read, and one stamped copy per distinct
    /// state (flagged or not: two when the recipients differ). A budget share smaller than this times the largest message makes that message impossible to accept. The rule the configuration is checked against.
    /// </summary>
    public const double SizingFactor = 4.2;

    /// <summary>The share of the budget one client network gets when none is configured (<c>Inbound:MaxInFlightBytesPerRemote</c> <c>0</c>): room for one largest message and a margin.</summary>
    public const double DerivedPerRemoteFactor = 4.5;

    /// <summary><c>Inbound:MaxConnections</c>: connections the port-25 listener may hold, below <c>Smtp:MaxConnections</c> (at most half of it) so anonymous senders cannot take the connections submission needs.</summary>
    public int MaxConnections { get; init; } = 1000;

    /// <summary><c>Inbound:MaxInFlightBytes</c>: bytes of messages the port-25 listener may be receiving at once, below <c>Smtp:MaxInFlightBytes</c> for the same reason.</summary>
    public long MaxInFlightBytes { get; init; } = 256L << 20;

    /// <summary><c>Inbound:MaxInFlightBytesPerRemote</c>: the share of that budget one client network (IPv4 address, IPv6 /64) may use. <c>0</c>: derived from the largest inbound message (<see cref="DerivedPerRemoteFactor"/> times it).</summary>
    public long MaxInFlightBytesPerRemote { get; init; }

    /// <summary>The per-network share in effect: the configured one, or the derived one.</summary>
    public long EffectiveMaxInFlightBytesPerRemote => MaxInFlightBytesPerRemote > 0 ? MaxInFlightBytesPerRemote : Math.Max(DerivedPerRemoteFloor, (long)(DerivedPerRemoteFactor * Ceilings.MaxMessageBytes));

    /// <summary>The least a derived per-network share is: message buffers come in segments of 16 KiB and up, so even a tiny message needs room.</summary>
    public const long DerivedPerRemoteFloor = 2L << 20;

    /// <summary><c>Inbound:MaxSessionDuration</c>: the longest an anonymous session lives between commands (a message being received is finished).</summary>
    public TimeSpan MaxSessionDuration { get; init; } = TimeSpan.FromMinutes(10);

    /// <summary><c>Inbound:Srs:MaxAgeDays</c>: how old an SRS address may be (21).</summary>
    public int SrsMaxAgeDays { get; init; } = 21;

    /// <summary>The receive path's options from the deployment configuration (<c>Inbound:*</c>, the retention keys of the storage options and <c>Smtp:MaxMessageSize</c> for the size default).</summary>
    public static InboundReceiveOptions From(MtaConfig config)
    {
        InboundSection i = config.Inbound;
        return new InboundReceiveOptions
        {
            Enabled = i.Enabled,
            Ceilings = new InboundCeilings(i.MaxMessageSize ?? config.Smtp.MaxMessageSize, i.MaxMessagesPerMinute, i.MaxMessagesPerMinutePerRemote, i.MaxStoredBytesPerDomain, i.MaxStoredBytesPerTenant, config.Storage.Inbound.MaxRetentionDays),
            ServerRetentionDays = config.Storage.Inbound.RetentionDays,
            MaxRecipients = i.MaxRecipients,
            MaxTransactionBytes = i.MaxTransactionBytes,
            AuthenticationResultsId = i.AuthenticationResultsId,
            VerificationTimeout = i.Verification.Timeout,
            VerificationMaxConcurrency = i.Verification.MaxConcurrency,
            VerificationMaxConcurrencyPerRemote = i.Verification.MaxConcurrencyPerRemote,
            TrustedArcSealers = i.Arc.TrustedSealers.Select(d => d.Trim().TrimEnd('.').ToLowerInvariant()).ToArray(),
            DnsblZones = i.Dnsbl.Zones,
            DnsblReject = i.Dnsbl.Action == InboundDnsblAction.Reject,
            DnsblTimeout = i.Dnsbl.Timeout,
            SrsMaxAgeDays = i.Srs.MaxAgeDays,
            CheckSpfForInternalClients = i.CheckSpfForInternalClients,
            // The anonymous port may take at most half of what the server allows in all: the other half stays for submission whatever the defaults say.
            MaxConnections = Math.Min(i.MaxConnections, Math.Max(1, config.Smtp.MaxConnections / 2)),
            MaxInFlightBytes = Math.Min(i.MaxInFlightBytes, Math.Max(1, config.Smtp.MaxInFlightBytes / 2)),
            MaxInFlightBytesPerRemote = i.MaxInFlightBytesPerRemote,
            MaxSessionDuration = i.MaxSessionDuration,
        };
    }

    /// <summary>How often the receive path reloads the enabled domains and their routes (not configurable; 30 s plus up to a tenth of jitter).</summary>
    public TimeSpan ConfigRefreshInterval { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>How long a cached configuration may be used after the refreshes started failing, before the receive path answers <c>451</c> instead.</summary>
    public TimeSpan ConfigMaxStaleness { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>How long the stored-bytes figures of a domain and a tenant are cached (not configurable).</summary>
    public TimeSpan UsageCacheLifetime { get; init; } = TimeSpan.FromSeconds(5);
}
