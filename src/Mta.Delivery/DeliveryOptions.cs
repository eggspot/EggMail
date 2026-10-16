using Mta.Dsn;
using Mta.Tls;

namespace Mta.Delivery;

/// <summary>Settings of the outbound delivery engine (configuration section <c>Delivery</c>).</summary>
public sealed class DeliveryOptions
{
    /// <summary>Lease owner name of this process; must be unique per replica.</summary>
    public string Owner { get; init; } = Environment.MachineName.ToLowerInvariant() + ":" + Guid.NewGuid().ToString("N")[..8];

    /// <summary>Our host name in DSNs (<c>Reporting-MTA</c>) and the EHLO name used by the pool.</summary>
    public string Hostname { get; init; } = Environment.MachineName.ToLowerInvariant();

    /// <summary>Most (message, recipient domain) groups processed at the same time.</summary>
    public int MaxConcurrentGroups { get; init; } = 64;

    /// <summary>Most deliveries leased per claim.</summary>
    public int ClaimBatchSize { get; init; } = 200;

    /// <summary>How long a claimed delivery stays reserved for this process before another worker may take it.</summary>
    public TimeSpan Lease { get; init; } = TimeSpan.FromMinutes(15);

    /// <summary>Longest sleep between claims when nothing is due; intake wakes the engine earlier.</summary>
    public TimeSpan IdlePoll { get; init; } = TimeSpan.FromSeconds(1);

    /// <summary>How often expired deliveries are collected and bounced.</summary>
    public TimeSpan ExpirySweepInterval { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>How often relay routes and TLS policies are reloaded from the configuration store.</summary>
    public TimeSpan ConfigRefreshInterval { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Destination port for direct MX delivery. 25 in production; tests point it at a loopback server.</summary>
    public int RemotePort { get; init; } = 25;

    /// <summary>
    /// Decides the destination port per MX host name when set (it also names the DANE TLSA record, <c>_port._tcp.host</c>). Null (production) means
    /// <see cref="RemotePort"/> for every host. A lab or test that runs several loopback servers behind one DNS zone needs a port per host name.
    /// <para>A delegate, so it cannot be bound from configuration, and it must stay that way: never expose it in <c>MtaConfig</c> or the API (it would let configuration redirect mail for a host name to any local port).</para>
    /// </summary>
    public Func<string, int>? RemotePortResolver { get; init; }

    internal int RemotePortFor(string mxHost) => RemotePortResolver?.Invoke(mxHost) ?? RemotePort;

    /// <summary>Most recipients in one SMTP transaction to one domain (RFC 5321 minimum for a server is 100).</summary>
    public int MaxRecipientsPerTransaction { get; init; } = 100;

    /// <summary>Most MX hosts tried per attempt.</summary>
    public int MaxMxHostsPerAttempt { get; init; } = 5;

    /// <summary>Most addresses tried per MX host.</summary>
    public int MaxAddressesPerHost { get; init; } = 2;

    /// <summary>Domain for per-message bounce addresses (<c>b+token@domain</c>); when null the original envelope sender is used as is.</summary>
    public string? BounceDomain { get; init; }

    /// <summary>Generate a bounce message to the sender of SMTP-submitted mail on permanent failure or expiry (API senders use webhooks).</summary>
    public bool GenerateDsnForSmtpSubmissions { get; init; } = true;

    /// <summary>Also generate bounce messages for API-submitted mail.</summary>
    public bool GenerateDsnForApiSubmissions { get; init; }

    /// <summary>How much of the original message a bounce carries.</summary>
    public DsnReturnContent DsnReturnContent { get; init; } = DsnReturnContent.Headers;

    /// <summary>Lifetime of a generated bounce message.</summary>
    public TimeSpan DsnLifetime { get; init; } = TimeSpan.FromDays(2);

    /// <summary>Retry a full mailbox (default) instead of bouncing it at once.</summary>
    public bool RetryMailboxFull { get; init; } = true;

    /// <summary>TLS behaviour for domains without an explicit policy.</summary>
    public OutboundTlsConfiguration DefaultTls { get; init; } = OutboundTlsConfiguration.Default;

    /// <summary>How long a signing key lookup is cached.</summary>
    public TimeSpan DkimCacheTtl { get; init; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// The address that receiving servers see for our connections, reported as <c>sending-mta-ip</c> in TLS-RPT reports (<c>Delivery:PublicSendingIp</c>).
    /// Set it when the host is behind NAT or a proxy; when unset the connection's local address is reported only if it is a public address.
    /// </summary>
    public string? PublicSendingIp { get; init; }

    /// <summary>Report private, loopback and link-local local addresses too. For tests and lab setups only; production reports must not carry them.</summary>
    public bool ReportNonPublicSendingIp { get; init; }

    internal void Validate()
    {
        if (!string.IsNullOrWhiteSpace(PublicSendingIp) && !System.Net.IPAddress.TryParse(PublicSendingIp, out _))
        {
            throw new ArgumentException("Delivery:PublicSendingIp is not an IP address.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(Owner);
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxConcurrentGroups, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(ClaimBatchSize, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxRecipientsPerTransaction, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxMxHostsPerAttempt, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxAddressesPerHost, 1);
        if (Lease <= TimeSpan.Zero || IdlePoll <= TimeSpan.Zero || ExpirySweepInterval <= TimeSpan.Zero || ConfigRefreshInterval <= TimeSpan.Zero)
        {
            throw new ArgumentException("Delivery intervals must be positive.");
        }
    }
}
