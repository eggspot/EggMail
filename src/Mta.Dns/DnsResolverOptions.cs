using System.Net;

namespace Mta.Dns;

/// <summary>
/// Settings for <see cref="UdpTcpDnsTransport"/> and <see cref="DnsClient"/>. A record, so
/// <c>options with { Use0x20 = true }</c> makes a modified copy; every property has a safe default.
/// </summary>
public sealed record DnsResolverOptions
{
    /// <summary>The recursive resolvers to ask, in order of preference. Empty means "discover from the system" in <see cref="DnsClient.Create"/>.</summary>
    public IReadOnlyList<IPEndPoint> Servers { get; init; } = [];

    /// <summary>How long to wait for a response in the first round. Later rounds wait <see cref="BackoffMultiplier"/> times longer each, up to <see cref="MaxAttemptTimeout"/>. Default 2 s.</summary>
    public TimeSpan AttemptTimeout { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>The factor applied to the timeout after each round over all servers. Default 2.</summary>
    public double BackoffMultiplier { get; init; } = 2.0;

    /// <summary>The upper bound for a single attempt's timeout. Default 8 s.</summary>
    public TimeSpan MaxAttemptTimeout { get; init; } = TimeSpan.FromSeconds(8);

    /// <summary>The number of rounds over the server list when servers time out (each round tries every server that has not given a definite failure). Default 3.</summary>
    public int Attempts { get; init; } = 3;

    /// <summary>Fall back to TCP when a UDP response has the TC bit. Default true.</summary>
    public bool EnableTcpFallback { get; init; } = true;

    /// <summary>The EDNS0 UDP payload size to advertise; 0 disables EDNS0 (and with it DO). Default 1232. Must be 0 or at least 512.</summary>
    public ushort EdnsUdpPayloadSize { get; init; } = DnsQueryOptions.DefaultEdnsUdpPayloadSize;

    /// <summary>Set the DO (DNSSEC OK) bit so a validating resolver (for example Unbound on loopback) reports AD. Default false.</summary>
    public bool RequestDnssecOk { get; init; }

    /// <summary>
    /// Report the server's AD bit in <see cref="DnsResponse.AuthenticatedData"/>. Only enable when every entry of
    /// <see cref="Servers"/> is a trusted local validating resolver reached over a trusted path (typically
    /// 127.0.0.1); otherwise AD is attacker-controlled. Default false: AD is always reported as false.
    /// </summary>
    public bool TrustAuthenticatedData { get; init; }

    /// <summary>Set the CD bit so a validating resolver returns data even when validation fails. Default false.</summary>
    public bool CheckingDisabled { get; init; }

    /// <summary>
    /// DNS 0x20 case randomization: send the question with randomized letter case and only accept a response that
    /// echoes it byte for byte. Adds entropy against spoofing, but breaks with resolvers that normalize the case of
    /// the question, so it is off by default.
    /// </summary>
    public bool Use0x20 { get; init; }

    /// <summary>The maximum number of cached answers (positive plus negative). 0 disables the cache. Default 10000.</summary>
    public int MaxCacheEntries { get; init; } = 10_000;

    /// <summary>Records with a smaller TTL are cached for this long instead. Default 5 s.</summary>
    public TimeSpan MinCacheTtl { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Records with a larger TTL are cached for at most this long. Default 1 day.</summary>
    public TimeSpan MaxCacheTtl { get; init; } = TimeSpan.FromDays(1);

    /// <summary>The upper bound for caching NXDOMAIN and NODATA (RFC 2308 allows up to 3 hours). Default 5 minutes.</summary>
    public TimeSpan NegativeCacheMaxTtl { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>The negative-caching TTL when the response carries no SOA. Default 30 s.</summary>
    public TimeSpan DefaultNegativeTtl { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>The maximum number of CNAME records followed for one question. A longer chain or a loop is a <see cref="DnsException"/>. Default 8.</summary>
    public int MaxCnameDepth { get; init; } = 8;

    /// <summary>When the system configuration names no resolver, also use 1.1.1.1 and 8.8.8.8 (after 127.0.0.1). Default false: mail servers should not leak queries to third parties unasked.</summary>
    public bool AllowPublicResolverFallback { get; init; }

    /// <summary>Throws <see cref="ArgumentException"/> if any setting is out of range.</summary>
    public void Validate()
    {
        Require(AttemptTimeout > TimeSpan.Zero, nameof(AttemptTimeout));
        Require(MaxAttemptTimeout >= AttemptTimeout, nameof(MaxAttemptTimeout) + " must not be smaller than " + nameof(AttemptTimeout));
        Require(BackoffMultiplier >= 1.0 && BackoffMultiplier <= 16.0, nameof(BackoffMultiplier));
        Require(Attempts is >= 1 and <= 10, nameof(Attempts));
        Require(EdnsUdpPayloadSize == 0 || EdnsUdpPayloadSize >= 512, nameof(EdnsUdpPayloadSize));
        Require(MaxCacheEntries >= 0, nameof(MaxCacheEntries));
        Require(MinCacheTtl >= TimeSpan.Zero && MaxCacheTtl >= MinCacheTtl, nameof(MinCacheTtl) + " and " + nameof(MaxCacheTtl));
        Require(NegativeCacheMaxTtl >= TimeSpan.Zero && DefaultNegativeTtl >= TimeSpan.Zero, nameof(NegativeCacheMaxTtl));
        Require(MaxCnameDepth is >= 0 and <= 32, nameof(MaxCnameDepth));
        ArgumentNullException.ThrowIfNull(Servers);
    }

    /// <summary>
    /// Options based on the machine's resolver configuration: servers, timeout and attempts from
    /// /etc/resolv.conf (or the network interfaces on Windows). See <see cref="SystemDnsConfiguration"/>.
    /// </summary>
    public static DnsResolverOptions FromSystemConfiguration(bool allowPublicResolverFallback = false)
    {
        var system = SystemDnsConfiguration.Discover(allowPublicResolverFallback);
        var options = new DnsResolverOptions { Servers = system.Servers, AllowPublicResolverFallback = allowPublicResolverFallback };
        if (system.Timeout is { } timeout)
        {
            options = options with { AttemptTimeout = timeout, MaxAttemptTimeout = Max(timeout, options.MaxAttemptTimeout) };
        }

        if (system.Attempts is { } attempts)
        {
            options = options with { Attempts = attempts };
        }

        return options;
    }

    private static TimeSpan Max(TimeSpan a, TimeSpan b) => a > b ? a : b;

    private static void Require(bool condition, string what)
    {
        if (!condition)
        {
            throw new ArgumentException("Invalid DNS resolver option: " + what + ".");
        }
    }
}
