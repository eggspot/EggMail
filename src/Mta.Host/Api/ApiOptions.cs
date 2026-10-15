using Mta.Webhooks;

namespace Mta.Host.Api;

/// <summary>How the dashboard session cookie is marked <c>Secure</c>.</summary>
public enum CookieSecureMode : byte
{
    /// <summary>Secure whenever the request arrived over HTTPS or from a non-loopback peer (a TLS-terminating proxy); only plain HTTP on loopback (development) is not Secure.</summary>
    Auto = 0,

    Always,
    Never,
}

/// <summary>Settings of the HTTP API (docs/api.md). Defaults are safe; the composition root fills the deployment-specific values.</summary>
public sealed class ApiOptions
{
    /// <summary>Largest JSON body of the sending endpoints (attachments travel as base64). Default 40 MiB.</summary>
    public long MaxSendBodyBytes { get; set; } = 40L * 1024 * 1024;

    /// <summary>Largest JSON body of every other endpoint. Default 1 MiB.</summary>
    public long MaxBodyBytes { get; set; } = 1024 * 1024;

    /// <summary>Largest message (decoded raw RFC 5322 bytes) accepted by <c>POST /messages</c> and <c>/messages/raw</c>; reported by capabilities.</summary>
    public long MaxMessageBytes { get; set; } = 25L * 1024 * 1024;

    /// <summary>Most recipients (To, Cc and Bcc together) of one message; reported by capabilities.</summary>
    public int MaxRecipients { get; set; } = 50;

    /// <summary>
    /// Bytes of send-request bodies the server holds in memory at once (a message is copied several times while it is decoded, composed and queued). A request that
    /// would exceed it is answered 429 with <c>Retry-After</c>. Default 512 MiB.
    /// </summary>
    public long MaxInFlightSendBytes { get; set; } = 512L * 1024 * 1024;

    public int MaxAttachments { get; set; } = 50;
    public int MaxCustomHeaders { get; set; } = 50;
    public int MaxTags { get; set; } = 10;

    /// <summary>Sign-in cookie name.</summary>
    public string SessionCookieName { get; set; } = "eggmail_session";

    public CookieSecureMode CookieSecure { get; set; } = CookieSecureMode.Auto;

    /// <summary>Absolute lifetime of a dashboard session. Default 12 hours.</summary>
    public TimeSpan SessionLifetime { get; set; } = TimeSpan.FromHours(12);

    /// <summary>A session unused for this long ends. Default 2 hours.</summary>
    public TimeSpan SessionIdleTimeout { get; set; } = TimeSpan.FromHours(2);

    /// <summary>PBKDF2 iterations for passwords the API hashes (null: <see cref="Mta.Host.Security.PasswordHasher.DefaultIterations"/>). Tests lower it; there is no configuration key.</summary>
    internal int? PasswordHashIterations { get; set; }

    /// <summary>Activity (session last-seen, API key last-used) is written at most this often per session or key.</summary>
    public TimeSpan TouchInterval { get; set; } = TimeSpan.FromMinutes(1);

    public int MaxDomainsPerTenant { get; set; } = 200;
    public int MaxApiKeysPerTenant { get; set; } = 100;
    public int MaxSmtpCredentialsPerTenant { get; set; } = 100;
    public int MaxWebhooksPerTenant { get; set; } = 50;

    /// <summary>Routes per inbound domain (<c>Api:MaxInboundRoutesPerDomain</c>); never more than <see cref="Mta.Storage.Logic.InboundRules.MaxRoutesPerDomain"/>.</summary>
    public int MaxInboundRoutesPerDomain { get; set; } = 100;

    /// <summary>The server defaults the inbound settings API reports as effective values.</summary>
    public InboundApiDefaults Inbound { get; set; } = new();

    /// <summary>Most rows one statistics query may return; larger ranges are refused with <c>validation_failed</c>.</summary>
    public int MaxStatsRows { get; set; } = 50_000;

    /// <summary>The operator's shared bounce domain; the per-domain return-path CNAME points at it. Null: no return-path record is required.</summary>
    public string? BounceDomain { get; set; }

    /// <summary>Optional SPF <c>include:</c> suggested to customers.</summary>
    public string? SpfInclude { get; set; }

    /// <summary>
    /// The full set of options of the DNS records suggested for a sending domain. When null, they are derived from <see cref="BounceDomain"/> and <see cref="SpfInclude"/>
    /// alone (no host name, so no bounce MX, MTA-STS or reverse-DNS advice).
    /// </summary>
    public Mta.Host.Domains.DomainRecordOptions? DomainRecords { get; set; }

    /// <summary>Domain used for generated Message-IDs of messages composed by the API when the From domain cannot be used.</summary>
    public string MessageIdDomain { get; set; } = "localhost";

    /// <summary>Webhook endpoint rules (HTTPS only unless <see cref="WebhookOptions.AllowHttp"/>).</summary>
    public WebhookOptions Webhooks { get; set; } = new();

    /// <summary>Configuration keys the deployment fixes (environment, files, command line): settings with these keys are <c>locked</c>.</summary>
    public IReadOnlySet<string> LockedKeys { get; set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>Serve <c>GET /metrics</c>.</summary>
    public bool MetricsEnabled { get; set; } = true;

    /// <summary><c>Delivery:AllowPrivateMxAddresses</c>: whether the delivery engine uses MX and relay hosts that resolve to loopback or reserved addresses. The relay route API warns when it is off and a host would be refused.</summary>
    public bool AllowPrivateMxAddresses { get; set; }

    /// <summary>
    /// Networks allowed to read <c>/metrics</c> (CIDR). Default: loopback and private ranges. The endpoint carries no credentials, so it must
    /// never be reachable from the public internet.
    /// </summary>
    public IReadOnlyList<IpNetwork> MetricsAllowedNetworks { get; set; } = DefaultMetricsNetworks();

    /// <summary>Capabilities and warnings are cached this long (the endpoint is unauthenticated).</summary>
    public TimeSpan CapabilitiesCacheTime { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>Domain verification scheduler (see <see cref="DomainVerificationService"/>).</summary>
    public TimeSpan VerificationPollInterval { get; set; } = TimeSpan.FromSeconds(15);

    public int VerificationBatchSize { get; set; } = 25;
    public int VerificationMaxParallel { get; set; } = 4;

    /// <summary>A retired DKIM key stays published (and is checked as advice) this long after it stopped signing (design section 8).</summary>
    public TimeSpan DkimRetirementGrace { get; set; } = TimeSpan.FromDays(7);

    public static IReadOnlyList<IpNetwork> DefaultMetricsNetworks() =>
    [
        IpNetwork.Parse("127.0.0.0/8"), IpNetwork.Parse("::1/128"), IpNetwork.Parse("10.0.0.0/8"), IpNetwork.Parse("172.16.0.0/12"),
        IpNetwork.Parse("192.168.0.0/16"), IpNetwork.Parse("fc00::/7"), IpNetwork.Parse("fe80::/10"),
    ];
}
