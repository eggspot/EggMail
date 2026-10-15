using System.Net;
using Mta.Host.Api;
using Mta.Host.Domains;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Webhooks;

namespace Mta.Host.Configuration;

/// <summary>
/// Typed deployment configuration (decision N precedence: command line > environment / mounted files > bootstrap file >
/// settings in the config store > built-in defaults). Keys use the usual double-underscore form in environment variables,
/// for example <c>Storage__Backend=Postgres</c>. Defaults are identical for both backends (decision J) except the storage
/// ones (decision Q: SQLite is the default backend).
/// </summary>
public sealed class MtaConfig
{
    /// <summary>Name announced in SMTP greetings, Received headers and EHLO (should match the PTR record of the sending IP).</summary>
    public string Hostname { get; init; } = Environment.MachineName.ToLowerInvariant();

    public SmtpSection Smtp { get; init; } = new();
    public BackupSection Backup { get; init; } = new();
    public SendingSection Sending { get; init; } = new();
    public DnsSection Dns { get; init; } = new();
    public StorageOptions Storage { get; init; } = new();
    public DeliverySection Delivery { get; init; } = new();
    public WebhookOptions Webhooks { get; init; } = new();
    public DashboardSection Dashboard { get; init; } = new();
    public SecretsSection Secrets { get; init; } = new();
    public ObservabilitySection Observability { get; init; } = new();
    public SwitchSection Switch { get; init; } = new();
    public StartupSection Startup { get; init; } = new();
    public TlsSection Tls { get; init; } = new();
    public AcmeSection Acme { get; init; } = new();
    public ApiSection Api { get; init; } = new();
    public DomainsSection Domains { get; init; } = new();
}

public sealed class SmtpSection
{
    public long MaxMessageSize { get; init; } = 25L * 1024 * 1024;
    public int MaxRecipients { get; init; } = 50;
    public int MaxConnections { get; init; } = 2000;
    public int MaxConnectionsPerIp { get; init; } = 100;
    public long MaxInFlightBytes { get; init; } = 512L * 1024 * 1024;
    public bool Chunking { get; init; } = true;
    public bool SmtpUtf8 { get; init; } = true;

    /// <summary>
    /// Listener definitions by name; the defaults are the container ports of decision 17. A listener named in configuration
    /// replaces the default with the same name member by member.
    /// </summary>
    public Dictionary<string, ListenerSection> Listeners { get; init; } = DefaultListeners();

    public static Dictionary<string, ListenerSection> DefaultListeners() => new(StringComparer.OrdinalIgnoreCase)
    {
        ["submission"] = new ListenerSection { Port = 5587, Mode = ListenerMode.StartTls, Role = ListenerRole.Submission, AuthRequired = true, Enabled = true },
        ["submissions"] = new ListenerSection { Port = 4465, Mode = ListenerMode.Implicit, Role = ListenerRole.Submission, AuthRequired = true, Enabled = true },
        ["alternate"] = new ListenerSection { Port = 2525, Mode = ListenerMode.StartTls, Role = ListenerRole.Submission, AuthRequired = true, Enabled = true },
        ["alternate-587"] = new ListenerSection { Port = 2587, Mode = ListenerMode.StartTls, Role = ListenerRole.Submission, AuthRequired = true, Enabled = false },
        ["alternate-465"] = new ListenerSection { Port = 2465, Mode = ListenerMode.Implicit, Role = ListenerRole.Submission, AuthRequired = true, Enabled = false },
        ["bounce"] = new ListenerSection { Port = 2526, Mode = ListenerMode.StartTls, Role = ListenerRole.Bounce, AuthRequired = false, Enabled = true },
    };
}

public sealed class ListenerSection
{
    public int Port { get; init; }
    public string BindAddress { get; init; } = "::";
    public ListenerMode Mode { get; init; } = ListenerMode.StartTls;
    public ListenerRole Role { get; init; } = ListenerRole.Submission;
    public bool AuthRequired { get; init; } = true;
    public bool Enabled { get; init; } = true;
    public bool AllowInsecureAuth { get; init; }

    public SmtpListenerOptions ToOptions(string name) => new()
    {
        Name = name,
        Port = Port,
        BindAddress = IPAddress.Parse(BindAddress),
        Mode = Mode,
        Role = Role,
        AuthRequired = AuthRequired,
        Enabled = Enabled,
        AllowInsecureAuth = AllowInsecureAuth,
    };
}

public sealed class DeliverySection
{
    /// <summary>Concurrent delivery workers.</summary>
    public int Workers { get; init; } = Math.Max(32, Environment.ProcessorCount * 8);

    public int ClaimBatchSize { get; init; } = 100;
    public TimeSpan ClaimLease { get; init; } = TimeSpan.FromMinutes(15);
    public TimeSpan PollInterval { get; init; } = TimeSpan.FromMilliseconds(250);

    /// <summary>EHLO name for outbound connections; defaults to <see cref="MtaConfig.Hostname"/>.</summary>
    public string? HeloName { get; init; }

    /// <summary>Domain used for bounce (return-path) addresses: <c>bounces+token@domain</c>.</summary>
    public string? BounceDomain { get; init; }

    public int MaxRecipientsPerTransaction { get; init; } = 100;
    public bool PreferChunking { get; init; }

    /// <summary>Per-destination connection and rate limits (adaptive: they start low and grow while the destination keeps accepting).</summary>
    public ThrottleSection Throttle { get; init; } = new();

    /// <summary>Delays between retries after the 1st, 2nd, ... failed attempt; the last one repeats until the delivery expires. Empty keeps the built-in ladder (2 m, 5 m, 15 m, 30 m, 1 h, 2 h, 4 h).</summary>
    public List<TimeSpan> RetryDelays { get; init; } = [];

    /// <summary>Destination port for direct MX delivery. Only change for lab setups; the Internet uses 25.</summary>
    public int RemotePort { get; init; } = 25;

    /// <summary>Allow MX hosts that resolve to loopback, private or other special-use addresses. Off in production (a hostile MX record must not aim us at the internal network); on for lab and test setups.</summary>
    public bool AllowPrivateMxAddresses { get; init; }

    /// <summary>The address receiving servers see for our connections, reported as <c>sending-mta-ip</c> in TLS-RPT reports. Set it behind NAT or a proxy; when unset only a public local address of the connection is reported.</summary>
    public string? PublicSendingIp { get; init; }
}

/// <summary>
/// Caps on how much mail may be sent per UTC hour and per UTC day (0 or unset = unlimited). A tenant can be given its own caps with the
/// tenant settings <c>Sending:PerHour</c> and <c>Sending:PerDay</c>. Counters are in memory: a restart starts the current hour and day at zero.
/// </summary>
public sealed class SendingSection
{
    public long GlobalPerHour { get; init; }
    public long GlobalPerDay { get; init; }

    /// <summary>Default caps of every tenant that has no tenant setting.</summary>
    public long TenantPerHour { get; init; }
    public long TenantPerDay { get; init; }

    /// <summary>Default caps of every sending domain.</summary>
    public long DomainPerHour { get; init; }
    public long DomainPerDay { get; init; }

    /// <summary>Limit each sending domain by the warm-up ramp (50, 100, 200 ... messages per day) counted from the day the domain was added.</summary>
    public bool WarmupEnabled { get; init; }
}

public sealed class BackupSection
{
    /// <summary>Scheduled consistent backups (<c>VACUUM INTO</c> per SQLite file, while running). PostgreSQL has no built-in backup here: use <c>pg_dump</c> or your platform's backups.</summary>
    public bool Enabled { get; init; } = true;

    /// <summary>Hours between backups (the first one runs shortly after start-up when none exists yet).</summary>
    public double IntervalHours { get; init; } = 24;

    /// <summary>How many of the newest backups to keep.</summary>
    public int Keep { get; init; } = 3;

    /// <summary>Where backups go; defaults to <c>backups</c> inside the SQLite data directory. Put it on a different disk than the data when you can.</summary>
    public string? Directory { get; init; }
}

public sealed class DnsSection
{
    /// <summary>Resolvers to use (IP with optional port). Empty means the system resolvers from <c>/etc/resolv.conf</c>, with public resolvers as the last resort.</summary>
    public List<string> Servers { get; init; } = [];

    /// <summary>Ask for DNSSEC records (DO bit). Needed for DANE.</summary>
    public bool RequestDnssec { get; init; } = true;

    /// <summary>Trust the AD bit of answers. Only safe when the configured resolver is local or otherwise trusted and validates DNSSEC.</summary>
    public bool TrustAuthenticatedData { get; init; }
}

public sealed class ThrottleSection
{
    /// <summary>Ceiling of concurrent connections to one destination domain.</summary>
    public int MaxConnections { get; init; } = 20;

    /// <summary>Ceiling of messages per minute to one destination domain.</summary>
    public double MaxMessagesPerMinute { get; init; } = 600;

    /// <summary>Messages sent over one connection before it is closed.</summary>
    public int MaxMessagesPerConnection { get; init; } = 100;

    /// <summary>Connections allowed at first, before the destination has shown it accepts more.</summary>
    public int InitialConnections { get; init; } = 5;

    /// <summary>Messages per minute allowed at first.</summary>
    public double InitialMessagesPerMinute { get; init; } = 120;
}

public sealed class DashboardSection
{
    public int HttpPort { get; init; } = 8080;
    public int HttpsPort { get; init; } = 8443;
    public string BindAddress { get; init; } = "::";
    public bool HttpsEnabled { get; init; } = true;

    /// <summary>Path of a file holding the initial admin password (created once if no admin exists).</summary>
    public string? BootstrapAdminPasswordFile { get; init; }

    public string BootstrapAdminUser { get; init; } = "admin";
}

public enum KeyProtectionMode : byte
{
    /// <summary>Data Protection keys are protected by a certificate (<see cref="SecretsSection.CertificatePath"/>).</summary>
    Certificate = 0,

    /// <summary>
    /// An external key service wraps the key ring (<see cref="SecretsSection.KmsProvider"/>): the ring in the database holds only wrapped keys. Built in is
    /// <c>LocalKey</c>, a 32-byte key from a file or the environment; a cloud key service plugs in through <c>IKeyWrapProvider</c> (not included, docs/open-questions.md).
    /// </summary>
    Kms,

    /// <summary>Development only: the key ring is stored unprotected.</summary>
    None,
}

public sealed class SecretsSection
{
    public KeyProtectionMode KeyProtection { get; init; } = KeyProtectionMode.None;

    /// <summary>PFX/PEM used to protect the Data Protection key ring (deployment configuration, never in the database).</summary>
    public string? CertificatePath { get; init; }

    public string? CertificatePasswordFile { get; init; }

    /// <summary>With <see cref="KeyProtectionMode.Kms"/>: the key service that wraps the ring. <c>LocalKey</c> is built in.</summary>
    public string KmsProvider { get; init; } = "LocalKey";

    /// <summary>With <c>KmsProvider=LocalKey</c>: file holding the 32-byte wrapping key (base64, hex or raw bytes). Prefer this to <see cref="KmsKey"/>.</summary>
    public string? KmsKeyFile { get; init; }

    /// <summary>With <c>KmsProvider=LocalKey</c>: the wrapping key itself (base64 or hex), for platforms that only pass environment variables.</summary>
    public string? KmsKey { get; init; }
}

public sealed class ObservabilitySection
{
    /// <summary>OTLP endpoint for metrics, traces and logs (for example <c>http://collector:4317</c>). Empty: nothing is exported over OTLP (and no span is ever created).</summary>
    public string? OtlpEndpoint { get; init; }

    /// <summary><c>Grpc</c> (default, port 4317) or <c>HttpProtobuf</c> (port 4318; the signal paths <c>/v1/metrics</c>, <c>/v1/traces</c>, <c>/v1/logs</c> are appended).</summary>
    public string OtlpProtocol { get; init; } = "Grpc";

    /// <summary>Share of messages whose trace is exported (0 to 1). The decision follows the message id, so a sampled message is traced from submission to webhook.</summary>
    public double TraceSampleRatio { get; init; } = 0.1;

    public bool MetricsEndpointEnabled { get; init; } = true;

    /// <summary>Seconds between samples of the queue for the <c>mta_delivery_queue_*</c> gauges (each sample reads the whole queue table). 0 turns the gauges off.</summary>
    public int QueueSampleSeconds { get; init; } = 15;
}

public sealed class SwitchSection
{
    /// <summary>Seconds to wait for in-flight deliveries when quiescing (decision R).</summary>
    public int QuiesceTimeoutSeconds { get; init; } = 30;

    /// <summary>Where the admin API writes switch bundles (a directory per switch); default <c>&lt;Sqlite:DataDirectory&gt;/switch</c> or the temp directory.</summary>
    public string? BundleDirectory { get; init; }
}

/// <summary>
/// Certificates live in the database (decision K). An optional file override (for example cert-manager mounts) takes
/// precedence over the database when configured.
/// </summary>
public sealed class TlsSection
{
    /// <summary>PEM certificate chain file, or a PFX file when <see cref="KeyPath"/> is empty.</summary>
    public string? CertificatePath { get; init; }

    public string? KeyPath { get; init; }
    public string? PfxPasswordFile { get; init; }

    /// <summary>How often replicas poll the store (and the override files) for changes.</summary>
    public TimeSpan PollInterval { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Send daily TLS-RPT reports (RFC 8460) to domains that publish MTA-STS or DANE and ask for them.</summary>
    public bool ReportingEnabled { get; init; } = true;

    /// <summary>Contact in the reports; defaults to <c>postmaster@</c> plus the host name.</summary>
    public string? ReportContact { get; init; }
}

public sealed class AcmeSection
{
    public bool Enabled { get; init; }
    public string DirectoryUrl { get; init; } = "https://acme-v02.api.letsencrypt.org/directory";
    public string? Email { get; init; }

    /// <summary>Names for one certificate (the SMTP and dashboard host names; wildcards need DNS-01, the default).</summary>
    public List<string> Domains { get; init; } = [];

    public string CertificateName { get; init; } = "default";

    /// <summary>Cloudflare is the first DNS provider (decision 19).</summary>
    public string DnsProvider { get; init; } = "Cloudflare";

    public string? CloudflareApiToken { get; init; }
    public string? CloudflareApiTokenFile { get; init; }
    public TimeSpan PropagationDelay { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Renew when this fraction of the lifetime remains (Let's Encrypt recommends one third).</summary>
    public double RenewAtRemainingFraction { get; init; } = 1.0 / 3.0;

    public TimeSpan CheckInterval { get; init; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Ask the CA when to renew (ACME Renewal Information, RFC 9773) and follow its window; when the CA has no ARI or it fails, or this is false,
    /// <see cref="RenewAtRemainingFraction"/> decides. The CA is asked no more often than <see cref="CheckInterval"/> and its Retry-After allow.
    /// </summary>
    public bool UseRenewalInfo { get; init; } = true;
}

/// <summary>
/// Limits and session settings of the HTTP API (docs/api.md). Defaults are those of <see cref="ApiOptions"/>, so an unset key keeps
/// the documented behaviour. <see cref="Smtp"/> settings (<c>Smtp:MaxMessageSize</c>, <c>Smtp:MaxRecipients</c>) also bound the API.
/// </summary>
public sealed class ApiSection
{
    private static readonly ApiOptions D = new();

    /// <summary>Largest JSON request body of every endpoint except the two sending endpoints (checked while streaming).</summary>
    public long MaxBodyBytes { get; init; } = D.MaxBodyBytes;

    /// <summary>Largest JSON request body of <c>POST /messages</c> and <c>/messages/raw</c> (attachments travel as base64).</summary>
    public long MaxSendBodyBytes { get; init; } = D.MaxSendBodyBytes;

    /// <summary>Bytes of send-request bodies held in memory at once; a request that would exceed it is answered <c>429</c>.</summary>
    public long MaxInFlightSendBytes { get; init; } = D.MaxInFlightSendBytes;

    public int MaxAttachments { get; init; } = D.MaxAttachments;
    public int MaxCustomHeaders { get; init; } = D.MaxCustomHeaders;
    public int MaxTags { get; init; } = D.MaxTags;

    /// <summary>Absolute lifetime of a dashboard session.</summary>
    public TimeSpan SessionLifetime { get; init; } = D.SessionLifetime;

    /// <summary>A dashboard session unused for this long ends.</summary>
    public TimeSpan SessionIdleTimeout { get; init; } = D.SessionIdleTimeout;

    /// <summary><c>Auto</c> (Secure unless plain HTTP from a loopback peer), <c>Always</c> or <c>Never</c>.</summary>
    public CookieSecureMode CookieSecure { get; init; } = D.CookieSecure;

    public int MaxDomainsPerTenant { get; init; } = D.MaxDomainsPerTenant;
    public int MaxApiKeysPerTenant { get; init; } = D.MaxApiKeysPerTenant;
    public int MaxSmtpCredentialsPerTenant { get; init; } = D.MaxSmtpCredentialsPerTenant;
    public int MaxWebhooksPerTenant { get; init; } = D.MaxWebhooksPerTenant;

    /// <summary>Most rows one statistics query may return.</summary>
    public int MaxStatsRows { get; init; } = D.MaxStatsRows;

    /// <summary>Networks (CIDR) allowed to read <c>/metrics</c>. Empty keeps the default: loopback and private ranges.</summary>
    public List<string> MetricsAllowedNetworks { get; init; } = [];

    /// <summary>SPF <c>include:</c> host suggested to customers in the DNS records of a sending domain.</summary>
    public string? SpfInclude { get; init; } = D.SpfInclude;
}

/// <summary>
/// Sending domains and the DNS records they need (docs/operations.md, "Adding a sending domain"). In an environment variable <see cref="Bootstrap"/>
/// is <c>Domains__Bootstrap</c>.
/// </summary>
public sealed class DomainsSection
{
    /// <summary>
    /// Domain names to register for the first tenant at start (the default tenant <c>Default</c> is created when there is no tenant). Idempotent: a domain that
    /// already exists is left alone, a newly registered one has its DKIM key generated and the DNS records to create written to the log. A list, given as
    /// indexed entries or as one value separated by commas, semicolons or spaces.
    /// </summary>
    public List<string> Bootstrap { get; init; } = [];

    /// <summary>Policy of the suggested DMARC record: <c>none</c> (monitor only), <c>quarantine</c> or <c>reject</c>.</summary>
    public string DmarcPolicy { get; init; } = "none";

    /// <summary>E-mail address in the <c>rua</c> of the suggested DMARC record; <c>{domain}</c> stands for the sending domain. Empty: <c>dmarc@{domain}</c>.</summary>
    public string? DmarcReportAddress { get; init; }

    /// <summary>Destination in the <c>rua</c> of the suggested TLS-RPT record: an e-mail address or an <c>https://</c> URL, <c>{domain}</c> stands for the sending domain. Empty: <c>tls-rpt@{domain}</c>.</summary>
    public string? TlsReportAddress { get; init; }

    /// <summary>
    /// <c>Off</c> (default), <c>None</c>, <c>Testing</c> or <c>Enforce</c>: serve the MTA-STS policy file at <c>https://mta-sts.&lt;domain&gt;/.well-known/mta-sts.txt</c> for every registered
    /// domain and suggest its DNS records. Only right when this server receives the mail of those domains.
    /// </summary>
    public MtaStsServingMode MtaStsMode { get; init; } = MtaStsServingMode.Off;

    /// <summary><c>max_age</c> of the served MTA-STS policy.</summary>
    public TimeSpan MtaStsMaxAge { get; init; } = TimeSpan.FromDays(7);

    /// <summary><c>mx:</c> lines of the served MTA-STS policy. Empty: <c>Hostname</c>.</summary>
    public List<string> MtaStsMx { get; init; } = [];
}
