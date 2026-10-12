using System.Net;
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
    public StorageOptions Storage { get; init; } = new();
    public DeliverySection Delivery { get; init; } = new();
    public WebhookOptions Webhooks { get; init; } = new();
    public DashboardSection Dashboard { get; init; } = new();
    public SecretsSection Secrets { get; init; } = new();
    public ObservabilitySection Observability { get; init; } = new();
    public SwitchSection Switch { get; init; } = new();
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
    public int Workers { get; init; } = Math.Max(4, Environment.ProcessorCount * 2);

    public int ClaimBatchSize { get; init; } = 100;
    public TimeSpan ClaimLease { get; init; } = TimeSpan.FromMinutes(10);
    public TimeSpan PollInterval { get; init; } = TimeSpan.FromMilliseconds(250);

    /// <summary>EHLO name for outbound connections; defaults to <see cref="MtaConfig.Hostname"/>.</summary>
    public string? HeloName { get; init; }

    /// <summary>Domain used for bounce (return-path) addresses: <c>bounces+token@domain</c>.</summary>
    public string? BounceDomain { get; init; }

    public int MaxRecipientsPerTransaction { get; init; } = 50;
    public bool PreferChunking { get; init; }
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

    /// <summary>A cloud KMS wraps the key ring (credentials from the environment). Not implemented in v1.</summary>
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
}

public sealed class ObservabilitySection
{
    public string? OtlpEndpoint { get; init; }
    public bool MetricsEndpointEnabled { get; init; } = true;
}

public sealed class SwitchSection
{
    /// <summary>Seconds to wait for in-flight deliveries when quiescing (decision R).</summary>
    public int QuiesceTimeoutSeconds { get; init; } = 30;
}
