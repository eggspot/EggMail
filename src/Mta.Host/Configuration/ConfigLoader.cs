using Microsoft.Extensions.Configuration;
using Mta.Storage;

namespace Mta.Host.Configuration;

/// <summary>Loads and validates <see cref="MtaConfig"/> and records which keys the deployment sets (those are "locked" in the dashboard).</summary>
public sealed class LoadedConfig
{
    public required MtaConfig Config { get; init; }

    /// <summary>Configuration keys supplied by the deployment layer (command line, environment, files).</summary>
    public required IReadOnlySet<string> LockedKeys { get; init; }

    public required IReadOnlyList<string> Errors { get; init; }

    /// <summary>The layered configuration this was loaded from (the backend switch reads <c>SwitchTarget:*</c> and detects the layer that supplies a key).</summary>
    public IConfiguration? Source { get; init; }

    public bool IsValid => Errors.Count == 0;
}

public static class ConfigLoader
{
    public const string BootstrapFileName = "bootstrap.json";

    /// <summary>The configuration key under which <see cref="Build"/> records where the bootstrap file is (or would be): the file a backend switch writes.</summary>
    public const string BootstrapPathKey = "Mta:BootstrapFile";

    /// <summary><c>appsettings.json</c> next to the executable (mount or copy one there); the layer below the bootstrap file.</summary>
    public static string DefaultAppSettingsPath => Path.Combine(AppContext.BaseDirectory, "appsettings.json");

    /// <summary>
    /// Where the bootstrap file lives: in the data directory (the hint, else <c>--Sqlite:DataDirectory</c> on the command line, else the
    /// <c>Sqlite__DataDirectory</c> environment variable, else <c>/data</c>; the same precedence the configuration itself uses). It has
    /// to be findable before the storage is known, which is why it cannot depend on <c>Storage:*</c>. (The command line used to be
    /// ignored here, so a server started with <c>--Sqlite:DataDirectory=/x</c> looked for, and a switch wrote, <c>/data/bootstrap.json</c>.)
    /// </summary>
    public static string ResolveBootstrapPath(string? dataDirectoryHint = null, IReadOnlyList<string>? args = null) =>
        Path.Combine(dataDirectoryHint ?? DataDirectoryFromArguments(args) ?? Environment.GetEnvironmentVariable("Sqlite__DataDirectory") ?? "/data", BootstrapFileName);

    /// <summary>The value of <c>Sqlite:DataDirectory</c> on the command line (<c>--Key=value</c>, <c>--Key value</c> or <c>/Key=value</c>), or null.</summary>
    internal static string? DataDirectoryFromArguments(IReadOnlyList<string>? args)
    {
        const string key = "Sqlite:DataDirectory";
        string? found = null;
        for (int i = 0; args is not null && i < args.Count; i++)
        {
            string a = args[i];
            string name = a.StartsWith("--", StringComparison.Ordinal) ? a[2..] : a.StartsWith('/') ? a[1..] : string.Empty;
            int eq = name.IndexOf('=', StringComparison.Ordinal);
            if (eq >= 0 && string.Equals(name[..eq], key, StringComparison.OrdinalIgnoreCase))
            {
                found = name[(eq + 1)..];
            }
            else if (eq < 0 && string.Equals(name, key, StringComparison.OrdinalIgnoreCase) && i + 1 < args.Count && !args[i + 1].StartsWith('-'))
            {
                found = args[++i];
            }
        }

        return string.IsNullOrWhiteSpace(found) ? null : found;
    }

    /// <summary>
    /// Builds the layered configuration for the process: appsettings (<paramref name="appSettingsPath"/>, default <see cref="DefaultAppSettingsPath"/>, if present), the bootstrap file in the data directory
    /// (storage pointer written by the backend switch), environment variables, then the command line (highest precedence).
    /// <paramref name="storedSettings"/> (the global settings kept in the config store) form the lowest layer, above the built-in defaults.
    /// </summary>
    public static IConfigurationRoot Build(string[] args, string? dataDirectoryHint = null, string? appSettingsPath = null, IEnumerable<KeyValuePair<string, string?>>? storedSettings = null, string? bootstrapFileOverride = null)
    {
        var builder = new ConfigurationBuilder();
        string bootstrapPath = ResolveBootstrapPath(dataDirectoryHint, args);
        builder.AddInMemoryCollection([new KeyValuePair<string, string?>(BootstrapPathKey, bootstrapPath)]);   // lowest layer: it only records where the file is
        if (storedSettings is not null)
        {
            builder.Add(new StoredSettingsConfigurationSource(storedSettings));   // layer 4 of decision N: settings persisted in the config store, below every deployment layer
        }

        appSettingsPath ??= DefaultAppSettingsPath;
        if (File.Exists(appSettingsPath))
        {
            builder.AddJsonFile(appSettingsPath, optional: true, reloadOnChange: false);
        }

        // The override lets the migrate-storage command read the pointer as it was before an activation rewrote the file ("" = no bootstrap file).
        string bootstrap = bootstrapFileOverride ?? bootstrapPath;
        if (bootstrap.Length > 0 && File.Exists(bootstrap))
        {
            builder.AddJsonFile(bootstrap, optional: true, reloadOnChange: false);
        }

        builder.AddEnvironmentVariables();
        builder.AddCommandLine(args);
        return builder.Build();
    }

    public static LoadedConfig Load(IConfiguration configuration)
    {
        var errors = new List<string>();
        MtaConfig cfg;
        try
        {
            cfg = Bind(configuration);
            Validate(cfg, errors);
        }
        catch (Exception ex) when (ex is InvalidOperationException or FormatException or OverflowException or ArgumentException)
        {
            // The binder reports a value of the wrong type ("12x" for a number, "soon" for a TimeSpan) by throwing; that is a configuration error, not a crash.
            cfg = new MtaConfig();
            errors.Add(ex.InnerException?.Message is { Length: > 0 } inner ? $"{ex.Message} ({inner})" : ex.Message);
        }

        var locked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, _) in configuration.AsEnumerable())
        {
            if (!string.IsNullOrEmpty(key) && configuration[key] is not null)
            {
                locked.Add(key);
            }
        }

        return new LoadedConfig { Config = cfg, LockedKeys = locked, Errors = errors, Source = configuration };
    }

    private static MtaConfig Bind(IConfiguration configuration)
    {
        var config = new MtaConfig();

        // Bind section by section so that listener dictionaries merge with the defaults instead of replacing them.
        var smtpSection = configuration.GetSection("Smtp");
        var smtp = new SmtpSection();
        smtpSection.Bind(smtp);
        var listeners = SmtpSection.DefaultListeners();
        foreach (var child in smtpSection.GetSection("Listeners").GetChildren())
        {
            var existing = listeners.TryGetValue(child.Key, out var def) ? def : new ListenerSection();
            // Start from the default listener's values, then apply what the configuration sets.
            var merged = Clone(existing);
            child.Bind(merged);
            listeners[child.Key] = merged;
        }

        // The binder appends configured list entries to a non-empty default, which would turn a configured schedule into "the default ladder, then these".
        var webhooks = Bind<Mta.Webhooks.WebhookOptions>(configuration, "Webhooks");
        var retrySchedule = configuration.GetSection("Webhooks:RetrySchedule").GetChildren().Select(c => c.Get<TimeSpan>()).ToList();
        if (retrySchedule.Count > 0)
        {
            webhooks = webhooks with { RetrySchedule = retrySchedule };
        }

        var acme = Bind<AcmeSection>(configuration, "Acme");
        var api = Bind<ApiSection>(configuration, "Api");
        SplitEntries(acme.Domains, configuration["Acme:Domains"]);
        SplitEntries(api.MetricsAllowedNetworks, configuration["Api:MetricsAllowedNetworks"]);

        return new MtaConfig
        {
            Hostname = configuration["Hostname"] ?? config.Hostname,
            Smtp = new SmtpSection
            {
                MaxMessageSize = smtp.MaxMessageSize, MaxRecipients = smtp.MaxRecipients, MaxConnections = smtp.MaxConnections,
                MaxConnectionsPerIp = smtp.MaxConnectionsPerIp, MaxInFlightBytes = smtp.MaxInFlightBytes, Chunking = smtp.Chunking,
                SmtpUtf8 = smtp.SmtpUtf8, Listeners = listeners,
            },
            Storage = BindStorage(configuration),
            Dns = Bind<DnsSection>(configuration, "Dns"),
            Backup = Bind<BackupSection>(configuration, "Backup"),
            Sending = Bind<SendingSection>(configuration, "Sending"),
            Delivery = Bind<DeliverySection>(configuration, "Delivery"),
            Webhooks = webhooks,
            Dashboard = Bind<DashboardSection>(configuration, "Dashboard"),
            Secrets = Bind<SecretsSection>(configuration, "Secrets"),
            Observability = Bind<ObservabilitySection>(configuration, "Observability"),
            Switch = Bind<SwitchSection>(configuration, "Switch"),
            Tls = Bind<TlsSection>(configuration, "Tls"),
            Acme = acme,
            Api = api,
        };
    }

    /// <summary>
    /// A list setting can be given as indexed entries (<c>Acme:Domains:0=a</c>) or, handy in an environment variable, as one value
    /// with several entries separated by commas, semicolons or white space. Rewrites the list in place with every entry split.
    /// </summary>
    private static void SplitEntries(List<string> list, string? scalar)
    {
        if (!string.IsNullOrWhiteSpace(scalar))
        {
            list.Add(scalar);   // the binder ignores a scalar value for a list
        }

        string[] split = list.SelectMany(e => e.Split([',', ';', ' ', '\t', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)).ToArray();
        list.Clear();
        list.AddRange(split);
    }

    /// <summary>
    /// Maps the documented configuration keys (design §4, §5.1, §6) onto <see cref="StorageOptions"/>:
    /// <c>Storage:Backend</c>, <c>Storage:Postgres:*</c>, <c>Mail:Database:Migrate</c>, <c>Sqlite:*</c>, <c>History:*</c>, <c>Content:*</c>,
    /// <c>Queue:MaxLifetime|MaxLifetimeDays</c>, <c>Retention:MetadataDays</c>, <c>Stats:*</c> and <c>Webhooks:OutboxRetentionDays|AttemptLogDays</c>.
    /// </summary>
    internal static StorageOptions BindStorage(IConfiguration c)
    {
        var d = new StorageOptions();
        var ret = d.Retention;
        var content = d.Content;
        return new StorageOptions
        {
            Backend = c.GetValue("Storage:Backend", d.Backend),
            History = new HistoryOptions
            {
                Mode = c.GetValue("History:Mode", d.History.Mode),
                RecentEvents = c.GetValue("History:RecentEvents", d.History.RecentEvents),
            },
            Queue = new QueueOptions { MaxLifetime = QueueMaxLifetime(c, d.Queue.MaxLifetime) },
            Content = new ContentOptions
            {
                Retain = !string.Equals(c["Content:Mode"], "None", StringComparison.OrdinalIgnoreCase),
                RetentionDays = c.GetValue("Content:RetentionDays", content.RetentionDays),
                StoreAttachments = c.GetValue("Content:StoreAttachments", content.StoreAttachments),
                AllowAttachmentStorage = c.GetValue("Content:AllowAttachmentStorage", content.AllowAttachmentStorage),
                MaxStoredBodyBytes = c.GetValue("Content:MaxStoredBodyBytes", content.MaxStoredBodyBytes),
                StoreSubject = c.GetValue("Content:StoreSubject", content.StoreSubject),
            },
            Retention = new RetentionOptions
            {
                MetadataDays = c.GetValue("Retention:MetadataDays", ret.MetadataDays),
                StatsHourlyDays = c.GetValue("Stats:HourlyRetentionDays", ret.StatsHourlyDays),
                StatsDailyDays = c.GetValue("Stats:DailyRetentionDays", ret.StatsDailyDays),
                RecipientDomainTopNHourly = c.GetValue("Stats:RecipientDomainTopNHourly", ret.RecipientDomainTopNHourly),
                RecipientDomainTopNDaily = c.GetValue("Stats:RecipientDomainTopNDaily", ret.RecipientDomainTopNDaily),
                MaxSeriesPerHour = c.GetValue("Stats:MaxSeriesPerHour", ret.MaxSeriesPerHour),
                WebhookOutboxDays = c.GetValue("Webhooks:OutboxRetentionDays", ret.WebhookOutboxDays),
                WebhookAttemptLogDays = c.GetValue("Webhooks:AttemptLogDays", ret.WebhookAttemptLogDays),
            },
            Sqlite = new SqliteOptions
            {
                DataDirectory = c.GetValue("Sqlite:DataDirectory", d.Sqlite.DataDirectory)!,
                SyncMode = c.GetValue("Sqlite:SyncMode", d.Sqlite.SyncMode),
                ConfigSyncMode = c.GetValue("Sqlite:ConfigSyncMode", d.Sqlite.ConfigSyncMode),
                QueuePersistence = c.GetValue("Sqlite:QueuePersistence", d.Sqlite.QueuePersistence),
                QuickCheck = c.GetValue("Sqlite:QuickCheck", d.Sqlite.QuickCheck),
                StatsFlushInterval = c.GetValue("Sqlite:StatsFlushInterval", d.Sqlite.StatsFlushInterval),
                RetentionDeleteBatchSize = c.GetValue("Sqlite:RetentionDeleteBatchSize", d.Sqlite.RetentionDeleteBatchSize),
                RetentionDeletePause = c.GetValue("Sqlite:RetentionDeletePause", d.Sqlite.RetentionDeletePause),
            },
            Postgres = new PostgresOptions
            {
                OwnerConnectionString = c["Storage:Postgres:OwnerConnectionString"],
                RuntimeConnectionString = c["Storage:Postgres:RuntimeConnectionString"],
                AutoMigrate = !string.Equals(c["Mail:Database:Migrate"], "Never", StringComparison.OrdinalIgnoreCase),
                MaxPoolSize = c.GetValue("Storage:Postgres:MaxPoolSize", d.Postgres.MaxPoolSize),
                PartitionsAheadDays = c.GetValue("Storage:Postgres:PartitionsAheadDays", d.Postgres.PartitionsAheadDays),
                StatsFlushInterval = c.GetValue("Storage:Postgres:StatsFlushInterval", d.Postgres.StatsFlushInterval),
                RetentionDeleteBatchSize = c.GetValue("Storage:Postgres:RetentionDeleteBatchSize", d.Postgres.RetentionDeleteBatchSize),
                RetentionDeletePause = c.GetValue("Storage:Postgres:RetentionDeletePause", d.Postgres.RetentionDeletePause),
                CommandTimeoutSeconds = c.GetValue("Storage:Postgres:CommandTimeoutSeconds", d.Postgres.CommandTimeoutSeconds),
            },
        };
    }

    /// <summary>
    /// How long a delivery may stay queued. <c>Queue:MaxLifetime</c> is a time span (<c>2.00:00:00</c>); <c>Queue:MaxLifetimeDays</c> is whole days, the form the
    /// settings API stores (docs/api.md). When a deployment layer sets both, <c>Queue:MaxLifetime</c> wins.
    /// </summary>
    internal static TimeSpan QueueMaxLifetime(IConfiguration c, TimeSpan fallback)
    {
        if (c["Queue:MaxLifetime"] is { Length: > 0 })
        {
            return c.GetValue("Queue:MaxLifetime", fallback);
        }

        return c["Queue:MaxLifetimeDays"] is { Length: > 0 } ? TimeSpan.FromDays(c.GetValue<int>("Queue:MaxLifetimeDays")) : fallback;
    }

    private static T Bind<T>(IConfiguration c, string section) where T : new()
    {
        var t = new T();
        c.GetSection(section).Bind(t);
        return t;
    }

    private static ListenerSection Clone(ListenerSection l) => new()
    {
        Port = l.Port, BindAddress = l.BindAddress, Mode = l.Mode, Role = l.Role, AuthRequired = l.AuthRequired, Enabled = l.Enabled, AllowInsecureAuth = l.AllowInsecureAuth,
    };

    /// <summary>Validates ranges and conventions (retention <c>0</c> = unlimited except content, decisions 28 and O).</summary>
    public static void Validate(MtaConfig c, List<string> errors)
    {
        var r = c.Storage.Retention;
        foreach (var (name, value) in new[]
        {
            ("Retention:MetadataDays", r.MetadataDays), ("Stats:HourlyRetentionDays", r.StatsHourlyDays), ("Stats:DailyRetentionDays", r.StatsDailyDays),
            ("Webhooks:OutboxRetentionDays", r.WebhookOutboxDays), ("Webhooks:AttemptLogDays", r.WebhookAttemptLogDays),
        })
        {
            if (value < 0)
            {
                errors.Add($"{name} must be 0 (keep forever) or a positive number of days, not {value}.");
            }
        }

        if (c.Storage.Content.RetentionDays is < 6 or > 30)
        {
            errors.Add($"Content:RetentionDays must be between 6 and 30 (no unlimited value), not {c.Storage.Content.RetentionDays}.");
        }

        if (c.Storage.Content.MaxStoredBodyBytes < 1024)
        {
            errors.Add("Content:MaxStoredBodyBytes must be at least 1024.");
        }

        if (c.Storage.Queue.MaxLifetime <= TimeSpan.Zero)
        {
            errors.Add("Queue:MaxLifetime must be positive.");
        }

        if (c.Storage.Queue.MaxLifetime >= TimeSpan.FromDays(c.Storage.Content.RetentionDays) && c.Storage.History.Mode == HistoryMode.Full)
        {
            errors.Add($"Queue:MaxLifetime ({c.Storage.Queue.MaxLifetime}) must be shorter than Content:RetentionDays so content outlives the queue.");
        }

        if (c.Storage.Backend == StorageBackend.Postgres && string.IsNullOrWhiteSpace(c.Storage.Postgres.RuntimeConnectionString))
        {
            errors.Add("Storage:Postgres:RuntimeConnectionString is required when Storage:Backend=Postgres.");
        }

        var obs = c.Observability;
        if (!string.IsNullOrWhiteSpace(obs.OtlpEndpoint) && !(Uri.TryCreate(obs.OtlpEndpoint, UriKind.Absolute, out Uri? otlp) && (otlp.Scheme == Uri.UriSchemeHttp || otlp.Scheme == Uri.UriSchemeHttps)))
        {
            errors.Add($"Observability:OtlpEndpoint must be an http or https URL (for example http://collector:4317), not '{obs.OtlpEndpoint}'.");
        }

        if (!obs.OtlpProtocol.Equals("Grpc", StringComparison.OrdinalIgnoreCase) && !obs.OtlpProtocol.Equals("HttpProtobuf", StringComparison.OrdinalIgnoreCase))
        {
            errors.Add($"Observability:OtlpProtocol must be Grpc or HttpProtobuf, not '{obs.OtlpProtocol}'.");
        }

        if (double.IsNaN(obs.TraceSampleRatio) || obs.TraceSampleRatio is < 0 or > 1)
        {
            errors.Add("Observability:TraceSampleRatio must be between 0 and 1.");
        }

        if (obs.QueueSampleSeconds is < 0 or > 3600)
        {
            errors.Add("Observability:QueueSampleSeconds must be between 0 (gauges off) and 3600.");
        }

        if (c.Smtp.MaxRecipients is < 1 or > 1000)
        {
            errors.Add("Smtp:MaxRecipients must be between 1 and 1000.");
        }

        if (c.Smtp.MaxMessageSize < 1024)
        {
            errors.Add("Smtp:MaxMessageSize must be at least 1024.");
        }

        var ports = new Dictionary<int, string>();
        foreach (var (name, l) in c.Smtp.Listeners.Where(x => x.Value.Enabled))
        {
            if (l.Port is < 0 or > 65535)
            {
                errors.Add($"Smtp:Listeners:{name}:Port is out of range.");
            }
            else if (l.Port != 0 && !ports.TryAdd(l.Port, name))
            {
                errors.Add($"Listeners '{ports[l.Port]}' and '{name}' use the same port {l.Port}.");
            }

            if (!System.Net.IPAddress.TryParse(l.BindAddress, out _))
            {
                errors.Add($"Smtp:Listeners:{name}:BindAddress is not an IP address.");
            }

            if (l.Mode == Mta.Smtp.Server.ListenerMode.Plain && l.AuthRequired && !l.AllowInsecureAuth && l.Role == Mta.Smtp.Server.ListenerRole.Submission)
            {
                errors.Add($"Listener '{name}' is plain text with AuthRequired and no AllowInsecureAuth, so nobody could ever authenticate.");
            }
        }

        if (c.Delivery.Workers < 1)
        {
            errors.Add("Delivery:Workers must be at least 1.");
        }

        if (c.Switch.QuiesceTimeoutSeconds < 1)
        {
            errors.Add("Switch:QuiesceTimeoutSeconds must be at least 1.");
        }

        ValidateStorageTuning(c.Storage, errors);
        ValidateTlsAndAcme(c, errors);
        ValidateApi(c.Api, errors);
    }

    private static void ValidateStorageTuning(StorageOptions s, List<string> errors)
    {
        var pg = s.Postgres;
        Require(pg.MaxPoolSize >= 1, "Storage:Postgres:MaxPoolSize must be at least 1.", errors);
        Require(pg.PartitionsAheadDays >= 0, "Storage:Postgres:PartitionsAheadDays must be 0 or more.", errors);
        Require(pg.StatsFlushInterval >= TimeSpan.Zero, "Storage:Postgres:StatsFlushInterval must not be negative.", errors);
        Require(pg.RetentionDeleteBatchSize >= 1, "Storage:Postgres:RetentionDeleteBatchSize must be at least 1.", errors);
        Require(pg.RetentionDeletePause >= TimeSpan.Zero, "Storage:Postgres:RetentionDeletePause must not be negative.", errors);
        Require(pg.CommandTimeoutSeconds >= 1, "Storage:Postgres:CommandTimeoutSeconds must be at least 1.", errors);
        Require(s.Sqlite.RetentionDeleteBatchSize >= 1, "Sqlite:RetentionDeleteBatchSize must be at least 1.", errors);
        Require(s.Sqlite.StatsFlushInterval >= TimeSpan.Zero, "Sqlite:StatsFlushInterval must not be negative.", errors);
        Require(s.Sqlite.RetentionDeletePause >= TimeSpan.Zero, "Sqlite:RetentionDeletePause must not be negative.", errors);
    }

    private static void ValidateTlsAndAcme(MtaConfig c, List<string> errors)
    {
        TlsSection tls = c.Tls;
        Require(string.IsNullOrEmpty(tls.KeyPath) || !string.IsNullOrEmpty(tls.CertificatePath), "Tls:KeyPath is set without Tls:CertificatePath.", errors);
        Require(string.IsNullOrEmpty(tls.PfxPasswordFile) || !string.IsNullOrEmpty(tls.CertificatePath), "Tls:PfxPasswordFile is set without Tls:CertificatePath.", errors);
        Require(tls.PollInterval > TimeSpan.Zero, "Tls:PollInterval must be positive.", errors);

        AcmeSection acme = c.Acme;
        if (!acme.Enabled)
        {
            return;
        }

        Require(Uri.TryCreate(acme.DirectoryUrl, UriKind.Absolute, out Uri? directory) && directory.Scheme is "https" or "http", "Acme:DirectoryUrl must be an absolute http(s) URL.", errors);
        Require(string.Equals(acme.DnsProvider, "Cloudflare", StringComparison.OrdinalIgnoreCase), $"Acme:DnsProvider '{acme.DnsProvider}' is not supported (only Cloudflare).", errors);
        Require(!string.IsNullOrWhiteSpace(acme.CloudflareApiToken) || !string.IsNullOrWhiteSpace(acme.CloudflareApiTokenFile), "Acme:CloudflareApiToken or Acme:CloudflareApiTokenFile is required when Acme:Enabled is true.", errors);
        Require(!string.IsNullOrWhiteSpace(acme.CertificateName), "Acme:CertificateName must not be empty.", errors);
        Require(acme.RenewAtRemainingFraction is > 0 and < 1, "Acme:RenewAtRemainingFraction must be between 0 and 1 (exclusive).", errors);
        Require(acme.CheckInterval > TimeSpan.Zero, "Acme:CheckInterval must be positive.", errors);
        Require(acme.PropagationDelay >= TimeSpan.Zero, "Acme:PropagationDelay must not be negative.", errors);
    }

    private static void ValidateApi(ApiSection api, List<string> errors)
    {
        foreach (var (name, value) in new[]
        {
            ("Api:MaxBodyBytes", api.MaxBodyBytes), ("Api:MaxSendBodyBytes", api.MaxSendBodyBytes), ("Api:MaxInFlightSendBytes", api.MaxInFlightSendBytes),
            ("Api:MaxAttachments", (long)api.MaxAttachments), ("Api:MaxCustomHeaders", api.MaxCustomHeaders), ("Api:MaxTags", api.MaxTags),
            ("Api:MaxDomainsPerTenant", api.MaxDomainsPerTenant), ("Api:MaxApiKeysPerTenant", api.MaxApiKeysPerTenant),
            ("Api:MaxSmtpCredentialsPerTenant", api.MaxSmtpCredentialsPerTenant), ("Api:MaxWebhooksPerTenant", api.MaxWebhooksPerTenant), ("Api:MaxStatsRows", api.MaxStatsRows),
        })
        {
            Require(value >= 1, $"{name} must be at least 1.", errors);
        }

        Require(api.SessionLifetime > TimeSpan.Zero, "Api:SessionLifetime must be positive.", errors);
        Require(api.SessionIdleTimeout > TimeSpan.Zero, "Api:SessionIdleTimeout must be positive.", errors);
        foreach (string network in api.MetricsAllowedNetworks)
        {
            try
            {
                Mta.Webhooks.IpNetwork.Parse(network);
            }
            catch (Exception ex) when (ex is FormatException or ArgumentException or OverflowException)
            {
                errors.Add($"Api:MetricsAllowedNetworks entry '{network}' is not a network in CIDR form (for example 10.0.0.0/8).");
            }
        }
    }

    private static void Require(bool condition, string error, List<string> errors)
    {
        if (!condition)
        {
            errors.Add(error);
        }
    }
}
