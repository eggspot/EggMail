using System.Net;
using Microsoft.Extensions.Configuration;
using Mta.Host.Tls;
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
    /// (storage pointer written by the backend switch), the simple <c>EGGMAIL_*</c> variables (<see cref="EnvironmentAliases"/>; read through <paramref name="environment"/>,
    /// the process environment by default), the long-form environment variables, then the command line (highest precedence).
    /// <paramref name="storedSettings"/> (the global settings kept in the config store) form the lowest layer, above the built-in defaults.
    /// </summary>
    public static IConfigurationRoot Build(string[] args, string? dataDirectoryHint = null, string? appSettingsPath = null, IEnumerable<KeyValuePair<string, string?>>? storedSettings = null, string? bootstrapFileOverride = null, Func<string, string?>? environment = null)
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

        // The simple names are aliases: they sit below the long-form environment variables and the command line, so a key set the long way always wins.
        // The one exception is Hostname: configuration keys are case-insensitive, so the HOSTNAME variable that Docker and Kubernetes set in every container
        // (the container id or pod name) IS the key "Hostname" and would silently outrank EGGMAIL_HOSTNAME. The host name alias therefore sits just above the
        // environment (and still below the command line).
        EnvironmentAliasResult aliases = EnvironmentAliases.Translate(environment ?? Environment.GetEnvironmentVariable);
        builder.Add(new EnvironmentAliasesSource(new EnvironmentAliasResult(aliases.Values.Where(v => v.Key != "Hostname").ToList(), aliases.Errors)));
        builder.AddEnvironmentVariables();
        builder.Add(new EnvironmentAliasesSource(new EnvironmentAliasResult(aliases.Values.Where(v => v.Key == "Hostname").ToList(), [])));
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

        if (configuration is IConfigurationRoot root)
        {
            errors.AddRange(root.Providers.OfType<EnvironmentAliasesProvider>().SelectMany(p => p.Errors));

            // EGGMAIL_ACME_STAGING / EGGMAIL_ACME_DIRECTORY only choose the CA. They are an error only when nothing, by whatever layer, turns ACME on:
            // Acme__Enabled=true in the environment or a mounted file is as good as EGGMAIL_ACME_EMAIL.
            if (!cfg.Acme.Enabled && root.Providers.OfType<EnvironmentAliasesProvider>().Any(p => p.TryGet("Acme:Directory", out _)))
            {
                errors.Add("EGGMAIL_ACME_STAGING / EGGMAIL_ACME_DIRECTORY only choose the CA; ACME stays off until both EGGMAIL_HOSTNAME and EGGMAIL_ACME_EMAIL are set (or Acme:Enabled is true). Set them, or remove the CA variable.");
            }
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
        var domains = Bind<DomainsSection>(configuration, "Domains");
        ApplyList(configuration, "Domains:Bootstrap", domains.Bootstrap);
        ApplyList(configuration, "Domains:MtaStsMx", domains.MtaStsMx);
        ApplyList(configuration, "Acme:Domains", acme.Domains);
        if (acme.Enabled && acme.Domains.Count == 0)
        {
            acme.Domains.Add(configuration["Hostname"] ?? config.Hostname);   // "set just the host name and an email": the certificate is for the server's own name
        }

        ApplyList(configuration, "Api:MetricsAllowedNetworks", api.MetricsAllowedNetworks);
        var inbound = Bind<InboundSection>(configuration, "Inbound");
        ApplyList(configuration, "Inbound:Arc:TrustedSealers", inbound.Arc.TrustedSealers);
        ApplyList(configuration, "Inbound:Dnsbl:Zones", inbound.Dnsbl.Zones);

        return new MtaConfig
        {
            Hostname = configuration["Hostname"] ?? config.Hostname,
            Startup = Bind<StartupSection>(configuration, "Startup"),
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
            Inbound = inbound,
            Domains = domains,
        };
    }

    /// <summary>
    /// A list setting is owned by the highest layer that mentions it: configuration layers merge lists by index (<c>:0</c>, <c>:1</c>), which would leave the
    /// stale entries of a lower layer behind a shorter list from a higher one (<c>appsettings.json</c> with two domains, <c>EGGMAIL_HOSTNAME</c> with one: two
    /// domains, one of them stale). The list is the one entry set of the highest layer that has any, indexed or as one separated value.
    /// </summary>
    internal static void ApplyList(IConfiguration configuration, string key, List<string> list)
    {
        if (configuration is IConfigurationRoot root)
        {
            foreach (IConfigurationProvider provider in root.Providers.Reverse())
            {
                var indexes = provider.GetChildKeys([], key).Where(k => int.TryParse(k, out _)).Select(int.Parse).Order().ToList();
                bool scalar = provider.TryGet(key, out string? value) && !string.IsNullOrWhiteSpace(value);
                if (indexes.Count == 0 && !scalar)
                {
                    continue;
                }

                list.Clear();
                if (scalar)
                {
                    list.Add(value!);
                }

                foreach (int index in indexes)
                {
                    if (provider.TryGet($"{key}:{index}", out string? entry) && !string.IsNullOrWhiteSpace(entry))
                    {
                        list.Add(entry);
                    }
                }

                SplitEntries(list, null);
                return;
            }
        }

        SplitEntries(list, configuration[key]);
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
            Inbound = new InboundStorageOptions { RetentionDays = c.GetValue("Inbound:RetentionDays", d.Inbound.RetentionDays), MaxRetentionDays = c.GetValue("Inbound:MaxRetentionDays", d.Inbound.MaxRetentionDays) },
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
                ReadOnlyConnectionString = c["Storage:Postgres:ReadOnlyConnectionString"],
                ReadOnlyStatementTimeoutSeconds = c.GetValue("Storage:Postgres:ReadOnlyStatementTimeoutSeconds", d.Postgres.ReadOnlyStatementTimeoutSeconds),
                ReadOnlyIdleInTransactionTimeoutSeconds = c.GetValue("Storage:Postgres:ReadOnlyIdleInTransactionTimeoutSeconds", d.Postgres.ReadOnlyIdleInTransactionTimeoutSeconds),
                ReadOnlyMaxPoolSize = c.GetValue("Storage:Postgres:ReadOnlyMaxPoolSize", d.Postgres.ReadOnlyMaxPoolSize),
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
            ("Webhooks:OutboxRetentionDays", r.WebhookOutboxDays), ("Webhooks:AttemptLogDays", r.WebhookAttemptLogDays), ("Inbound:RetentionDays", c.Storage.Inbound.RetentionDays), ("Inbound:MaxRetentionDays", c.Storage.Inbound.MaxRetentionDays),
        })
        {
            if (value < 0)
            {
                errors.Add($"{name} must be 0 (keep forever) or a positive number of days, not {value}.");
            }
        }

        if (c.Storage.Inbound.MaxRetentionDays > 0 && (c.Storage.Inbound.RetentionDays == 0 || c.Storage.Inbound.RetentionDays > c.Storage.Inbound.MaxRetentionDays))
        {
            errors.Add("Inbound:RetentionDays must be between 1 and Inbound:MaxRetentionDays when that ceiling is set.");
        }

        if (c.Inbound.MaxMessagesPerMinute < 1 || c.Inbound.MaxMessagesPerMinutePerRemote < 1 || c.Inbound.MaxStoredBytesPerDomain < 0 || c.Inbound.MaxStoredBytesPerTenant < 0 || c.Inbound.MaxMessageSize is < 1024)
        {
            errors.Add("Inbound:MaxMessagesPerMinute and MaxMessagesPerMinutePerRemote must be at least 1, MaxMessageSize at least 1024, and the stored-bytes limits not negative (0 is unlimited).");
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

        if (!string.IsNullOrWhiteSpace(c.Storage.Postgres.ReadOnlyConnectionString))
        {
            try
            {
                if (string.IsNullOrWhiteSpace(new Npgsql.NpgsqlConnectionStringBuilder(c.Storage.Postgres.ReadOnlyConnectionString).Username))
                {
                    errors.Add("Storage:Postgres:ReadOnlyConnectionString must name the role to connect as (Username=...).");
                }
            }
            catch (ArgumentException)
            {
                errors.Add("Storage:Postgres:ReadOnlyConnectionString is not a valid connection string.");
            }
        }

        foreach (var (name, value) in new[]
        {
            ("Storage:Postgres:ReadOnlyStatementTimeoutSeconds", c.Storage.Postgres.ReadOnlyStatementTimeoutSeconds),
            ("Storage:Postgres:ReadOnlyIdleInTransactionTimeoutSeconds", c.Storage.Postgres.ReadOnlyIdleInTransactionTimeoutSeconds),
            ("Storage:Postgres:ReadOnlyMaxPoolSize", c.Storage.Postgres.ReadOnlyMaxPoolSize),
        })
        {
            if (value < 1)
            {
                errors.Add($"{name} must be at least 1.");
            }
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

        if (!string.IsNullOrWhiteSpace(c.Delivery.PublicSendingIp) && !System.Net.IPAddress.TryParse(c.Delivery.PublicSendingIp, out _))
        {
            errors.Add("Delivery:PublicSendingIp is not an IP address.");
        }

        Secrets.SecretsConfigurationCheck.Validate(c.Secrets, errors);

        if (c.Delivery.Workers < 1)
        {
            errors.Add("Delivery:Workers must be at least 1.");
        }

        if (c.Delivery.MaxIdleConnectionsPerTarget is < 0 or > 256)
        {
            errors.Add("Delivery:MaxIdleConnectionsPerTarget must be between 0 and 256.");
        }

        if (c.Switch.QuiesceTimeoutSeconds < 1)
        {
            errors.Add("Switch:QuiesceTimeoutSeconds must be at least 1.");
        }

        ValidateStorageTuning(c.Storage, errors);
        ValidateRelay(c, errors);
        ValidateTlsAndAcme(c, errors);
        ValidateApi(c.Api, errors);
        ValidateDomains(c, errors);
        ValidateInbound(c, errors);
    }

    private static void ValidateInboundSizing(MtaConfig c, List<string> errors)
    {
        InboundSection i = c.Inbound;
        if (c.Smtp.MaxInFlightBytes < 2)
        {
            errors.Add("Smtp:MaxInFlightBytes must be at least 2 when Inbound:Enabled (the port-25 listener may use half of it).");
            return;
        }

        double largest = i.MaxMessageSize ?? c.Smtp.MaxMessageSize;
        double need = Mta.Host.Ingest.InboundReceiveOptions.SizingFactor * largest;
        long usable = Math.Min(i.MaxInFlightBytes, c.Smtp.MaxInFlightBytes / 2);
        string factor = Mta.Host.Ingest.InboundReceiveOptions.SizingFactor.ToString(System.Globalization.CultureInfo.InvariantCulture);
        if (usable < need)
        {
            errors.Add(FormattableString.Invariant($"Inbound:MaxInFlightBytes (at most half of Smtp:MaxInFlightBytes is used: {usable}) must be at least {factor} times the largest inbound message ({(long)need} bytes for {(long)largest}): raise it and Smtp:MaxInFlightBytes, or lower Inbound:MaxMessageSize."));
        }

        if (i.MaxInFlightBytesPerRemote > 0 && i.MaxInFlightBytesPerRemote < need)
        {
            errors.Add(FormattableString.Invariant($"Inbound:MaxInFlightBytesPerRemote must be at least {factor} times the largest inbound message ({(long)need} bytes), or 0 to derive it."));
        }
    }

    /// <summary>The inbound limits (design section 11.13): checked even while <c>Inbound:Enabled</c> is off, so switching it on later does not start a server with a contradictory configuration.</summary>
    private static void ValidateInbound(MtaConfig c, List<string> errors)
    {
        InboundSection i = c.Inbound;
        if ((i.MaxMessageSize ?? c.Smtp.MaxMessageSize) > i.MaxTransactionBytes)
        {
            errors.Add("Inbound:MaxTransactionBytes must be at least the largest inbound message (Inbound:MaxMessageSize, else Smtp:MaxMessageSize): otherwise a single message could never be accepted.");
        }

        if (i.MaxConnections < 1 || i.MaxInFlightBytes < 1 || i.MaxInFlightBytesPerRemote < 0 || i.MaxSessionDuration < TimeSpan.FromSeconds(1))
        {
            errors.Add("Inbound:MaxConnections and Inbound:MaxInFlightBytes must be at least 1, Inbound:MaxInFlightBytesPerRemote not negative (0 derives it) and Inbound:MaxSessionDuration at least one second.");
        }

        // The sizing rule: a message of the largest size takes about 4 times its size from the in-flight budget while it is handled (the buffer, the copy the checks read, one or two stamped copies). A share
        // smaller than that makes the largest messages impossible to accept, with a 452 that looks temporary and never ends.
        // Only for a server that receives mail: with inbound off these values are not used, and a server that never receives must not fail to start for them.
        if (i.Enabled)
        {
            ValidateInboundSizing(c, errors);
        }

        if (i.MaxMessageSize is < 1024)
        {
            errors.Add("Inbound:MaxMessageSize must be at least 1024.");
        }

        if (i.MaxRecipients is < 1 or > 1000)
        {
            errors.Add("Inbound:MaxRecipients must be between 1 and 1000.");
        }

        if (i.MaxTransactionBytes < 1024)
        {
            errors.Add("Inbound:MaxTransactionBytes must be at least 1024.");
        }

        if (i.MaxMessagesPerMinute < 1 || i.MaxMessagesPerMinutePerRemote < 1)
        {
            errors.Add("Inbound:MaxMessagesPerMinute and Inbound:MaxMessagesPerMinutePerRemote must be at least 1.");
        }

        if (i.MaxStoredBytesPerDomain < 0 || i.MaxStoredBytesPerTenant < 0)
        {
            errors.Add("Inbound:MaxStoredBytesPerDomain and Inbound:MaxStoredBytesPerTenant must not be negative (0 is unlimited).");
        }

        if (i.Verification.Timeout <= TimeSpan.Zero || i.Verification.Timeout > TimeSpan.FromMinutes(5))
        {
            errors.Add("Inbound:Verification:Timeout must be between 1 millisecond and 5 minutes.");
        }

        if (i.Verification.MaxConcurrency < 1 || i.Verification.MaxConcurrencyPerRemote < 1)
        {
            errors.Add("Inbound:Verification:MaxConcurrency and Inbound:Verification:MaxConcurrencyPerRemote must be at least 1.");
        }

        if (i.Srs.MaxAgeDays is < 1 or > 500)
        {
            errors.Add("Inbound:Srs:MaxAgeDays must be between 1 and 500.");
        }

        if (i.Dnsbl.Timeout <= TimeSpan.Zero || i.Dnsbl.Timeout > TimeSpan.FromSeconds(30))
        {
            errors.Add("Inbound:Dnsbl:Timeout must be between 1 millisecond and 30 seconds.");
        }

        if (i.Dnsbl.Zones.Count > Mta.Host.Ingest.DnsblChecker.MaxZones)
        {
            errors.Add($"Inbound:Dnsbl:Zones lists {i.Dnsbl.Zones.Count} zones; at most {Mta.Host.Ingest.DnsblChecker.MaxZones} (every one is a lookup per connection).");
        }

        foreach (string zone in i.Dnsbl.Zones.Concat(i.Arc.TrustedSealers))
        {
            if (!Mta.Host.Domains.DomainNames.TryNormalize(zone.Trim().TrimEnd('.'), out _))
            {
                errors.Add($"Inbound:Dnsbl:Zones and Inbound:Arc:TrustedSealers entries must be domain names; '{zone}' is not.");
            }
        }

        if (!string.IsNullOrWhiteSpace(i.AuthenticationResultsId) && i.AuthenticationResultsId.Any(ch => ch <= ' ' || ch >= 127 || ch is ';' or '(' or ')' or '"' or '\\'))
        {
            errors.Add("Inbound:AuthenticationResultsId must be a plain host or domain name.");
        }
    }

    /// <summary>One destination for the <c>rua</c> tag of a DMARC or TLS-RPT record: it must not be able to end the tag or add a second one.</summary>
    private static bool ValidReportDestination(string value, bool allowHttps)
    {
        string v = value.Trim();
        if (v.Length == 0 || v.Length > 200 || v.Any(ch => char.IsWhiteSpace(ch) || char.IsControl(ch) || ch is ';' or ',' or '"' or '\\'))
        {
            return false;
        }

        if (allowHttps && v.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return v.Length > "https://".Length;
        }

        string address = v.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase) ? v["mailto:".Length..] : v;
        int at = address.IndexOf('@', StringComparison.Ordinal);
        return at > 0 && at == address.LastIndexOf('@') && at < address.Length - 1;
    }

    private static void ValidateDomains(MtaConfig c, List<string> errors)
    {
        DomainsSection d = c.Domains;
        foreach (string name in d.Bootstrap)
        {
            if (!Mta.Host.Domains.DomainNames.TryNormalize(name, out _))
            {
                errors.Add($"Domains:Bootstrap entry '{name}' is not a valid domain name (such as mail.example.com).");
            }
        }

        if (d.DmarcPolicy is not ("none" or "quarantine" or "reject"))
        {
            errors.Add($"Domains:DmarcPolicy must be none, quarantine or reject, not '{d.DmarcPolicy}'.");
        }

        if (d.MtaStsMaxAge < TimeSpan.FromMinutes(1) || d.MtaStsMaxAge > TimeSpan.FromSeconds(31_557_600))
        {
            errors.Add("Domains:MtaStsMaxAge must be between 1 minute and 31557600 seconds (RFC 8461).");
        }

        foreach (string mx in d.MtaStsMx)
        {
            if (Mta.Host.Domains.DomainRecordOptions.NormalizeMtaStsMx(mx) is null)
            {
                errors.Add($"Domains:MtaStsMx entry '{mx}' is not a fully qualified host name without a trailing dot (a single leading '*.' is allowed).");
            }
        }

        if (d.DmarcReportAddress is { Length: > 0 } dmarc && !ValidReportDestination(dmarc, allowHttps: false))
        {
            errors.Add("Domains:DmarcReportAddress must be one e-mail address (it is written into the rua tag of a DNS record; no ';', ',' or white space). {domain} stands for the sending domain.");
        }

        if (d.TlsReportAddress is { Length: > 0 } tls && !ValidReportDestination(tls, allowHttps: true))
        {
            errors.Add("Domains:TlsReportAddress must be one e-mail address or one https:// URL (it is written into the rua tag of a DNS record; no ';', ',' or white space). {domain} stands for the sending domain.");
        }

        if (d.MtaStsMode != Mta.Host.Domains.MtaStsServingMode.Off && Mta.Host.Domains.DomainRecordOptions.UsableHostname(c.Hostname) is null)
        {
            errors.Add("Domains:MtaStsMode needs a fully qualified Hostname: mta-sts.<domain> has to point at it and it is the default mx: line of the policy.");
        }
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

    /// <summary>The relay from configuration: a combination that cannot work stops the start with a message that says what to set. (The first administrator's name and password are checked when the account is created, see <see cref="Mta.Host.Hosting.FirstAdministrator"/>.)</summary>
    private static void ValidateRelay(MtaConfig c, List<string> errors)
    {
        RelaySection relay = c.Delivery.Relay;
        if (string.IsNullOrWhiteSpace(relay.Address))
        {
            Require(string.IsNullOrWhiteSpace(relay.User) && string.IsNullOrEmpty(relay.Password) && string.IsNullOrWhiteSpace(relay.PasswordFile),
                "Delivery:Relay:User / Password / PasswordFile are set without Delivery:Relay:Address (host:port).", errors);
            return;
        }

        if (EnvironmentAliases.RelayProblem(relay.Address.Trim()) is { } relayProblem)
        {
            errors.Add("Delivery:Relay:Address: " + relayProblem);
        }

        Require(string.IsNullOrEmpty(relay.Password) || string.IsNullOrWhiteSpace(relay.PasswordFile), "Delivery:Relay:Password and Delivery:Relay:PasswordFile are both set. Set only one.", errors);
        bool hasPassword = !string.IsNullOrEmpty(relay.Password) || !string.IsNullOrWhiteSpace(relay.PasswordFile);
        Require(string.IsNullOrWhiteSpace(relay.User) == !hasPassword, "Delivery:Relay:User and a password (Delivery:Relay:Password or PasswordFile) go together: set both or neither.", errors);
        string[] modes = ["none", "starttls", "required", "verify", "implicit"];
        Require(string.IsNullOrWhiteSpace(relay.TlsMode) || modes.Contains(relay.TlsMode.Trim().ToLowerInvariant()), $"Delivery:Relay:TlsMode must be one of: {string.Join(", ", modes)}.", errors);
        Require(string.IsNullOrWhiteSpace(relay.User) || !string.Equals(relay.TlsMode?.Trim(), "none", StringComparison.OrdinalIgnoreCase),
            "Delivery:Relay:TlsMode none cannot be combined with a login: the password would travel in clear text.", errors);
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

        string? directoryUrl = acme.EffectiveDirectoryUrl();
        Require(directoryUrl is not null && Uri.TryCreate(directoryUrl, UriKind.Absolute, out Uri? directory) && directory.Scheme is "https" or "http",
            string.IsNullOrWhiteSpace(acme.Directory)
                ? "Acme:DirectoryUrl must be an absolute http(s) URL."
                : $"Acme:Directory '{acme.Directory}' must be LetsEncrypt, LetsEncryptStaging, ZeroSsl or the absolute http(s) URL of an ACME directory.", errors);
        if (directoryUrl is not null && Uri.TryCreate(directoryUrl, UriKind.Absolute, out Uri? parsed))
        {
            // The URL is logged and shown to operators: it must not carry a password (userinfo), a token (query) or a fragment.
            Require(parsed.UserInfo.Length == 0 && parsed.Query.Length == 0 && parsed.Fragment.Length == 0,
                "Acme:Directory / Acme:DirectoryUrl must not contain credentials (user:password@), a query string or a fragment.", errors);
        }

        Require(string.Equals(acme.DnsProvider, "Cloudflare", StringComparison.OrdinalIgnoreCase), $"Acme:DnsProvider '{acme.DnsProvider}' is not supported (only Cloudflare).", errors);
        Require(acme.Challenge != AcmeChallengeMode.Dns01 || acme.HasDnsCredentials(), "Acme:CloudflareApiToken or Acme:CloudflareApiTokenFile is required when Acme:Challenge is Dns01.", errors);
        Require(!string.IsNullOrWhiteSpace(acme.CertificateName), "Acme:CertificateName must not be empty.", errors);
        Require(acme.RenewAtRemainingFraction is > 0 and < 1, "Acme:RenewAtRemainingFraction must be between 0 and 1 (exclusive).", errors);
        Require(acme.CheckInterval > TimeSpan.Zero, "Acme:CheckInterval must be positive.", errors);
        Require(acme.PropagationDelay >= TimeSpan.Zero, "Acme:PropagationDelay must not be negative.", errors);
        Require(string.IsNullOrWhiteSpace(acme.EabKeyId) == (string.IsNullOrWhiteSpace(acme.EabHmacKey) && string.IsNullOrWhiteSpace(acme.EabHmacKeyFile)),
            "Acme:EabKeyId and Acme:EabHmacKey (or Acme:EabHmacKeyFile) must be set together (external account binding).", errors);

        foreach (string name in acme.Domains)
        {
            if (AcmeNames.TryNormalize(name, out string? error) is null)
            {
                errors.Add(acme.Domains.Count == 1 && string.Equals(name, c.Hostname, StringComparison.OrdinalIgnoreCase)
                    ? $"Acme is enabled without Acme:Domains, so the certificate is for the Hostname, and '{c.Hostname}' is not a public host name: set Hostname to the name of this server, for example mail.example.com."
                    : "Acme:Domains: " + error);
            }
        }

        bool wildcards = acme.Domains.Any(AcmeNames.IsWildcard);
        if (wildcards && !acme.UsesDns01())
        {
            errors.Add("Acme:Domains has a wildcard name, which only DNS-01 can prove: set Acme:CloudflareApiToken (or Acme:CloudflareApiTokenFile) and, if Acme:Challenge is Http01, set it to Auto or Dns01.");
        }

        if (acme.UsesHttp01())
        {
            Require(acme.Http01ListenPort is >= 1 and <= 65535, "Acme:Http01ListenPort must be between 1 and 65535.", errors);
            Require(IPAddress.TryParse(acme.Http01BindAddress, out _), "Acme:Http01BindAddress must be an IP address (:: for all).", errors);
            Require(acme.Http01ListenPort != c.Dashboard.HttpPort && (!c.Dashboard.HttpsEnabled || acme.Http01ListenPort != c.Dashboard.HttpsPort),
                $"Acme:Http01ListenPort {acme.Http01ListenPort} is the port of the dashboard (Dashboard:HttpPort / Dashboard:HttpsPort); the challenge listener needs a port of its own (it answers nothing but /.well-known/acme-challenge/).", errors);
            Require(!c.Smtp.Listeners.Values.Any(l => l.Enabled && l.Port == acme.Http01ListenPort), $"Acme:Http01ListenPort {acme.Http01ListenPort} is also the port of an SMTP listener.", errors);
        }
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
