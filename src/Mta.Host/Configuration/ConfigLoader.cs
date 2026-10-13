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

    /// <summary>
    /// Where the bootstrap file lives: in the data directory (the hint, else the <c>Sqlite__DataDirectory</c> environment variable,
    /// else <c>/data</c>). It has to be findable before the storage is known, which is why it cannot depend on <c>Storage:*</c>.
    /// </summary>
    public static string ResolveBootstrapPath(string? dataDirectoryHint = null) =>
        Path.Combine(dataDirectoryHint ?? Environment.GetEnvironmentVariable("Sqlite__DataDirectory") ?? "/data", BootstrapFileName);

    /// <summary>
    /// Builds the layered configuration for the process: appsettings (if present), the bootstrap file in the data directory
    /// (storage pointer written by the backend switch), environment variables, then the command line (highest precedence).
    /// <paramref name="storedSettings"/> (the global settings kept in the config store) form the lowest layer, above the built-in defaults.
    /// </summary>
    public static IConfigurationRoot Build(string[] args, string? dataDirectoryHint = null, string? appSettingsPath = null, IEnumerable<KeyValuePair<string, string?>>? storedSettings = null, string? bootstrapFileOverride = null)
    {
        var builder = new ConfigurationBuilder();
        if (storedSettings is not null)
        {
            builder.AddInMemoryCollection(storedSettings);   // layer 4 of decision N: settings persisted in the config store, below every deployment layer
        }

        if (appSettingsPath is not null && File.Exists(appSettingsPath))
        {
            builder.AddJsonFile(appSettingsPath, optional: true, reloadOnChange: false);
        }

        // The override lets the migrate-storage command read the pointer as it was before an activation rewrote the file ("" = no bootstrap file).
        string bootstrap = bootstrapFileOverride ?? ResolveBootstrapPath(dataDirectoryHint);
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
        var config = new MtaConfig();
        var errors = new List<string>();

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

        var storage = BindStorage(configuration);

        var cfg = new MtaConfig
        {
            Hostname = configuration["Hostname"] ?? config.Hostname,
            Smtp = new SmtpSection
            {
                MaxMessageSize = smtp.MaxMessageSize, MaxRecipients = smtp.MaxRecipients, MaxConnections = smtp.MaxConnections,
                MaxConnectionsPerIp = smtp.MaxConnectionsPerIp, MaxInFlightBytes = smtp.MaxInFlightBytes, Chunking = smtp.Chunking,
                SmtpUtf8 = smtp.SmtpUtf8, Listeners = listeners,
            },
            Storage = storage,
            Dns = Bind<DnsSection>(configuration, "Dns"),
            Backup = Bind<BackupSection>(configuration, "Backup"),
            Sending = Bind<SendingSection>(configuration, "Sending"),
            Delivery = Bind<DeliverySection>(configuration, "Delivery"),
            Webhooks = Bind<Mta.Webhooks.WebhookOptions>(configuration, "Webhooks"),
            Dashboard = Bind<DashboardSection>(configuration, "Dashboard"),
            Secrets = Bind<SecretsSection>(configuration, "Secrets"),
            Observability = Bind<ObservabilitySection>(configuration, "Observability"),
            Switch = Bind<SwitchSection>(configuration, "Switch"),
        };

        Validate(cfg, errors);
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

    /// <summary>
    /// Maps the documented configuration keys (design §4, §5.1, §6) onto <see cref="StorageOptions"/>:
    /// <c>Storage:Backend</c>, <c>Storage:Postgres:*</c>, <c>Mail:Database:Migrate</c>, <c>Sqlite:*</c>, <c>History:*</c>, <c>Content:*</c>,
    /// <c>Queue:MaxLifetime</c>, <c>Retention:MetadataDays</c>, <c>Stats:*</c> and <c>Webhooks:OutboxRetentionDays|AttemptLogDays</c>.
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
            Queue = new QueueOptions { MaxLifetime = c.GetValue("Queue:MaxLifetime", d.Queue.MaxLifetime) },
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
            },
            Postgres = new PostgresOptions
            {
                OwnerConnectionString = c["Storage:Postgres:OwnerConnectionString"],
                RuntimeConnectionString = c["Storage:Postgres:RuntimeConnectionString"],
                AutoMigrate = !string.Equals(c["Mail:Database:Migrate"], "Never", StringComparison.OrdinalIgnoreCase),
                MaxPoolSize = c.GetValue("Storage:Postgres:MaxPoolSize", d.Postgres.MaxPoolSize),
            },
        };
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
    }
}
