using System.Net.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Mta.Core;
using Mta.Host.Configuration;
using Mta.Host.Hosting;
using Mta.Host.Switching;
using Mta.Host.Tls;
using Mta.Observability;
using Mta.Storage;

namespace Mta.Host;

/// <summary>The <c>mta</c> command line: <c>serve</c> (default), <c>--healthcheck</c>, <c>migrate-db</c>, <c>migrate-storage</c>, <c>--version</c>.</summary>
internal static class Cli
{
    public static async Task<int> RunAsync(string[] args)
    {
        string command = args.FirstOrDefault(a => !a.StartsWith("--", StringComparison.Ordinal) || a is "--healthcheck" or "--version") ?? "serve";
        string[] rest = args.Where(a => a != command).ToArray();
        switch (command)
        {
            case "--version":
                Console.WriteLine(typeof(Cli).Assembly.GetName().Version?.ToString(3) ?? "0.0.0");
                return 0;
            case "--healthcheck":
                return await HealthCheckAsync(rest).ConfigureAwait(false);
            case "migrate-db":
                return await MigrateDbAsync(rest).ConfigureAwait(false);
            case "migrate-storage":
                return await MigrateStorageCommand.RunAsync(rest, Console.Out, Console.Error).ConfigureAwait(false);
            case "admin":
                return await AdminCommand.RunAsync(rest, Console.Out, Console.Error).ConfigureAwait(false);
            case "serve":
                return await ServeAsync(rest).ConfigureAwait(false);
            default:
                Console.Error.WriteLine($"Unknown command '{command}'. Commands: serve (default), migrate-db, migrate-storage, admin, --healthcheck, --version.");
                return 64;
        }
    }

    private static LoadedConfig? Load(string[] args)
    {
        var loaded = ConfigLoader.Load(ConfigLoader.Build(args));
        if (loaded.IsValid)
        {
            return loaded;
        }

        foreach (string error in loaded.Errors)
        {
            Console.Error.WriteLine("configuration error: " + error);
        }

        return null;
    }

    /// <summary>Liveness probe for container health checks: succeeds when the local HTTP endpoint answers /healthz.</summary>
    private static async Task<int> HealthCheckAsync(string[] args)
    {
        var loaded = ConfigLoader.Load(ConfigLoader.Build(args));
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(4) };
        try
        {
            using var response = await http.GetAsync($"http://127.0.0.1:{loaded.Config.Dashboard.HttpPort}/healthz").ConfigureAwait(false);
            return response.IsSuccessStatusCode ? 0 : 1;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return 1;
        }
    }

    /// <summary>Creates or upgrades the schema of the configured backend and exits.</summary>
    private static async Task<int> MigrateDbAsync(string[] args)
    {
        if (Load(args) is not { } loaded)
        {
            return 2;
        }

        using var factory = LoggerFactory.Create(b => b.AddJsonConsole());
        var log = new MtaLogAdapter(factory);
        StorageOptions options = loaded.Config.Storage;
        if (options.Backend == StorageBackend.Postgres && !options.Postgres.AutoMigrate)
        {
            // Mail:Database:Migrate=Never means the serving process does not migrate; this command is the one that does.
            options = new StorageOptions
            {
                Backend = options.Backend,
                History = options.History,
                Retention = options.Retention,
                Sqlite = options.Sqlite,
                Content = options.Content,
                Queue = options.Queue,
                Postgres = new PostgresOptions
                {
                    OwnerConnectionString = options.Postgres.OwnerConnectionString,
                    RuntimeConnectionString = options.Postgres.RuntimeConnectionString,
                    AutoMigrate = true,
                    MaxPoolSize = options.Postgres.MaxPoolSize,
                    PartitionsAheadDays = options.Postgres.PartitionsAheadDays,
                    StatsFlushInterval = options.Postgres.StatsFlushInterval,
                    RetentionDeleteBatchSize = options.Postgres.RetentionDeleteBatchSize,
                    RetentionDeletePause = options.Postgres.RetentionDeletePause,
                    CommandTimeoutSeconds = options.Postgres.CommandTimeoutSeconds,
                },
            };
        }

        await using var storage = StorageFactory.Create(options, SystemClock.Instance, log);
        await storage.InitializeAsync(CancellationToken.None).ConfigureAwait(false);
        Console.WriteLine($"storage ready: backend {storage.Backend}, history {storage.HistoryMode}");
        return 0;
    }

    private static ObservabilityOptions ObservabilityOptionsFrom(ObservabilitySection section) => new()
    {
        OtlpEndpoint = section.OtlpEndpoint,
        PrometheusEnabled = section.MetricsEndpointEnabled,
        OtlpTransport = Enum.Parse<OtlpTransport>(section.OtlpProtocol, ignoreCase: true),
        TraceSampleRatio = section.TraceSampleRatio,
        ServiceVersion = typeof(Cli).Assembly.GetName().Version?.ToString(3) ?? "0.0.0",
    };

    private static async Task<int> ServeAsync(string[] args)
    {
        if (Load(args) is not { } loaded)
        {
            return 2;
        }

        var observability = ObservabilityOptionsFrom(loaded.Config.Observability);
        var builder = WebApplication.CreateBuilder(args);
        builder.Logging.ClearProviders().AddJsonConsole().AddMtaOtlpLogging(observability);
        builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);

        // The factory behind the runtime's own log (IMtaLog): JSON console, and OTLP when an endpoint is configured.
        using var startupLogs = OtlpLoggerFactory.Create(observability, b => b.AddJsonConsole());
        var startupLog = new MtaLogAdapter(startupLogs.Factory);
        var clock = SystemClock.Instance;
        // One process owns a SQLite data directory (the offline migrate-storage commands take the same lock).
        using DataDirectoryLock? directoryLock = loaded.Config.Storage.Backend == StorageBackend.Sqlite ? DataDirectoryLock.Acquire(loaded.Config.Storage.Sqlite.DataDirectory) : null;
        var storage = StorageFactory.Create(loaded.Config.Storage, clock, startupLog);
        await storage.InitializeAsync(CancellationToken.None).ConfigureAwait(false);
        (loaded, storage) = await SettingsLayering.ApplyAsync(args, loaded, storage, clock, startupLog, CancellationToken.None).ConfigureAwait(false);
        var config = loaded.Config;

        // Backend switch startup gate (design 4.6): a confirmed target becomes Active, a fenced source or an unactivated target stays quiet.
        var gate = await StartupGate.EvaluateAsync(storage, clock, startupLog, CancellationToken.None).ConfigureAwait(false);
        await using var runtime = await EggMailRuntime.CreateAsync(config, storage, clock, startupLog, CancellationToken.None).ConfigureAwait(false);
        await ApiHosting.EnsureBootstrapAdminAsync(config, storage, clock, startupLog, CancellationToken.None).ConfigureAwait(false);

        builder.Services.AddSingleton(loaded);
        builder.Services.AddSingleton(config);
        builder.Services.AddSingleton(runtime);
        builder.Services.AddSingleton(storage);
        builder.Services.AddSingleton<IClock>(clock);
        builder.Services.AddMtaObservability(observability);
        if (config.Observability.QueueSampleSeconds > 0)
        {
            builder.Services.AddHostedService(_ => new QueueGaugesService(runtime, TimeSpan.FromSeconds(config.Observability.QueueSampleSeconds)));   // in every mode: the dashboard shows the queue of a fenced source too
        }
        var switchState = new SwitchRuntimeState(gate);
        var switchControl = new HostSwitchControl(runtime, switchState);
        builder.Services.AddSingleton(gate);
        builder.Services.AddSingleton(switchState);
        builder.Services.AddSingleton<Mta.Storage.Portability.ISwitchHostControl>(switchControl);
        if (!gate.AcceptMail)
        {
            runtime.SmtpServer.AcceptingMail = false; // listeners answer 421, the API answers 503 (SwitchRuntimeState.AcceptingApi)
        }

        // The listeners always start (they answer 421 while the instance does not accept mail, so senders retry cleanly).
        builder.Services.AddHostedService<SmtpListenerService>();
        if (gate.Mode == StartupMode.Normal || gate.Mode == StartupMode.Draining)
        {
            builder.Services.AddHostedService<RuntimeStateService>();   // before the services that produce the state: it stops after them
            builder.Services.AddHostedService<DeliveryService>();
            builder.Services.AddHostedService<WebhookService>();
            builder.Services.AddHostedService<CertificateService>();
            builder.Services.AddHostedService<MaintenanceService>();
            builder.Services.AddHostedService<TlsReportService>();
            builder.Services.AddHostedService<BackupService>();
            builder.Services.AddHostedService<SendingLimitsService>();
            builder.Services.AddHostedService(_ => new SwitchStateWatcher(runtime, switchControl, TimeSpan.FromSeconds(5)));
        }
        else
        {
            // A fenced source or a target that is not active: dashboard and API only. No dispatch, no maintenance, no
            // certificate renewal (the old data stays exactly as it is until the switch is finalized or rolled back).
            startupLog.Write(MtaLogLevel.Warning, "switch", "starting restricted: " + gate.Banner);
        }
        ApiHosting.AddServices(builder, loaded, runtime);
        builder.Services.Configure<HostOptions>(o => o.ShutdownTimeout = TimeSpan.FromSeconds(45));

        builder.WebHost.ConfigureKestrel(k => KestrelHosting.Configure(k, config, runtime.Certificates));

        var app = builder.Build();
        DashboardHosting.Map(app);
        ApiHosting.Map(app, runtime);
        await app.RunAsync().ConfigureAwait(false);
        return 0;
    }
}
