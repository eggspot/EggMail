using System.Net.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Mta.Core;
using Mta.Host.Configuration;
using Mta.Host.Domains;
using Mta.Host.Hosting;
using Mta.Host.Switching;
using Mta.Host.Tls;
using Mta.Observability;
using Mta.Storage;

namespace Mta.Host;

/// <summary>The <c>mta</c> command line: <c>serve</c> (default), <c>--healthcheck</c>, <c>migrate-db</c>, <c>migrate-storage</c>, <c>admin</c>, <c>domains</c>, <c>self-test</c>, <c>--version</c>.</summary>
internal static class Cli
{
    public static async Task<int> RunAsync(string[] args)
    {
        (string command, string[] rest) = SplitCommand(args);
        // Every command that handles mail, addresses or accounts needs working Unicode; --version, --healthcheck and self-test (which reports it) do not.
        if (command is "serve" or "migrate-db" or "migrate-storage" or "admin" or "domains" or "secrets" && !UnicodeSelfTest.Enforce(RequiresUnicodeSupport(rest), UnicodeLog(command), Console.Error))
        {
            return UnicodeSelfTest.FailedExitCode;
        }

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
            case "domains":
                return await DomainsCommand.RunAsync(rest, Console.Out, Console.Error).ConfigureAwait(false);
            case "self-test":
                return SelfTest(rest);
            case "serve":
                return await ServeAsync(rest).ConfigureAwait(false);
            default:
                Console.Error.WriteLine($"Unknown command '{command}'. Commands: serve (default), migrate-db, migrate-storage, admin, domains, self-test, --healthcheck, --version.");
                return 64;
        }
    }

    /// <summary><c>Startup:RequireUnicodeSupport</c> from the configuration these arguments select (true when the configuration cannot be loaded: that error is reported by the command itself).</summary>
    private static bool RequiresUnicodeSupport(string[] args)
    {
        try
        {
            LoadedConfig loaded = ConfigLoader.Load(ConfigLoader.Build(args));
            return !loaded.IsValid || loaded.Config.Startup.RequireUnicodeSupport;
        }
        catch (FormatException)
        {
            return true;   // command-line arguments the configuration cannot parse (the command reports them)
        }
    }

    /// <summary>The server logs as JSON; the one-off commands print their own output, so the check stays quiet there unless it fails.</summary>
    private static IMtaLog UnicodeLog(string command) =>
        command == "serve" ? new MtaLogAdapter(LoggerFactory.Create(b => b.AddJsonConsole())) : NullMtaLog.Instance;

    /// <summary>
    /// The command is the first argument that is not an option; only that one argument is taken out. (Removing every argument equal to the
    /// command name also removed option values: <c>admin create --role admin</c> lost its <c>admin</c>.)
    /// </summary>
    internal static (string Command, string[] Arguments) SplitCommand(string[] args)
    {
        int index = Array.FindIndex(args, a => !a.StartsWith("--", StringComparison.Ordinal) || a is "--healthcheck" or "--version");
        return index < 0 ? ("serve", args) : (args[index], args.Where((_, i) => i != index).ToArray());
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

    /// <summary>Runs the startup Unicode self-test and reports the result (exit code 71 when it fails). Lets an operator check an image or host before deploying.</summary>
    private static int SelfTest(string[] args)
    {
        _ = args;
        UnicodeSelfTestResult result = UnicodeSelfTest.Run();
        if (result.Passed)
        {
            Console.WriteLine(result.Describe());
            return 0;
        }

        Console.Error.WriteLine(result.Describe());
        return UnicodeSelfTest.FailedExitCode;
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
                Inbound = options.Inbound,
                Postgres = new PostgresOptions
                {
                    OwnerConnectionString = options.Postgres.OwnerConnectionString,
                    RuntimeConnectionString = options.Postgres.RuntimeConnectionString,
                    ReadOnlyConnectionString = options.Postgres.ReadOnlyConnectionString,
                    ReadOnlyStatementTimeoutSeconds = options.Postgres.ReadOnlyStatementTimeoutSeconds,
                    ReadOnlyIdleInTransactionTimeoutSeconds = options.Postgres.ReadOnlyIdleInTransactionTimeoutSeconds,
                    ReadOnlyMaxPoolSize = options.Postgres.ReadOnlyMaxPoolSize,
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

        if (loaded.Config.Storage.Backend == StorageBackend.Sqlite && StartupChecks.DataDirectoryProblem(loaded.Config.Storage.Sqlite.DataDirectory) is { } dataProblem)
        {
            Console.Error.WriteLine("configuration error: " + dataProblem);
            return 2;
        }

        // One process owns a SQLite data directory (the offline migrate-storage commands take the same lock).
        using DataDirectoryLock? directoryLock = loaded.Config.Storage.Backend == StorageBackend.Sqlite ? DataDirectoryLock.Acquire(loaded.Config.Storage.Sqlite.DataDirectory) : null;
        var storage = StorageFactory.Create(loaded.Config.Storage, clock, startupLog);
        await storage.InitializeAsync(CancellationToken.None).ConfigureAwait(false);
        (loaded, storage) = await SettingsLayering.ApplyAsync(args, loaded, storage, clock, startupLog, CancellationToken.None).ConfigureAwait(false);
        var config = loaded.Config;

        // Backend switch startup gate (design 4.6): a confirmed target becomes Active, a fenced source or an unactivated target stays quiet.
        var gate = await StartupGate.EvaluateAsync(storage, clock, startupLog, CancellationToken.None).ConfigureAwait(false);
        EggMailRuntime createdRuntime;
        try
        {
            createdRuntime = await EggMailRuntime.CreateAsync(config, storage, clock, startupLog, CancellationToken.None, hostnameConfigured: StartupChecks.HostnameConfigured(config, Environment.GetEnvironmentVariable)).ConfigureAwait(false);
        }
        catch (Mta.Host.Secrets.SecretsConfigurationException ex)
        {
            // The stored key ring does not fit Secrets:* (a wrong key, a switched protection): say what to do instead of a stack trace.
            Console.Error.WriteLine("configuration error: " + ex.Message);
            return 2;
        }

        await using var runtime = createdRuntime;
        FirstAdministratorResult admin = await ApiHosting.EnsureFirstAdministratorAsync(config, storage, clock, startupLog, CancellationToken.None).ConfigureAwait(false);
        if (admin.Outcome == FirstAdministratorOutcome.Problem)
        {
            Console.Error.WriteLine("configuration error: " + admin.Problem);
            return 2;
        }

        if (admin.GeneratedPassword is { } generatedPassword)
        {
            FirstAdministrator.WriteGeneratedPasswordNotice(Console.Out, admin.UserName, generatedPassword, config.Dashboard.HttpsPort);
        }

        if (gate.Mode == StartupMode.Normal && await RelayBootstrap.ApplyAsync(config, storage.Config, runtime.Secrets, startupLog, CancellationToken.None).ConfigureAwait(false) is { } relayProblem)
        {
            Console.Error.WriteLine("configuration error: " + relayProblem);
            return 2;
        }

        if (gate.Mode == StartupMode.Normal && config.Domains.Bootstrap.Count > 0)
        {
            await DomainBootstrap.RunAsync(config, storage, runtime.Secrets, clock, startupLog, CancellationToken.None).ConfigureAwait(false);   // Domains:Bootstrap (EGGMAIL_DOMAINS)
        }

        StartupChecks.LogAdvice(config, startupLog, source: loaded.Source);

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
        if (runtime.InboundConfiguration is not null)
        {
            builder.Services.AddHostedService<InboundConfigurationService>();   // before the listeners: they must know the inbound domains when the first sender connects
        }

        builder.Services.AddHostedService<SmtpListenerService>();
        if (gate.Mode == StartupMode.Normal || gate.Mode == StartupMode.Draining)
        {
            builder.Services.AddHostedService<RuntimeStateService>();   // before the services that produce the state: it stops after them
            builder.Services.AddHostedService<ReplicaCoordinationService>();
            builder.Services.AddHostedService<DeliveryService>();
            builder.Services.AddHostedService<WebhookService>();
            builder.Services.AddHostedService<InboundActionService>();
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
        app.UseMtaStsPolicy();   // the MTA-STS policy file of the registered domains, when Domains:MtaStsMode serves it; before the dashboard's static files, which must not answer under that host name
        DashboardHosting.Map(app);
        ApiHosting.Map(app, runtime);
        await app.RunAsync().ConfigureAwait(false);
        return 0;
    }
}
