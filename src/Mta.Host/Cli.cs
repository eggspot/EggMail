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
using Mta.Observability;
using Mta.Storage;

namespace Mta.Host;

/// <summary>The <c>mta</c> command line: <c>serve</c> (default), <c>--healthcheck</c>, <c>migrate-db</c>, <c>--version</c>.</summary>
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
            case "serve":
                return await ServeAsync(rest).ConfigureAwait(false);
            default:
                Console.Error.WriteLine($"Unknown command '{command}'. Commands: serve (default), migrate-db, --healthcheck, --version.");
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
                },
            };
        }

        await using var storage = StorageFactory.Create(options, SystemClock.Instance, log);
        await storage.InitializeAsync(CancellationToken.None).ConfigureAwait(false);
        Console.WriteLine($"storage ready: backend {storage.Backend}, history {storage.HistoryMode}");
        return 0;
    }

    private static async Task<int> ServeAsync(string[] args)
    {
        if (Load(args) is not { } loaded)
        {
            return 2;
        }

        var config = loaded.Config;
        var builder = WebApplication.CreateBuilder(args);
        builder.Logging.ClearProviders().AddJsonConsole();
        builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);

        using var startupFactory = LoggerFactory.Create(b => b.AddJsonConsole());
        var startupLog = new MtaLogAdapter(startupFactory);
        var clock = SystemClock.Instance;
        var storage = StorageFactory.Create(config.Storage, clock, startupLog);
        await storage.InitializeAsync(CancellationToken.None).ConfigureAwait(false);
        await using var runtime = await EggMailRuntime.CreateAsync(config, storage, clock, startupLog, CancellationToken.None).ConfigureAwait(false);

        builder.Services.AddSingleton(loaded);
        builder.Services.AddSingleton(config);
        builder.Services.AddSingleton(runtime);
        builder.Services.AddSingleton(storage);
        builder.Services.AddSingleton<IClock>(clock);
        builder.Services.AddMtaObservability(new ObservabilityOptions { OtlpEndpoint = config.Observability.OtlpEndpoint, ServiceVersion = typeof(Cli).Assembly.GetName().Version?.ToString(3) ?? "0.0.0" });
        builder.Services.AddHostedService<SmtpListenerService>();
        builder.Services.AddHostedService<DeliveryService>();
        builder.Services.AddHostedService<WebhookService>();
        builder.Services.AddHostedService<CertificateService>();
        builder.Services.AddHostedService<MaintenanceService>();
        builder.Services.AddHostedService<TlsReportService>();
        builder.Services.Configure<HostOptions>(o => o.ShutdownTimeout = TimeSpan.FromSeconds(45));

        builder.WebHost.ConfigureKestrel(k =>
        {
            var bind = System.Net.IPAddress.Parse(config.Dashboard.BindAddress);
            k.Listen(bind, config.Dashboard.HttpPort);
            if (config.Dashboard.HttpsEnabled)
            {
                k.Listen(bind, config.Dashboard.HttpsPort, l => l.UseHttps(https => https.ServerCertificateSelector = (_, name) => runtime.Certificates.GetCertificate(name)));
            }

            k.Limits.MaxRequestBodySize = 64L * 1024 * 1024;
        });

        var app = builder.Build();
        DashboardHosting.Map(app);
        await app.RunAsync().ConfigureAwait(false);
        return 0;
    }
}
