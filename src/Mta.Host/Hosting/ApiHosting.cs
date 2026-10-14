using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Mta.Core;
using Mta.Host.Api;
using Mta.Host.Configuration;
using Mta.Storage;

namespace Mta.Host.Hosting;

/// <summary>Connects the HTTP API (<c>Mta.Host/Api</c>) to the runtime: the services it needs from the process, the routes, and the first administrator.</summary>
public static class ApiHosting
{
    public static void AddServices(WebApplicationBuilder builder, LoadedConfig loaded, EggMailRuntime runtime)
    {
        IServiceCollection services = builder.Services;
        services.AddSingleton(runtime.Submission);
        services.AddSingleton(runtime.Secrets);
        services.AddSingleton(runtime.AuthThrottle); // the same instance the SMTP ingest counts failures in: one lockout for both
        services.AddSingleton(runtime.Dns);
        if (runtime.Acme is { } acme)
        {
            services.AddSingleton(acme);
        }

        AddSwitchService(services, loaded, runtime);
        services.AddEggMailApi(loaded);
    }

    /// <summary>The backend switch behind <c>/admin/storage/switch</c>: the engine over the storage this process runs on.</summary>
    private static void AddSwitchService(IServiceCollection services, LoadedConfig loaded, EggMailRuntime runtime)
    {
        MtaConfig config = loaded.Config;
        var options = new Mta.Host.Switching.StorageSwitchServiceOptions
        {
            BundleDirectory = config.Switch.BundleDirectory,
            SourceKeysProtectedAtRest = config.Secrets.KeyProtection != KeyProtectionMode.None,
            QuiesceTimeout = TimeSpan.FromSeconds(Math.Max(1, config.Switch.QuiesceTimeoutSeconds)),
        };
        AddSwitchTargetServices(services, loaded);
        services.AddSingleton<IStorageSwitchService>(sp => new Mta.Host.Switching.StorageSwitchService(
            runtime.Storage, config.Storage, runtime.Secrets, runtime.Clock,
            sp.GetRequiredService<Mta.Host.Switching.ISwitchTargetResolver>(),
            sp.GetService<Mta.Storage.Portability.ISwitchActivator>(),
            sp.GetService<Mta.Storage.Portability.ISwitchHostControl>(),
            options));
    }

    /// <summary>
    /// Registers what the switch needs from the layered configuration: the resolver that turns a request into a target (<c>SwitchTarget:*</c>) and the
    /// activator that rewrites the bootstrap file. Both need <see cref="LoadedConfig.Source"/>; a <see cref="LoadedConfig"/> built without it has neither
    /// and the dashboard's switch flow cannot find a target.
    /// </summary>
    public static void AddSwitchTargetServices(IServiceCollection services, LoadedConfig loaded)
    {
        Microsoft.Extensions.Configuration.IConfiguration source = loaded.Source ?? new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build();
        services.AddSingleton<Mta.Host.Switching.ISwitchTargetResolver>(new Mta.Host.Switching.ConfiguredSwitchTargetResolver(source));
        if (source is Microsoft.Extensions.Configuration.IConfigurationRoot root)
        {
            services.AddSingleton<Mta.Storage.Portability.ISwitchActivator>(new Mta.Host.Switching.SwitchActivator(root, root[ConfigLoader.BootstrapPathKey] ?? ConfigLoader.ResolveBootstrapPath()));
        }
    }

    public static void Map(WebApplication app, EggMailRuntime runtime)
    {
        app.MapEggMailApi();

        // Webhook endpoints of tenants an administrator allowed to reach internal networks.
        runtime.Webhooks.AllowlistProvider = app.Services.GetRequiredService<SettingsService>().GetWebhookAllowlistSnapshot;
    }

    /// <summary>
    /// Creates the first administrator from <c>Dashboard:BootstrapAdminUser</c> and the password in <c>Dashboard:BootstrapAdminPasswordFile</c> when no admin
    /// exists yet. The password is read from a file so it never appears in the environment or the process list.
    /// </summary>
    public static async Task EnsureBootstrapAdminAsync(MtaConfig config, IStorage storage, IClock clock, IMtaLog log, CancellationToken ct)
    {
        string? file = config.Dashboard.BootstrapAdminPasswordFile;
        if (string.IsNullOrWhiteSpace(file))
        {
            return;
        }

        try
        {
            if ((await storage.Config.GetDashboardUsersAsync(ct).ConfigureAwait(false)).Any(u => u.Role == DashboardRole.Admin))
            {
                return;
            }

            string password = (await File.ReadAllTextAsync(file, ct).ConfigureAwait(false)).Trim();
            if (await DashboardAccounts.EnsureAdminAsync(storage.Config, clock, config.Dashboard.BootstrapAdminUser, password, ct).ConfigureAwait(false))
            {
                log.Write(MtaLogLevel.Information, "startup", $"Created the first dashboard administrator '{config.Dashboard.BootstrapAdminUser}'.");
            }
        }
        catch (StorageConflictException)
        {
            // Another replica created the administrator at the same moment.
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            log.Write(MtaLogLevel.Error, "startup", "The bootstrap administrator could not be created (Dashboard:BootstrapAdminPasswordFile): " + ex.Message);
        }
    }
}
