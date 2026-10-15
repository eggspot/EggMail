using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Mta.Core;
using Mta.Host.Api;
using Mta.Host.Configuration;
using Mta.Storage;

namespace Mta.Host.Hosting;

/// <summary>Makes the delivery engine of this process reload relay routes and TLS policies as soon as the API changed them.</summary>
internal sealed class DeliveryEngineRoutingNotifier(Mta.Delivery.DeliveryEngine engine) : IRoutingConfigNotifier
{
    public void Changed() => engine.RequestConfigRefresh();
}

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

        services.AddSingleton<IRoutingConfigNotifier>(new DeliveryEngineRoutingNotifier(runtime.Delivery));
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
            SourceKeysProtectedAtRest = runtime.KeysProtectedAtRest,
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
    /// Creates the first administrator when no administrator exists yet (<see cref="FirstAdministrator"/>): from <c>Dashboard:BootstrapAdminPassword</c>, from the file
    /// <c>Dashboard:BootstrapAdminPasswordFile</c>, or with a generated password (returned in the result so the caller can print it once; it is never logged).
    /// </summary>
    public static Task<FirstAdministratorResult> EnsureFirstAdministratorAsync(MtaConfig config, IStorage storage, IClock clock, IMtaLog log, CancellationToken ct) =>
        FirstAdministrator.EnsureAsync(config, storage.Config, clock, log, ct);
}
