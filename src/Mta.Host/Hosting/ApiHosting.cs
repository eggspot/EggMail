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

        services.AddEggMailApi(loaded);
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
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            log.Write(MtaLogLevel.Error, "startup", "The bootstrap administrator could not be created (Dashboard:BootstrapAdminPasswordFile): " + ex.Message);
        }
    }
}
