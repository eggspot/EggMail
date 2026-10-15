using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Mta.Core;
using Mta.Host.Configuration;
using Mta.Host.Domains;
using Mta.Host.Security;
using Mta.Observability;
using Mta.Policy;

namespace Mta.Host.Api;

/// <summary>
/// Registration and routing of the HTTP API v1 (docs/api.md). This is not the composition root: the host that owns <c>Program.cs</c> calls
/// <see cref="AddEggMailApi(IServiceCollection, ApiOptions?)"/> and <see cref="MapEggMailApi"/>.
/// <para>The services the API needs from the host (it registers none of them): <c>IStorage</c>, <c>StorageOptions</c>, <c>ISecretProtector</c>,
/// <c>SubmissionService</c> and <c>IDnsResolver</c>. Optional: <c>IClock</c>, <c>AuthThrottle</c> (share the instance with the SMTP ingest so lockouts are
/// shared), <c>IStorageSwitchService</c>, <c>AcmeRenewalService</c>, <c>PrometheusTextExporter</c>, <c>IStoragePressureSource</c>.</para>
/// </summary>
public static class EggMailApiExtensions
{
    /// <summary>Registers the API services and the domain verification background service.</summary>
    public static IServiceCollection AddEggMailApi(this IServiceCollection services, ApiOptions? options = null)
    {
        options ??= new ApiOptions();
        services.AddLogging();
        services.TryAddSingleton(options);
        services.TryAddSingleton<IClock>(SystemClock.Instance);
        services.TryAddSingleton<AuthThrottle>();
        services.TryAddSingleton<VerificationSchedule>();
        services.TryAddSingleton(sp =>
        {
            ApiOptions o = sp.GetRequiredService<ApiOptions>();
            return o.DomainRecords ?? new DomainRecordOptions { BounceDomain = o.BounceDomain, SpfInclude = o.SpfInclude };
        });
        services.TryAddSingleton<DomainChecker>();
        services.TryAddSingleton<IStorageSwitchService, UnavailableStorageSwitchService>();
        services.TryAddSingleton<IAcmeCertificateRequester, AcmeCertificateRequester>();
        services.TryAddSingleton<HealthService>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHealthContributor, StorageHealthContributor>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHealthContributor, CertificateHealthContributor>());

        services.TryAddSingleton<ApiAuthenticator>();
        services.TryAddSingleton<SessionService>();
        services.TryAddSingleton<CapabilitiesService>();
        services.TryAddSingleton<SettingsService>();
        services.TryAddSingleton<MaintenanceRunner>();
        services.TryAddSingleton<ApiRuntimeInfo>();
        services.TryAddSingleton<DomainVerificationService>();
        services.AddHostedService(sp => sp.GetRequiredService<DomainVerificationService>());

        services.TryAddSingleton<CapabilitiesApi>();
        services.TryAddSingleton<SessionApi>();
        services.TryAddSingleton<SendBudget>();
        services.TryAddSingleton<SendingApi>();
        services.TryAddSingleton<MessagesApi>();
        services.TryAddSingleton<DomainsApi>();
        services.TryAddSingleton<SuppressionsApi>();
        services.TryAddSingleton<WebhooksApi>();
        services.TryAddSingleton<CredentialsApi>();
        services.TryAddSingleton<StatsApi>();
        services.TryAddSingleton<TenantSettingsApi>();
        services.TryAddSingleton<AdminApi>();
        services.TryAddSingleton<RoutingAdminApi>();
        services.TryAddSingleton<UsersApi>();
        return services;
    }

    /// <summary>Registers the API with the options derived from the loaded deployment configuration (limits, bounce domain, locked keys, webhooks, metrics).</summary>
    public static IServiceCollection AddEggMailApi(this IServiceCollection services, LoadedConfig loaded, Action<ApiOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(loaded);
        MtaConfig config = loaded.Config;
        var options = ApiOptionsFrom(config, loaded.LockedKeys);
        configure?.Invoke(options);
        services.TryAddSingleton(config.Storage);
        return services.AddEggMailApi(options);
    }

    /// <summary>The API settings the deployment configuration yields: <c>Api:*</c>, plus the SMTP limits, bounce domain, webhook rules and metrics switch the API shares with the rest of the process.</summary>
    public static ApiOptions ApiOptionsFrom(MtaConfig config, IReadOnlySet<string> lockedKeys)
    {
        ApiSection api = config.Api;
        return new ApiOptions
        {
            MaxMessageBytes = config.Smtp.MaxMessageSize,
            MaxRecipients = config.Smtp.MaxRecipients,
            BounceDomain = config.Delivery.BounceDomain,
            MessageIdDomain = config.Hostname,
            Webhooks = config.Webhooks,
            LockedKeys = lockedKeys,
            MetricsEnabled = config.Observability.MetricsEndpointEnabled,
            AllowPrivateMxAddresses = config.Delivery.AllowPrivateMxAddresses,
            MaxBodyBytes = api.MaxBodyBytes,
            MaxSendBodyBytes = api.MaxSendBodyBytes,
            MaxInFlightSendBytes = api.MaxInFlightSendBytes,
            MaxAttachments = api.MaxAttachments,
            MaxCustomHeaders = api.MaxCustomHeaders,
            MaxTags = api.MaxTags,
            SessionLifetime = api.SessionLifetime,
            SessionIdleTimeout = api.SessionIdleTimeout,
            CookieSecure = api.CookieSecure,
            MaxDomainsPerTenant = api.MaxDomainsPerTenant,
            MaxApiKeysPerTenant = api.MaxApiKeysPerTenant,
            MaxSmtpCredentialsPerTenant = api.MaxSmtpCredentialsPerTenant,
            MaxWebhooksPerTenant = api.MaxWebhooksPerTenant,
            MaxStatsRows = api.MaxStatsRows,
            SpfInclude = api.SpfInclude,
            DomainRecords = DomainRecordOptionsFrom(config),
            MetricsAllowedNetworks = api.MetricsAllowedNetworks.Count == 0
                ? ApiOptions.DefaultMetricsNetworks()
                : api.MetricsAllowedNetworks.Select(Mta.Webhooks.IpNetwork.Parse).ToList(),
        };
    }

    /// <summary>The options of the DNS records suggested for a sending domain: the bounce domain, host name, sending IP and the <c>Domains:*</c> settings.</summary>
    public static DomainRecordOptions DomainRecordOptionsFrom(MtaConfig config)
    {
        DomainsSection d = config.Domains;
        return new DomainRecordOptions
        {
            BounceDomain = config.Delivery.BounceDomain,
            SpfInclude = config.Api.SpfInclude,
            ServerHostname = DomainRecordOptions.UsableHostname(config.Hostname),
            PublicSendingIp = config.Delivery.PublicSendingIp,
            DmarcPolicy = d.DmarcPolicy,
            DmarcReportAddress = d.DmarcReportAddress,
            TlsReportAddress = d.TlsReportAddress,
            MtaStsMode = d.MtaStsMode,
            MtaStsMaxAge = d.MtaStsMaxAge,
            MtaStsMx = d.MtaStsMx.Select(m => m.Trim().ToLowerInvariant()).ToList(),
        };
    }

    /// <summary>
    /// Maps <c>/api/v1/**</c> and the operational endpoints (<c>/healthz</c>, <c>/readyz</c>, <c>/metrics</c>). Unknown paths below <c>/api/v1</c> answer a
    /// problem+json 404. Returns the <c>/api/v1</c> group so the host can add conventions (for example rate limiting).
    /// </summary>
    public static RouteGroupBuilder MapEggMailApi(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        IServiceProvider sp = endpoints.ServiceProvider;
        RouteGroupBuilder api = endpoints.MapGroup("/api/v1");
        api.AddEndpointFilter<ApiEndpointFilter>();

        CapabilitiesApi capabilities = sp.GetRequiredService<CapabilitiesApi>();
        capabilities.MapApi(api);
        sp.GetRequiredService<SessionApi>().Map(api);
        sp.GetRequiredService<SendingApi>().Map(api);
        sp.GetRequiredService<MessagesApi>().Map(api);
        sp.GetRequiredService<DomainsApi>().Map(api);
        sp.GetRequiredService<SuppressionsApi>().Map(api);
        sp.GetRequiredService<WebhooksApi>().Map(api);
        sp.GetRequiredService<CredentialsApi>().Map(api);
        sp.GetRequiredService<StatsApi>().Map(api);
        sp.GetRequiredService<TenantSettingsApi>().Map(api);
        sp.GetRequiredService<AdminApi>().Map(api);
        sp.GetRequiredService<RoutingAdminApi>().Map(api);
        sp.GetRequiredService<UsersApi>().Map(api);
        api.MapFallback("{**path}", (HttpContext context) => new ProblemResult(ApiException.NotFound($"No endpoint {context.Request.Method} {context.Request.Path.Value}.")));

        capabilities.MapOperational(endpoints);
        return api;
    }
}
