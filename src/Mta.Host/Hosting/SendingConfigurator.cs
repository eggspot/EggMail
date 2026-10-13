using Mta.Core;
using Mta.Host.Configuration;
using Mta.Policy;
using Mta.Storage;

namespace Mta.Host.Hosting;

/// <summary>
/// Feeds <see cref="SendingLimits"/> from configuration: the global and default caps are constructor options; tenant overrides (tenant
/// settings <c>Sending:PerHour</c> / <c>Sending:PerDay</c>) and domain warm-up (the ramp counted from the day a domain was added) are
/// re-read from the config store periodically so changes in the dashboard apply without a restart.
/// </summary>
public static class SendingConfigurator
{
    public const string PerHourKey = "Sending:PerHour";
    public const string PerDayKey = "Sending:PerDay";

    public static SendingLimitsOptions OptionsFrom(SendingSection s) => new()
    {
        Global = Set(s.GlobalPerHour, s.GlobalPerDay),
        DefaultTenant = Set(s.TenantPerHour, s.TenantPerDay),
        DefaultSendingDomain = Set(s.DomainPerHour, s.DomainPerDay),
    };

    private static LimitSet Set(long perHour, long perDay) => new(perHour > 0 ? perHour : null, perDay > 0 ? perDay : null);

    /// <summary>One refresh pass. Tenants without the settings fall back to the defaults; domains are put on (or taken off) the warm-up ramp.</summary>
    public static async Task RefreshAsync(SendingLimits limits, SendingSection config, IConfigStore store, CancellationToken ct)
    {
        var tenants = await store.GetTenantsAsync(ct).ConfigureAwait(false);
        foreach (var tenant in tenants)
        {
            var settings = await store.GetSettingsAsync(tenant.Id, ct).ConfigureAwait(false);
            long? perHour = Read(settings, PerHourKey);
            long? perDay = Read(settings, PerDayKey);
            limits.SetTenantLimits(tenant.Id, perHour is null && perDay is null ? null : new LimitSet(Positive(perHour), Positive(perDay)));
        }

        var domains = await store.GetDomainsAsync(null, ct).ConfigureAwait(false);
        foreach (var domain in domains)
        {
            if (config.WarmupEnabled)
            {
                limits.StartWarmup(domain.Name, DateOnly.FromDateTime(domain.CreatedAt.UtcDateTime));
            }
            else
            {
                limits.StopWarmup(domain.Name);
            }
        }
    }

    private static long? Positive(long? v) => v is > 0 ? v : null;

    private static long? Read(IReadOnlyList<SettingRecord> settings, string key)
    {
        var row = settings.FirstOrDefault(s => s.Key == key);
        return row is not null && StoredSettings.TryScalar(row.ValueJson, out string? v) && long.TryParse(v, out long n) && n > 0 ? n : null;
    }
}
