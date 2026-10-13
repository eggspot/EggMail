using Mta.Core;
using Mta.Host.Configuration;
using Mta.Host.Hosting;
using Mta.Policy;
using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Host.Tests;

public class SendingConfiguratorTests
{
    [Fact]
    public async Task Defaults_come_from_configuration_and_tenant_overrides_and_warmup_from_the_store()
    {
        await using var storage = new InMemoryStorage(new StorageOptions());
        await storage.InitializeAsync(default);
        var now = DateTimeOffset.UtcNow;
        var capped = Guid.NewGuid();
        var free = Guid.NewGuid();
        await storage.Config.UpsertTenantAsync(new Tenant(capped, "Capped", "capped", true, now, false), default);
        await storage.Config.UpsertTenantAsync(new Tenant(free, "Free", "free", true, now, false), default);
        await storage.Config.SetSettingAsync(new SettingRecord("Sending:PerHour", capped, "2", now), default);
        await storage.Config.UpsertDomainAsync(new DomainRecord(Guid.NewGuid(), capped, "newdomain.example", DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);

        var section = new SendingSection { TenantPerHour = 100, WarmupEnabled = true };
        var limits = new SendingLimits(SystemClock.Instance, null, SendingConfigurator.OptionsFrom(section));
        await SendingConfigurator.RefreshAsync(limits, section, storage.Config, default);

        Assert.True(limits.TryReserve(capped, null, 2).IsAllowed);
        Assert.Equal(SendingDecisionKind.Deferred, limits.TryReserve(capped, null, 1).Kind);      // the tenant override (2 per hour) beats the default (100)
        Assert.True(limits.TryReserve(free, null, 100).IsAllowed);
        Assert.Equal(SendingDecisionKind.Deferred, limits.TryReserve(free, null, 1).Kind);        // the default applies
        Assert.Equal(50, limits.GetWarmupCap("newdomain.example"));                               // day 0 of the ramp
    }

    [Fact]
    public async Task Removing_the_override_returns_the_tenant_to_the_default()
    {
        await using var storage = new InMemoryStorage(new StorageOptions());
        await storage.InitializeAsync(default);
        var tenant = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        await storage.Config.UpsertTenantAsync(new Tenant(tenant, "T", "t", true, now, false), default);
        await storage.Config.SetSettingAsync(new SettingRecord("Sending:PerDay", tenant, "1", now), default);
        var section = new SendingSection();
        var limits = new SendingLimits(SystemClock.Instance, null, SendingConfigurator.OptionsFrom(section));
        await SendingConfigurator.RefreshAsync(limits, section, storage.Config, default);
        Assert.True(limits.TryReserve(tenant, null, 1).IsAllowed);
        Assert.False(limits.TryReserve(tenant, null, 1).IsAllowed);

        await storage.Config.SetSettingAsync(new SettingRecord("Sending:PerDay", tenant, "0", now), default);
        await SendingConfigurator.RefreshAsync(limits, section, storage.Config, default);

        Assert.True(limits.TryReserve(tenant, null, 50).IsAllowed);
    }
}
