using Mta.Core;
using Mta.Delivery;
using Mta.Host.Api;
using Mta.Storage;
using Mta.TestSupport;

namespace Mta.Integration.Tests.Lifecycle;

public class DkimKeyUnavailableLifecycleTests
{
    [Fact]
    public async Task An_unreadable_stored_key_fails_closed_until_a_good_key_is_activated_on_sqlite()
    {
        var clock = new VirtualClock();
        await using HostBackend backend = await HostBackend.SqliteAsync(clock);
        await RunAsync(backend, clock);
    }

    [PostgresFact]
    public async Task An_unreadable_stored_key_fails_closed_until_a_good_key_is_activated_on_postgres()
    {
        var clock = new VirtualClock();
        await using HostBackend backend = await HostBackend.PostgresAsync(clock);
        await RunAsync(backend, clock);
    }

    private static async Task RunAsync(HostBackend backend, VirtualClock clock)
    {
        DomainHarness h = await DomainHarness.CreateAsync(backend, clock);
        Assert.NotNull(await h.Signers.GetSignerAsync(DomainHarness.DomainName, default));

        DkimKeyRecord good = (await h.KeysAsync()).Single(k => k.Active);
        DkimKeyRecord unreadable = good with { Id = Ids.New(), Selector = "broken", PrivateKeyProtected = [.. "another-key-ring|"u8, .. good.PrivateKeyProtected], Active = false, CreatedAt = clock.UtcNow };
        await h.Config.AddDkimKeyAsync(unreadable, default);
        await h.Config.SetActiveDkimKeyAsync(h.DomainId, unreadable.Id, clock.UtcNow, default);

        var failure = await Assert.ThrowsAsync<DkimKeyUnavailableException>(() => h.Signers.GetSignerAsync("news." + DomainHarness.DomainName, default).AsTask());
        Assert.Equal(unreadable.Id, failure.KeyId);
        Assert.Equal(DomainHarness.DomainName, failure.Domain);

        await backend.RestartAsync();
        h.Rebind();
        await Assert.ThrowsAsync<DkimKeyUnavailableException>(() => h.Signers.GetSignerAsync(DomainHarness.DomainName, default).AsTask());

        clock.Advance(TimeSpan.FromMinutes(1));
        DkimKeyRecord replacement = await DomainVerificationService.CreateKeyAsync(h.DomainId, "repaired", h.Protector, clock.UtcNow, active: false);
        await h.Config.AddDkimKeyAsync(replacement, default);
        await h.Config.SetActiveDkimKeyAsync(h.DomainId, replacement.Id, clock.UtcNow, default);

        Assert.Equal("repaired", (await h.Signers.GetSignerAsync(DomainHarness.DomainName, default))!.Selector);
    }
}
