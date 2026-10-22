using System.Security.Cryptography;
using Mta.Core;
using Mta.Dsn;
using Mta.Host.Hosting;
using Mta.Storage;
using Mta.TestSupport;

namespace Mta.Integration.Tests.Lifecycle;

/// <summary>
/// Rotation of the VERP keys (decision 110): a new key after the period that signs an hour later, the old one retired an hour after that and deleted once what it signed has expired,
/// one new key however many replicas run the pass, and the running codec reloaded from the table. Both backends.
/// </summary>
public class VerpKeyRotationTests
{
    private static readonly Guid TenantId = Guid.Parse("a0000000-0000-7000-8000-000000000002");
    private static readonly Guid DomainId = Guid.Parse("d0000000-0000-7000-8000-000000000002");
    private static readonly TimeSpan MaxTokenAge = TimeSpan.FromDays(14);
    private const int SrsMaxAgeDays = 21;

    /// <summary>Marks the bytes so a test can tell protected from plain and refuse what another ring protected.</summary>
    private sealed class MarkingProtector : ISecretProtector
    {
        public byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose) => [0x5A, .. plaintext];

        public byte[] Unprotect(ReadOnlySpan<byte> protectedData, string purpose) =>
            protectedData.Length > 0 && protectedData[0] == 0x5A ? protectedData[1..].ToArray() : throw new CryptographicException("not protected by this ring");
    }

    private static readonly ISecretProtector Secrets = new MarkingProtector();

    [Fact]
    public Task A_key_is_replaced_after_the_period_and_the_old_one_verifies_until_its_addresses_expire_on_sqlite() => OnSqliteAsync(LifecycleAsync);

    [PostgresFact]
    public Task A_key_is_replaced_after_the_period_and_the_old_one_verifies_until_its_addresses_expire_on_postgres() => OnPostgresAsync(LifecycleAsync);

    [Fact]
    public Task Replicas_that_rotate_at_the_same_time_add_one_key_and_load_the_same_set_on_sqlite() => OnSqliteAsync(ReplicasAsync);

    [PostgresFact]
    public Task Replicas_that_rotate_at_the_same_time_add_one_key_and_load_the_same_set_on_postgres() => OnPostgresAsync(ReplicasAsync);

    [Fact]
    public Task With_rotation_off_no_key_is_added_but_retired_keys_are_pruned_and_changes_reloaded_on_sqlite() => OnSqliteAsync(RotationOffAsync);

    [PostgresFact]
    public Task With_rotation_off_no_key_is_added_but_retired_keys_are_pruned_and_changes_reloaded_on_postgres() => OnPostgresAsync(RotationOffAsync);

    [Fact]
    public Task Key_ids_wrap_after_15_and_skip_the_ids_in_use_on_sqlite() => OnSqliteAsync(WrapAsync);

    [PostgresFact]
    public Task Key_ids_wrap_after_15_and_skip_the_ids_in_use_on_postgres() => OnPostgresAsync(WrapAsync);

    [Fact]
    public Task A_key_this_ring_cannot_open_leaves_the_codec_as_it_was_on_sqlite() => OnSqliteAsync(UnreadableAsync);

    [PostgresFact]
    public Task A_key_this_ring_cannot_open_leaves_the_codec_as_it_was_on_postgres() => OnPostgresAsync(UnreadableAsync);

    private static async Task OnSqliteAsync(Func<HostBackend, VirtualClock, Task> test)
    {
        var clock = new VirtualClock();
        await using HostBackend backend = await HostBackend.SqliteAsync(clock);
        await test(backend, clock);
    }

    private static async Task OnPostgresAsync(Func<HostBackend, VirtualClock, Task> test)
    {
        var clock = new VirtualClock();
        await using HostBackend backend = await HostBackend.PostgresAsync(clock);
        await test(backend, clock);
    }

    private static VerpKeyRotation Rotation(HostBackend backend, VerpCodec codec, IClock clock, int rotationDays = 90) =>
        new(backend.Storage.Config, Secrets, codec, clock, rotationDays, SrsMaxAgeDays);

    private static string Address(VerpCodec codec, IClock clock) => codec.CreateLocalPart(TenantId, DomainId, clock.UtcNow, "example.net");

    private static async Task LifecycleAsync(HostBackend backend, VirtualClock clock)
    {
        VerpCodec codec = await VerpKeyStore.LoadOrCreateAsync(backend.Storage.Config, Secrets, default, clock);
        VerpKeyRotation rotation = Rotation(backend, codec, clock);
        IConfigStore config = backend.Storage.Config;

        clock.Advance(TimeSpan.FromDays(90) - TimeSpan.FromMinutes(1));
        await rotation.RunOnceAsync(default);
        Assert.Single(await config.GetVerpKeysAsync(default));   // not yet

        clock.Advance(TimeSpan.FromMinutes(1));
        await rotation.RunOnceAsync(default);
        IReadOnlyList<VerpKeyRecord> keys = await config.GetVerpKeysAsync(default);
        Assert.Equal([1, 2], keys.Select(k => k.KeyId));
        Assert.Equal(clock.UtcNow + VerpKeyRotation.PendingPeriod, keys[1].ActivatesAt);
        Assert.Equal(1, codec.ActiveKeyId);   // the new key waits an hour: every replica loads it before any signs with it
        Assert.Equal([1, 2], codec.KeyIds.Order());
        string fromKey1 = Address(codec, clock);

        await rotation.RunOnceAsync(default);
        Assert.Equal(2, (await config.GetVerpKeysAsync(default)).Count);   // a key is waiting: no second one

        clock.Advance(VerpKeyRotation.PendingPeriod);
        await rotation.RunOnceAsync(default);
        Assert.Equal(2, codec.ActiveKeyId);
        Assert.Null((await config.GetVerpKeysAsync(default))[0].RetiredAt);   // retired an hour later, for replicas whose clocks are behind
        string fromKey2 = Address(codec, clock);
        Assert.True(codec.TryDecode(fromKey1, clock.UtcNow, MaxTokenAge, out _));

        clock.Advance(VerpKeyRotation.PendingPeriod);
        await rotation.RunOnceAsync(default);
        VerpKeyRecord retired = (await config.GetVerpKeysAsync(default))[0];
        Assert.Equal(clock.UtcNow, retired.RetiredAt);
        Assert.True(codec.TryDecode(fromKey1, clock.UtcNow, MaxTokenAge, out _), "a retired key still verifies");

        // A restarted replica builds the same ring from the table.
        await backend.RestartAsync();
        config = backend.Storage.Config;
        VerpCodec restarted = await VerpKeyStore.LoadOrCreateAsync(config, Secrets, default, clock);
        Assert.Equal(2, restarted.ActiveKeyId);
        Assert.True(restarted.TryDecode(fromKey1, clock.UtcNow, MaxTokenAge, out _));
        rotation = Rotation(backend, codec, clock);

        // Kept for the longest an address is accepted (SRS: 21 days) plus a day, then deleted.
        TimeSpan retention = VerpKeyRotation.RetentionFor(SrsMaxAgeDays);
        Assert.Equal(TimeSpan.FromDays(22), retention);
        clock.Advance(retention - TimeSpan.FromMinutes(1));
        await rotation.RunOnceAsync(default);
        Assert.Equal(2, (await config.GetVerpKeysAsync(default)).Count);
        clock.Advance(TimeSpan.FromMinutes(1));
        await rotation.RunOnceAsync(default);
        Assert.Equal([2], (await config.GetVerpKeysAsync(default)).Select(k => k.KeyId));
        Assert.Equal([2], codec.KeyIds);
        Assert.False(codec.TryDecode(fromKey1, clock.UtcNow, TimeSpan.FromDays(365), out _), "a deleted key verifies nothing");
        Assert.True(codec.TryDecode(fromKey2, clock.UtcNow, TimeSpan.FromDays(365), out _));

        // The next period counts from the activation of key 2, and the next id follows it.
        clock.Advance(TimeSpan.FromDays(90) - retention - VerpKeyRotation.PendingPeriod);
        await rotation.RunOnceAsync(default);
        Assert.Equal([2, 3], (await config.GetVerpKeysAsync(default)).Select(k => k.KeyId));
    }

    private static async Task ReplicasAsync(HostBackend backend, VirtualClock clock)
    {
        VerpCodec first = await VerpKeyStore.LoadOrCreateAsync(backend.Storage.Config, Secrets, default, clock);
        VerpCodec second = await VerpKeyStore.LoadOrCreateAsync(backend.Storage.Config, Secrets, default, clock);
        VerpCodec third = await VerpKeyStore.LoadOrCreateAsync(backend.Storage.Config, Secrets, default, clock);
        VerpKeyRotation[] replicas = [Rotation(backend, first, clock), Rotation(backend, second, clock), Rotation(backend, third, clock)];

        clock.Advance(TimeSpan.FromDays(91));
        await Task.WhenAll(replicas.Select(r => r.RunOnceAsync(default)));
        await Task.WhenAll(replicas.Select(r => r.RunOnceAsync(default)));   // a replica that missed the lease in the first pass sees the key now
        Assert.Equal([1, 2], (await backend.Storage.Config.GetVerpKeysAsync(default)).Select(k => k.KeyId));

        clock.Advance(VerpKeyRotation.PendingPeriod);
        await Task.WhenAll(replicas.Select(r => r.RunOnceAsync(default)));
        Assert.All(new[] { first, second, third }, c => Assert.Equal(2, c.ActiveKeyId));
        string signed = Address(first, clock);
        Assert.Equal(signed, Address(third, clock));   // one key set: what one replica signs, the others verify
        Assert.True(second.TryDecode(signed, clock.UtcNow, MaxTokenAge, out _));

        // A replica whose clock is up to the pending hour behind still finds a key to sign with after the old one is retired.
        clock.Advance(VerpKeyRotation.PendingPeriod);
        await Task.WhenAll(replicas.Select(r => r.RunOnceAsync(default)));
        Assert.NotNull((await backend.Storage.Config.GetVerpKeysAsync(default))[0].RetiredAt);
        var behind = new VirtualClock(clock.UtcNow - VerpKeyRotation.PendingPeriod + TimeSpan.FromSeconds(1));
        VerpCodec late = await VerpKeyStore.LoadOrCreateAsync(backend.Storage.Config, Secrets, default, behind);
        Assert.Equal(2, late.ActiveKeyId);
    }

    private static async Task RotationOffAsync(HostBackend backend, VirtualClock clock)
    {
        IConfigStore config = backend.Storage.Config;
        VerpCodec codec = await VerpKeyStore.LoadOrCreateAsync(config, Secrets, default, clock);
        VerpKeyRotation rotation = Rotation(backend, codec, clock, rotationDays: 0);

        clock.Advance(TimeSpan.FromDays(400));
        await rotation.RunOnceAsync(default);
        Assert.Single(await config.GetVerpKeysAsync(default));

        // An operator adds a key by hand and retires key 1: the running codec follows, and key 1 goes once its addresses have expired.
        byte[] key = VerpCodec.GenerateKey();
        await config.AddVerpKeysAsync([new VerpKeyRecord(7, Secrets.Protect(key, SecretPurposes.VerpKey), clock.UtcNow, clock.UtcNow, null)], default);
        Assert.True(await config.RetireVerpKeyAsync(1, clock.UtcNow, default));
        await rotation.RunOnceAsync(default);
        Assert.Equal(7, codec.ActiveKeyId);
        Assert.Equal(new VerpCodec(new Dictionary<int, byte[]> { [7] = key }, 7).CreateLocalPart(TenantId, DomainId, clock.UtcNow, "example.net"), Address(codec, clock));

        clock.Advance(VerpKeyRotation.RetentionFor(SrsMaxAgeDays));
        await rotation.RunOnceAsync(default);
        Assert.Equal([7], (await config.GetVerpKeysAsync(default)).Select(k => k.KeyId));
        Assert.Equal([7], codec.KeyIds);
    }

    private static async Task WrapAsync(HostBackend backend, VirtualClock clock)
    {
        IConfigStore config = backend.Storage.Config;
        DateTimeOffset longAgo = clock.UtcNow - TimeSpan.FromDays(100);
        // Key 15 signs; key 0 is retired but still kept; key 3 is retired too.
        await config.AddVerpKeysAsync(
        [
            new VerpKeyRecord(0, Secrets.Protect(VerpCodec.GenerateKey(), SecretPurposes.VerpKey), longAgo, DateTimeOffset.UnixEpoch, clock.UtcNow),
            new VerpKeyRecord(3, Secrets.Protect(VerpCodec.GenerateKey(), SecretPurposes.VerpKey), longAgo, DateTimeOffset.UnixEpoch, clock.UtcNow),
            new VerpKeyRecord(15, Secrets.Protect(VerpCodec.GenerateKey(), SecretPurposes.VerpKey), longAgo, longAgo, null),
        ], default);
        VerpCodec codec = await VerpKeyStore.LoadOrCreateAsync(config, Secrets, default, clock);
        Assert.Equal(15, codec.ActiveKeyId);

        await Rotation(backend, codec, clock).RunOnceAsync(default);
        Assert.Equal([0, 1, 3, 15], (await config.GetVerpKeysAsync(default)).Select(k => k.KeyId));
    }

    private static async Task UnreadableAsync(HostBackend backend, VirtualClock clock)
    {
        IConfigStore config = backend.Storage.Config;
        VerpCodec codec = await VerpKeyStore.LoadOrCreateAsync(config, Secrets, default, clock);
        string before = Address(codec, clock);
        await config.AddVerpKeysAsync([new VerpKeyRecord(4, [1, 2, 3], clock.UtcNow, clock.UtcNow, null)], default);   // protected by another ring

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => Rotation(backend, codec, clock).RunOnceAsync(default));
        Assert.Contains("VERP key 4", ex.Message, StringComparison.Ordinal);
        Assert.Equal(1, codec.ActiveKeyId);
        Assert.Equal([1], codec.KeyIds);
        Assert.Equal(before, Address(codec, clock));
    }
}
