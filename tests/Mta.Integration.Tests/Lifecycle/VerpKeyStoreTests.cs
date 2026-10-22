using System.Security.Cryptography;
using System.Text.Json;
using Mta.Core;
using Mta.Dsn;
using Mta.Host.Hosting;
using Mta.Storage;
using Mta.TestSupport;

namespace Mta.Integration.Tests.Lifecycle;

/// <summary>
/// The VERP keys at rest (decision 107): protected in <c>verp_key</c>, never plain in the configuration store; the plain setting of builds before schema version 11 is moved
/// into the table with the same ids, so bounce addresses already sent keep verifying, and is overwritten so no key material stays behind. Both backends.
/// </summary>
public class VerpKeyStoreTests
{
    private static readonly Guid TenantId = Guid.Parse("a0000000-0000-7000-8000-000000000001");
    private static readonly Guid DomainId = Guid.Parse("d0000000-0000-7000-8000-000000000001");
    private static readonly TimeSpan MaxTokenAge = TimeSpan.FromDays(14);

    /// <summary>XORs the bytes with a key derived from the purpose: the stored bytes never contain the plain key, and another purpose cannot open them.</summary>
    private sealed class ScramblingProtector : ISecretProtector
    {
        private const byte Marker = 0xA5;

        public byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose) => [Marker, .. Xor(plaintext, purpose)];

        public byte[] Unprotect(ReadOnlySpan<byte> protectedData, string purpose) =>
            protectedData.Length > 0 && protectedData[0] == Marker ? Xor(protectedData[1..], purpose) : throw new CryptographicException("not protected by this ring");

        private static byte[] Xor(ReadOnlySpan<byte> data, string purpose)
        {
            byte[] pad = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(purpose));
            byte[] result = data.ToArray();
            for (int i = 0; i < result.Length; i++)
            {
                result[i] ^= pad[i % pad.Length];
            }

            return result;
        }
    }

    private static readonly ISecretProtector Secrets = new ScramblingProtector();

    [Fact]
    public Task A_first_start_stores_one_protected_key_on_sqlite() => OnSqliteAsync(FirstStartAsync);

    [PostgresFact]
    public Task A_first_start_stores_one_protected_key_on_postgres() => OnPostgresAsync(FirstStartAsync);

    [Fact]
    public Task The_plain_setting_of_an_older_build_is_moved_and_its_addresses_still_verify_on_sqlite() => OnSqliteAsync(LegacyMoveAsync);

    [PostgresFact]
    public Task The_plain_setting_of_an_older_build_is_moved_and_its_addresses_still_verify_on_postgres() => OnPostgresAsync(LegacyMoveAsync);

    [Fact]
    public Task Key_material_that_reappears_in_the_setting_is_overwritten_and_ignored_on_sqlite() => OnSqliteAsync(ScrubAsync);

    [PostgresFact]
    public Task Key_material_that_reappears_in_the_setting_is_overwritten_and_ignored_on_postgres() => OnPostgresAsync(ScrubAsync);

    [Fact]
    public Task A_key_another_key_ring_protected_stops_the_start_on_sqlite() => OnSqliteAsync(UnreadableAsync);

    [PostgresFact]
    public Task A_key_another_key_ring_protected_stops_the_start_on_postgres() => OnPostgresAsync(UnreadableAsync);

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

    private static async Task FirstStartAsync(HostBackend backend, VirtualClock clock)
    {
        VerpCodec codec = await VerpKeyStore.LoadOrCreateAsync(backend.Storage.Config, Secrets, default, clock);
        Assert.Equal(1, codec.ActiveKeyId);

        VerpKeyRecord stored = Assert.Single(await backend.Storage.Config.GetVerpKeysAsync(default));
        Assert.Equal(1, stored.KeyId);
        Assert.Null(stored.RetiredAt);
        Assert.Equal(clock.UtcNow, stored.ActivatesAt);
        byte[] plain = Secrets.Unprotect(stored.KeyProtected, SecretPurposes.VerpKey);
        Assert.Equal(32, plain.Length);
        Assert.False(stored.KeyProtected.AsSpan().IndexOf(plain.AsSpan(0, 16)) >= 0, "the key is stored protected, not plain");
        Assert.DoesNotContain(await backend.Storage.Config.GetSettingsAsync(null, default), s => s.Key == VerpKeyStore.SettingKey);

        // A restart reads the same key.
        string token = codec.CreateLocalPart(TenantId, DomainId, clock.UtcNow, "example.net");
        await backend.RestartAsync();
        VerpCodec again = await VerpKeyStore.LoadOrCreateAsync(backend.Storage.Config, Secrets, default, clock);
        Assert.True(again.TryDecode(token, clock.UtcNow, MaxTokenAge, out _));
    }

    private static async Task LegacyMoveAsync(HostBackend backend, VirtualClock clock)
    {
        // What a build before schema version 11 left: two keys in plain JSON, key 2 signing, key 1 kept for the addresses it made.
        byte[] key1 = VerpCodec.GenerateKey();
        byte[] key2 = VerpCodec.GenerateKey();
        var legacy = new VerpCodec(new Dictionary<int, byte[]> { [1] = key1, [2] = key2 }, 2);
        var oldKeyOnly = new VerpCodec(new Dictionary<int, byte[]> { [1] = key1 }, 1);
        string json = JsonSerializer.Serialize(new { Active = 2, Keys = new Dictionary<int, string> { [1] = Convert.ToBase64String(key1), [2] = Convert.ToBase64String(key2) } });
        await backend.Storage.Config.SetSettingAsync(new SettingRecord(VerpKeyStore.SettingKey, null, json, clock.UtcNow), default);
        string fromOldKey = oldKeyOnly.CreateLocalPart(TenantId, DomainId, clock.UtcNow, "example.net");
        string fromActiveKey = legacy.CreateLocalPart(TenantId, DomainId, clock.UtcNow, "example.net");

        clock.Advance(TimeSpan.FromHours(3));
        VerpCodec codec = await VerpKeyStore.LoadOrCreateAsync(backend.Storage.Config, Secrets, default, clock);
        Assert.Equal(2, codec.ActiveKeyId);
        Assert.True(codec.TryDecode(fromOldKey, clock.UtcNow, MaxTokenAge, out _), "an address made with the retired key still verifies");
        Assert.True(codec.TryDecode(fromActiveKey, clock.UtcNow, MaxTokenAge, out _));
        Assert.Equal(legacy.CreateLocalPart(TenantId, DomainId, clock.UtcNow, "example.net"), codec.CreateLocalPart(TenantId, DomainId, clock.UtcNow, "example.net"));
        Assert.Equal(legacy.DeriveKey(2, "EggMail.Srs.v1"), codec.DeriveKey(2, "EggMail.Srs.v1"));   // SRS and the hop marker derive from the same ring: forwarded mail keeps verifying

        IReadOnlyList<VerpKeyRecord> keys = await backend.Storage.Config.GetVerpKeysAsync(default);
        Assert.Equal([1, 2], keys.Select(k => k.KeyId));
        Assert.Equal(clock.UtcNow, keys[0].RetiredAt);
        Assert.Null(keys[1].RetiredAt);
        Assert.Equal(key1, Secrets.Unprotect(keys[0].KeyProtected, SecretPurposes.VerpKey));
        Assert.Equal(key2, Secrets.Unprotect(keys[1].KeyProtected, SecretPurposes.VerpKey));

        // No key material is left in the setting.
        SettingRecord setting = (await backend.Storage.Config.GetSettingsAsync(null, default)).Single(s => s.Key == VerpKeyStore.SettingKey);
        Assert.Equal(VerpKeyStore.MovedMarker, setting.ValueJson);
        Assert.DoesNotContain(Convert.ToBase64String(key1), setting.ValueJson);

        // A restart reads the table and moves nothing again.
        await backend.RestartAsync();
        VerpCodec again = await VerpKeyStore.LoadOrCreateAsync(backend.Storage.Config, Secrets, default, clock);
        Assert.Equal(2, again.ActiveKeyId);
        Assert.True(again.TryDecode(fromOldKey, clock.UtcNow, MaxTokenAge, out _));
        Assert.Equal(2, (await backend.Storage.Config.GetVerpKeysAsync(default)).Count);
    }

    private static async Task ScrubAsync(HostBackend backend, VirtualClock clock)
    {
        // The table holds the keys; plain key material appears in the setting again (a bundle of an older build imported into this store, or a move that stopped after its first write).
        VerpCodec codec = await VerpKeyStore.LoadOrCreateAsync(backend.Storage.Config, Secrets, default, clock);
        byte[] foreign = VerpCodec.GenerateKey();
        string json = JsonSerializer.Serialize(new { Active = 5, Keys = new Dictionary<int, string> { [5] = Convert.ToBase64String(foreign) } });
        await backend.Storage.Config.SetSettingAsync(new SettingRecord(VerpKeyStore.SettingKey, null, json, clock.UtcNow), default);

        VerpCodec again = await VerpKeyStore.LoadOrCreateAsync(backend.Storage.Config, Secrets, default, clock);
        Assert.Equal(codec.ActiveKeyId, again.ActiveKeyId);
        Assert.Equal([1], again.KeyIds);   // the table wins; the setting's key is not taken
        Assert.Equal(VerpKeyStore.MovedMarker, (await backend.Storage.Config.GetSettingsAsync(null, default)).Single(s => s.Key == VerpKeyStore.SettingKey).ValueJson);
    }

    private static async Task UnreadableAsync(HostBackend backend, VirtualClock clock)
    {
        await backend.Storage.Config.AddVerpKeysAsync([new VerpKeyRecord(3, [1, 2, 3, 4], clock.UtcNow, clock.UtcNow, null)], default);
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => VerpKeyStore.LoadOrCreateAsync(backend.Storage.Config, Secrets, default, clock));
        Assert.Contains("VERP key 3", ex.Message, StringComparison.Ordinal);
        Assert.Single(await backend.Storage.Config.GetVerpKeysAsync(default));   // nothing replaced: the operator restores the right key ring
    }
}
