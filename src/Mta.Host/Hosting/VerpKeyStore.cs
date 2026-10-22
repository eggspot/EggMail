using System.Security.Cryptography;
using System.Text.Json;
using Mta.Core;
using Mta.Dsn;
using Mta.Storage;

namespace Mta.Host.Hosting;

/// <summary>
/// Loads (or creates on first start) the VERP signing keys. They live in the <c>verp_key</c> table of the configuration store, protected with Data Protection like the other
/// secrets (decision 107), so every replica and every backend shares them and a backend switch carries them re-protected. The first key is created under a lease
/// (like <see cref="Mta.Host.Security.AuthThrottleKeyStore"/>): two replicas starting together on an empty store used to each create a key and the later write replaced the earlier one, so the
/// replicas signed bounce addresses with different keys and a bounce that arrived at the other replica was ignored until it was restarted.
/// <para>Builds before schema version 11 kept the keys as plain JSON in the setting <see cref="SettingKey"/>. The first start of this version moves them into the table with the same ids
/// (the addresses already sent keep verifying), and every start overwrites a setting that still holds key material with <see cref="MovedMarker"/>.</para>
/// </summary>
public static class VerpKeyStore
{
    /// <summary>The setting older builds kept the keys in, as plain JSON. Still read once, to move its keys into the table.</summary>
    public const string SettingKey = "bounce.verp.keys";

    /// <summary>What the setting holds once its keys were moved: no key material.</summary>
    public const string MovedMarker = "{\"movedTo\":\"verp_key\"}";

    private const string LeaseName = "verp-keys";

    /// <summary>
    /// When the keys of the first key set start signing: the epoch, not the creator's clock. Another replica whose clock is a few seconds behind would otherwise find no key
    /// active yet and refuse to start.
    /// </summary>
    private static readonly DateTimeOffset FirstKeysActivateAt = DateTimeOffset.UnixEpoch;

    private sealed record LegacyStored(int Active, Dictionary<int, string>? Keys);

    public static async Task<VerpCodec> LoadOrCreateAsync(IConfigStore config, ISecretProtector secrets, CancellationToken ct, IClock? clock = null)
    {
        clock ??= SystemClock.Instance;
        IReadOnlyList<VerpKeyRecord> keys = await config.GetVerpKeysAsync(ct).ConfigureAwait(false);
        if (keys.Count == 0)
        {
            string owner = "verp-keys-" + Guid.NewGuid().ToString("N");
            for (int attempt = 0; keys.Count == 0; attempt++)
            {
                if (await config.TryAcquireLeaseAsync(LeaseName, owner, TimeSpan.FromSeconds(30), clock.UtcNow, ct).ConfigureAwait(false) is not null)
                {
                    try
                    {
                        keys = await config.GetVerpKeysAsync(ct).ConfigureAwait(false);   // another replica may have been first
                        if (keys.Count == 0)
                        {
                            keys = await CreateAsync(config, secrets, clock.UtcNow, ct).ConfigureAwait(false);
                        }
                    }
                    finally
                    {
                        await config.ReleaseLeaseAsync(LeaseName, owner, CancellationToken.None).ConfigureAwait(false);
                    }
                }
                else
                {
                    // Another replica is creating the keys: wait for them to appear. A creator that died holds the lease for at most its duration (30 s on the given clock).
                    // The wait itself is real time (100 ms, 60 s in all) whatever the clock: with a clock a test froze, a lease that is never released is never seen to expire,
                    // and the loop ends with the exception below instead of waiting forever.
                    await Task.Delay(100, ct).ConfigureAwait(false);
                    keys = await config.GetVerpKeysAsync(ct).ConfigureAwait(false);
                    if (keys.Count == 0 && attempt >= 600)
                    {
                        throw new InvalidOperationException("The VERP keys could not be created: another replica holds the creation lease and wrote nothing.");
                    }
                }
            }
        }

        await ScrubLegacySettingAsync(config, clock.UtcNow, ct).ConfigureAwait(false);
        return ToCodec(keys, secrets, clock.UtcNow);
    }

    /// <summary>
    /// The key that signs at <paramref name="now"/>: of the keys not retired whose activation has come, the one activated last (ties: the higher id). Null when there is none.
    /// </summary>
    public static VerpKeyRecord? SigningKey(IReadOnlyList<VerpKeyRecord> keys, DateTimeOffset now) =>
        keys.Where(k => k.RetiredAt is null && k.ActivatesAt <= now).OrderByDescending(k => k.ActivatesAt).ThenByDescending(k => k.KeyId).FirstOrDefault();

    private static VerpCodec ToCodec(IReadOnlyList<VerpKeyRecord> keys, ISecretProtector secrets, DateTimeOffset now)
    {
        VerpKeyRecord signing = SigningKey(keys, now)
            ?? throw new InvalidOperationException("No VERP key can sign: every key in verp_key is retired or not active yet.");
        var plain = new Dictionary<int, byte[]>();
        foreach (VerpKeyRecord key in keys)
        {
            try
            {
                plain[key.KeyId] = secrets.Unprotect(key.KeyProtected, SecretPurposes.VerpKey);
            }
            catch (CryptographicException ex)
            {
                // A key that cannot be read with this key ring would sign or verify nothing: refuse to start rather than send bounce addresses that no replica can check.
                throw new InvalidOperationException(
                    $"The VERP key {key.KeyId} cannot be unprotected with this Data Protection key ring ({ex.Message}). The key ring of the deployment, and its Secrets:KeyProtection certificate, must be the ones the key was created with.", ex);
            }
        }

        return new VerpCodec(plain, signing.KeyId);
    }

    /// <summary>The first key set: the keys of the legacy setting when there is one (same ids; only its active key signs), else one new key with id 1.</summary>
    private static async Task<IReadOnlyList<VerpKeyRecord>> CreateAsync(IConfigStore config, ISecretProtector secrets, DateTimeOffset now, CancellationToken ct)
    {
        LegacyStored? legacy = await TryReadLegacyAsync(config, ct).ConfigureAwait(false);
        var records = new List<VerpKeyRecord>();
        if (legacy?.Keys is { Count: > 0 } legacyKeys)
        {
            if (!legacyKeys.ContainsKey(legacy.Active))
            {
                throw new InvalidOperationException($"The stored VERP key setting names key {legacy.Active} as active but does not hold it.");
            }

            foreach ((int id, string base64) in legacyKeys.OrderBy(k => k.Key))
            {
                byte[] key = Convert.FromBase64String(base64);
                try
                {
                    records.Add(new VerpKeyRecord(id, secrets.Protect(key, SecretPurposes.VerpKey), now, FirstKeysActivateAt, id == legacy.Active ? null : now));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(key);
                }
            }
        }
        else
        {
            byte[] key = VerpCodec.GenerateKey();
            try
            {
                records.Add(new VerpKeyRecord(1, secrets.Protect(key, SecretPurposes.VerpKey), now, FirstKeysActivateAt, null));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }

        await config.AddVerpKeysAsync(records, ct).ConfigureAwait(false);
        return records;
    }

    /// <summary>Overwrites the legacy setting when it still holds key material (a move that stopped between the two writes, or a bundle from an older build imported since).</summary>
    private static async Task ScrubLegacySettingAsync(IConfigStore config, DateTimeOffset now, CancellationToken ct)
    {
        if (await TryReadLegacyAsync(config, ct).ConfigureAwait(false) is { Keys.Count: > 0 })
        {
            await config.SetSettingAsync(new SettingRecord(SettingKey, null, MovedMarker, now), ct).ConfigureAwait(false);
        }
    }

    private static async Task<LegacyStored?> TryReadLegacyAsync(IConfigStore config, CancellationToken ct)
    {
        var settings = await config.GetSettingsAsync(null, ct).ConfigureAwait(false);
        var existing = settings.FirstOrDefault(s => s.Key == SettingKey && s.TenantId is null);
        return existing is null
            ? null
            : JsonSerializer.Deserialize<LegacyStored>(existing.ValueJson) ?? throw new InvalidOperationException("The stored VERP key setting is unreadable.");
    }
}
