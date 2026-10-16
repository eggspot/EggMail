using System.Text.Json;
using Mta.Core;
using Mta.Dsn;
using Mta.Storage;

namespace Mta.Host.Hosting;

/// <summary>
/// Loads (or creates on first start) the VERP signing keys, kept in the configuration store so every replica and every backend shares them. The first key is created under a lease
/// (like <see cref="Mta.Host.Security.AuthThrottleKeyStore"/>): two replicas starting together on an empty store used to each create a key and the later write replaced the earlier one, so the
/// replicas signed bounce addresses with different keys and a bounce that arrived at the other replica was ignored until it was restarted.
/// </summary>
public static class VerpKeyStore
{
    public const string SettingKey = "bounce.verp.keys";

    private const string LeaseName = "verp-keys";

    private sealed record Stored(int Active, Dictionary<int, string> Keys);

    public static async Task<VerpCodec> LoadOrCreateAsync(IConfigStore config, CancellationToken ct, IClock? clock = null)
    {
        clock ??= SystemClock.Instance;
        Stored? stored = await TryReadAsync(config, ct).ConfigureAwait(false);
        if (stored is null)
        {
            string owner = "verp-keys-" + Guid.NewGuid().ToString("N");
            for (int attempt = 0; stored is null; attempt++)
            {
                if (await config.TryAcquireLeaseAsync(LeaseName, owner, TimeSpan.FromSeconds(30), clock.UtcNow, ct).ConfigureAwait(false) is not null)
                {
                    try
                    {
                        stored = await TryReadAsync(config, ct).ConfigureAwait(false);   // another replica may have been first
                        if (stored is null)
                        {
                            stored = new Stored(1, new Dictionary<int, string> { [1] = Convert.ToBase64String(VerpCodec.GenerateKey()) });
                            await config.SetSettingAsync(new SettingRecord(SettingKey, null, JsonSerializer.Serialize(stored), clock.UtcNow), ct).ConfigureAwait(false);
                        }
                    }
                    finally
                    {
                        await config.ReleaseLeaseAsync(LeaseName, owner, CancellationToken.None).ConfigureAwait(false);
                    }
                }
                else
                {
                    // Another replica is creating the keys: wait for them to appear. A creator that died holds the lease for at most its duration.
                    await Task.Delay(100, ct).ConfigureAwait(false);
                    stored = await TryReadAsync(config, ct).ConfigureAwait(false);
                    if (stored is null && attempt >= 600)
                    {
                        throw new InvalidOperationException("The VERP keys could not be created: another replica holds the creation lease and wrote nothing.");
                    }
                }
            }
        }

        return new VerpCodec(stored.Keys.ToDictionary(k => k.Key, k => Convert.FromBase64String(k.Value)), stored.Active);
    }

    private static async Task<Stored?> TryReadAsync(IConfigStore config, CancellationToken ct)
    {
        var settings = await config.GetSettingsAsync(null, ct).ConfigureAwait(false);
        var existing = settings.FirstOrDefault(s => s.Key == SettingKey && s.TenantId is null);
        return existing is null
            ? null
            : JsonSerializer.Deserialize<Stored>(existing.ValueJson) ?? throw new InvalidOperationException("The stored VERP key setting is unreadable.");
    }
}
