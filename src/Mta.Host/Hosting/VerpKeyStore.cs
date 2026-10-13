using System.Text.Json;
using Mta.Dsn;
using Mta.Storage;

namespace Mta.Host.Hosting;

/// <summary>Loads (or creates on first start) the VERP signing keys, kept in the configuration store so every replica and every backend shares them.</summary>
public static class VerpKeyStore
{
    public const string SettingKey = "bounce.verp.keys";

    private sealed record Stored(int Active, Dictionary<int, string> Keys);

    public static async Task<VerpCodec> LoadOrCreateAsync(IConfigStore config, CancellationToken ct)
    {
        var settings = await config.GetSettingsAsync(null, ct).ConfigureAwait(false);
        var existing = settings.FirstOrDefault(s => s.Key == SettingKey && s.TenantId is null);
        Stored stored;
        if (existing is not null)
        {
            stored = JsonSerializer.Deserialize<Stored>(existing.ValueJson) ?? throw new InvalidOperationException("The stored VERP key setting is unreadable.");
        }
        else
        {
            stored = new Stored(1, new Dictionary<int, string> { [1] = Convert.ToBase64String(VerpCodec.GenerateKey()) });
            await config.SetSettingAsync(new SettingRecord(SettingKey, null, JsonSerializer.Serialize(stored), DateTimeOffset.UtcNow), ct).ConfigureAwait(false);
        }

        return new VerpCodec(stored.Keys.ToDictionary(k => k.Key, k => Convert.FromBase64String(k.Value)), stored.Active);
    }
}
