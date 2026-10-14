using System.Security.Cryptography;
using System.Text.Json;
using Mta.Core;
using Mta.Storage;

namespace Mta.Host.Security;

/// <summary>
/// The secret the replicas digest failed-login keys with (<see cref="AuthThrottle"/>): 32 random bytes, protected by Data Protection like the other secrets and kept in the
/// configuration store so every replica reads the same. Created on first use under a lease, so two replicas starting together do not each create their own. The value is
/// ephemeral by nature (the counts it keys last fifteen minutes): one that cannot be read any more, for example after the key ring was replaced, is simply replaced.
/// </summary>
public static class AuthThrottleKeyStore
{
    public const string SettingKey = "auth.throttle.key";

    private const string LeaseName = "auth-throttle-key";

    /// <summary>The key, or null if it could neither be read nor created (the caller then counts failures per process).</summary>
    public static async Task<byte[]?> LoadOrCreateAsync(IConfigStore config, ISecretProtector secrets, IClock clock, CancellationToken ct)
    {
        if (await TryReadAsync(config, secrets, ct).ConfigureAwait(false) is { } existing)
        {
            return existing;
        }

        string owner = "auth-key-" + Guid.NewGuid().ToString("N");
        for (int attempt = 0; attempt < 50; attempt++)
        {
            if (await config.TryAcquireLeaseAsync(LeaseName, owner, TimeSpan.FromSeconds(30), clock.UtcNow, ct).ConfigureAwait(false) is not null)
            {
                try
                {
                    if (await TryReadAsync(config, secrets, ct).ConfigureAwait(false) is { } created)
                    {
                        return created;   // another replica was first
                    }

                    byte[] key = RandomNumberGenerator.GetBytes(32);
                    string json = JsonSerializer.Serialize(new Stored(Convert.ToBase64String(secrets.Protect(key, SecretPurposes.AuthThrottleKey))));
                    await config.SetSettingAsync(new SettingRecord(SettingKey, null, json, clock.UtcNow), ct).ConfigureAwait(false);
                    return key;
                }
                finally
                {
                    await config.ReleaseLeaseAsync(LeaseName, owner, CancellationToken.None).ConfigureAwait(false);
                }
            }

            await Task.Delay(100, ct).ConfigureAwait(false);   // another replica is creating it
            if (await TryReadAsync(config, secrets, ct).ConfigureAwait(false) is { } appeared)
            {
                return appeared;
            }
        }

        return null;
    }

    private sealed record Stored(string Protected);

    private static async Task<byte[]?> TryReadAsync(IConfigStore config, ISecretProtector secrets, CancellationToken ct)
    {
        var setting = (await config.GetSettingsAsync(null, ct).ConfigureAwait(false)).FirstOrDefault(s => s.Key == SettingKey && s.TenantId is null);
        if (setting is null)
        {
            return null;
        }

        try
        {
            var stored = JsonSerializer.Deserialize<Stored>(setting.ValueJson);
            byte[] key = secrets.Unprotect(Convert.FromBase64String(stored!.Protected), SecretPurposes.AuthThrottleKey);
            return key.Length >= 16 ? key : null;
        }
        catch (Exception ex) when (ex is JsonException or FormatException or CryptographicException or NullReferenceException)
        {
            return null;   // unreadable (another key ring, damaged): replaced by the next creation
        }
    }
}
