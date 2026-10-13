using System.Text.Json;
using Mta.Core;
using Mta.Host.Configuration;
using Mta.Storage;

namespace Mta.Host.Hosting;

/// <summary>
/// Applies the settings stored in the configuration store (layer 4 of decision N) once the storage is open. The storage pointer itself comes
/// from the deployment layers, so the store can only be opened first; if the stored settings change how the storage must be configured (for
/// example <c>History:Mode</c>), the storage is closed and opened again with the merged options. A stored value that does not validate is
/// ignored with a warning: a bad row must never keep the server from starting.
/// </summary>
public static class SettingsLayering
{
    public static async Task<(LoadedConfig Config, IStorage Storage)> ApplyAsync(string[] args, LoadedConfig deployment, IStorage storage, IClock clock, IMtaLog log, CancellationToken ct)
    {
        var stored = await StoredSettings.LoadAsync(storage.Config, ct).ConfigureAwait(false);
        if (stored.Count == 0)
        {
            return (deployment, storage);
        }

        var merged = ConfigLoader.Load(ConfigLoader.Build(args, storedSettings: stored));
        if (!merged.IsValid)
        {
            foreach (string error in merged.Errors)
            {
                log.Write(MtaLogLevel.Warning, "startup", "ignoring stored settings: " + error);
            }

            return (deployment, storage);
        }

        // Only the stored layer is added: which keys are locked (set by the deployment) is decided by the deployment layers alone.
        // Source stays the layered configuration (now including the stored layer): the backend switch reads SwitchTarget:* from it and its activator rewrites the bootstrap layer.
        var final = new LoadedConfig { Config = merged.Config, LockedKeys = deployment.LockedKeys, Errors = merged.Errors, Source = merged.Source };
        if (SameStorageOptions(deployment.Config.Storage, final.Config.Storage))
        {
            return (final, storage);
        }

        log.Write(MtaLogLevel.Information, "startup", "stored settings change the storage options; reopening the storage");
        await storage.DisposeAsync().ConfigureAwait(false);
        var reopened = StorageFactory.Create(final.Config.Storage, clock, log);
        await reopened.InitializeAsync(ct).ConfigureAwait(false);
        return (final, reopened);
    }

    private static bool SameStorageOptions(StorageOptions a, StorageOptions b) => JsonSerializer.Serialize(a) == JsonSerializer.Serialize(b);
}
