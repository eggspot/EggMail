using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Mta.Storage;
using Mta.Storage.Portability;

namespace Mta.Host.Switching;

/// <summary>One setting of the new storage pointer (or of the effective values that must stay the same).</summary>
/// <param name="Key">Configuration key with colons, for example <c>Storage:Backend</c>.</param>
/// <param name="Value">The new value.</param>
/// <param name="Secret">Never printed; referenced by name in a patch.</param>
public sealed record PointerSetting(string Key, string Value, bool Secret)
{
    /// <summary>The environment variable form (<c>Storage__Backend</c>).</summary>
    public string EnvironmentName => Key.Replace(":", "__", StringComparison.Ordinal);
}

/// <summary>
/// Activation (design §4.6): the storage pointer is deployment configuration. The switch never rewrites environment variables,
/// ConfigMaps or compose files. If every key of the new pointer is free in the deployment layers above the bootstrap file, the
/// pointer is written into the bootstrap file on the data volume (the previous file is kept for rollback). Otherwise a cutover
/// patch is produced for the operator, and secrets are referenced by name, never printed.
/// </summary>
public sealed class SwitchActivator(IConfigurationRoot configuration, string bootstrapPath, string? loadedBootstrapPath = null) : ISwitchActivator
{
    private const string SecretName = "eggmail-storage";

    /// <summary>The pointer to the target: what must change so the next start opens the new storage.</summary>
    public static IReadOnlyList<PointerSetting> PointerFor(StorageOptions target)
    {
        var list = new List<PointerSetting> { new("Storage:Backend", target.Backend.ToString(), false) };
        var defaults = new StorageOptions();
        if (target.Backend == StorageBackend.Postgres)
        {
            if (target.Postgres.RuntimeConnectionString is { Length: > 0 } runtime)
            {
                list.Add(new PointerSetting("Storage:Postgres:RuntimeConnectionString", runtime, true));
            }

            if (target.Postgres.OwnerConnectionString is { Length: > 0 } owner)
            {
                list.Add(new PointerSetting("Storage:Postgres:OwnerConnectionString", owner, true));
            }

            if (!target.Postgres.AutoMigrate)
            {
                list.Add(new PointerSetting("Mail:Database:Migrate", "Never", false));
            }

            if (target.Postgres.MaxPoolSize != defaults.Postgres.MaxPoolSize)
            {
                list.Add(new PointerSetting("Storage:Postgres:MaxPoolSize", target.Postgres.MaxPoolSize.ToString(CultureInfo.InvariantCulture), false));
            }
        }
        else
        {
            list.Add(new PointerSetting("Sqlite:DataDirectory", target.Sqlite.DataDirectory, false));
            if (target.Sqlite.SyncMode != defaults.Sqlite.SyncMode)
            {
                list.Add(new PointerSetting("Sqlite:SyncMode", target.Sqlite.SyncMode.ToString(), false));
            }

            if (target.Sqlite.ConfigSyncMode != defaults.Sqlite.ConfigSyncMode)
            {
                list.Add(new PointerSetting("Sqlite:ConfigSyncMode", target.Sqlite.ConfigSyncMode.ToString(), false));
            }

            if (target.Sqlite.QueuePersistence != defaults.Sqlite.QueuePersistence)
            {
                list.Add(new PointerSetting("Sqlite:QueuePersistence", target.Sqlite.QueuePersistence.ToString(), false));
            }
        }

        list.Add(new PointerSetting("History:Mode", target.History.Mode.ToString(), false));
        return list;
    }

    /// <summary>The effective source settings that differ from the built-in defaults: carried so the behavior does not change silently.</summary>
    public static IReadOnlyList<PointerSetting> CarriedSettings(StorageOptions source, IReadOnlyDictionary<string, string> effective)
    {
        var defaults = EffectiveSettings.Describe(new StorageOptions());
        return effective
            .Where(kv => kv.Key != "History:Mode" && defaults.TryGetValue(kv.Key, out string? d) && d != kv.Value)
            .Select(kv => new PointerSetting(kv.Key, kv.Value, false))
            .ToList();
    }

    /// <summary>Which provider of the layered configuration supplies a key above the bootstrap file, if any.</summary>
    public string? DeploymentSupplier(string key)
    {
        foreach (IConfigurationProvider provider in configuration.Providers.Reverse())
        {
            // The bootstrap file is what the activation rewrites, and a value from the config store (below every deployment layer) is not a deployment lock.
            if (!provider.TryGet(key, out _) || IsBootstrap(provider) || provider is Mta.Host.Configuration.StoredSettingsProvider)
            {
                continue;
            }

            return provider switch
            {
                Microsoft.Extensions.Configuration.EnvironmentVariables.EnvironmentVariablesConfigurationProvider => "an environment variable",
                Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider => "the command line",
                FileConfigurationProvider => "a mounted configuration file",
                _ => "the deployment configuration",
            };
        }

        return null;
    }

    private bool IsBootstrap(IConfigurationProvider provider) =>
        provider is FileConfigurationProvider file
        && file.Source.FileProvider?.GetFileInfo(file.Source.Path ?? string.Empty).PhysicalPath is { } physical
        && (string.Equals(Path.GetFullPath(physical), Path.GetFullPath(bootstrapPath), StringComparison.Ordinal)
            || (loadedBootstrapPath is { Length: > 0 } && string.Equals(Path.GetFullPath(physical), Path.GetFullPath(loadedBootstrapPath), StringComparison.Ordinal)));

    public async Task<SwitchActivation> ActivateAsync(SwitchActivationRequest request, CancellationToken cancellationToken)
    {
        var pointer = PointerFor(request.Target).ToList();
        var carried = CarriedSettings(request.Source, request.EffectiveSettings);
        var all = pointer.Concat(carried).ToList();
        var locked = pointer.Select(p => (Setting: p, By: DeploymentSupplier(p.Key))).Where(x => x.By is not null).ToList();

        if (locked.Count > 0)
        {
            string patch = BuildPatch(request.SwitchId, pointer, carried, locked.ToDictionary(x => x.Setting.Key, x => x.By!));
            return new SwitchActivation(
                ActivationKind.CutoverPatch,
                $"The storage pointer is supplied by the deployment ({string.Join(", ", locked.Select(x => $"{x.Setting.Key} by {x.By}"))}), so EggMail does not rewrite it. Apply the patch below and restart; the target becomes Active when it starts.",
                patch,
                null);
        }

        await WriteBootstrapAsync(request.SwitchId, all, cancellationToken).ConfigureAwait(false);
        return new SwitchActivation(
            ActivationKind.BootstrapFileWritten,
            $"The bootstrap file {bootstrapPath} now points at the {request.Target.Backend} target (the previous file is kept for rollback). Restart the application; the target becomes Active when it starts.",
            null,
            bootstrapPath);
    }

    private string BackupPath(Guid switchId) => bootstrapPath + ".pre-" + switchId.ToString("N");

    private string AbsentMarkerPath(Guid switchId) => bootstrapPath + ".none-" + switchId.ToString("N");

    private async Task WriteBootstrapAsync(Guid switchId, IReadOnlyList<PointerSetting> settings, CancellationToken ct)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(bootstrapPath))!);
        JsonNode root;
        if (File.Exists(bootstrapPath))
        {
            if (!File.Exists(BackupPath(switchId)))
            {
                File.Copy(bootstrapPath, BackupPath(switchId));
            }

            root = JsonNode.Parse(await File.ReadAllTextAsync(bootstrapPath, ct).ConfigureAwait(false), documentOptions: new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip }) ?? new JsonObject();
        }
        else
        {
            await File.WriteAllTextAsync(AbsentMarkerPath(switchId), string.Empty, ct).ConfigureAwait(false);
            root = new JsonObject();
        }

        foreach (PointerSetting s in settings)
        {
            Set((JsonObject)root, s.Key.Split(':'), s.Value);
        }

        string temp = bootstrapPath + ".tmp";
        await File.WriteAllTextAsync(temp, root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }), new UTF8Encoding(false), ct).ConfigureAwait(false);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite); // it may hold a connection string
        }

        File.Move(temp, bootstrapPath, overwrite: true);
    }

    private static void Set(JsonObject node, string[] path, string value)
    {
        JsonObject current = node;
        for (int i = 0; i < path.Length - 1; i++)
        {
            if (current[path[i]] is not JsonObject next)
            {
                next = new JsonObject();
                current[path[i]] = next;
            }

            current = next;
        }

        current[path[^1]] = value;
    }

    /// <summary>
    /// After an activation rewrote the bootstrap file, the pointer a later command (rollback, finalize, status) must read is the one
    /// from before: the kept copy (its path), or "" when there was no file. Null when no activation is pending.
    /// </summary>
    public static string? PendingOriginalBootstrap(string bootstrapPath)
    {
        string? directory = Path.GetDirectoryName(Path.GetFullPath(bootstrapPath));
        if (directory is null || !Directory.Exists(directory))
        {
            return null;
        }

        string name = Path.GetFileName(bootstrapPath);
        string? kept = Directory.EnumerateFiles(directory, name + ".pre-*").FirstOrDefault();
        if (kept is not null)
        {
            return kept;
        }

        return Directory.EnumerateFiles(directory, name + ".none-*").Any() ? string.Empty : null;
    }

    public Task ForgetAsync(Guid switchId, CancellationToken cancellationToken)
    {
        File.Delete(BackupPath(switchId));
        File.Delete(AbsentMarkerPath(switchId));
        return Task.CompletedTask;
    }

    public Task RestoreAsync(Guid switchId, CancellationToken cancellationToken)
    {
        if (File.Exists(BackupPath(switchId)))
        {
            File.Move(BackupPath(switchId), bootstrapPath, overwrite: true);
        }
        else if (File.Exists(AbsentMarkerPath(switchId)))
        {
            File.Delete(bootstrapPath);
        }

        if (File.Exists(AbsentMarkerPath(switchId)))
        {
            File.Delete(AbsentMarkerPath(switchId));
        }

        return Task.CompletedTask;
    }

    private string BuildPatch(Guid switchId, IReadOnlyList<PointerSetting> pointer, IReadOnlyList<PointerSetting> carried, IReadOnlyDictionary<string, string> suppliers)
    {
        var sb = new StringBuilder();
        string Was(PointerSetting s) => s.Secret ? "<secret, not shown>" : configuration[s.Key] ?? "<not set>";
        static string ComposeVariable(PointerSetting s) => "EGGMAIL_" + s.EnvironmentName.Replace("__", "_", StringComparison.Ordinal).ToUpperInvariant();

        sb.AppendLine($"# Cutover patch for backend switch {switchId}");
        sb.AppendLine("# Secrets are referenced by name and never printed.");
        sb.AppendLine();
        sb.AppendLine("## Environment variables (change or add)");
        foreach (PointerSetting s in pointer.Concat(carried))
        {
            string note = suppliers.TryGetValue(s.Key, out string? by) ? $"  (set by {by}; was: {Was(s)})" : $"  (was: {Was(s)})";
            sb.AppendLine(s.Secret ? $"{s.EnvironmentName}=<value of secret {SecretName}/{SecretKey(s)}>{note}" : $"{s.EnvironmentName}={s.Value}{note}");
        }

        sb.AppendLine();
        sb.AppendLine("## Kubernetes ConfigMap patch (kubectl patch configmap eggmail --type merge -p ...)");
        sb.AppendLine("data:");
        foreach (PointerSetting s in pointer.Concat(carried).Where(s => !s.Secret))
        {
            sb.AppendLine($"  {s.EnvironmentName}: \"{s.Value}\"");
        }

        foreach (PointerSetting s in pointer.Where(s => s.Secret))
        {
            sb.AppendLine($"# secret: create or update key '{SecretKey(s)}' in Secret '{SecretName}' and reference it as environment variable {s.EnvironmentName} (valueFrom.secretKeyRef)");
        }

        sb.AppendLine();
        sb.AppendLine("## Docker Compose override (docker-compose.override.yml)");
        sb.AppendLine("services:");
        sb.AppendLine("  eggmail:");
        sb.AppendLine("    environment:");
        foreach (PointerSetting s in pointer.Concat(carried))
        {
            sb.AppendLine(s.Secret ? $"      {s.EnvironmentName}: ${{{ComposeVariable(s)}}}" : $"      {s.EnvironmentName}: \"{s.Value}\"");
        }

        sb.AppendLine();
        sb.AppendLine("After the restart the target is confirmed Active by the startup gate and starts accepting and dispatching.");
        return sb.ToString();
    }

    private static string SecretKey(PointerSetting s) => s.Key[(s.Key.LastIndexOf(':') + 1)..].ToLowerInvariant();
}
