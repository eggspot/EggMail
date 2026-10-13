using Mta.Core;
using Mta.Host.Configuration;
using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Host.Tests;

public class StoredSettingsTests
{
    private static async Task<InMemoryStorage> StorageWithAsync(params (string Key, string Json, Guid? Tenant)[] rows)
    {
        var s = new InMemoryStorage(new StorageOptions());
        await s.InitializeAsync(default);
        foreach (var r in rows)
        {
            await s.Config.SetSettingAsync(new SettingRecord(r.Key, r.Tenant, r.Json, DateTimeOffset.UtcNow), default);
        }

        return s;
    }

    [Fact]
    public async Task Only_global_configuration_shaped_scalar_rows_are_loaded()
    {
        await using var storage = await StorageWithAsync(
            ("History:Mode", "\"StatsOnly\"", null),
            ("Retention:MetadataDays", "14", null),
            ("Content:StoreAttachments", "true", null),
            ("dataprotection.key.key-1", "\"<key/>\"", null),
            ("bounce.verp.keys", "{\"active\":1}", null),
            ("Content:StoreAttachments", "false", Guid.NewGuid()),
            ("Smtp:Weird", "[1,2]", null));

        var loaded = await StoredSettings.LoadAsync(storage.Config, default);

        Assert.Equal(
            ["Content:StoreAttachments=true", "History:Mode=StatsOnly", "Retention:MetadataDays=14"],
            loaded.Select(kv => $"{kv.Key}={kv.Value}").OrderBy(x => x).ToArray());
    }

    [Fact]
    public async Task Stored_values_are_the_lowest_layer_below_environment_style_and_command_line_values()
    {
        await using var storage = await StorageWithAsync(("Retention:MetadataDays", "14", null), ("History:Mode", "\"StatsOnly\"", null), ("Queue:MaxLifetime", "\"2.00:00:00\"", null));
        var stored = await StoredSettings.LoadAsync(storage.Config, default);

        var withoutStored = ConfigLoader.Load(ConfigLoader.Build(["--History:Mode=Full"], dataDirectoryHint: Path.GetTempPath()));
        var withStored = ConfigLoader.Load(ConfigLoader.Build(["--History:Mode=Full"], dataDirectoryHint: Path.GetTempPath(), storedSettings: stored));

        Assert.Equal(30, withoutStored.Config.Storage.Retention.MetadataDays);
        Assert.Equal(14, withStored.Config.Storage.Retention.MetadataDays);                  // the stored value applies...
        Assert.Equal(HistoryMode.Full, withStored.Config.Storage.History.Mode);              // ...unless the command line says otherwise
        Assert.Equal(TimeSpan.FromDays(2), withStored.Config.Storage.Queue.MaxLifetime);
    }
}

public class SettingsLayeringTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("eggmail-layer-").FullName;

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Directory.Delete(_dir, recursive: true);
    }

    [Fact]
    public async Task A_stored_history_mode_reopens_the_storage_with_the_merged_options_and_deployment_values_stay_locked()
    {
        string[] args = [$"--Sqlite:DataDirectory={_dir}", "--Retention:MetadataDays=9"];
        var deployment = ConfigLoader.Load(ConfigLoader.Build(args));
        var storage = Mta.Storage.Sqlite.SqliteStorage.Create(deployment.Config.Storage);
        await storage.InitializeAsync(default);
        Assert.Equal(HistoryMode.Full, storage.HistoryMode);
        await storage.Config.SetSettingAsync(new SettingRecord("History:Mode", null, "\"StatsOnly\"", DateTimeOffset.UtcNow), default);
        await storage.Config.SetSettingAsync(new SettingRecord("Retention:MetadataDays", null, "3", DateTimeOffset.UtcNow), default);

        var (final, reopened) = await Mta.Host.Hosting.SettingsLayering.ApplyAsync(args, deployment, storage, SystemClock.Instance, NullMtaLog.Instance, default);
        await using var _ = reopened;

        Assert.Equal(HistoryMode.StatsOnly, final.Config.Storage.History.Mode);
        Assert.Equal(HistoryMode.StatsOnly, reopened.HistoryMode);
        Assert.Equal(9, final.Config.Storage.Retention.MetadataDays);             // the command line beats the stored 3
        Assert.Contains("Retention:MetadataDays", final.LockedKeys, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("History:Mode", final.LockedKeys, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task An_invalid_stored_value_is_ignored_and_the_server_still_starts()
    {
        string[] args = [$"--Sqlite:DataDirectory={_dir}"];
        var deployment = ConfigLoader.Load(ConfigLoader.Build(args));
        var storage = Mta.Storage.Sqlite.SqliteStorage.Create(deployment.Config.Storage);
        await storage.InitializeAsync(default);
        await storage.Config.SetSettingAsync(new SettingRecord("Content:RetentionDays", null, "400", DateTimeOffset.UtcNow), default);   // content retention is limited to 6..30 days

        var (final, same) = await Mta.Host.Hosting.SettingsLayering.ApplyAsync(args, deployment, storage, SystemClock.Instance, NullMtaLog.Instance, default);
        await using var _ = same;

        Assert.Same(storage, same);
        Assert.Equal(7, final.Config.Storage.Content.RetentionDays);
    }
}
