using Microsoft.Extensions.Configuration;
using Mta.Host.Configuration;
using Mta.Smtp.Server;
using Mta.Storage;

namespace Mta.Host.Tests;

public class ConfigTests
{
    private static LoadedConfig Load(params (string Key, string? Value)[] values)
    {
        var cfg = new ConfigurationBuilder().AddInMemoryCollection(values.ToDictionary(v => v.Key, v => v.Value)).Build();
        return ConfigLoader.Load(cfg);
    }

    [Fact]
    public void Defaults_follow_the_decisions()
    {
        var l = Load();
        Assert.True(l.IsValid, string.Join("; ", l.Errors));
        var c = l.Config;
        Assert.Equal(StorageBackend.Sqlite, c.Storage.Backend);                 // decision Q
        Assert.Equal(HistoryMode.Full, c.Storage.History.Mode);                 // decision J
        Assert.Equal(SqliteSyncMode.Off, c.Storage.Sqlite.SyncMode);            // decision D
        Assert.Equal(SqliteSyncMode.Full, c.Storage.Sqlite.ConfigSyncMode);     // decision F
        Assert.Equal(7, c.Storage.Content.RetentionDays);
        Assert.Equal(TimeSpan.FromDays(5), c.Storage.Queue.MaxLifetime);
        Assert.Equal(25L * 1024 * 1024, c.Smtp.MaxMessageSize);
        Assert.Equal(30, c.Switch.QuiesceTimeoutSeconds);
        Assert.Equal(30, c.Storage.Retention.MetadataDays);
        Assert.Equal(7, c.Storage.Retention.WebhookOutboxDays);
        Assert.Equal(8080, c.Dashboard.HttpPort);
        Assert.Equal(8443, c.Dashboard.HttpsPort);
    }

    [Fact]
    public void Default_listeners_match_the_ports_decision()
    {
        var ls = Load().Config.Smtp.Listeners;
        Assert.Equal(5587, ls["submission"].Port);
        Assert.Equal(ListenerMode.StartTls, ls["submission"].Mode);
        Assert.Equal(4465, ls["submissions"].Port);
        Assert.Equal(ListenerMode.Implicit, ls["submissions"].Mode);
        Assert.Equal(2525, ls["alternate"].Port);
        Assert.Equal(2526, ls["bounce"].Port);
        Assert.Equal(ListenerRole.Bounce, ls["bounce"].Role);
        Assert.False(ls["bounce"].AuthRequired);
        Assert.False(ls["alternate-587"].Enabled);   // 2587 and 2465 are off by default
        Assert.False(ls["alternate-465"].Enabled);
    }

    [Fact]
    public void Listener_overrides_merge_with_defaults_member_by_member()
    {
        var l = Load(("Smtp:Listeners:submission:Port", "587"), ("Smtp:Listeners:alternate-587:Enabled", "true"), ("Smtp:Listeners:custom:Port", "9999"), ("Smtp:Listeners:custom:Mode", "Plain"), ("Smtp:Listeners:custom:AuthRequired", "false"));
        Assert.True(l.IsValid, string.Join("; ", l.Errors));
        var ls = l.Config.Smtp.Listeners;
        Assert.Equal(587, ls["submission"].Port);
        Assert.Equal(ListenerMode.StartTls, ls["submission"].Mode);      // kept from the default
        Assert.True(ls["submission"].AuthRequired);
        Assert.True(ls["alternate-587"].Enabled);
        Assert.Equal(9999, ls["custom"].Port);
        Assert.Equal(ListenerMode.Plain, ls["custom"].Mode);
    }

    [Fact]
    public void Documented_keys_are_honored()
    {
        var l = Load(
            ("Storage:Backend", "Postgres"), ("Storage:Postgres:RuntimeConnectionString", "Host=x"), ("Mail:Database:Migrate", "Never"),
            ("History:Mode", "StatsOnly"), ("Sqlite:SyncMode", "Full"), ("Sqlite:ConfigSyncMode", "Normal"), ("Sqlite:QueuePersistence", "Memory"),
            ("Content:Mode", "None"), ("Content:RetentionDays", "14"), ("Queue:MaxLifetime", "2.00:00:00"),
            ("Stats:HourlyRetentionDays", "0"), ("Webhooks:OutboxRetentionDays", "0"), ("Retention:MetadataDays", "90"), ("Smtp:MaxMessageSize", "1048576"));
        Assert.True(l.IsValid, string.Join("; ", l.Errors));
        var s = l.Config.Storage;
        Assert.Equal(StorageBackend.Postgres, s.Backend);
        Assert.False(s.Postgres.AutoMigrate);
        Assert.Equal(HistoryMode.StatsOnly, s.History.Mode);
        Assert.Equal(SqliteSyncMode.Full, s.Sqlite.SyncMode);
        Assert.Equal(QueuePersistence.Memory, s.Sqlite.QueuePersistence);
        Assert.False(s.Content.Retain);
        Assert.Equal(14, s.Content.RetentionDays);
        Assert.Equal(TimeSpan.FromDays(2), s.Queue.MaxLifetime);
        Assert.Equal(0, s.Retention.StatsHourlyDays);          // 0 = unlimited is valid
        Assert.Equal(0, s.Retention.WebhookOutboxDays);
        Assert.Equal(90, s.Retention.MetadataDays);
        Assert.Equal(1048576, l.Config.Smtp.MaxMessageSize);
    }

    [Theory]
    [InlineData("Content:RetentionDays", "0")]       // no unlimited for content (decision O)
    [InlineData("Content:RetentionDays", "5")]
    [InlineData("Content:RetentionDays", "31")]
    [InlineData("Retention:MetadataDays", "-1")]
    [InlineData("Stats:DailyRetentionDays", "-5")]
    [InlineData("Webhooks:AttemptLogDays", "-1")]
    [InlineData("Smtp:MaxRecipients", "0")]
    [InlineData("Switch:QuiesceTimeoutSeconds", "0")]
    [InlineData("Delivery:Workers", "0")]
    [InlineData("Delivery:MaxIdleConnectionsPerTarget", "-1")]
    [InlineData("Delivery:MaxIdleConnectionsPerTarget", "257")]
    [InlineData("Delivery:Throttle:MaxMessagesPerConnection", "0")]
    [InlineData("Smtp:Listeners:submission:BindAddress", "not-an-ip")]
    [InlineData("Smtp:Listeners:submission:Port", "70000")]
    public void Invalid_values_are_reported(string key, string value)
    {
        var l = Load((key, value));
        Assert.False(l.IsValid);
    }

    [Fact]
    public void Structural_validation()
    {
        Assert.Contains(Load(("Storage:Backend", "Postgres")).Errors, e => e.Contains("RuntimeConnectionString"));
        Assert.Contains(Load(("Smtp:Listeners:alternate:Port", "5587")).Errors, e => e.Contains("same port"));
        Assert.Contains(Load(("Smtp:Listeners:submission:Mode", "Plain")).Errors, e => e.Contains("nobody could ever authenticate"));
        Assert.Contains(Load(("Queue:MaxLifetime", "10.00:00:00")).Errors, e => e.Contains("shorter than Content:RetentionDays"));
        // With StatsOnly there is no stored content, so a long queue lifetime is fine.
        Assert.True(Load(("Queue:MaxLifetime", "10.00:00:00"), ("History:Mode", "StatsOnly")).IsValid);
    }

    [Fact]
    public void Deployment_keys_are_reported_as_locked()
    {
        var l = Load(("History:Mode", "StatsOnly"), ("Sqlite:SyncMode", "Normal"));
        Assert.Contains("History:Mode", l.LockedKeys);
        Assert.Contains("Sqlite:SyncMode", l.LockedKeys);
        Assert.DoesNotContain("Queue:MaxLifetime", l.LockedKeys);
    }

    [Fact]
    public void Layering_command_line_beats_environment_beats_bootstrap_file()
    {
        string dir = Directory.CreateTempSubdirectory().FullName;
        try
        {
            File.WriteAllText(Path.Combine(dir, ConfigLoader.BootstrapFileName), "{ \"Storage\": { \"Backend\": \"Postgres\", \"Postgres\": { \"RuntimeConnectionString\": \"Host=boot\" } }, \"History\": { \"Mode\": \"StatsOnly\" } }");
            var fromBootstrap = ConfigLoader.Load(ConfigLoader.Build([], dir));
            Assert.Equal(StorageBackend.Postgres, fromBootstrap.Config.Storage.Backend);
            Assert.Equal("Host=boot", fromBootstrap.Config.Storage.Postgres.RuntimeConnectionString);

            var withArgs = ConfigLoader.Load(ConfigLoader.Build(["--Storage:Backend=Sqlite", "--History:Mode=Full"], dir));
            Assert.Equal(StorageBackend.Sqlite, withArgs.Config.Storage.Backend);
            Assert.Equal(HistoryMode.Full, withArgs.Config.Storage.History.Mode);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Theory]
    [InlineData("--Sqlite:DataDirectory=/srv/eggmail", "/srv/eggmail")]
    [InlineData("--sqlite:datadirectory=/srv/eggmail", "/srv/eggmail")]
    [InlineData("/Sqlite:DataDirectory=/srv/eggmail", "/srv/eggmail")]
    public void The_command_line_data_directory_is_found_in_the_usual_forms(string argument, string expected) =>
        Assert.Equal(expected, ConfigLoader.DataDirectoryFromArguments(["--Dashboard:HttpPort=1", argument]));

    [Fact]
    public void The_space_separated_form_and_the_last_occurrence_win_like_the_configuration_does()
    {
        Assert.Equal("/b", ConfigLoader.DataDirectoryFromArguments(["--Sqlite:DataDirectory", "/b"]));
        Assert.Equal("/b", ConfigLoader.DataDirectoryFromArguments(["--Sqlite:DataDirectory=/a", "--Sqlite:DataDirectory=/b"]));
        Assert.Null(ConfigLoader.DataDirectoryFromArguments(["--Sqlite:DataDirectory"]));
        Assert.Null(ConfigLoader.DataDirectoryFromArguments(["--Sqlite:DataDirectory=", "--Sqlite:SyncMode=Off"]));
        Assert.Null(ConfigLoader.DataDirectoryFromArguments(null));
    }

    [Fact]
    public void The_bootstrap_file_lives_in_the_data_directory_given_on_the_command_line()
    {
        // Regression: a server started with --Sqlite:DataDirectory=<dir> read, and a backend switch wrote, /data/bootstrap.json.
        string dir = Directory.CreateTempSubdirectory().FullName;
        try
        {
            string expected = Path.Combine(dir, ConfigLoader.BootstrapFileName);
            Assert.Equal(expected, ConfigLoader.ResolveBootstrapPath(args: ["--Sqlite:DataDirectory=" + dir]));
            Assert.Equal(Path.Combine("/explicit", ConfigLoader.BootstrapFileName), ConfigLoader.ResolveBootstrapPath("/explicit", ["--Sqlite:DataDirectory=" + dir])); // a hint still wins

            File.WriteAllText(expected, "{ \"History\": { \"Mode\": \"StatsOnly\" } }");
            IConfigurationRoot root = ConfigLoader.Build(["--Sqlite:DataDirectory=" + dir]);
            Assert.Equal(HistoryMode.StatsOnly, ConfigLoader.Load(root).Config.Storage.History.Mode);
            Assert.Equal(expected, root[ConfigLoader.BootstrapPathKey]); // what the switch activator is given
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }
}
