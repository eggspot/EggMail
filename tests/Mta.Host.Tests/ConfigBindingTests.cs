using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Mta.Core;
using Mta.Host.Api;
using Mta.Host.Configuration;
using Mta.Host.Hosting;
using Mta.Host.Switching;
using Mta.Storage;
using Mta.Storage.InMemory;
using Mta.Storage.Portability;

namespace Mta.Host.Tests;

/// <summary>Every key the documentation promises is bound, validated and reaches the component that uses it (docs/operations.md, docs/api.md).</summary>
public class ConfigBindingTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("eggmail-config-").FullName;

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Directory.Delete(_dir, recursive: true);
    }

    private static LoadedConfig Load(params (string Key, string? Value)[] values) =>
        ConfigLoader.Load(new ConfigurationBuilder().AddInMemoryCollection(values.ToDictionary(v => v.Key, v => v.Value)).Build());

    private static LoadedConfig Valid(params (string Key, string? Value)[] values)
    {
        LoadedConfig loaded = Load(values);
        Assert.True(loaded.IsValid, string.Join("; ", loaded.Errors));
        return loaded;
    }

    // Tls and Acme

    [Fact]
    public void Tls_and_Acme_settings_come_from_appsettings_json_and_the_command_line()
    {
        string appSettings = Path.Combine(_dir, "appsettings.json");
        File.WriteAllText(appSettings, """
            {
              "Tls": { "CertificatePath": "/certs/tls.crt", "KeyPath": "/certs/tls.key", "PfxPasswordFile": "/run/secrets/pfx", "PollInterval": "00:01:00", "ReportingEnabled": false, "ReportContact": "tls@example.org" },
              "Acme": { "Enabled": true, "Email": "ops@example.org", "Domains": [ "mx.example.org", "*.example.org" ], "CloudflareApiTokenFile": "/run/secrets/cf",
                        "CertificateName": "main", "RenewAtRemainingFraction": 0.25, "CheckInterval": "02:00:00", "PropagationDelay": "00:00:10" }
            }
            """);

        // The command line is the highest layer; it changes the directory to the ACME staging server.
        LoadedConfig loaded = ConfigLoader.Load(ConfigLoader.Build(["--Acme:DirectoryUrl=https://acme-staging-v02.api.letsencrypt.org/directory"], _dir, appSettings));

        Assert.True(loaded.IsValid, string.Join("; ", loaded.Errors));
        TlsSection tls = loaded.Config.Tls;
        Assert.Equal("/certs/tls.crt", tls.CertificatePath);
        Assert.Equal("/certs/tls.key", tls.KeyPath);
        Assert.Equal("/run/secrets/pfx", tls.PfxPasswordFile);
        Assert.Equal(TimeSpan.FromMinutes(1), tls.PollInterval);
        Assert.False(tls.ReportingEnabled);
        Assert.Equal("tls@example.org", tls.ReportContact);

        AcmeSection acme = loaded.Config.Acme;
        Assert.True(acme.Enabled);
        Assert.Equal("https://acme-staging-v02.api.letsencrypt.org/directory", acme.DirectoryUrl);
        Assert.Equal("ops@example.org", acme.Email);
        Assert.Equal(["mx.example.org", "*.example.org"], acme.Domains);
        Assert.Equal("/run/secrets/cf", acme.CloudflareApiTokenFile);
        Assert.Equal("main", acme.CertificateName);
        Assert.Equal(0.25, acme.RenewAtRemainingFraction);
        Assert.Equal(TimeSpan.FromHours(2), acme.CheckInterval);
        Assert.Equal(TimeSpan.FromSeconds(10), acme.PropagationDelay);
    }

    [Fact]
    public void Tls_and_Acme_defaults_are_those_of_the_sections()
    {
        LoadedConfig loaded = Valid();
        Assert.False(loaded.Config.Acme.Enabled);
        Assert.True(loaded.Config.Tls.ReportingEnabled);
        Assert.Null(loaded.Config.Tls.CertificatePath);
        Assert.Equal(TimeSpan.FromSeconds(30), loaded.Config.Tls.PollInterval);
        Assert.Equal("https://acme-v02.api.letsencrypt.org/directory", loaded.Config.Acme.DirectoryUrl);
        Assert.Empty(loaded.Config.Acme.Domains);
    }

    [Fact]
    public void Acme_domains_may_be_one_comma_separated_value_as_an_environment_variable_would_carry_them()
    {
        LoadedConfig loaded = Valid(("Acme:Enabled", "true"), ("Acme:CloudflareApiToken", "t"), ("Acme:Domains", "mx.example.org, *.example.org;api.example.org"));
        Assert.Equal(["mx.example.org", "*.example.org", "api.example.org"], loaded.Config.Acme.Domains);
    }

    [Theory]
    [InlineData("Acme:Enabled=true", "Acme:CloudflareApiToken")]
    [InlineData("Acme:Enabled=true;Acme:CloudflareApiToken=t;Acme:DnsProvider=Route53", "Acme:DnsProvider")]
    [InlineData("Acme:Enabled=true;Acme:CloudflareApiToken=t;Acme:DirectoryUrl=not a url", "Acme:DirectoryUrl")]
    [InlineData("Acme:Enabled=true;Acme:CloudflareApiToken=t;Acme:RenewAtRemainingFraction=1.5", "Acme:RenewAtRemainingFraction")]
    [InlineData("Acme:Enabled=true;Acme:CloudflareApiToken=t;Acme:CheckInterval=00:00:00", "Acme:CheckInterval")]
    [InlineData("Tls:KeyPath=/k.pem", "Tls:KeyPath")]
    [InlineData("Tls:PollInterval=00:00:00", "Tls:PollInterval")]
    public void Unusable_Tls_and_Acme_settings_are_reported_at_start(string settings, string expectedInError)
    {
        LoadedConfig loaded = Load(settings.Split(';').Select(s => (s[..s.IndexOf('=')], (string?)s[(s.IndexOf('=') + 1)..])).ToArray());
        Assert.Contains(loaded.Errors, e => e.Contains(expectedInError, StringComparison.Ordinal));
    }

    [Fact]
    public void Acme_settings_are_not_checked_while_ACME_is_off()
    {
        Assert.True(Load(("Acme:DnsProvider", "Route53"), ("Acme:RenewAtRemainingFraction", "7")).IsValid);
    }

    [Theory]
    [InlineData("Smtp:MaxRecipients", "many")]
    [InlineData("Tls:PollInterval", "soon")]
    [InlineData("Acme:Enabled", "maybe")]
    [InlineData("Queue:MaxLifetimeDays", "1.5")]
    [InlineData("Api:CookieSecure", "Sometimes")]
    public void A_value_of_the_wrong_type_is_a_configuration_error_not_a_crash(string key, string value)
    {
        LoadedConfig loaded = Load((key, value));
        Assert.False(loaded.IsValid);
        Assert.Contains(loaded.Errors, e => e.Contains(key, StringComparison.Ordinal));
    }

    // Queue lifetime

    [Fact]
    public void Queue_MaxLifetimeDays_is_read_and_the_time_span_form_still_works_and_wins()
    {
        Assert.Equal(TimeSpan.FromDays(3), Valid(("Queue:MaxLifetimeDays", "3")).Config.Storage.Queue.MaxLifetime);
        Assert.Equal(TimeSpan.FromDays(2), Valid(("Queue:MaxLifetime", "2.00:00:00")).Config.Storage.Queue.MaxLifetime);
        Assert.Equal(TimeSpan.FromDays(2), Valid(("Queue:MaxLifetime", "2.00:00:00"), ("Queue:MaxLifetimeDays", "3")).Config.Storage.Queue.MaxLifetime);
        Assert.Equal(TimeSpan.FromDays(5), Valid().Config.Storage.Queue.MaxLifetime);
        Assert.Contains(Load(("Queue:MaxLifetimeDays", "0")).Errors, e => e.Contains("must be positive", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_queue_lifetime_saved_through_the_settings_api_is_what_the_next_start_runs_with()
    {
        await using var storage = new InMemoryStorage(new StorageOptions());
        await storage.InitializeAsync(default);
        var service = new SettingsService(storage, new StorageOptions(), new ApiOptions(), SystemClock.Instance);

        await service.UpdateGlobalAsync(new Dictionary<string, JsonElement> { ["Queue:MaxLifetimeDays"] = JsonSerializer.SerializeToElement(3) }, default);

        var stored = await StoredSettings.LoadAsync(storage.Config, default);
        LoadedConfig next = ConfigLoader.Load(ConfigLoader.Build([], _dir, appSettingsPath: Path.Combine(_dir, "none.json"), storedSettings: stored));
        Assert.True(next.IsValid, string.Join("; ", next.Errors));
        Assert.Equal(TimeSpan.FromDays(3), next.Config.Storage.Queue.MaxLifetime);

        // The settings page then shows what is in force, and a deployment that sets either spelling locks it.
        var listed = await service.ListGlobalAsync(default);
        Assert.Equal(3, listed.Items.Single(i => i.Key == "Queue:MaxLifetimeDays").Value.GetInt32());
        foreach (string deploymentKey in new[] { "Queue:MaxLifetime", "Queue:MaxLifetimeDays" })
        {
            var locking = new SettingsService(storage, new StorageOptions(), new ApiOptions { LockedKeys = new HashSet<string>([deploymentKey], StringComparer.OrdinalIgnoreCase) }, SystemClock.Instance);
            Assert.True((await locking.ListGlobalAsync(default)).Items.Single(i => i.Key == "Queue:MaxLifetimeDays").Locked, deploymentKey);
        }
    }

    // Api

    [Fact]
    public void Api_defaults_are_the_documented_defaults()
    {
        ApiOptions fromConfig = EggMailApiExtensions.ApiOptionsFrom(Valid().Config, new HashSet<string>());
        var defaults = new ApiOptions();
        Assert.Equal(defaults.MaxBodyBytes, fromConfig.MaxBodyBytes);
        Assert.Equal(1024 * 1024, fromConfig.MaxBodyBytes);
        Assert.Equal(40L * 1024 * 1024, fromConfig.MaxSendBodyBytes);
        Assert.Equal(TimeSpan.FromHours(12), fromConfig.SessionLifetime);
        Assert.Equal(TimeSpan.FromHours(2), fromConfig.SessionIdleTimeout);
        Assert.Equal(CookieSecureMode.Auto, fromConfig.CookieSecure);
        Assert.Equal(200, fromConfig.MaxDomainsPerTenant);
        Assert.Equal(defaults.MetricsAllowedNetworks.Select(n => n.ToString()), fromConfig.MetricsAllowedNetworks.Select(n => n.ToString()));
        Assert.Null(fromConfig.SpfInclude);
    }

    [Fact]
    public void Api_settings_reach_ApiOptions()
    {
        LoadedConfig loaded = Valid(
            ("Api:MaxBodyBytes", "2097152"), ("Api:MaxSendBodyBytes", "10485760"), ("Api:MaxInFlightSendBytes", "104857600"),
            ("Api:MaxAttachments", "5"), ("Api:MaxCustomHeaders", "7"), ("Api:MaxTags", "3"),
            ("Api:SessionLifetime", "08:00:00"), ("Api:SessionIdleTimeout", "00:30:00"), ("Api:CookieSecure", "Always"),
            ("Api:MaxDomainsPerTenant", "20"), ("Api:MaxApiKeysPerTenant", "21"), ("Api:MaxSmtpCredentialsPerTenant", "22"), ("Api:MaxWebhooksPerTenant", "23"),
            ("Api:MaxStatsRows", "1000"), ("Api:MetricsAllowedNetworks", "203.0.113.0/24, 2001:db8::/32"), ("Api:SpfInclude", "spf.mail.example.org"),
            ("Smtp:MaxMessageSize", "1048576"), ("Smtp:MaxRecipients", "9"));

        ApiOptions o = EggMailApiExtensions.ApiOptionsFrom(loaded.Config, loaded.LockedKeys);

        Assert.Equal(2097152, o.MaxBodyBytes);
        Assert.Equal(10485760, o.MaxSendBodyBytes);
        Assert.Equal(104857600, o.MaxInFlightSendBytes);
        Assert.Equal((5, 7, 3), (o.MaxAttachments, o.MaxCustomHeaders, o.MaxTags));
        Assert.Equal(TimeSpan.FromHours(8), o.SessionLifetime);
        Assert.Equal(TimeSpan.FromMinutes(30), o.SessionIdleTimeout);
        Assert.Equal(CookieSecureMode.Always, o.CookieSecure);
        Assert.Equal((20, 21, 22, 23), (o.MaxDomainsPerTenant, o.MaxApiKeysPerTenant, o.MaxSmtpCredentialsPerTenant, o.MaxWebhooksPerTenant));
        Assert.Equal(1000, o.MaxStatsRows);
        Assert.Equal(["203.0.113.0/24", "2001:db8::/32"], o.MetricsAllowedNetworks.Select(n => n.ToString()));
        Assert.Equal("spf.mail.example.org", o.SpfInclude);
        Assert.Equal(1048576, o.MaxMessageBytes);
        Assert.Equal(9, o.MaxRecipients);
        Assert.Contains("Api:MaxBodyBytes", o.LockedKeys);
    }

    [Theory]
    [InlineData("Api:MaxBodyBytes", "0")]
    [InlineData("Api:SessionLifetime", "00:00:00")]
    [InlineData("Api:SessionIdleTimeout", "-00:01:00")]
    [InlineData("Api:MaxWebhooksPerTenant", "0")]
    [InlineData("Api:MetricsAllowedNetworks", "10.0.0.0/8, not-a-network")]
    public void Unusable_Api_settings_are_reported_at_start(string key, string value)
    {
        LoadedConfig loaded = Load((key, value));
        Assert.Contains(loaded.Errors, e => e.Contains(key, StringComparison.Ordinal));
    }

    [Fact]
    public void The_kestrel_request_limit_never_undercuts_what_the_api_allows_for_a_send()
    {
        Assert.Equal(64L * 1024 * 1024, KestrelHosting.RequestBodyLimit(Valid().Config.Api));
        Assert.Equal(100L * 1024 * 1024, KestrelHosting.RequestBodyLimit(Valid(("Api:MaxSendBodyBytes", "104857600")).Config.Api));
    }

    [Fact]
    public void Webhook_settings_including_the_retry_schedule_are_bound()
    {
        var w = Valid(("Webhooks:Timeout", "00:00:20"), ("Webhooks:AllowHttp", "true"), ("Webhooks:RetrySchedule:0", "00:00:01"), ("Webhooks:RetrySchedule:1", "00:10:00")).Config.Webhooks;
        Assert.Equal(TimeSpan.FromSeconds(20), w.Timeout);
        Assert.True(w.AllowHttp);
        Assert.Equal([TimeSpan.FromSeconds(1), TimeSpan.FromMinutes(10)], w.RetrySchedule);
    }

    // PostgreSQL and SQLite tuning

    [Fact]
    public void Storage_tuning_knobs_are_bound_for_both_backends()
    {
        StorageOptions s = Valid(
            ("Storage:Postgres:PartitionsAheadDays", "14"), ("Storage:Postgres:StatsFlushInterval", "00:00:05"), ("Storage:Postgres:RetentionDeleteBatchSize", "1000"),
            ("Storage:Postgres:RetentionDeletePause", "00:00:00.100"), ("Storage:Postgres:CommandTimeoutSeconds", "60"), ("Storage:Postgres:MaxPoolSize", "12"),
            ("Sqlite:StatsFlushInterval", "00:00:20"), ("Sqlite:RetentionDeleteBatchSize", "2000"), ("Sqlite:RetentionDeletePause", "00:00:00.050")).Config.Storage;

        Assert.Equal(14, s.Postgres.PartitionsAheadDays);
        Assert.Equal(TimeSpan.FromSeconds(5), s.Postgres.StatsFlushInterval);
        Assert.Equal(1000, s.Postgres.RetentionDeleteBatchSize);
        Assert.Equal(TimeSpan.FromMilliseconds(100), s.Postgres.RetentionDeletePause);
        Assert.Equal(60, s.Postgres.CommandTimeoutSeconds);
        Assert.Equal(12, s.Postgres.MaxPoolSize);
        Assert.Equal(TimeSpan.FromSeconds(20), s.Sqlite.StatsFlushInterval);
        Assert.Equal(2000, s.Sqlite.RetentionDeleteBatchSize);
        Assert.Equal(TimeSpan.FromMilliseconds(50), s.Sqlite.RetentionDeletePause);
    }

    [Fact]
    public void Storage_tuning_defaults_are_those_of_the_options_classes()
    {
        StorageOptions s = Valid().Config.Storage;
        var d = new StorageOptions();
        Assert.Equal(d.Postgres.PartitionsAheadDays, s.Postgres.PartitionsAheadDays);
        Assert.Equal(d.Postgres.StatsFlushInterval, s.Postgres.StatsFlushInterval);
        Assert.Equal(d.Postgres.RetentionDeleteBatchSize, s.Postgres.RetentionDeleteBatchSize);
        Assert.Equal(d.Postgres.RetentionDeletePause, s.Postgres.RetentionDeletePause);
        Assert.Equal(d.Postgres.CommandTimeoutSeconds, s.Postgres.CommandTimeoutSeconds);
        Assert.Equal(d.Sqlite.StatsFlushInterval, s.Sqlite.StatsFlushInterval);
        Assert.Equal(d.Sqlite.RetentionDeleteBatchSize, s.Sqlite.RetentionDeleteBatchSize);
    }

    [Theory]
    [InlineData("Storage:Postgres:PartitionsAheadDays", "-1")]
    [InlineData("Storage:Postgres:RetentionDeleteBatchSize", "0")]
    [InlineData("Storage:Postgres:CommandTimeoutSeconds", "0")]
    [InlineData("Storage:Postgres:StatsFlushInterval", "-00:00:01")]
    [InlineData("Storage:Postgres:MaxPoolSize", "0")]
    [InlineData("Sqlite:RetentionDeleteBatchSize", "0")]
    [InlineData("Sqlite:StatsFlushInterval", "-00:00:01")]
    public void Out_of_range_tuning_knobs_are_reported_at_start_not_when_the_storage_is_created(string key, string value)
    {
        Assert.Contains(Load((key, value)).Errors, e => e.Contains(key, StringComparison.Ordinal));
    }

    // Layering keeps the source (the switch flow)

    [Fact]
    public async Task After_a_global_setting_was_saved_the_switch_flow_still_finds_its_target_and_activator()
    {
        string bootstrapDirectory = _dir;
        string[] args = [$"--Sqlite:DataDirectory={_dir}", "--SwitchTarget:Connections:pg=Host=db.example.org;Database=egg;Username=u;Password=p"];
        LoadedConfig deployment = ConfigLoader.Load(ConfigLoader.Build(args, bootstrapDirectory));
        IStorage storage = Mta.Storage.Sqlite.SqliteStorage.Create(deployment.Config.Storage);
        await storage.InitializeAsync(default);
        await storage.Config.SetSettingAsync(new SettingRecord("Retention:MetadataDays", null, "14", DateTimeOffset.UtcNow), default);   // a saved global setting

        var (final, current) = await SettingsLayering.ApplyAsync(args, deployment, storage, SystemClock.Instance, NullMtaLog.Instance, default);
        await using var _ = current;

        Assert.Equal(14, final.Config.Storage.Retention.MetadataDays);
        Assert.NotNull(final.Source);
        var services = new ServiceCollection();
        ApiHosting.AddSwitchTargetServices(services, final);
        using ServiceProvider provider = services.BuildServiceProvider();
        Assert.NotNull(provider.GetService<ISwitchActivator>());
        ResolvedSwitchTarget target = provider.GetRequiredService<ISwitchTargetResolver>().Resolve(
            new Mta.Host.Api.SwitchRequestModel { To = "postgres", Target = new Mta.Host.Api.SwitchTargetModel { ConnectionName = "pg" } });
        Assert.Equal(StorageBackend.Postgres, target.Storage.Backend);
        Assert.Contains("db.example.org", target.Storage.Postgres.RuntimeConnectionString);
    }

    [Fact]
    public void A_stored_setting_is_not_a_deployment_lock_for_the_switch_activator()
    {
        string bootstrap = Path.Combine(_dir, ConfigLoader.BootstrapFileName);
        IConfigurationRoot stored = ConfigLoader.Build([], _dir, Path.Combine(_dir, "none.json"), [new("History:Mode", "StatsOnly")]);
        Assert.Equal(HistoryMode.StatsOnly, ConfigLoader.Load(stored).Config.Storage.History.Mode);
        Assert.Null(new SwitchActivator(stored, bootstrap).DeploymentSupplier("History:Mode"));

        IConfigurationRoot withCommandLine = ConfigLoader.Build(["--History:Mode=Full"], _dir, Path.Combine(_dir, "none.json"), [new("History:Mode", "StatsOnly")]);
        Assert.Equal("the command line", new SwitchActivator(withCommandLine, bootstrap).DeploymentSupplier("History:Mode"));
    }
}
