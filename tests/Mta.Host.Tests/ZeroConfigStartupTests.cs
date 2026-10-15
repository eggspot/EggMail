using System.Text;
using Microsoft.Extensions.Configuration;
using Mta.Core;
using Mta.Host.Api;
using Mta.Host.Configuration;
using Mta.Host.Hosting;
using Mta.Host.Tls;
using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Host.Tests;

/// <summary>What a first start with little or no configuration does: the first administrator, the relay from configuration, the self-signed certificate, the data directory.</summary>
public sealed class ZeroConfigStartupTests : IAsyncLifetime
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "eggmail-zero-" + Guid.NewGuid().ToString("N"));
    private InMemoryStorage _storage = null!;

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(_dir);
        _storage = new InMemoryStorage(new StorageOptions(), SystemClock.Instance);
        await _storage.InitializeAsync(default);
    }

    public async Task DisposeAsync()
    {
        await _storage.DisposeAsync();
        Directory.Delete(_dir, recursive: true);   // created by this test
    }

    private sealed class RecordingLog : IMtaLog
    {
        public List<string> Lines { get; } = [];

        public bool IsEnabled(MtaLogLevel level) => true;

        public void Write(MtaLogLevel level, string component, string message, Exception? exception = null) => Lines.Add($"{level} {component}: {message}");
    }

    private static MtaConfig Config(Action<DashboardSectionBuilder>? dashboard = null, RelaySection? relay = null)
    {
        var b = new DashboardSectionBuilder();
        dashboard?.Invoke(b);
        return new MtaConfig
        {
            Dashboard = new DashboardSection { BootstrapAdminUser = b.User, BootstrapAdminPassword = b.Password, BootstrapAdminPasswordFile = b.PasswordFile },
            Delivery = new DeliverySection { Relay = relay ?? new RelaySection() },
        };
    }

    private sealed class DashboardSectionBuilder
    {
        public string User { get; set; } = "admin";
        public string? Password { get; set; }
        public string? PasswordFile { get; set; }
    }

    // The first administrator

    [Fact]
    public async Task A_password_from_the_environment_is_used_and_nothing_is_printed()
    {
        var log = new RecordingLog();
        BootstrapAdminResult result = await BootstrapAdmin.EnsureAsync(Config(d => { d.User = "owner"; d.Password = "a-long-chosen-password"; }), _storage, SystemClock.Instance, log, default);

        Assert.Equal(BootstrapAdminOutcome.Created, result.Outcome);
        Assert.Null(result.GeneratedPassword);
        DashboardUser user = Assert.Single(await _storage.Config.GetDashboardUsersAsync(default));
        Assert.Equal("owner", user.UserName);
        Assert.Equal(DashboardRole.Admin, user.Role);
        Assert.True(Mta.Host.Security.PasswordHasher.Verify("a-long-chosen-password", user.PasswordHash));
        Assert.DoesNotContain(log.Lines, l => l.Contains("a-long-chosen-password", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_generated_password_is_random_hashed_and_never_logged()
    {
        var log = new RecordingLog();
        BootstrapAdminResult first = await BootstrapAdmin.EnsureAsync(Config(), _storage, SystemClock.Instance, log, default);

        Assert.Equal(BootstrapAdminOutcome.CreatedWithGeneratedPassword, first.Outcome);
        string password = first.GeneratedPassword!;
        Assert.True(password.Length >= 20);
        DashboardUser user = Assert.Single(await _storage.Config.GetDashboardUsersAsync(default));
        Assert.True(Mta.Host.Security.PasswordHasher.Verify(password, user.PasswordHash));
        Assert.DoesNotContain(password, user.PasswordHash, StringComparison.Ordinal);
        Assert.DoesNotContain(log.Lines, l => l.Contains(password, StringComparison.Ordinal));   // a structured log may be shipped to a collector
        Assert.Contains(log.Lines, l => l.Contains("GENERATED", StringComparison.Ordinal));

        // A second installation gets another password.
        await using var other = new InMemoryStorage(new StorageOptions(), SystemClock.Instance);
        await other.InitializeAsync(default);
        BootstrapAdminResult second = await BootstrapAdmin.EnsureAsync(Config(), other, SystemClock.Instance, log, default);
        Assert.NotEqual(password, second.GeneratedPassword);
    }

    [Fact]
    public async Task The_next_start_with_an_administrator_creates_and_prints_nothing()
    {
        await BootstrapAdmin.EnsureAsync(Config(), _storage, SystemClock.Instance, NullMtaLog.Instance, default);

        BootstrapAdminResult again = await BootstrapAdmin.EnsureAsync(Config(), _storage, SystemClock.Instance, NullMtaLog.Instance, default);

        Assert.Equal(BootstrapAdminOutcome.AlreadyExists, again.Outcome);
        Assert.Null(again.GeneratedPassword);
        Assert.Single(await _storage.Config.GetDashboardUsersAsync(default));
    }

    [Fact]
    public async Task A_user_name_taken_by_a_non_administrator_is_a_problem_not_a_silent_success()
    {
        Tenant tenant = await MakeTenantAsync();
        await DashboardAccounts.CreateAsync(_storage.Config, SystemClock.Instance, "admin", "some-long-password", DashboardRole.Tenant, tenant.Id, default);

        BootstrapAdminResult result = await BootstrapAdmin.EnsureAsync(Config(), _storage, SystemClock.Instance, NullMtaLog.Instance, default);

        Assert.Equal(BootstrapAdminOutcome.Problem, result.Outcome);
        Assert.Contains("EGGMAIL_ADMIN_USER", result.Problem, StringComparison.Ordinal);
    }

    private async Task<Tenant> MakeTenantAsync()
    {
        var tenant = new Tenant(Ids.New(), "Acme", "acme", true, SystemClock.Instance.UtcNow, false);
        await _storage.Config.UpsertTenantAsync(tenant, default);
        return tenant;
    }

    [Fact]
    public void The_notice_is_delimited_and_carries_the_password_once()
    {
        var output = new StringWriter();

        BootstrapAdmin.WriteGeneratedPasswordNotice(output, "admin", "s3cret-generated-value", 8443);

        string text = output.ToString();
        Assert.Contains(BootstrapAdmin.NoticeBegin, text, StringComparison.Ordinal);
        Assert.Contains(BootstrapAdmin.NoticeEnd, text, StringComparison.Ordinal);
        Assert.Equal(1, text.Split("s3cret-generated-value").Length - 1);
        Assert.Contains("ONLY THIS ONCE", text, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Dashboard:BootstrapAdminPassword", "short", "at least 10")]
    public void A_short_configured_password_stops_the_start_in_validation(string key, string value, string expected)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { [key] = value }).Build();

        LoadedConfig loaded = ConfigLoader.Load(config);

        Assert.Contains(loaded.Errors, e => e.Contains(expected, StringComparison.Ordinal));
    }

    [Fact]
    public void A_password_and_a_password_file_together_stop_the_start()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Dashboard:BootstrapAdminPassword"] = "a-long-chosen-password", ["Dashboard:BootstrapAdminPasswordFile"] = "/run/secrets/pw",
        }).Build();

        Assert.Contains(ConfigLoader.Load(config).Errors, e => e.Contains("both set", StringComparison.Ordinal));
    }

    // The relay from configuration

    private static RelaySection Relay(string? address = "smtp.relay.example:587", string? user = null, string? password = null, string? passwordFile = null, string? tlsMode = null) =>
        new() { Address = address, User = user, Password = password, PasswordFile = passwordFile, TlsMode = tlsMode };

    [Fact]
    public async Task The_relay_route_is_created_from_configuration_with_the_password_protected()
    {
        var protector = new TestProtector();
        string? problem = await RelayBootstrap.ApplyAsync(Config(relay: Relay("Smtp.Relay.Example:587", "relay-user", "relay-secret")), _storage.Config, protector, NullMtaLog.Instance, default);

        Assert.Null(problem);
        RelayRouteRecord route = Assert.Single(await _storage.Config.GetRelayRoutesAsync(default));
        Assert.Equal(RelaySection.RouteName, route.Name);
        Assert.Equal("smtp.relay.example", route.Host);
        Assert.Equal(587, route.Port);
        Assert.Equal("verify", route.TlsMode);
        Assert.Equal("relay-user", route.UserName);
        Assert.Equal(["*"], route.Domains);
        Assert.True(route.Enabled);
        Assert.Equal("relay-secret", Encoding.UTF8.GetString(protector.Unprotect(route.PasswordProtected!, SecretPurposes.RelayPassword)));
    }

    [Fact]
    public async Task Port_465_means_implicit_tls_and_a_mode_can_be_chosen()
    {
        await RelayBootstrap.ApplyAsync(Config(relay: Relay("smtp.relay.example:465")), _storage.Config, new TestProtector(), NullMtaLog.Instance, default);
        Assert.Equal("implicit", Assert.Single(await _storage.Config.GetRelayRoutesAsync(default)).TlsMode);

        await RelayBootstrap.ApplyAsync(Config(relay: Relay("smtp.relay.example:2525", tlsMode: "Required")), _storage.Config, new TestProtector(), NullMtaLog.Instance, default);
        Assert.Equal("required", Assert.Single(await _storage.Config.GetRelayRoutesAsync(default)).TlsMode);
    }

    [Fact]
    public async Task A_restart_changes_nothing_and_a_new_address_updates_the_same_route_keeping_the_administrators_choices()
    {
        var protector = new TestProtector();
        await RelayBootstrap.ApplyAsync(Config(relay: Relay(user: "u", password: "p")), _storage.Config, protector, NullMtaLog.Instance, default);
        RelayRouteRecord created = Assert.Single(await _storage.Config.GetRelayRoutesAsync(default));

        await RelayBootstrap.ApplyAsync(Config(relay: Relay(user: "u", password: "p")), _storage.Config, protector, NullMtaLog.Instance, default);
        RelayRouteRecord same = Assert.Single(await _storage.Config.GetRelayRoutesAsync(default));
        Assert.Equal(created.PasswordProtected, same.PasswordProtected);

        // The administrator narrows the route to one domain and sets its priority; a changed address keeps both.
        await _storage.Config.UpsertRelayRouteAsync(same with { Domains = ["example.org"], Priority = 7 }, default);
        await RelayBootstrap.ApplyAsync(Config(relay: Relay("other.relay.example:2525", "u", "p")), _storage.Config, protector, NullMtaLog.Instance, default);

        RelayRouteRecord updated = Assert.Single(await _storage.Config.GetRelayRoutesAsync(default));
        Assert.Equal(created.Id, updated.Id);
        Assert.Equal("other.relay.example", updated.Host);
        Assert.Equal(2525, updated.Port);
        Assert.Equal(["example.org"], updated.Domains);
        Assert.Equal(7, updated.Priority);
    }

    [Fact]
    public async Task Removing_the_configuration_removes_only_the_route_it_made()
    {
        await _storage.Config.UpsertRelayRouteAsync(new RelayRouteRecord(Ids.New(), "office", "relay.office.example", 587, "verify", null, null, 50, true, ["example.org"]), default);
        await RelayBootstrap.ApplyAsync(Config(relay: Relay()), _storage.Config, new TestProtector(), NullMtaLog.Instance, default);
        Assert.Equal(2, (await _storage.Config.GetRelayRoutesAsync(default)).Count);

        await RelayBootstrap.ApplyAsync(Config(), _storage.Config, new TestProtector(), NullMtaLog.Instance, default);

        Assert.Equal("office", Assert.Single(await _storage.Config.GetRelayRoutesAsync(default)).Name);
    }

    [Fact]
    public async Task The_relay_password_can_come_from_a_file_and_a_missing_file_is_a_problem()
    {
        string file = Path.Combine(_dir, "relay-password");
        await File.WriteAllTextAsync(file, "from-file\n");
        var protector = new TestProtector();

        Assert.Null(await RelayBootstrap.ApplyAsync(Config(relay: Relay(user: "u", passwordFile: file)), _storage.Config, protector, NullMtaLog.Instance, default));
        Assert.Equal("from-file", Encoding.UTF8.GetString(protector.Unprotect(Assert.Single(await _storage.Config.GetRelayRoutesAsync(default)).PasswordProtected!, SecretPurposes.RelayPassword)));

        string? problem = await RelayBootstrap.ApplyAsync(Config(relay: Relay(user: "u", passwordFile: Path.Combine(_dir, "missing"))), _storage.Config, protector, NullMtaLog.Instance, default);
        Assert.Contains("cannot be read", problem, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Delivery:Relay:Address", "smtp.relay.example", "not host:port")]
    [InlineData("Delivery:Relay:User", "u", "without Delivery:Relay:Address")]
    public void A_relay_that_cannot_work_stops_the_start_in_validation(string key, string value, string expected)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { [key] = value }).Build();

        Assert.Contains(ConfigLoader.Load(config).Errors, e => e.Contains(expected, StringComparison.Ordinal));
    }

    [Fact]
    public void A_login_without_tls_is_refused()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Delivery:Relay:Address"] = "smtp.relay.example:587", ["Delivery:Relay:User"] = "u", ["Delivery:Relay:Password"] = "p", ["Delivery:Relay:TlsMode"] = "none",
        }).Build();

        Assert.Contains(ConfigLoader.Load(config).Errors, e => e.Contains("clear text", StringComparison.Ordinal));
    }

    // The self-signed certificate

    private DatabaseCertificateProvider Provider(string hostname, IClock? clock = null, RecordingLog? log = null) =>
        new(_storage.Config, new TestProtector(), hostname, new TlsSection(), clock ?? SystemClock.Instance, log);

    [Fact]
    public async Task The_first_start_makes_a_self_signed_certificate_and_says_so_in_the_log_at_every_start()
    {
        var first = new RecordingLog();
        var provider = Provider("mail.example.com", log: first);
        await provider.InitializeAsync(default);

        Assert.True(provider.UsingSelfSignedOnly);
        Assert.Contains("mail.example.com", provider.Describe().Single().Subjects);
        Assert.Contains(first.Lines, l => l.StartsWith("Warning tls:", StringComparison.Ordinal) && l.Contains("SELF-SIGNED", StringComparison.Ordinal) && l.Contains("EGGMAIL_ACME_EMAIL", StringComparison.Ordinal));

        var second = new RecordingLog();
        await Provider("mail.example.com", log: second).InitializeAsync(default);

        Assert.Single(await _storage.Config.GetCertificatesAsync(default), c => c.Active);   // nothing was generated again
        Assert.Contains(second.Lines, l => l.Contains("SELF-SIGNED", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_new_host_name_gets_a_new_self_signed_certificate_and_the_old_one_is_retired()
    {
        await Provider("3f2a1b9c").InitializeAsync(default);
        var renamed = Provider("mail.example.com");

        await renamed.InitializeAsync(default);

        Assert.Contains("mail.example.com", renamed.Describe().Single().Subjects);
        Assert.Single(await _storage.Config.GetCertificatesAsync(default), c => c.Active);
        Assert.Equal(2, (await _storage.Config.GetCertificatesAsync(default)).Count);

        // Going back to the first name works too (certificate names are unique).
        await Provider("3f2a1b9c").InitializeAsync(default);
        Assert.Equal(3, (await _storage.Config.GetCertificatesAsync(default)).Count);
    }

    [Fact]
    public async Task A_self_signed_certificate_close_to_expiry_is_replaced_at_start()
    {
        await Provider("mail.example.com").InitializeAsync(default);
        string before = (await _storage.Config.GetCertificatesAsync(default)).Single().Thumbprint;

        await Provider("mail.example.com", clock: new ShiftedClock(TimeSpan.FromDays(340))).InitializeAsync(default);   // 25 days left

        Assert.NotEqual(before, (await _storage.Config.GetCertificatesAsync(default)).Single(c => c.Active).Thumbprint);
    }

    [Fact]
    public async Task A_real_certificate_wins_over_the_self_signed_placeholder_whatever_it_is_called()
    {
        var provider = Provider("mail.example.com");
        await provider.InitializeAsync(default);
        var protector = new TestProtector();
        CertificateRecord real = CertificateMaterial.CreateSelfSigned("mail.example.com", protector, DateTimeOffset.UtcNow);
        // Named so that it sorts AFTER "selfsigned:" ("upload:" does), which used to let the placeholder be served first.
        await _storage.Config.UpsertCertificateAsync(real with { Id = Ids.New(), Name = "zz-real", Source = "acme" }, default);

        await provider.ReloadAsync(force: true, default);

        Assert.False(provider.UsingSelfSignedOnly);
        Assert.Equal("acme", provider.Describe()[0].Source);
        Assert.Equal(real.Thumbprint, provider.GetCertificate("mail.example.com")!.Thumbprint, ignoreCase: true);
    }

    private sealed class ShiftedClock(TimeSpan shift) : IClock
    {
        public DateTimeOffset UtcNow => DateTimeOffset.UtcNow + shift;
        public long Timestamp => System.Diagnostics.Stopwatch.GetTimestamp();
    }

    // The data directory

    [Fact]
    public void A_missing_data_directory_is_created_and_an_unwritable_one_is_explained()
    {
        string fresh = Path.Combine(_dir, "a", "b");
        Assert.Null(StartupChecks.DataDirectoryProblem(fresh));
        Assert.True(Directory.Exists(fresh));
        Assert.Empty(Directory.GetFiles(fresh));   // the probe file is gone

        string file = Path.Combine(_dir, "a-file");
        File.WriteAllText(file, "x");
        string? problem = StartupChecks.DataDirectoryProblem(Path.Combine(file, "data"));   // a path below a file cannot exist
        Assert.Contains("named volume", problem, StringComparison.Ordinal);
    }

    [Fact]
    public void Advice_is_given_when_no_host_name_is_configured()
    {
        var log = new RecordingLog();
        var unset = ConfigLoader.Load(new ConfigurationBuilder().Build());
        StartupChecks.LogAdvice(unset.Config, unset, log);

        Assert.Contains(log.Lines, l => l.Contains("EGGMAIL_HOSTNAME", StringComparison.Ordinal));

        var set = ConfigLoader.Load(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Hostname"] = "mail.example.com" }).Build());
        var quiet = new RecordingLog();
        StartupChecks.LogAdvice(set.Config, set, quiet);
        Assert.DoesNotContain(quiet.Lines, l => l.Contains("No host name is configured", StringComparison.Ordinal));
    }
}
