using System.Reflection;
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
        FirstAdministratorResult result = await FirstAdministrator.EnsureAsync(Config(d => { d.User = "owner"; d.Password = "a-long-chosen-password"; }), _storage.Config, SystemClock.Instance, log, default);

        Assert.Equal(FirstAdministratorOutcome.Created, result.Outcome);
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
        FirstAdministratorResult first = await FirstAdministrator.EnsureAsync(Config(), _storage.Config, SystemClock.Instance, log, default);

        Assert.Equal(FirstAdministratorOutcome.CreatedWithGeneratedPassword, first.Outcome);
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
        FirstAdministratorResult second = await FirstAdministrator.EnsureAsync(Config(), other.Config, SystemClock.Instance, log, default);
        Assert.NotEqual(password, second.GeneratedPassword);
    }

    [Fact]
    public async Task The_next_start_with_an_administrator_creates_and_prints_nothing()
    {
        await FirstAdministrator.EnsureAsync(Config(), _storage.Config, SystemClock.Instance, NullMtaLog.Instance, default);

        FirstAdministratorResult again = await FirstAdministrator.EnsureAsync(Config(), _storage.Config, SystemClock.Instance, NullMtaLog.Instance, default);

        Assert.Equal(FirstAdministratorOutcome.AlreadyExists, again.Outcome);
        Assert.Null(again.GeneratedPassword);
        Assert.Single(await _storage.Config.GetDashboardUsersAsync(default));
    }

    [Fact]
    public async Task A_user_name_taken_by_a_non_administrator_is_a_problem_not_a_silent_success()
    {
        Tenant tenant = await MakeTenantAsync();
        await DashboardAccounts.CreateAsync(_storage.Config, SystemClock.Instance, "admin", "some-long-password", DashboardRole.Tenant, tenant.Id, default);

        FirstAdministratorResult result = await FirstAdministrator.EnsureAsync(Config(), _storage.Config, SystemClock.Instance, NullMtaLog.Instance, default);

        Assert.Equal(FirstAdministratorOutcome.Problem, result.Outcome);
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

        FirstAdministrator.WriteGeneratedPasswordNotice(output, "admin", "s3cret-generated-value", 8443);

        string text = output.ToString();
        Assert.Contains(FirstAdministrator.NoticeBegin, text, StringComparison.Ordinal);
        Assert.Contains(FirstAdministrator.NoticeEnd, text, StringComparison.Ordinal);
        Assert.Equal(1, text.Split("s3cret-generated-value").Length - 1);
        Assert.Contains("ONLY THIS ONCE", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_generated_password_is_temporary_and_a_chosen_one_is_not()
    {
        await FirstAdministrator.EnsureAsync(Config(), _storage.Config, SystemClock.Instance, NullMtaLog.Instance, default);
        DashboardUser generated = Assert.Single(await _storage.Config.GetDashboardUsersAsync(default));
        Assert.True(Mta.Host.Security.PasswordHasher.MustChange(generated.PasswordHash));

        await using var other = new InMemoryStorage(new StorageOptions(), SystemClock.Instance);
        await other.InitializeAsync(default);
        await FirstAdministrator.EnsureAsync(Config(d => d.Password = "a-long-chosen-password"), other.Config, SystemClock.Instance, NullMtaLog.Instance, default);
        Assert.False(Mta.Host.Security.PasswordHasher.MustChange(Assert.Single(await other.Config.GetDashboardUsersAsync(default)).PasswordHash));
    }

    [Fact]
    public async Task A_password_file_is_read_trimmed_and_checked()
    {
        string good = Path.Combine(_dir, "good");
        await File.WriteAllTextAsync(good, "  a-long-file-password \r\n");
        FirstAdministratorResult created = await FirstAdministrator.EnsureAsync(Config(d => d.PasswordFile = good), _storage.Config, SystemClock.Instance, NullMtaLog.Instance, default);
        DashboardUser user = Assert.Single(await _storage.Config.GetDashboardUsersAsync(default));
        Assert.Equal(FirstAdministratorOutcome.Created, created.Outcome);
        Assert.True(Mta.Host.Security.PasswordHasher.Verify("a-long-file-password", user.PasswordHash));
        Assert.False(Mta.Host.Security.PasswordHasher.MustChange(user.PasswordHash));

        await using var empty = new InMemoryStorage(new StorageOptions(), SystemClock.Instance);
        await empty.InitializeAsync(default);
        string blank = Path.Combine(_dir, "blank");
        await File.WriteAllTextAsync(blank, " \n");
        FirstAdministratorResult problem = await FirstAdministrator.EnsureAsync(Config(d => d.PasswordFile = blank), empty.Config, SystemClock.Instance, NullMtaLog.Instance, default);
        Assert.Equal(FirstAdministratorOutcome.Problem, problem.Outcome);
        Assert.Contains("at least 10", problem.Problem, StringComparison.Ordinal);
        Assert.Empty(await empty.Config.GetDashboardUsersAsync(default));
    }

    [Fact]
    public async Task A_directory_as_the_password_file_is_a_problem_and_a_file_is_not_read_when_an_administrator_exists()
    {
        FirstAdministratorResult directory = await FirstAdministrator.EnsureAsync(Config(d => d.PasswordFile = _dir), _storage.Config, SystemClock.Instance, NullMtaLog.Instance, default);
        Assert.Equal(FirstAdministratorOutcome.Problem, directory.Outcome);
        Assert.Contains("cannot be read", directory.Problem, StringComparison.Ordinal);

        await FirstAdministrator.EnsureAsync(Config(d => d.Password = "a-long-chosen-password"), _storage.Config, SystemClock.Instance, NullMtaLog.Instance, default);
        FirstAdministratorResult later = await FirstAdministrator.EnsureAsync(Config(d => d.PasswordFile = Path.Combine(_dir, "missing")), _storage.Config, SystemClock.Instance, NullMtaLog.Instance, default);
        Assert.Equal(FirstAdministratorOutcome.AlreadyExists, later.Outcome);   // a leftover variable does not stop a server that has its administrator
    }

    [Fact]
    public async Task A_password_and_a_password_file_together_or_a_short_password_are_problems_of_the_first_start_only()
    {
        FirstAdministratorResult both = await FirstAdministrator.EnsureAsync(Config(d => { d.Password = "a-long-chosen-password"; d.PasswordFile = "/run/secrets/pw"; }), _storage.Config, SystemClock.Instance, NullMtaLog.Instance, default);
        Assert.Equal(FirstAdministratorOutcome.Problem, both.Outcome);
        Assert.Contains("both set", both.Problem, StringComparison.Ordinal);

        FirstAdministratorResult weak = await FirstAdministrator.EnsureAsync(Config(d => d.Password = "short"), _storage.Config, SystemClock.Instance, NullMtaLog.Instance, default);
        Assert.Equal(FirstAdministratorOutcome.Problem, weak.Outcome);
        Assert.Contains("EGGMAIL_ADMIN_PASSWORD", weak.Problem, StringComparison.Ordinal);
        Assert.DoesNotContain("short", weak.Problem!.Replace("shorter", "", StringComparison.Ordinal), StringComparison.Ordinal);   // the value is not repeated
        Assert.Empty(await _storage.Config.GetDashboardUsersAsync(default));

        FirstAdministratorResult badName = await FirstAdministrator.EnsureAsync(Config(d => { d.User = "  "; d.Password = "a-long-chosen-password"; }), _storage.Config, SystemClock.Instance, NullMtaLog.Instance, default);
        Assert.Equal(FirstAdministratorOutcome.Problem, badName.Outcome);
    }

    /// <summary>An <see cref="IConfigStore"/> whose first write of a dashboard user loses a race: another replica's administrator is stored first and the write is refused as a name conflict.</summary>
    public class LosesTheAdminRace : DispatchProxy
    {
        public IConfigStore Target { get; set; } = null!;
        public string OtherAdminName { get; set; } = "";
        private bool _raced;

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            if (targetMethod!.Name == nameof(IConfigStore.UpsertDashboardUserAsync) && !_raced)
            {
                _raced = true;
                var mine = (DashboardUser)args![0]!;
                Target.UpsertDashboardUserAsync(mine with { Id = Ids.New(), UserName = OtherAdminName }, default).AsTask().GetAwaiter().GetResult();
                throw new StorageConflictException("name taken");
            }

            try
            {
                return targetMethod.Invoke(Target, args);
            }
            catch (TargetInvocationException ex) when (ex.InnerException is not null)
            {
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
                throw;
            }
        }
    }

    [Fact]
    public async Task Losing_the_race_to_another_replica_is_not_an_error_and_prints_no_password()
    {
        IConfigStore racing = DispatchProxy.Create<IConfigStore, LosesTheAdminRace>();
        ((LosesTheAdminRace)racing).Target = _storage.Config;
        ((LosesTheAdminRace)racing).OtherAdminName = "admin";   // the other replica made 'admin' first, with the password it printed

        FirstAdministratorResult result = await FirstAdministrator.EnsureAsync(Config(), racing, SystemClock.Instance, NullMtaLog.Instance, default);

        Assert.Equal(FirstAdministratorOutcome.AlreadyExists, result.Outcome);
        Assert.Null(result.GeneratedPassword);   // the loser must not print a password that does not work
        Assert.Single(await _storage.Config.GetDashboardUsersAsync(default));
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

    private static void AssertUntouched(RelayRouteRecord expected, RelayRouteRecord actual)
    {
        Assert.Equal((expected.Id, expected.Name, expected.Host, expected.Port, expected.TlsMode, expected.Priority, expected.Enabled), (actual.Id, actual.Name, actual.Host, actual.Port, actual.TlsMode, actual.Priority, actual.Enabled));
        Assert.Equal(expected.Domains, actual.Domains);
    }

    [Fact]
    public async Task A_route_an_administrator_made_with_the_same_name_is_never_changed_or_deleted()
    {
        var handMade = new RelayRouteRecord(Ids.New(), RelaySection.RouteName, "relay.office.example", 587, "verify", null, null, 50, true, ["example.org"]);
        await _storage.Config.UpsertRelayRouteAsync(handMade, default);

        string? clash = await RelayBootstrap.ApplyAsync(Config(relay: Relay()), _storage.Config, new TestProtector(), NullMtaLog.Instance, default);
        Assert.Contains("did not create", clash, StringComparison.Ordinal);
        AssertUntouched(handMade, Assert.Single(await _storage.Config.GetRelayRoutesAsync(default)));

        Assert.Null(await RelayBootstrap.ApplyAsync(Config(), _storage.Config, new TestProtector(), NullMtaLog.Instance, default));   // the configuration is gone: still not deleted
        AssertUntouched(handMade, Assert.Single(await _storage.Config.GetRelayRoutesAsync(default)));
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

    private DatabaseCertificateProvider Provider(string hostname, IClock? clock = null, RecordingLog? log = null, bool replaceOnHostnameChange = true) =>
        new(_storage.Config, new TestProtector(), hostname, new TlsSection(), clock ?? SystemClock.Instance, log, replaceOnHostnameChange);

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
    public async Task A_host_name_nobody_chose_does_not_replace_the_certificate_each_time_but_expiry_always_does()
    {
        // A recreated container gets a new random host name every time: a certificate each time would only pile up.
        await Provider("3f2a1b9c", replaceOnHostnameChange: false).InitializeAsync(default);
        var recreated = Provider("77aa00bb", replaceOnHostnameChange: false);
        await recreated.InitializeAsync(default);

        Assert.Single(await _storage.Config.GetCertificatesAsync(default));
        Assert.Contains("3f2a1b9c", recreated.Describe().Single().Subjects);

        await Provider("77aa00bb", clock: new ShiftedClock(TimeSpan.FromDays(340)), replaceOnHostnameChange: false).InitializeAsync(default);   // 25 days left
        Assert.Equal(2, (await _storage.Config.GetCertificatesAsync(default)).Count);
        Assert.Single(await _storage.Config.GetCertificatesAsync(default), c => c.Active);
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
    public void Advice_is_given_when_nothing_names_the_server_even_though_the_container_runtime_set_HOSTNAME()
    {
        var unset = ConfigLoader.Load(new ConfigurationBuilder().Build());
        // What a container has: HOSTNAME is the machine name, and that is all.
        Func<string, string?> container = name => name == "HOSTNAME" ? unset.Config.Hostname : null;
        var log = new RecordingLog();

        StartupChecks.LogAdvice(unset.Config, log, container);

        Assert.Contains(log.Lines, l => l.Contains("No host name is configured", StringComparison.Ordinal) && l.Contains("EGGMAIL_HOSTNAME", StringComparison.Ordinal));
        Assert.False(StartupChecks.HostnameConfigured(unset.Config, container));
    }

    [Fact]
    public void No_advice_when_the_server_is_named_by_any_means()
    {
        var named = ConfigLoader.Load(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Hostname"] = "mail.example.com" }).Build());
        var viaAlias = ConfigLoader.Load(new ConfigurationBuilder().Build());

        var quiet = new RecordingLog();
        StartupChecks.LogAdvice(named.Config, quiet, _ => null);
        Assert.DoesNotContain(quiet.Lines, l => l.Contains("No host name is configured", StringComparison.Ordinal));
        Assert.True(StartupChecks.HostnameConfigured(viaAlias.Config, name => name == "EGGMAIL_HOSTNAME" ? "x.example.com" : null));
        Assert.True(StartupChecks.HostnameConfigured(viaAlias.Config, name => name == "Hostname" ? viaAlias.Config.Hostname : null));
    }

    [Fact]
    public void EGGMAIL_HOSTNAME_says_when_it_overrides_a_different_Hostname_from_a_file_or_the_environment()
    {
        string directory = Path.Combine(_dir, "override");
        Directory.CreateDirectory(directory);
        string appSettings = Path.Combine(directory, "appsettings.json");
        File.WriteAllText(appSettings, """{ "Hostname": "from-file.example.com" }""");
        Func<string, string?> env = name => name == "EGGMAIL_HOSTNAME" ? "alias.example.com" : null;
        IConfigurationRoot root = ConfigLoader.Build([], dataDirectoryHint: directory, appSettingsPath: appSettings, environment: env);
        MtaConfig config = ConfigLoader.Load(root).Config;

        Assert.Equal("alias.example.com", config.Hostname);
        string note = StartupChecks.HostnameOverrideNote(config, root, env)!;
        Assert.Contains("from-file.example.com", note, StringComparison.Ordinal);
        Assert.Contains("overrides", note, StringComparison.Ordinal);
        var log = new RecordingLog();
        StartupChecks.LogAdvice(config, log, env, root);
        Assert.Contains(log.Lines, l => l.StartsWith("Warning ", StringComparison.Ordinal) && l.Contains("overrides", StringComparison.Ordinal));

        // The long-form environment variable (exact case), too; the same value, a missing alias and the HOSTNAME of the container runtime say nothing.
        Assert.Contains("long.example.com", StartupChecks.HostnameOverrideNote(config, null, n => n switch { "EGGMAIL_HOSTNAME" => "alias.example.com", "Hostname" => "long.example.com", _ => null })!, StringComparison.Ordinal);
        Assert.Null(StartupChecks.HostnameOverrideNote(config, null, n => n switch { "EGGMAIL_HOSTNAME" => "alias.example.com", "Hostname" => "ALIAS.example.com.", _ => null }));
        Assert.Null(StartupChecks.HostnameOverrideNote(config, root, _ => null));
        Assert.Null(StartupChecks.HostnameOverrideNote(config, null, n => n switch { "EGGMAIL_HOSTNAME" => "alias.example.com", "HOSTNAME" => "3f2a1b9c0d11", _ => null }));
    }

    [Theory]
    [InlineData("mail.example.com", 0)]
    [InlineData("mail_01.example.com", 1)]
    [InlineData("mail", 1)]
    [InlineData("my_mail", 2)]
    public void A_host_name_that_receiving_servers_dislike_is_warned_about(string name, int warnings)
    {
        Assert.Equal(warnings, StartupChecks.HeloNameWarnings(name).Count);
    }

    [Fact]
    public void The_helo_warnings_are_logged_for_a_configured_but_odd_name()
    {
        var config = ConfigLoader.Load(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Hostname"] = "my_mail" }).Build());
        var log = new RecordingLog();

        StartupChecks.LogAdvice(config.Config, log, _ => null);

        Assert.Contains(log.Lines, l => l.Contains("underscore", StringComparison.Ordinal));
        Assert.Contains(log.Lines, l => l.Contains("single label", StringComparison.Ordinal));
    }

    [Fact]
    public void PostgreSQL_selected_next_to_the_sqlite_files_of_an_earlier_run_is_a_loud_warning()
    {
        string data = Path.Combine(_dir, "earlier");
        Directory.CreateDirectory(data);
        File.WriteAllText(Path.Combine(data, "config.db"), "x");
        MtaConfig postgres = ConfigLoader.Load(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Storage:Backend"] = "Postgres", ["Sqlite:DataDirectory"] = data, ["Storage:Postgres:RuntimeConnectionString"] = "Host=db;Username=u",
        }).Build()).Config;

        string? warning = StartupChecks.AbandonedSqliteDataWarning(postgres);

        Assert.Contains("NOT used", warning, StringComparison.Ordinal);
        Assert.Contains("migrate-storage", warning, StringComparison.Ordinal);
        var log = new RecordingLog();
        StartupChecks.LogAdvice(postgres, log, _ => null);
        Assert.Contains(log.Lines, l => l.StartsWith("Warning ", StringComparison.Ordinal) && l.Contains("NOT used", StringComparison.Ordinal));

        // A deliberate switch writes the bootstrap file: then the old files are the rollback copy, not a mistake.
        File.WriteAllText(Path.Combine(data, ConfigLoader.BootstrapFileName), "{}");
        Assert.Null(StartupChecks.AbandonedSqliteDataWarning(postgres));
        // And SQLite next to its own files is normal.
        Assert.Null(StartupChecks.AbandonedSqliteDataWarning(ConfigLoader.Load(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sqlite:DataDirectory"] = data }).Build()).Config));
    }
}
