using Microsoft.Extensions.Configuration;
using Mta.Core;
using Mta.Host.Configuration;
using Mta.Host.Domains;
using Mta.Host.Hosting;
using Mta.Host.Tests.Api;
using Mta.Storage;
using Mta.Host.Api;
using Mta.Storage.Sqlite;

namespace Mta.Host.Tests;

/// <summary>
/// <c>Domains:Bootstrap</c> (EGGMAIL_DOMAINS): the listed domains are registered once for the first tenant, the DNS records to create are logged, and running it
/// again, or on several replicas at the same moment, changes nothing.
/// </summary>
public class DomainBootstrapTests : IAsyncLifetime
{
    private readonly TestClock _clock = new(ApiFixture.Start);
    private readonly TestProtector _protector = new();
    private readonly ListLog _log = new();
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "eggmail-bootstrap-" + Guid.NewGuid().ToString("N"));
    private IStorage _storage = null!;

    public async Task InitializeAsync()
    {
        var options = new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = _directory, StatsFlushInterval = TimeSpan.Zero } };
        _storage = SqliteStorage.Create(options, _clock);
        await _storage.InitializeAsync(default);
    }

    public async Task DisposeAsync()
    {
        await _storage.DisposeAsync();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);   // the unique directory this test created
        }
    }

    private sealed class ListLog : IMtaLog
    {
        private readonly object _gate = new();
        private readonly List<string> _lines = [];

        public IReadOnlyList<string> Lines
        {
            get
            {
                lock (_gate)
                {
                    return _lines.ToList();
                }
            }
        }

        public bool IsEnabled(MtaLogLevel level) => true;

        public void Write(MtaLogLevel level, string source, string message, Exception? exception = null)
        {
            lock (_gate)
            {
                _lines.Add($"{level} {source}: {message}");
            }
        }
    }

    private static MtaConfig ConfigFor(params string[] domains) => new()
    {
        Hostname = "mta.mail.test",
        Delivery = new DeliverySection { BounceDomain = "bounces.mail.test", PublicSendingIp = "192.0.2.10" },
        Domains = new DomainsSection { Bootstrap = [.. domains] },
    };

    private Task<DomainBootstrapResult> RunAsync(MtaConfig config) => DomainBootstrap.RunAsync(config, _storage, _protector, _clock, _log, default);

    [Fact]
    public async Task Creates_the_default_tenant_registers_each_domain_with_a_dkim_key_and_logs_the_records_to_create()
    {
        DomainBootstrapResult result = await RunAsync(ConfigFor("Example.COM", "mail.example.org."));

        Assert.Equal(["example.com", "mail.example.org"], result.Registered.Select(r => r.Domain));
        Assert.Empty(result.AlreadyRegistered);
        Assert.Empty(result.Skipped);

        Tenant tenant = Assert.Single(await _storage.Config.GetTenantsAsync(default));
        Assert.Equal(("Default", "default", true), (tenant.Name, tenant.Slug, tenant.Enabled));
        foreach (string name in new[] { "example.com", "mail.example.org" })
        {
            DomainRecord domain = (await _storage.Config.FindDomainByNameAsync(name, default))!;
            Assert.Equal(tenant.Id, domain.TenantId);
            Assert.Equal(DomainStatus.Pending, domain.Status);
            Assert.Equal("bounce." + name, domain.ReturnPathHost);
            Assert.NotNull(domain.NextCheckAt);   // the verification service picks it up
            DkimKeyRecord key = Assert.Single(await _storage.Config.GetDkimKeysAsync(domain.Id, default));
            Assert.True(key.Active);
        }

        // The log carries the exact records, one line each, in zone-file syntax.
        string log = string.Join('\n', _log.Lines);
        Assert.Contains("Information domains: Registered example.com for tenant 'Default'.", log);
        Assert.Contains("DNS records to create for example.com", log);
        Assert.Contains("._domainkey.example.com. 3600 IN TXT \"v=DKIM1; k=rsa; p=", log);
        Assert.Contains("example.com. 3600 IN TXT \"v=spf1 ip4:192.0.2.10 ~all\"", log);
        Assert.Contains("_dmarc.example.com. 3600 IN TXT \"v=DMARC1; p=none; rua=mailto:dmarc@example.com\"", log);
        Assert.Contains("bounce.example.com. 3600 IN CNAME bounces.mail.test.", log);
        Assert.Contains("; MX bounces.mail.test -> 10 mta.mail.test (published once by whoever runs EggMail, not in this zone)", log);
        Assert.Contains("_smtp._tls.example.com. 3600 IN TXT \"v=TLSRPTv1; rua=mailto:tls-rpt@example.com\"", log);
        Assert.Contains("DNS records to create for mail.example.org", log);
        Assert.All(_log.Lines, line => Assert.DoesNotContain('\n', line));
        // The private key never reaches the log.
        Assert.DoesNotContain("PRIVATE", log, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Running_it_again_changes_nothing_and_prints_nothing_new()
    {
        await RunAsync(ConfigFor("example.com"));
        int logged = _log.Lines.Count;
        Guid domainId = (await _storage.Config.FindDomainByNameAsync("example.com", default))!.Id;
        Guid keyId = Assert.Single(await _storage.Config.GetDkimKeysAsync(domainId, default)).Id;

        DomainBootstrapResult again = await RunAsync(ConfigFor("example.com", "EXAMPLE.com"));
        Assert.Empty(again.Registered);
        Assert.Equal(["example.com"], again.AlreadyRegistered);
        Assert.Equal(logged, _log.Lines.Count);
        Assert.Single(await _storage.Config.GetTenantsAsync(default));
        Assert.Single(await _storage.Config.GetDomainsAsync(null, default));
        Assert.Equal(keyId, Assert.Single(await _storage.Config.GetDkimKeysAsync(domainId, default)).Id);   // no second key

        // A new domain added to the list later is registered and printed; the old one is not printed again.
        DomainBootstrapResult more = await RunAsync(ConfigFor("example.com", "second.example.com"));
        Assert.Equal(["second.example.com"], more.Registered.Select(r => r.Domain));
        Assert.DoesNotContain(_log.Lines.Skip(logged), l => l.Contains("DNS records to create for example.com", StringComparison.Ordinal));
        Assert.Contains(_log.Lines.Skip(logged), l => l.Contains("DNS records to create for second.example.com", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Uses_the_oldest_tenant_when_there_is_one_and_does_not_create_another()
    {
        var older = new Tenant(Guid.NewGuid(), "Acme", "acme", true, ApiFixture.Start.AddDays(-30), false);
        var newer = new Tenant(Guid.NewGuid(), "Globex", "globex", true, ApiFixture.Start.AddDays(-2), false);
        await _storage.Config.UpsertTenantAsync(newer, default);
        await _storage.Config.UpsertTenantAsync(older, default);

        await RunAsync(ConfigFor("example.com"));

        Assert.Equal(2, (await _storage.Config.GetTenantsAsync(default)).Count);
        Assert.Equal(older.Id, (await _storage.Config.FindDomainByNameAsync("example.com", default))!.TenantId);
        Assert.Contains("for tenant 'Acme'", string.Join('\n', _log.Lines));
    }

    [Fact]
    public async Task A_domain_that_another_tenant_registered_is_left_alone_with_a_warning()
    {
        var first = new Tenant(Guid.NewGuid(), "Acme", "acme", true, ApiFixture.Start.AddDays(-30), false);
        var second = new Tenant(Guid.NewGuid(), "Globex", "globex", true, ApiFixture.Start.AddDays(-2), false);
        await _storage.Config.UpsertTenantAsync(first, default);
        await _storage.Config.UpsertTenantAsync(second, default);
        await _storage.Config.UpsertDomainAsync(new DomainRecord(Guid.NewGuid(), second.Id, "taken.example.com", DomainStatus.Verified, null, false, ApiFixture.Start, null, null, 0, null, false, null), default);

        DomainBootstrapResult result = await RunAsync(ConfigFor("taken.example.com", "free.example.com"));

        Assert.Equal(["free.example.com"], result.Registered.Select(r => r.Domain));
        Assert.Equal([("taken.example.com", "registered by another tenant")], result.Skipped);
        Assert.Equal(second.Id, (await _storage.Config.FindDomainByNameAsync("taken.example.com", default))!.TenantId);
        Assert.Contains(_log.Lines, l => l.StartsWith("Warning domains:", StringComparison.Ordinal) && l.Contains("taken.example.com", StringComparison.Ordinal));
    }

    [Fact]
    public async Task The_per_tenant_domain_limit_and_invalid_names_are_reported_not_fatal()
    {
        MtaConfig config = new()
        {
            Hostname = "mta.mail.test",
            Api = new ApiSection { MaxDomainsPerTenant = 1 },
            Domains = new DomainsSection { Bootstrap = ["a.example.com", "b.example.com", "not a domain"] },
        };
        DomainBootstrapResult result = await RunAsync(config);
        Assert.Equal(["a.example.com"], result.Registered.Select(r => r.Domain));
        Assert.Equal([("b.example.com", "tenant domain limit reached"), ("not a domain", "not a valid domain name")], result.Skipped);
    }

    [Fact]
    public async Task Nothing_is_touched_when_the_list_is_empty()
    {
        DomainBootstrapResult result = await RunAsync(ConfigFor());
        Assert.Empty(result.Registered);
        Assert.Empty(await _storage.Config.GetTenantsAsync(default));   // not even the default tenant
        Assert.Empty(_log.Lines);
    }

    [Fact]
    public async Task Replicas_starting_together_register_each_domain_once()
    {
        string[] names = Enumerable.Range(1, 6).Select(i => $"d{i}.example.com").ToArray();
        MtaConfig config = ConfigFor(names);

        DomainBootstrapResult[] results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() => RunAsync(config))));

        // Whoever got the lease registered; the others either saw the lease taken or found the domains already there.
        Assert.Equal(names.Order(), results.SelectMany(r => r.Registered).Select(r => r.Domain).Order());
        Assert.All(results, r => Assert.Empty(r.Skipped));
        Assert.Single(await _storage.Config.GetTenantsAsync(default));
        var domains = await _storage.Config.GetDomainsAsync(null, default);
        Assert.Equal(names.Order(), domains.Select(d => d.Name).Order());
        foreach (DomainRecord domain in domains)
        {
            Assert.Single(await _storage.Config.GetDkimKeysAsync(domain.Id, default));
        }

        // Each domain's records are printed once, however many replicas ran.
        foreach (string name in names)
        {
            Assert.Single(_log.Lines, l => l.Contains("DNS records to create for " + name + ".", StringComparison.Ordinal));
        }
    }

    [Fact]
    public async Task A_replica_that_finds_the_lease_taken_does_nothing()
    {
        Assert.NotNull(await _storage.Config.TryAcquireLeaseAsync(DomainBootstrap.LeaseName, "another-replica", TimeSpan.FromMinutes(2), _clock.UtcNow, default));

        DomainBootstrapResult result = await RunAsync(ConfigFor("example.com"));

        Assert.True(result.LeaseHeldElsewhere);
        Assert.Empty(result.Registered);
        Assert.Empty(await _storage.Config.GetDomainsAsync(null, default));
        Assert.Empty(await _storage.Config.GetTenantsAsync(default));

        // The lease expires (the other replica died): the next start registers the domains.
        _clock.Advance(TimeSpan.FromMinutes(3));
        Assert.Equal(["example.com"], (await RunAsync(ConfigFor("example.com"))).Registered.Select(r => r.Domain));
    }

    [Fact]
    public async Task The_lease_is_released_so_a_later_start_is_not_blocked()
    {
        await RunAsync(ConfigFor("example.com"));
        Assert.NotNull(await _storage.Config.TryAcquireLeaseAsync(DomainBootstrap.LeaseName, "next-start", TimeSpan.FromMinutes(2), _clock.UtcNow, default));
    }

    [Fact]
    public async Task The_registered_domain_is_picked_up_by_the_verification_schedule()
    {
        await RunAsync(ConfigFor("example.com"));
        DomainRecord domain = (await _storage.Config.FindDomainByNameAsync("example.com", default))!;
        _clock.Advance(TimeSpan.FromSeconds(91));
        Assert.Contains(await _storage.Config.GetDomainsDueForCheckAsync(_clock.UtcNow, 10, default), d => d.Id == domain.Id);
    }

    // Binding of the setting

    private static MtaConfig Bind(params (string Key, string Value)[] values)
    {
        IConfiguration configuration = new ConfigurationBuilder().AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value))).Build();
        LoadedConfig loaded = ConfigLoader.Load(configuration);
        Assert.True(loaded.IsValid, string.Join("; ", loaded.Errors));
        return loaded.Config;
    }

    [Fact]
    public void Domains_Bootstrap_takes_a_comma_or_space_separated_value_like_the_environment_alias_gives_it()
    {
        Assert.Equal(["a.example.com", "b.example.org", "c.example.net"], Bind(("Domains:Bootstrap", "a.example.com, b.example.org;c.example.net")).Domains.Bootstrap);
        Assert.Equal(["a.example.com", "b.example.org"], Bind(("Domains:Bootstrap:0", "a.example.com"), ("Domains:Bootstrap:1", "b.example.org")).Domains.Bootstrap);
        Assert.Empty(Bind().Domains.Bootstrap);
    }

    [Fact]
    public void Invalid_domain_settings_stop_the_start_with_a_message_naming_the_key()
    {
        string[] Errors(params (string Key, string Value)[] values) =>
            ConfigLoader.Load(new ConfigurationBuilder().AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value))).Build()).Errors.ToArray();

        Assert.Contains(Errors(("Domains:Bootstrap", "ok.example.com, not_a_domain")), e => e.Contains("Domains:Bootstrap entry 'not_a_domain'", StringComparison.Ordinal));
        Assert.Contains(Errors(("Domains:DmarcPolicy", "maybe")), e => e.Contains("Domains:DmarcPolicy", StringComparison.Ordinal));
        Assert.Contains(Errors(("Domains:MtaStsMaxAge", "00:00:05")), e => e.Contains("Domains:MtaStsMaxAge", StringComparison.Ordinal));
        Assert.Contains(Errors(("Domains:MtaStsMx:0", "not a host")), e => e.Contains("Domains:MtaStsMx", StringComparison.Ordinal));
        Assert.Contains(Errors(("Domains:MtaStsMode", "Testing"), ("Hostname", "localhost")), e => e.Contains("Domains:MtaStsMode needs a fully qualified Hostname", StringComparison.Ordinal));
        Assert.Empty(Errors(("Domains:MtaStsMode", "Enforce"), ("Hostname", "mta.example.net"), ("Domains:MtaStsMx:0", "*.mx.example.net")));
    }

    [Fact]
    public void The_domain_settings_reach_the_record_options()
    {
        MtaConfig config = Bind(
            ("Hostname", "MTA.Example.NET"), ("Delivery:BounceDomain", "bounces.example.net"), ("Delivery:PublicSendingIp", "203.0.113.5"), ("Api:SpfInclude", "spf.example.net"),
            ("Domains:DmarcPolicy", "quarantine"), ("Domains:DmarcReportAddress", "reports@example.net"), ("Domains:TlsReportAddress", "tls@example.net"),
            ("Domains:MtaStsMode", "enforce"), ("Domains:MtaStsMaxAge", "1.00:00:00"), ("Domains:MtaStsMx", "mx1.example.net mx2.example.net"));
        DomainRecordOptions options = EggMailApiExtensions.DomainRecordOptionsFrom(config);
        Assert.Equal("mta.example.net", options.ServerHostname);
        Assert.Equal("bounces.example.net", options.BounceDomain);
        Assert.Equal("203.0.113.5", options.PublicSendingIp);
        Assert.Equal("spf.example.net", options.SpfInclude);
        Assert.Equal("quarantine", options.DmarcPolicy);
        Assert.Equal(MtaStsServingMode.Enforce, options.MtaStsMode);
        Assert.Equal(TimeSpan.FromDays(1), options.MtaStsMaxAge);
        Assert.Equal(["mx1.example.net", "mx2.example.net"], options.MtaStsMx);
        Assert.True(options.MtaStsEnabled);
    }
}
