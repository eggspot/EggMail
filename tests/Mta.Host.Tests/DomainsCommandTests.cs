using Mta.Core;
using Mta.Dns;
using Mta.Host.Configuration;
using Mta.Host.Domains;
using Mta.Host.Hosting;
using Mta.Host.Tests.Api;
using Mta.Storage;
using Mta.Storage.Sqlite;

namespace Mta.Host.Tests;

/// <summary><c>mta domains records DOMAIN</c> and <c>mta domains check DOMAIN</c>: the records to create, on demand, for a domain that is registered.</summary>
public class DomainsCommandTests : IAsyncLifetime
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "eggmail-domains-cli-" + Guid.NewGuid().ToString("N"));
    private string[] Config => [$"--Sqlite:DataDirectory={_directory}", "--Hostname=mta.mail.test", "--Delivery:BounceDomain=bounces.mail.test"];

    public async Task InitializeAsync()
    {
        // A domain registered the way Domains:Bootstrap does it, in a data directory no server has open.
        var storage = SqliteStorage.Create(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = _directory } }, SystemClock.Instance);
        await storage.InitializeAsync(default);
        var config = new MtaConfig
        {
            Hostname = "mta.mail.test",
            Delivery = new DeliverySection { BounceDomain = "bounces.mail.test" },
            Domains = new DomainsSection { Bootstrap = ["example.com"] },
        };
        await DomainBootstrap.RunAsync(config, storage, new TestProtector(), SystemClock.Instance, NullMtaLog.Instance, default);
        await storage.DisposeAsync();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
    }

    public Task DisposeAsync()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);   // the unique directory this test created
        }

        return Task.CompletedTask;
    }

    private async Task<(int Code, string Out, string Err)> RunAsync(IDnsResolver? dns, params string[] args)
    {
        var o = new StringWriter();
        var e = new StringWriter();
        int code = await DomainsCommand.RunAsync(args.Concat(Config).ToArray(), o, e, dns);
        return (code, o.ToString(), e.ToString());
    }

    [Fact]
    public async Task Records_prints_the_zone_file_of_a_registered_domain()
    {
        var result = await RunAsync(null, "records", "Example.COM");
        Assert.Equal(0, result.Code);
        Assert.StartsWith("DNS records to create for example.com.", result.Out);
        Assert.Contains("; DNS records for example.com", result.Out);
        Assert.Contains("._domainkey.example.com. 3600 IN TXT \"v=DKIM1; k=rsa; p=", result.Out);
        Assert.Contains("bounce.example.com. 3600 IN CNAME bounces.mail.test.", result.Out);
        Assert.Contains("; MX bounces.mail.test -> 10 mta.mail.test (published once by whoever runs EggMail, not in this zone)", result.Out);
        Assert.Contains("_dmarc.example.com. 3600 IN TXT \"v=DMARC1; p=none; rua=mailto:dmarc@example.com\"", result.Out);
        Assert.Equal("", result.Err);
    }

    [Fact]
    public async Task An_unregistered_domain_says_how_to_add_it()
    {
        var result = await RunAsync(null, "records", "stranger.example");
        Assert.Equal(1, result.Code);
        Assert.Contains("stranger.example is not registered", result.Err);
        Assert.Contains("Domains:Bootstrap", result.Err);
    }

    [Fact]
    public async Task Bad_usage_and_bad_names_are_refused()
    {
        Assert.Equal(64, (await RunAsync(null)).Code);
        Assert.Equal(64, (await RunAsync(null, "records")).Code);
        Assert.Equal(64, (await RunAsync(null, "frobnicate", "example.com")).Code);
        var bad = await RunAsync(null, "records", "not a domain");
        Assert.Equal(64, bad.Code);
        Assert.Contains("not a valid domain name", bad.Err);
    }

    [Fact]
    public async Task A_running_sqlite_server_holds_the_directory_and_the_command_says_where_else_to_look()
    {
        using var held = Mta.Host.Switching.DataDirectoryLock.Acquire(_directory);
        var result = await RunAsync(null, "records", "example.com");
        Assert.Equal(3, result.Code);
        Assert.Contains("Stop the server first", result.Err);
        Assert.Contains("/records", result.Err);
    }

    [Fact]
    public async Task Check_prints_each_record_with_its_status_and_what_was_found_next_to_what_is_expected()
    {
        // Publish the required records only; the DKIM key is read from the store to build the answer.
        string records = (await RunAsync(null, "records", "example.com")).Out;
        string dkimLine = records.Split('\n').Single(l => l.Contains("._domainkey.example.com. 3600 IN TXT"));
        string dkimHost = dkimLine[..dkimLine.IndexOf(". ", StringComparison.Ordinal)];
        string dkimValue = string.Concat(dkimLine[(dkimLine.IndexOf("TXT ", StringComparison.Ordinal) + 4)..].Split("\" \"")).Trim('"');
        var dns = new StaticDnsResolver().AddTxt(dkimHost, dkimValue).AddCname("bounce.example.com", "bounces.mail.test").AddTxt("example.com", "v=spf1 include:other.test ~all");

        var result = await RunAsync(dns, "check", "example.com");

        Assert.Equal(0, result.Code);   // the required records are there
        Assert.Matches(@"OK\s+DKIM\s+required\s+TXT egg\d{6}\._domainkey\.example\.com", result.Out);
        Assert.Matches(@"OK\s+Return-path\s+required\s+CNAME bounce\.example\.com", result.Out);
        Assert.Matches(@"MISMATCH\s+SPF\s+recommended\s+TXT example\.com", result.Out);
        Assert.Contains("found:    v=spf1 include:other.test ~all", result.Out);
        Assert.Contains("expected: v=spf1 a:mta.mail.test ~all", result.Out);
        Assert.Matches(@"MISSING\s+DMARC\s+recommended", result.Out);
        Assert.Contains("found:    (nothing)", result.Out);
        Assert.Contains("every required record is published", result.Out);
    }

    [Fact]
    public async Task Check_exits_with_one_when_a_required_record_is_missing()
    {
        var result = await RunAsync(new StaticDnsResolver(), "check", "example.com");
        Assert.Equal(1, result.Code);
        Assert.Matches(@"MISSING\s+DKIM\s+required", result.Out);
        Assert.Contains("example.com: Dkim record", result.Out);
    }
}
