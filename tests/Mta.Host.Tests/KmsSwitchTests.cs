using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Mta.Core;
using Mta.Host.Configuration;
using Mta.Host.Secrets;
using Mta.Host.Switching;
using Mta.Storage;
using Mta.Storage.Sqlite;

namespace Mta.Host.Tests;

/// <summary>A backend switch from a source whose key ring is wrapped by an external key (<c>Secrets:KeyProtection=Kms</c>) to targets with another key, and with none.</summary>
[Collection("CpuHeavy")]
public class KmsSwitchTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("eggmail-kms-switch-").FullName;

    private string Source => Path.Combine(_root, "source");

    private string Target => Path.Combine(_root, "target");

    private string Bundle => Path.Combine(_root, "bundle");

    private string Bootstrap => Path.Combine(_root, "bootstrap.json");

    private string PassphraseFile => Path.Combine(_root, "passphrase.txt");

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Directory.Delete(_root, recursive: true);
    }

    private string WriteKey(string name)
    {
        string path = Path.Combine(_root, name);
        File.WriteAllText(path, Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
        return path;
    }

    private SecretsSection KmsSection(string keyFile) => new() { KeyProtection = KeyProtectionMode.Kms, KmsKeyFile = keyFile };

    /// <summary>The source's data directory with one DKIM key protected by the given secrets configuration; the bootstrap file carries the source's and the target's <c>Secrets</c>.</summary>
    private async Task PrepareAsync(string sourceKeyFile, string? targetKeyFile)
    {
        File.WriteAllText(PassphraseFile, "correct horse battery staple\n");
        var storage = SqliteStorage.Create(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = Source, StatsFlushInterval = TimeSpan.Zero } });
        await storage.InitializeAsync(default);
        var secrets = SecretsFactory.Create(KmsSection(sourceKeyFile), storage.Config);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        Guid tenant = Ids.New();
        Guid domain = Ids.New();
        await storage.Config.UpsertTenantAsync(new Tenant(tenant, "Acme", "acme", true, now, false), default);
        await storage.Config.UpsertDomainAsync(new DomainRecord(domain, tenant, "example.com", DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
        await storage.Config.AddDkimKeyAsync(new DkimKeyRecord(Ids.New(), domain, "egg1", secrets.Protect("dkim-private-key"u8, SecretPurposes.DkimKey), "PUB", now, true, null), default);
        await storage.DisposeAsync();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();

        var bootstrap = new JsonObject
        {
            ["Sqlite"] = new JsonObject { ["DataDirectory"] = Source },
            ["Secrets"] = new JsonObject { ["KeyProtection"] = "Kms", ["KmsKeyFile"] = sourceKeyFile },
            ["SwitchTarget"] = new JsonObject
            {
                ["Secrets"] = targetKeyFile is null
                    ? new JsonObject { ["KeyProtection"] = "None" }
                    : new JsonObject { ["KeyProtection"] = "Kms", ["KmsKeyFile"] = targetKeyFile },
            },
        };
        File.WriteAllText(Bootstrap, bootstrap.ToJsonString());
    }

    private async Task<(int Code, string Out, string Err)> RunAsync(params string[] args)
    {
        var o = new StringWriter();
        var e = new StringWriter();
        int code = await MigrateStorageCommand.RunAsync(args, o, e);
        return (code, o.ToString(), e.ToString());
    }

    private string[] ToTarget(params string[] more) => ["--to", "sqlite", "--target-dir", Target, "--bootstrap-file", Bootstrap, .. more];

    private async Task<(byte[] Cipher, ISecretProtector Protector)> TargetDkimKeyAsync(SecretsSection secrets)
    {
        var storage = SqliteStorage.Create(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = Target, StatsFlushInterval = TimeSpan.Zero } });
        await storage.InitializeAsync(default);
        try
        {
            ISecretProtector protector = SecretsFactory.Create(secrets, storage.Config);
            var domain = (await storage.Config.GetDomainsAsync(null, default))[0];
            return ((await storage.Config.GetDkimKeysAsync(domain.Id, default))[0].PrivateKeyProtected, protector);
        }
        finally
        {
            await storage.DisposeAsync();
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        }
    }

    [Fact]
    public async Task A_Kms_source_moves_to_a_target_with_another_key_and_only_the_target_key_opens_it()
    {
        string sourceKey = WriteKey("source.key");
        string targetKey = WriteKey("target.key");
        await PrepareAsync(sourceKey, targetKey);

        var export = await RunAsync(["export", .. ToTarget("--bundle", Bundle, "--quiesce", "--passphrase-file", PassphraseFile)]);
        Assert.True(export.Code == 0, export.Out + export.Err);
        var import = await RunAsync(["import", .. ToTarget("--bundle", Bundle, "--passphrase-file", PassphraseFile)]);
        Assert.True(import.Code == 0, import.Out + import.Err);

        var (cipher, underTarget) = await TargetDkimKeyAsync(KmsSection(targetKey));
        Assert.Equal("dkim-private-key"u8.ToArray(), underTarget.Unprotect(cipher, SecretPurposes.DkimKey));

        // The source's key does not open the target's ring: two independent protections, and a clear message at start.
        var wrong = await Assert.ThrowsAsync<SecretsConfigurationException>(() => TargetDkimKeyAsync(KmsSection(sourceKey)));
        Assert.Contains("Configure the original key", wrong.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_Kms_source_moves_to_an_unprotected_target_only_when_that_is_acknowledged()
    {
        string sourceKey = WriteKey("source.key");
        await PrepareAsync(sourceKey, targetKeyFile: null);

        var refused = await RunAsync(["preflight", .. ToTarget("--bundle", Bundle)]);
        Assert.Equal(MigrateStorageCommand.Refused, refused.Code);
        Assert.Contains("key-protection", refused.Out, StringComparison.Ordinal);

        Assert.Equal(0, (await RunAsync(["export", .. ToTarget("--bundle", Bundle, "--quiesce", "--passphrase-file", PassphraseFile, "--accept-unprotected-keys")])).Code);
        var import = await RunAsync(["import", .. ToTarget("--bundle", Bundle, "--passphrase-file", PassphraseFile, "--accept-unprotected-keys")]);
        Assert.True(import.Code == 0, import.Out + import.Err);

        var (cipher, plain) = await TargetDkimKeyAsync(new SecretsSection());
        Assert.Equal("dkim-private-key"u8.ToArray(), plain.Unprotect(cipher, SecretPurposes.DkimKey));
    }
}
