using Mta.Core;
using Mta.Host.Hosting;
using Mta.Storage;
using Mta.Storage.Sqlite;

namespace Mta.Host.Tests;

public class AdminCommandTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("eggmail-admin-").FullName;

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Directory.Delete(_dir, recursive: true);
    }

    private async Task<(int Code, string Out, string Err)> RunAsync(params string[] args)
    {
        var o = new StringWriter();
        var e = new StringWriter();
        int code = await AdminCommand.RunAsync(args, o, e);
        return (code, o.ToString(), e.ToString());
    }

    [Fact]
    public async Task Creates_an_admin_and_a_tenant_user_and_refuses_duplicates_and_bad_input()
    {
        string pw = Path.Combine(_dir, "pw");
        await File.WriteAllTextAsync(pw, "a-long-password\n");
        string data = $"--Sqlite:DataDirectory={Path.Combine(_dir, "data")}";

        var admin = await RunAsync("create", "--user", "root", "--password-file", pw, data);
        Assert.Equal(0, admin.Code);
        Assert.Contains("created admin 'root'", admin.Out);
        Assert.Equal(1, (await RunAsync("create", "--user", "root", "--password-file", pw, data)).Code);
        Assert.Equal(64, (await RunAsync("create", "--user", "t1", "--role", "tenant", "--tenant", "nope", "--password-file", pw, data)).Code);
        Assert.Equal(64, (await RunAsync("create", "--user", "short", "--password-file", Path.Combine(_dir, "missing"), data)).Code);
        Assert.Equal(64, (await RunAsync("frobnicate")).Code);

        var storage = SqliteStorage.Create(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = Path.Combine(_dir, "data") } });
        await storage.InitializeAsync(default);
        var tenant = Guid.NewGuid();
        await storage.Config.UpsertTenantAsync(new Tenant(tenant, "Acme", "acme", true, DateTimeOffset.UtcNow, false), default);
        await storage.DisposeAsync();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        var tenantUser = await RunAsync("create", "--user", "t1", "--role", "tenant", "--tenant", "acme", "--password-file", pw, data);
        Assert.Equal(0, tenantUser.Code);
    }

    [Fact]
    public async Task A_running_sqlite_server_holds_the_directory_and_the_command_says_so()
    {
        string data = Path.Combine(_dir, "data");
        using var held = Mta.Host.Switching.DataDirectoryLock.Acquire(data);
        string pw = Path.Combine(_dir, "pw");
        await File.WriteAllTextAsync(pw, "a-long-password");

        var result = await RunAsync("create", "--user", "root", "--password-file", pw, $"--Sqlite:DataDirectory={data}");

        Assert.Equal(3, result.Code);
        Assert.Contains("Stop the server", result.Err);
    }
}
