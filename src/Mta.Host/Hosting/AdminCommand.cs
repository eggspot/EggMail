using Microsoft.Extensions.Configuration;
using Mta.Core;
using Mta.Host.Api;
using Mta.Host.Configuration;
using Mta.Host.Switching;
using Mta.Storage;

namespace Mta.Host.Hosting;

/// <summary>
/// <c>mta admin create --user NAME [--role admin|tenant] [--tenant SLUG] --password-file FILE</c> (or the password in the environment variable
/// <c>MTA_ADMIN_PASSWORD</c>; never on the command line). Creates a dashboard account directly in the store, for first set-up and for locked-out
/// installations. With a SQLite backend the server must be stopped (one process owns the data directory); a running server can create
/// the first administrator at start from <c>Dashboard:BootstrapAdminPasswordFile</c>, or, once an administrator exists, accounts are made in the dashboard or with <c>POST /api/v1/admin/users</c> (docs/api.md, "Dashboard users").
/// </summary>
public static class AdminCommand
{
    public static async Task<int> RunAsync(string[] args, TextWriter output, TextWriter error)
    {
        if (args.FirstOrDefault() != "create")
        {
            error.WriteLine("Usage: mta admin create --user NAME [--role admin|tenant] [--tenant SLUG] --password-file FILE");
            return 64;
        }

        var options = new ConfigurationBuilder().AddCommandLine(args.Skip(1).ToArray()).Build();   // command line only: environment variables such as USER must not leak in
        string? user = options["user"];
        string role = options["role"] ?? "admin";
        string? tenantSlug = options["tenant"];
        string? passwordFile = options["password-file"];
        string? password = passwordFile is not null ? (File.Exists(passwordFile) ? File.ReadAllText(passwordFile).Trim() : null) : Environment.GetEnvironmentVariable("MTA_ADMIN_PASSWORD");
        if (string.IsNullOrWhiteSpace(user) || string.IsNullOrEmpty(password) || role is not ("admin" or "tenant"))
        {
            error.WriteLine("Needs --user, a password from --password-file (or MTA_ADMIN_PASSWORD) and --role admin|tenant.");
            return 64;
        }

        var loaded = ConfigLoader.Load(ConfigLoader.Build(ConfigurationArguments(args.Skip(1))));
        if (!loaded.IsValid)
        {
            foreach (string e in loaded.Errors)
            {
                error.WriteLine("configuration error: " + e);
            }

            return 2;
        }

        DataDirectoryLock? directoryLock = null;
        try
        {
            directoryLock = loaded.Config.Storage.Backend == StorageBackend.Sqlite ? DataDirectoryLock.Acquire(loaded.Config.Storage.Sqlite.DataDirectory) : null;
        }
        catch (IOException ex)
        {
            error.WriteLine(ex.Message + " Stop the server first, or use Dashboard:BootstrapAdminPasswordFile / the API (POST /api/v1/admin/users).");
            return 3;
        }

        using (directoryLock)
        {
            await using var storage = StorageFactory.Create(loaded.Config.Storage, SystemClock.Instance, NullMtaLog.Instance);
            await storage.InitializeAsync(CancellationToken.None).ConfigureAwait(false);
            Guid? tenantId = null;
            if (role == "tenant")
            {
                var tenant = tenantSlug is null ? null : await storage.Config.GetTenantBySlugAsync(tenantSlug, CancellationToken.None).ConfigureAwait(false);
                if (tenant is null)
                {
                    error.WriteLine("A tenant user needs --tenant with the slug of an existing tenant.");
                    return 64;
                }

                tenantId = tenant.Id;
            }

            try
            {
                var created = await DashboardAccounts.CreateAsync(storage.Config, SystemClock.Instance, user, password, role == "admin" ? DashboardRole.Admin : DashboardRole.Tenant, tenantId, CancellationToken.None).ConfigureAwait(false);
                output.WriteLine($"created {role} '{created.UserName}'");
                return 0;
            }
            catch (StorageConflictException)
            {
                error.WriteLine($"The user name '{user}' is already taken.");
                return 1;
            }
            catch (ArgumentException ex)
            {
                error.WriteLine(ex.Message);
                return 64;
            }
        }
    }

    private static readonly string[] OwnOptions = ["--user", "--role", "--tenant", "--password-file"];

    /// <summary>The arguments that are configuration (everything except this command's own options and their values).</summary>
    private static string[] ConfigurationArguments(IEnumerable<string> args)
    {
        var result = new List<string>();
        var list = args.ToList();
        for (int i = 0; i < list.Count; i++)
        {
            string a = list[i];
            bool own = OwnOptions.Any(o => a == o || a.StartsWith(o + "=", StringComparison.Ordinal));
            if (!own)
            {
                result.Add(a);
            }
            else if (!a.Contains('='))
            {
                i++;   // skip the value
            }
        }

        return result.ToArray();
    }
}
