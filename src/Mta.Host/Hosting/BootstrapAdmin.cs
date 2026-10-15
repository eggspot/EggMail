using Mta.Core;
using Mta.Host.Api;
using Mta.Host.Configuration;
using Mta.Storage;

namespace Mta.Host.Hosting;

public enum BootstrapAdminOutcome : byte
{
    /// <summary>An administrator exists already (or another replica created it at the same moment): nothing was done.</summary>
    AlreadyExists,

    /// <summary>Created with the password from <c>Dashboard:BootstrapAdminPassword</c> or <c>Dashboard:BootstrapAdminPasswordFile</c>.</summary>
    Created,

    /// <summary>Created with a generated password, in <see cref="BootstrapAdminResult.GeneratedPassword"/>: print it once and never again.</summary>
    CreatedWithGeneratedPassword,

    /// <summary>The configuration names a password that cannot be used; <see cref="BootstrapAdminResult.Problem"/> says what to change. The server must not start without an administrator.</summary>
    Problem,
}

public sealed record BootstrapAdminResult(BootstrapAdminOutcome Outcome, string UserName, string? GeneratedPassword = null, string? Problem = null);

/// <summary>
/// The first dashboard administrator of a new installation. With no administrator in the store the server creates one: with the password the deployment
/// gives (<c>EGGMAIL_ADMIN_PASSWORD_FILE</c> or <c>EGGMAIL_ADMIN_PASSWORD</c>) or, when it gives none, with a generated one that is printed once
/// (<see cref="WriteGeneratedPasswordNotice"/>) and kept only as a hash. After the first start an administrator exists, so nothing is created or printed again.
/// </summary>
public static class BootstrapAdmin
{
    public const string NoticeBegin = "==================== EGGMAIL FIRST START: DASHBOARD ADMINISTRATOR ====================";
    public const string NoticeEnd = "==================== END OF THE ONE-TIME PASSWORD (it is never shown again) ====================";

    public static async Task<BootstrapAdminResult> EnsureAsync(MtaConfig config, IStorage storage, IClock clock, IMtaLog log, CancellationToken ct)
    {
        DashboardSection dashboard = config.Dashboard;
        string userName = dashboard.BootstrapAdminUser.Trim();
        if (await AnyAdminAsync(storage.Config, ct).ConfigureAwait(false))
        {
            return new BootstrapAdminResult(BootstrapAdminOutcome.AlreadyExists, userName);
        }

        string password;
        bool generated = false;
        if (!string.IsNullOrEmpty(dashboard.BootstrapAdminPassword))
        {
            password = dashboard.BootstrapAdminPassword;
        }
        else if (!string.IsNullOrWhiteSpace(dashboard.BootstrapAdminPasswordFile))
        {
            string file = dashboard.BootstrapAdminPasswordFile;
            try
            {
                password = (await File.ReadAllTextAsync(file, ct).ConfigureAwait(false)).Trim();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return Problem(userName, $"The administrator password file '{file}' cannot be read ({ex.Message}). Create it (the application user must be able to read it), or leave EGGMAIL_ADMIN_PASSWORD_FILE unset and the server generates a password and prints it once.");
            }

            if (DashboardAccounts.PasswordProblem(password) is { } weak)
            {
                return Problem(userName, $"The administrator password in '{file}' is not acceptable: {weak} Put a longer one in the file, or leave EGGMAIL_ADMIN_PASSWORD_FILE unset and the server generates a password and prints it once.");
            }
        }
        else
        {
            password = DashboardAccounts.GeneratePassword();
            generated = true;
        }

        try
        {
            if (!await DashboardAccounts.EnsureAdminAsync(storage.Config, clock, userName, password, ct).ConfigureAwait(false))
            {
                return new BootstrapAdminResult(BootstrapAdminOutcome.AlreadyExists, userName);
            }
        }
        catch (StorageConflictException)
        {
            // Another replica created the administrator at the same moment (its password is the one that counts), or the name belongs to a user who is not an administrator.
            return await AnyAdminAsync(storage.Config, ct).ConfigureAwait(false)
                ? new BootstrapAdminResult(BootstrapAdminOutcome.AlreadyExists, userName)
                : Problem(userName, $"The user name '{userName}' is already used by an account that is not an administrator. Choose another with EGGMAIL_ADMIN_USER.");
        }
        catch (ArgumentException ex)
        {
            return Problem(userName, ex.Message);
        }

        if (generated)
        {
            // The password itself is never logged: the structured log may be shipped to a collector. The caller prints it once, to the console only.
            log.Write(MtaLogLevel.Warning, "startup", $"Created the first dashboard administrator '{userName}' with a GENERATED password, shown once in the delimited block of the console log. Sign in and change it on the Account page.");
            return new BootstrapAdminResult(BootstrapAdminOutcome.CreatedWithGeneratedPassword, userName, GeneratedPassword: password);
        }

        log.Write(MtaLogLevel.Information, "startup", $"Created the first dashboard administrator '{userName}'.");
        return new BootstrapAdminResult(BootstrapAdminOutcome.Created, userName);
    }

    private static BootstrapAdminResult Problem(string userName, string problem) => new(BootstrapAdminOutcome.Problem, userName, Problem: problem);

    private static async Task<bool> AnyAdminAsync(IConfigStore config, CancellationToken ct) =>
        (await config.GetDashboardUsersAsync(ct).ConfigureAwait(false)).Any(u => u.Role == DashboardRole.Admin);

    /// <summary>The block that shows a generated password once: delimited so it is easy to find in <c>docker logs</c>, plain text (not a structured log entry) so it never reaches a log exporter.</summary>
    public static void WriteGeneratedPasswordNotice(TextWriter output, string userName, string password, int httpsPort)
    {
        output.WriteLine();
        output.WriteLine(NoticeBegin);
        output.WriteLine($"  user name: {userName}");
        output.WriteLine($"  password:  {password}");
        output.WriteLine();
        output.WriteLine("  This password is shown ONLY THIS ONCE and is stored only as a hash: copy it now.");
        output.WriteLine($"  Sign in at https://<this server>:{httpsPort} (with the Docker quick start that is https://localhost:8443; the certificate is self-signed until you set up a real one),");
        output.WriteLine("  then change the password on the Account page. To choose the password yourself instead, set EGGMAIL_ADMIN_PASSWORD_FILE");
        output.WriteLine("  (or EGGMAIL_ADMIN_PASSWORD) before the first start. If you lose it: stop the server and run `mta admin create`, see docs/operations.md.");
        output.WriteLine(NoticeEnd);
        output.WriteLine();
        output.Flush();
    }
}
