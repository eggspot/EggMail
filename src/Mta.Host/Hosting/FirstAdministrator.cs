using Mta.Core;
using Mta.Host.Api;
using Mta.Host.Configuration;
using Mta.Storage;

namespace Mta.Host.Hosting;

public enum FirstAdministratorOutcome : byte
{
    /// <summary>An administrator exists already (or another replica created it at the same moment): nothing was done.</summary>
    AlreadyExists,

    /// <summary>Created with the password from <c>Dashboard:BootstrapAdminPassword</c> or <c>Dashboard:BootstrapAdminPasswordFile</c>.</summary>
    Created,

    /// <summary>Created with a generated password, in <see cref="FirstAdministratorResult.GeneratedPassword"/>: print it once and never again.</summary>
    CreatedWithGeneratedPassword,

    /// <summary>The configuration names a password or user name that cannot be used; <see cref="FirstAdministratorResult.Problem"/> says what to change. The server must not start without an administrator.</summary>
    Problem,
}

public sealed record FirstAdministratorResult(FirstAdministratorOutcome Outcome, string UserName, string? GeneratedPassword = null, string? Problem = null);

/// <summary>
/// The first administrator of a new installation. With no administrator in the store the server creates one: with the password the deployment
/// gives (<c>EGGMAIL_ADMIN_PASSWORD_FILE</c> or <c>EGGMAIL_ADMIN_PASSWORD</c>) or, when it gives none, with a generated one that is printed once
/// (<see cref="WriteGeneratedPasswordNotice"/>), kept only as a hash and marked temporary: the dashboard makes the person choose another at the first sign-in
/// (<see cref="Mta.Host.Security.PasswordHasher.MarkMustChange"/>). After the first start an administrator exists, so nothing is created or printed again.
/// </summary>
public static class FirstAdministrator
{
    public const string NoticeBegin = "==================== EGGMAIL FIRST START: DASHBOARD ADMINISTRATOR ====================";
    public const string NoticeEnd = "==================== END OF THE ONE-TIME PASSWORD (it is never shown again) ====================";

    public static async Task<FirstAdministratorResult> EnsureAsync(MtaConfig config, IConfigStore store, IClock clock, IMtaLog log, CancellationToken ct)
    {
        DashboardSection dashboard = config.Dashboard;
        string userName = dashboard.BootstrapAdminUser.Trim();
        if (await AnyAdminAsync(store, ct).ConfigureAwait(false))
        {
            return new FirstAdministratorResult(FirstAdministratorOutcome.AlreadyExists, userName);
        }

        string? inline = string.IsNullOrWhiteSpace(dashboard.BootstrapAdminPassword) ? null : dashboard.BootstrapAdminPassword.Trim();   // trimmed like the contents of the file
        string? file = string.IsNullOrWhiteSpace(dashboard.BootstrapAdminPasswordFile) ? null : dashboard.BootstrapAdminPasswordFile;
        if (inline is not null && file is not null)
        {
            return Problem(userName, "EGGMAIL_ADMIN_PASSWORD and EGGMAIL_ADMIN_PASSWORD_FILE are both set (Dashboard:BootstrapAdminPassword and Dashboard:BootstrapAdminPasswordFile). Set only one: the file form keeps the password out of the environment.");
        }

        string password;
        bool generated = false;
        if (inline is not null)
        {
            password = inline;
            if (DashboardAccounts.PasswordProblem(password) is { } weakInline)
            {
                return Problem(userName, $"EGGMAIL_ADMIN_PASSWORD is not acceptable: {weakInline} Choose a longer one, or leave it unset and the server generates a password and prints it once.");
            }
        }
        else if (file is not null)
        {
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
            if (!await DashboardAccounts.EnsureAdminAsync(store, clock, userName, password, ct, mustChangePassword: generated).ConfigureAwait(false))
            {
                return new FirstAdministratorResult(FirstAdministratorOutcome.AlreadyExists, userName);
            }
        }
        catch (StorageConflictException)
        {
            // Another replica created the administrator at the same moment (its password is the one that counts), or the name belongs to a user who is not an administrator.
            return await AnyAdminAsync(store, ct).ConfigureAwait(false)
                ? new FirstAdministratorResult(FirstAdministratorOutcome.AlreadyExists, userName)
                : Problem(userName, $"The user name '{userName}' is already used by an account that is not an administrator. Choose another with EGGMAIL_ADMIN_USER.");
        }
        catch (ArgumentException ex)
        {
            return Problem(userName, "EGGMAIL_ADMIN_USER / EGGMAIL_ADMIN_PASSWORD: " + ex.Message);
        }

        if (generated)
        {
            // The password itself is never logged: the structured log may be shipped to a collector. The caller prints it once, to the console only.
            log.Write(MtaLogLevel.Warning, "startup", $"Created the first dashboard administrator '{userName}' with a GENERATED password, shown once in the delimited block of the console log. Sign in and choose a new password: the dashboard asks for it first.");
            return new FirstAdministratorResult(FirstAdministratorOutcome.CreatedWithGeneratedPassword, userName, GeneratedPassword: password);
        }

        log.Write(MtaLogLevel.Information, "startup", $"Created the first dashboard administrator '{userName}'.");
        return new FirstAdministratorResult(FirstAdministratorOutcome.Created, userName);
    }

    private static FirstAdministratorResult Problem(string userName, string problem) => new(FirstAdministratorOutcome.Problem, userName, Problem: problem);

    private static async Task<bool> AnyAdminAsync(IConfigStore config, CancellationToken ct) =>
        (await config.GetDashboardUsersAsync(ct).ConfigureAwait(false)).Any(u => u.Role == DashboardRole.Admin);

    /// <summary>
    /// The command that makes another administrator when the password is lost, for the container image (the entry point is <c>/app/mta</c>, so the arguments are the
    /// command). With SQLite the server container must be stopped first (one process owns the data directory); with PostgreSQL it can run.
    /// </summary>
    public const string RecoveryCommand =
        "docker stop eggmail && docker run --rm -v eggmail-data:/data -e MTA_ADMIN_PASSWORD='<a new password>' ghcr.io/eggspot/eggmail:nightly admin create --user rescue && docker start eggmail";

    /// <summary>The block that shows a generated password once: delimited so it is easy to find in <c>docker logs</c>, plain text (not a structured log entry) so it never reaches a log exporter.</summary>
    public static void WriteGeneratedPasswordNotice(TextWriter output, string userName, string password, int httpsPort)
    {
        output.WriteLine();
        output.WriteLine(NoticeBegin);
        output.WriteLine($"  user name: {userName}");
        output.WriteLine($"  password:  {password}");
        output.WriteLine();
        output.WriteLine("  This password is shown ONLY THIS ONCE and is stored only as a hash: copy it now. It is a temporary one: the dashboard asks you to choose");
        output.WriteLine("  your own at the first sign-in. Until then anyone who can read this log (docker log files, a log shipper) can sign in; change it at once.");
        output.WriteLine($"  Sign in at https://<this server>:{httpsPort} (with the Docker quick start that is https://localhost:8443; the certificate is self-signed until you set up a real one).");
        output.WriteLine("  To choose the password yourself, set EGGMAIL_ADMIN_PASSWORD_FILE (or EGGMAIL_ADMIN_PASSWORD) before the first start: then nothing is printed.");
        output.WriteLine("  If you lose it, create another administrator (with SQLite the server container must be stopped, the image name and volume are yours to adapt):");
        output.WriteLine("    " + RecoveryCommand);
        output.WriteLine(NoticeEnd);
        output.WriteLine();
        output.Flush();
    }
}
