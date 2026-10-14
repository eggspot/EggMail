using Mta.Core;
using Mta.Host.Security;
using Mta.Storage;

namespace Mta.Host.Api;

/// <summary>
/// Creating and changing dashboard users: the rules shared by <c>mta admin create</c>, the first-run bootstrap and the user management API
/// (<see cref="UsersApi"/>). Passwords are hashed with PBKDF2 (<see cref="PasswordHasher"/>); changing a password signs the user out everywhere.
/// </summary>
public static class DashboardAccounts
{
    public const int MinimumPasswordLength = 10;

    /// <summary>The longest password accepted anywhere (sign-in refuses longer ones too), so a request cannot make the server hash megabytes.</summary>
    public const int MaximumPasswordLength = 1024;

    public const int MaximumUserNameLength = 256;

    /// <summary>Why <paramref name="userName"/> cannot be a dashboard user name, or null when it can (trimmed, 1 to 256 characters, no control characters).</summary>
    public static string? UserNameProblem(string? userName)
    {
        string name = userName?.Trim() ?? "";
        return name.Length is 0 or > MaximumUserNameLength || name.Any(char.IsControl)
            ? $"A user name of 1 to {MaximumUserNameLength} characters without control characters is required."
            : null;
    }

    /// <summary>Why <paramref name="password"/> is not acceptable (length only: 10 to 1,024 characters), or null.</summary>
    public static string? PasswordProblem(string? password) => password switch
    {
        null => "A password is required.",
        { Length: < MinimumPasswordLength } => $"The password must have at least {MinimumPasswordLength} characters.",
        { Length: > MaximumPasswordLength } => $"The password must have at most {MaximumPasswordLength} characters.",
        _ => null,
    };

    /// <summary>A random password (24 characters, 144 bits) for the server to hand out once.</summary>
    public static string GeneratePassword() => SessionService.Base64Url(System.Security.Cryptography.RandomNumberGenerator.GetBytes(18));

    /// <summary>Hashes a password with the default (or given) PBKDF2 cost. CPU heavy: call it off the request thread (<c>Task.Run</c>).</summary>
    public static string HashPassword(string password, int? hashIterations = null) => Hash(password, hashIterations);

    public static async ValueTask<DashboardUser> CreateAsync(
        IConfigStore config, IClock clock, string userName, string password, DashboardRole role, Guid? tenantId, CancellationToken ct, int? hashIterations = null)
    {
        if (UserNameProblem(userName) is { } nameProblem)
        {
            throw new ArgumentException(nameProblem, nameof(userName));
        }

        string name = userName.Trim();
        ValidatePassword(password);
        if (role == DashboardRole.Tenant && tenantId is null)
        {
            throw new ArgumentException("A tenant user needs a tenant.", nameof(tenantId));
        }

        if (role == DashboardRole.Admin && tenantId is not null)
        {
            throw new ArgumentException("An admin does not belong to a tenant.", nameof(tenantId));
        }

        var user = new DashboardUser(Ids.New(clock.UtcNow), name, Hash(password, hashIterations), role, tenantId, true, clock.UtcNow);
        await config.UpsertDashboardUserAsync(user, ct).ConfigureAwait(false); // StorageConflictException when the name is taken
        return user;
    }

    /// <summary>Creates the first admin if no admin exists yet. Returns true when it was created.</summary>
    public static async ValueTask<bool> EnsureAdminAsync(IConfigStore config, IClock clock, string userName, string password, CancellationToken ct, int? hashIterations = null)
    {
        if ((await config.GetDashboardUsersAsync(ct).ConfigureAwait(false)).Any(u => u.Role == DashboardRole.Admin))
        {
            return false;
        }

        await CreateAsync(config, clock, userName, password, DashboardRole.Admin, null, ct, hashIterations).ConfigureAwait(false);
        return true;
    }

    /// <summary>Sets a new password and ends every session of the user.</summary>
    public static async ValueTask SetPasswordAsync(IConfigStore config, Guid userId, string newPassword, CancellationToken ct, int? hashIterations = null)
    {
        ValidatePassword(newPassword);
        string hash = Hash(newPassword, hashIterations);
        // One guarded write (the stored row is changed and the sessions end with it), not a read, an upsert and a delete that could undo a concurrent change.
        DashboardUserUpdate result = await config.UpdateDashboardUserGuardedAsync(userId, u => u with { PasswordHash = hash }, endSessions: true, keepSessionHash: null, ct).ConfigureAwait(false);
        if (result.Result == DashboardUserWriteResult.NotFound)
        {
            throw new KeyNotFoundException("No such dashboard user.");
        }
    }

    private static string Hash(string password, int? iterations) => iterations is { } n ? PasswordHasher.Hash(password, n) : PasswordHasher.Hash(password);

    private static void ValidatePassword(string password)
    {
        if (PasswordProblem(password) is { } problem)
        {
            throw new ArgumentException(problem, nameof(password));
        }
    }
}
