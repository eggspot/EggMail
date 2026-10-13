using Mta.Core;
using Mta.Host.Security;
using Mta.Storage;

namespace Mta.Host.Api;

/// <summary>
/// Creating and changing dashboard users outside the HTTP API (the future <c>mta admin create</c> command and first-run bootstrap use these).
/// Passwords are hashed with PBKDF2 (<see cref="PasswordHasher"/>); changing a password signs the user out everywhere.
/// </summary>
public static class DashboardAccounts
{
    public const int MinimumPasswordLength = 10;

    public static async ValueTask<DashboardUser> CreateAsync(
        IConfigStore config, IClock clock, string userName, string password, DashboardRole role, Guid? tenantId, CancellationToken ct, int? hashIterations = null)
    {
        string name = userName?.Trim() ?? "";
        if (name.Length is 0 or > 256 || name.Any(char.IsControl))
        {
            throw new ArgumentException("A user name of 1 to 256 characters without control characters is required.", nameof(userName));
        }

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
        DashboardUser user = await config.GetDashboardUserAsync(userId, ct).ConfigureAwait(false) ?? throw new KeyNotFoundException("No such dashboard user.");
        await config.UpsertDashboardUserAsync(user with { PasswordHash = Hash(newPassword, hashIterations) }, ct).ConfigureAwait(false);
        await config.DeleteDashboardSessionsOfUserAsync(userId, ct).ConfigureAwait(false);
    }

    private static string Hash(string password, int? iterations) => iterations is { } n ? PasswordHasher.Hash(password, n) : PasswordHasher.Hash(password);

    private static void ValidatePassword(string password)
    {
        if (password is null || password.Length < MinimumPasswordLength)
        {
            throw new ArgumentException($"The password must have at least {MinimumPasswordLength} characters.", nameof(password));
        }
    }
}
