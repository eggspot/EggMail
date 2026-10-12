using Mta.Storage.Model;

namespace Mta.Storage.Logic;

/// <summary>Raised when a write violates a uniqueness or key constraint (for example a duplicate tenant slug).</summary>
public sealed class StorageConflictException(string message, Exception? inner = null) : InvalidOperationException(message, inner);

/// <summary>Lease semantics with fencing tokens, shared by every backend (they differ only in how the row is read and written atomically).</summary>
public static class LeaseRules
{
    /// <summary>
    /// Acquires or re-enters a lease. Returns the row to store, or null when another owner holds an unexpired lease.
    /// The fencing token increases whenever the lease changes hands or is taken again after it expired.
    /// </summary>
    public static LeaseEntity? Acquire(LeaseEntity? existing, string name, string owner, TimeSpan duration, DateTimeOffset now)
    {
        DateTimeOffset until = StorageTime.Normalize(now + duration);
        if (existing is null)
        {
            return new LeaseEntity { Name = name, Owner = owner, LeaseUntil = until, FencingToken = 1 };
        }

        if (existing.LeaseUntil > now)
        {
            return existing.Owner == owner
                ? new LeaseEntity { Name = name, Owner = owner, LeaseUntil = until, FencingToken = existing.FencingToken }
                : null;
        }

        return new LeaseEntity { Name = name, Owner = owner, LeaseUntil = until, FencingToken = existing.FencingToken + 1 };
    }

    /// <summary>Renews when the caller still holds the lease with the given token (nobody took it over).</summary>
    public static LeaseEntity? Renew(LeaseEntity? existing, string owner, long fencingToken, TimeSpan duration, DateTimeOffset now) =>
        existing is not null && existing.Owner == owner && existing.FencingToken == fencingToken
            ? new LeaseEntity { Name = existing.Name, Owner = owner, LeaseUntil = StorageTime.Normalize(now + duration), FencingToken = fencingToken }
            : null;

    /// <summary>Expires the lease immediately but keeps the row so fencing tokens never go backwards.</summary>
    public static LeaseEntity? Release(LeaseEntity? existing, string owner) =>
        existing is not null && existing.Owner == owner
            ? new LeaseEntity { Name = existing.Name, Owner = owner, LeaseUntil = StorageTime.Epoch, FencingToken = existing.FencingToken }
            : null;
}
