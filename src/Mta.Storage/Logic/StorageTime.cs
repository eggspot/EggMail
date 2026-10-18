using Mta.Core;

namespace Mta.Storage.Logic;

/// <summary>
/// Time helpers shared by every backend. All persisted instants have millisecond precision (SQLite keeps UTC unix
/// milliseconds), so the in-memory backend rounds the same way to stay observably identical.
/// </summary>
public static class StorageTime
{
    public static readonly DateTimeOffset Epoch = DateTimeOffset.UnixEpoch;

    public static long ToUnixMs(DateTimeOffset value) => value.ToUnixTimeMilliseconds();

    public static DateTimeOffset FromUnixMs(long ms) => DateTimeOffset.FromUnixTimeMilliseconds(ms);

    /// <summary>Truncates to whole milliseconds and normalizes to UTC.</summary>
    public static DateTimeOffset Normalize(DateTimeOffset value) => FromUnixMs(ToUnixMs(value));

    public static DateTimeOffset? Normalize(DateTimeOffset? value) => value is { } v ? Normalize(v) : null;

    /// <summary>Days since 1970-01-01 (UTC) for an instant.</summary>
    public static int DayNumber(DateTimeOffset value) => (int)Math.Floor(value.ToUnixTimeMilliseconds() / 86_400_000d);

    /// <summary>
    /// The history <c>day</c> key of a message: the UTC day embedded in its UUIDv7 id. Computed from the raw time field, so an id that is not ours (the API passes ids
    /// from URLs through) gets a day that matches no row, and the lookup answers "not found" instead of throwing: before, about one random GUID in ten made
    /// <c>GET /messages/{id}</c> answer 500.
    /// </summary>
    public static int DayNumber(Guid messageId) => (int)(Ids.GetUnixMilliseconds(messageId) / 86_400_000L);

    public static DateTimeOffset DayStart(int dayNumber) => FromUnixMs(dayNumber * 86_400_000L);

    public static DateTimeOffset DayStart(DateTimeOffset value) => DayStart(DayNumber(value));

    public static DateTimeOffset HourStart(DateTimeOffset value)
    {
        long ms = ToUnixMs(value);
        return FromUnixMs(ms - (((ms % 3_600_000L) + 3_600_000L) % 3_600_000L));
    }
}
