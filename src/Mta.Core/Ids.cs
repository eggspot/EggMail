namespace Mta.Core;

/// <summary>
/// Time-ordered identifiers (UUIDv7). The creation day is recoverable from the id, which the history layout
/// and switch bundle chunking rely on.
/// </summary>
public static class Ids
{
    public static Guid New() => Guid.CreateVersion7();

    public static Guid New(DateTimeOffset timestamp) => Guid.CreateVersion7(timestamp);

    /// <summary>
    /// The 48-bit millisecond field a UUIDv7 starts with, read from any GUID without validation. An id that arrived from outside (a URL, a webhook payload) need not be a
    /// UUIDv7: a random GUID yields a value up to 2^48 - 1, which is later than <see cref="DateTimeOffset.MaxValue"/> in about one case in ten, so this is the form to
    /// use whenever the id is not known to be ours.
    /// </summary>
    public static long GetUnixMilliseconds(Guid id)
    {
        Span<byte> bytes = stackalloc byte[16];
        id.TryWriteBytes(bytes, bigEndian: true, out _);
        return ((long)bytes[0] << 40) | ((long)bytes[1] << 32) | ((long)bytes[2] << 24)
               | ((long)bytes[3] << 16) | ((long)bytes[4] << 8) | bytes[5];
    }

    /// <summary>Extracts the embedded UTC timestamp from a UUIDv7. Throws for an id whose time field is beyond the year 9999 (see <see cref="GetUnixMilliseconds"/>).</summary>
    public static DateTimeOffset GetTimestamp(Guid id) => DateTimeOffset.FromUnixTimeMilliseconds(GetUnixMilliseconds(id));

    /// <summary>The UTC calendar day embedded in a UUIDv7.</summary>
    public static DateOnly GetDay(Guid id) => DateOnly.FromDateTime(GetTimestamp(id).UtcDateTime);

    /// <summary>Compact lowercase hex form without hyphens (used in Message-ID / VERP / file names).</summary>
    public static string ToCompact(Guid id) => id.ToString("N");

    public static ulong Prefix64(Guid id)
    {
        Span<byte> bytes = stackalloc byte[16];
        id.TryWriteBytes(bytes, bigEndian: true, out _);
        return System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(bytes);
    }
}
