namespace Mta.Core;

/// <summary>
/// Time-ordered identifiers (UUIDv7). The creation day is recoverable from the id, which the history layout
/// and switch bundle chunking rely on.
/// </summary>
public static class Ids
{
    public static Guid New() => Guid.CreateVersion7();

    public static Guid New(DateTimeOffset timestamp) => Guid.CreateVersion7(timestamp);

    /// <summary>Extracts the embedded UTC timestamp from a UUIDv7.</summary>
    public static DateTimeOffset GetTimestamp(Guid id)
    {
        Span<byte> bytes = stackalloc byte[16];
        id.TryWriteBytes(bytes, bigEndian: true, out _);
        long ms = ((long)bytes[0] << 40) | ((long)bytes[1] << 32) | ((long)bytes[2] << 24)
                  | ((long)bytes[3] << 16) | ((long)bytes[4] << 8) | bytes[5];
        return DateTimeOffset.FromUnixTimeMilliseconds(ms);
    }

    /// <summary>The UTC calendar day embedded in a UUIDv7.</summary>
    public static DateOnly GetDay(Guid id) => DateOnly.FromDateTime(GetTimestamp(id).UtcDateTime);

    /// <summary>Compact lowercase hex form without hyphens (used in Message-ID / VERP / file names).</summary>
    public static string ToCompact(Guid id) => id.ToString("N");
}
