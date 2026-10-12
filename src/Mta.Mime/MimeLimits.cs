namespace Mta.Mime;

/// <summary>
/// Explicit resource limits applied by every parser in this library. All input is treated as hostile: limits bound
/// the memory that is materialized and the work that is done, and exceeding one never throws; instead the parser
/// truncates what it produces and sets the matching <see cref="MimeAnomaly"/> flag.
/// </summary>
public sealed record MimeLimits
{
    private readonly int _maxHeaderBytes = 256 * 1024;
    private readonly int _maxHeaderCount = 1000;
    private readonly int _maxLineLength = 998;
    private readonly int _maxHeaderValueBytes = 64 * 1024;
    private readonly int _maxDepth = 20;
    private readonly int _maxParts = 1000;
    private readonly long _maxDecodedBytes = 64L * 1024 * 1024;
    private readonly int _maxParameters = 64;
    private readonly int _maxAddresses = 1000;
    private readonly int _maxBoundaryLength = 200;

    /// <summary>Hard ceiling for <see cref="MaxDepth"/>; parsing is recursive and the stack must stay bounded.</summary>
    public const int AbsoluteMaxDepth = 64;

    /// <summary>The default limits (safe for hostile input).</summary>
    public static MimeLimits Default { get; } = new();

    /// <summary>Maximum number of bytes of a header block that is recorded (default 256 KiB). The block is still scanned to find the body.</summary>
    public int MaxHeaderBytes { get => _maxHeaderBytes; init => _maxHeaderBytes = Positive(value, nameof(MaxHeaderBytes)); }

    /// <summary>Maximum number of header fields recorded per header block (default 1000).</summary>
    public int MaxHeaderCount { get => _maxHeaderCount; init => _maxHeaderCount = Positive(value, nameof(MaxHeaderCount)); }

    /// <summary>Line length (excluding the line ending) above which <see cref="MimeAnomaly.HeaderLineTooLong"/> or <see cref="MimeAnomaly.BodyLineTooLong"/> is set (default 998, RFC 5322).</summary>
    public int MaxLineLength { get => _maxLineLength; init => _maxLineLength = Positive(value, nameof(MaxLineLength)); }

    /// <summary>Maximum size of one unfolded header value that is converted to a string (default 64 KiB); longer values are truncated.</summary>
    public int MaxHeaderValueBytes { get => _maxHeaderValueBytes; init => _maxHeaderValueBytes = Positive(value, nameof(MaxHeaderValueBytes)); }

    /// <summary>Maximum MIME nesting depth (default 20, ceiling <see cref="AbsoluteMaxDepth"/>). Deeper entities are kept as opaque leaves.</summary>
    public int MaxDepth
    {
        get => _maxDepth;
        init => _maxDepth = value is >= 0 and <= AbsoluteMaxDepth ? value : throw new ArgumentOutOfRangeException(nameof(MaxDepth));
    }

    /// <summary>Maximum number of MIME entities (parts) in one message (default 1000). Further parts are dropped.</summary>
    public int MaxParts { get => _maxParts; init => _maxParts = Positive(value, nameof(MaxParts)); }

    /// <summary>Maximum number of bytes produced by one body decode operation (default 64 MiB). Output beyond it is dropped.</summary>
    public long MaxDecodedBytes
    {
        get => _maxDecodedBytes;
        init => _maxDecodedBytes = value > 0 ? value : throw new ArgumentOutOfRangeException(nameof(MaxDecodedBytes));
    }

    /// <summary>Maximum parameters kept for one structured header (default 64).</summary>
    public int MaxParameters { get => _maxParameters; init => _maxParameters = Positive(value, nameof(MaxParameters)); }

    /// <summary>Maximum addresses (mailboxes) returned for one address header (default 1000).</summary>
    public int MaxAddresses { get => _maxAddresses; init => _maxAddresses = Positive(value, nameof(MaxAddresses)); }

    /// <summary>Maximum accepted multipart boundary length (default 200; RFC 2046 allows 70). Longer boundaries are treated as missing.</summary>
    public int MaxBoundaryLength { get => _maxBoundaryLength; init => _maxBoundaryLength = Positive(value, nameof(MaxBoundaryLength)); }

    private static int Positive(int value, string name) =>
        value > 0 ? value : throw new ArgumentOutOfRangeException(name, "Limit must be positive.");
}
