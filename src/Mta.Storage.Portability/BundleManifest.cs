using System.Text.Json;
using System.Text.Json.Serialization;

namespace Mta.Storage.Portability;

/// <summary>Describes a portable storage bundle (design §4.6). JSON on disk as <c>manifest.json</c>.</summary>
public sealed class BundleManifest
{
    /// <summary>Semantic version of the bundle format. A reader accepts the same major and any minor; it refuses a newer major.</summary>
    public const string CurrentFormatVersion = "1.3.0";

    public string FormatVersion { get; set; } = CurrentFormatVersion;
    public Guid SwitchId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public string CreatedBy { get; set; } = "";
    public BundleSource Source { get; set; } = new();
    public BundleIncludes Includes { get; set; } = new();

    /// <summary>Effective values of settings at export time; written explicitly into the target so behavior never changes silently (decision 30).</summary>
    public Dictionary<string, string> EffectiveSettings { get; set; } = new();

    public List<BundleFile> Files { get; set; } = [];
    public BundleSecrets Secrets { get; set; } = new();

    /// <summary>Per-table row counts and checksums (added in format 1.1); the target recomputes them from its own tables.</summary>
    public List<BundleTable> Tables { get; set; } = [];

    /// <summary>How the queue was handed over and the state of the resumable history export (added in format 1.1).</summary>
    public BundleSwitch Switch { get; set; } = new();

    [JsonIgnore]
    public static JsonSerializerOptions Json { get; } = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public static bool IsCompatible(string version, out string reason)
    {
        reason = "";
        if (!Version.TryParse(version, out var v))
        {
            reason = $"'{version}' is not a valid bundle format version.";
            return false;
        }

        var current = Version.Parse(CurrentFormatVersion);
        if (v.Major > current.Major)
        {
            reason = $"Bundle format {version} is newer than this EggMail understands ({CurrentFormatVersion}); upgrade EggMail first.";
            return false;
        }

        if (v.Major < current.Major)
        {
            reason = $"Bundle format {version} is no longer supported by this EggMail ({CurrentFormatVersion}).";
            return false;
        }

        return true;
    }
}

public sealed class BundleSource
{
    public string Backend { get; set; } = "";
    public string SchemaVersion { get; set; } = "";
    public string HistoryMode { get; set; } = "";
    public string AppVersion { get; set; } = "";
}

public sealed class BundleIncludes
{
    public bool Config { get; set; } = true;
    public bool Stats { get; set; } = true;
    public bool Queue { get; set; }
    public bool History { get; set; }
}

public sealed class BundleFile
{
    /// <summary>Path relative to the bundle root, with forward slashes.</summary>
    public string Path { get; set; } = "";

    public string Sha256 { get; set; } = "";
    public long Bytes { get; set; }

    /// <summary>NDJSON row count (0 for binary files).</summary>
    public long Rows { get; set; }

    /// <summary>For chunked history: the chunk's inclusive UTC day range, used for resumable copies.</summary>
    public string? ChunkFrom { get; set; }

    public string? ChunkTo { get; set; }

    /// <summary>The table the file belongs to (format 1.1); null for secrets files.</summary>
    public string? Table { get; set; }

    /// <summary>What the file holds: <c>rows</c> (NDJSON), <c>bodies</c> (the raw messages of the rows of the chunk with the same stem) or <c>secrets</c>.</summary>
    public string? Kind { get; set; }
}

/// <summary>Row count and checksums of one table as exported (order independent: the sum of the SHA-256 of every canonical row, see TableChecksum).</summary>
public sealed class BundleTable
{
    public string Name { get; set; } = "";
    public string Part { get; set; } = "";
    public long Rows { get; set; }

    /// <summary>The rows a switch holds back from dispatch (received mail holds its pending actions only). Null in a bundle written before this member existed: every row of a table with a hold.</summary>
    public long? HeldRows { get; set; }

    /// <summary>Hex of the 256-bit sum of the row hashes (secret columns excluded).</summary>
    public string Checksum { get; set; } = "";

    /// <summary>Hex of the 256-bit sum of keyed hashes of the plain secrets (null when the table has none); verified with the passphrase.</summary>
    public string? SecretDigest { get; set; }
}

public sealed class BundleSwitch
{
    /// <summary><c>drain</c> or <c>quiesce</c>.</summary>
    public string Mode { get; set; } = "drain";

    public bool HistoryIncluded { get; set; }

    /// <summary>True once every history day has been exported; an interrupted export resumes after <see cref="LastHistoryDay"/>.</summary>
    public bool HistoryComplete { get; set; }

    /// <summary>The last fully exported history day (days since 1970-01-01), or null before the first.</summary>
    public int? LastHistoryDay { get; set; }

    /// <summary>The newest history day of the source when the export started; the export is complete when it reaches it.</summary>
    public int? HistoryThroughDay { get; set; }
}

public sealed class BundleSecrets
{
    /// <summary>Protection scheme of every secret in the bundle (design §4.6, decision H).</summary>
    public string Scheme { get; set; } = "dp-pkcs12-v1";

    public string CertificateFile { get; set; } = "secrets/bundle-cert.pfx";
    public string KeyRingDirectory { get; set; } = "secrets/keyring";

    /// <summary>The key of the secret digests, protected with the bundle key ring (base64). Opening it needs the export passphrase.</summary>
    public string? DigestKeyProtected { get; set; }
}
