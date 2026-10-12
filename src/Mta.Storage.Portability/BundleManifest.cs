using System.Text.Json;
using System.Text.Json.Serialization;

namespace Mta.Storage.Portability;

/// <summary>Describes a portable storage bundle (design §4.6). JSON on disk as <c>manifest.json</c>.</summary>
public sealed class BundleManifest
{
    /// <summary>Semantic version of the bundle format. A reader accepts the same major and any minor; it refuses a newer major.</summary>
    public const string CurrentFormatVersion = "1.0.0";

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
}

public sealed class BundleSecrets
{
    /// <summary>Protection scheme of every secret in the bundle (design §4.6, decision H).</summary>
    public string Scheme { get; set; } = "dp-pkcs12-v1";

    public string CertificateFile { get; set; } = "secrets/bundle-cert.pfx";
    public string KeyRingDirectory { get; set; } = "secrets/keyring";
}
