using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace Mta.Storage.Portability;

public sealed record BundleVerification(bool Ok, IReadOnlyList<string> Problems, long FilesChecked, long BytesChecked);

/// <summary>Reads and verifies a bundle directory.</summary>
public sealed class BundleReader
{
    private BundleReader(string root, BundleManifest manifest)
    {
        Root = root;
        Manifest = manifest;
    }

    public string Root { get; }

    public BundleManifest Manifest { get; }

    /// <summary>Opens a bundle. Throws <see cref="BundleException"/> if the manifest is missing, malformed or from an incompatible format.</summary>
    public static async Task<BundleReader> OpenAsync(string rootDirectory, CancellationToken ct)
    {
        string root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(rootDirectory));   // "dir/" and "dir" are the same bundle
        string manifestPath = Path.Combine(root, "manifest.json");
        if (!File.Exists(manifestPath))
        {
            throw new BundleException($"'{root}' is not a complete bundle (manifest.json is missing).");
        }

        BundleManifest? manifest;
        try
        {
            await using var s = File.OpenRead(manifestPath);
            manifest = await JsonSerializer.DeserializeAsync<BundleManifest>(s, BundleManifest.Json, ct).ConfigureAwait(false);
        }
        catch (JsonException ex)
        {
            throw new BundleException("manifest.json is not valid: " + ex.Message, ex);
        }

        if (manifest is null)
        {
            throw new BundleException("manifest.json is empty.");
        }

        if (!BundleManifest.IsCompatible(manifest.FormatVersion, out string reason))
        {
            throw new BundleException(reason);
        }

        foreach (var f in manifest.Files)
        {
            string full = Path.GetFullPath(Path.Combine(root, f.Path));
            if (!full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            {
                throw new BundleException($"Manifest path '{f.Path}' escapes the bundle directory.");
            }
        }

        return new BundleReader(root, manifest);
    }

    /// <summary>The absolute path of a file of the bundle; a path that leaves the bundle directory is refused (the manifest is checked when the bundle is opened, this is the same rule for every other caller).</summary>
    // Containment is decided on the path as written: a symbolic link inside the bundle directory is not resolved. The bundle is a directory the administrator
    // wrote and chose; the manifest hashes (VerifyAsync) are what notice a changed file.
    public string PathOf(string relativePath)
    {
        string full = Path.GetFullPath(Path.Combine(Root, relativePath));
        if (!full.StartsWith(Root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
        {
            throw new BundleException($"Path '{relativePath}' escapes the bundle directory.");
        }

        return full;
    }

    public IEnumerable<BundleFile> FilesUnder(string prefix) => Manifest.Files.Where(f => f.Path.StartsWith(prefix, StringComparison.Ordinal));

    /// <summary>Recomputes the SHA-256 and size of every file listed in the manifest (streaming) and reports every mismatch.</summary>
    public async Task<BundleVerification> VerifyAsync(CancellationToken ct)
    {
        var problems = new List<string>();
        long bytes = 0;
        foreach (var f in Manifest.Files)
        {
            string full = PathOf(f.Path);
            if (!File.Exists(full))
            {
                problems.Add($"{f.Path}: file is missing");
                continue;
            }

            await using var s = File.OpenRead(full);
            if (s.Length != f.Bytes)
            {
                problems.Add($"{f.Path}: size {s.Length} differs from manifest {f.Bytes}");
            }

            string hash = Convert.ToHexString(await SHA256.HashDataAsync(s, ct).ConfigureAwait(false)).ToLowerInvariant();
            if (hash != f.Sha256)
            {
                problems.Add($"{f.Path}: SHA-256 differs from the manifest");
            }

            bytes += s.Length;
        }

        // Files present on disk but not listed are suspicious.
        var listed = Manifest.Files.Select(f => f.Path).ToHashSet(StringComparer.Ordinal);
        foreach (string file in Directory.EnumerateFiles(Root, "*", SearchOption.AllDirectories))
        {
            string rel = Path.GetRelativePath(Root, file).Replace('\\', '/');
            if (rel != "manifest.json" && !listed.Contains(rel))
            {
                problems.Add($"{rel}: file is not listed in the manifest");
            }
        }

        return new BundleVerification(problems.Count == 0, problems, Manifest.Files.Count, bytes);
    }

    /// <summary>Streams the rows of an NDJSON file. Unknown members are ignored (forward compatibility within a major version).</summary>
    public async IAsyncEnumerable<T> ReadNdjsonAsync<T>(string relativePath, [EnumeratorCancellation] CancellationToken ct, JsonSerializerOptions? options = null)
    {
        await using var s = new FileStream(PathOf(relativePath), FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var reader = new StreamReader(s, System.Text.Encoding.UTF8, false, 64 * 1024);
        var opts = options ?? BundleJson.Options;
        long line = 0;
        while (await reader.ReadLineAsync(ct).ConfigureAwait(false) is { } text)
        {
            line++;
            if (text.Length == 0)
            {
                continue;
            }

            T? row;
            try
            {
                row = JsonSerializer.Deserialize<T>(text, opts);
            }
            catch (JsonException ex)
            {
                throw new BundleException($"{relativePath}, line {line}: {ex.Message}", ex);
            }

            if (row is null)
            {
                throw new BundleException($"{relativePath}, line {line}: null row");
            }

            yield return row;
        }
    }
}

public sealed class BundleException : Exception
{
    public BundleException(string message, Exception? inner = null) : base(message, inner)
    {
    }
}
