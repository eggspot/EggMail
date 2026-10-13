using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Mta.Storage.Portability;

/// <summary>
/// Writes a bundle directory: NDJSON files (one JSON document per line, streamed so memory stays bounded), binary files
/// (spool bodies, retained raw) and finally <c>manifest.json</c> with the SHA-256 and size of every file.
/// </summary>
public sealed class BundleWriter : IDisposable
{
    private readonly string _root;
    private readonly BundleManifest _manifest;
    private readonly List<BundleFile> _files = [];
    private bool _completed;

    public BundleWriter(string rootDirectory, BundleManifest manifest)
    {
        _root = Path.GetFullPath(rootDirectory);
        _manifest = manifest;
        Directory.CreateDirectory(_root);
        if (Directory.EnumerateFileSystemEntries(_root).Any())
        {
            throw new IOException($"Bundle directory '{_root}' is not empty.");
        }
    }

    private BundleWriter(string root, BundleManifest manifest, bool append)
    {
        _root = root;
        _manifest = manifest;
        _files.AddRange(manifest.Files);
        _ = append;
    }

    /// <summary>
    /// Reopens a bundle whose manifest is already written to add files to it (the resumable history export). The manifest stays
    /// consistent on disk: it is only ever replaced atomically by <see cref="CheckpointAsync"/>.
    /// </summary>
    public static async Task<BundleWriter> OpenForAppendAsync(string rootDirectory, CancellationToken ct)
    {
        string root = Path.GetFullPath(rootDirectory);
        string manifestPath = Path.Combine(root, "manifest.json");
        if (!File.Exists(manifestPath))
        {
            throw new BundleException($"'{root}' is not a bundle (manifest.json is missing).");
        }

        BundleManifest? manifest;
        await using (var s = File.OpenRead(manifestPath))
        {
            manifest = await JsonSerializer.DeserializeAsync<BundleManifest>(s, BundleManifest.Json, ct).ConfigureAwait(false);
        }

        return new BundleWriter(root, manifest ?? throw new BundleException("manifest.json is empty."), append: true);
    }

    public string Root => _root;

    public BundleManifest Manifest => _manifest;

    /// <summary>Opens a file of NDJSON lines that a table already serialized and records it with its table and chunk metadata.</summary>
    public LineFileWriter OpenLines(string relativePath, string table, string? chunkFrom = null, string? chunkTo = null) =>
        new(this, relativePath, table, chunkFrom, chunkTo);

    /// <summary>Opens a body pack: the raw messages of one row chunk, in row order.</summary>
    public BodyPackWriter OpenBodies(string relativePath, string table, string? chunkFrom = null, string? chunkTo = null) =>
        new(this, relativePath, table, chunkFrom, chunkTo);

    /// <summary>Deletes files under <paramref name="prefix"/> that the manifest does not list (leftovers of an interrupted export).</summary>
    public int DeleteUnlistedUnder(string prefix)
    {
        string dir = Path.Combine(_root, prefix);
        if (!Directory.Exists(dir))
        {
            return 0;
        }

        HashSet<string> listed;
        lock (_files)
        {
            listed = _files.Select(f => f.Path).ToHashSet(StringComparer.Ordinal);
        }

        int n = 0;
        foreach (string file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
        {
            string rel = Path.GetRelativePath(_root, file).Replace('\\', '/');
            if (!listed.Contains(rel))
            {
                File.Delete(file);
                n++;
            }
        }

        return n;
    }

    /// <summary>Opens an NDJSON file for writing rows of type <typeparamref name="T"/>.</summary>
    public NdjsonFileWriter<T> OpenNdjson<T>(string relativePath, JsonSerializerOptions? options = null, string? chunkFrom = null, string? chunkTo = null) =>
        new(this, relativePath, options ?? BundleJson.Options, chunkFrom, chunkTo);

    /// <summary>Writes a binary file (for example a spool body) and records its hash.</summary>
    public async Task WriteBinaryAsync(string relativePath, ReadOnlyMemory<byte> content, CancellationToken ct)
    {
        string full = ResolvePath(relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        await File.WriteAllBytesAsync(full, content.ToArray(), ct).ConfigureAwait(false);
        Register(relativePath, SHA256.HashData(content.Span), content.Length, 0, null, null);
    }

    /// <summary>Absolute path inside the bundle (rejects paths that escape it).</summary>
    public string ResolvePath(string relativePath)
    {
        string full = Path.GetFullPath(Path.Combine(_root, relativePath));
        if (!full.StartsWith(_root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
        {
            throw new ArgumentException($"Path '{relativePath}' escapes the bundle directory.", nameof(relativePath));
        }

        return full;
    }

    internal void Register(string relativePath, byte[] sha256, long bytes, long rows, string? chunkFrom, string? chunkTo, string? table = null, string? kind = null)
    {
        lock (_files)
        {
            _files.Add(new BundleFile
            {
                Path = relativePath.Replace('\\', '/'),
                Sha256 = Convert.ToHexString(sha256).ToLowerInvariant(),
                Bytes = bytes,
                Rows = rows,
                ChunkFrom = chunkFrom,
                ChunkTo = chunkTo,
                Table = table,
                Kind = kind,
            });
        }
    }

    /// <summary>Registers a file that was written directly (the secrets files) so it is covered by the manifest.</summary>
    public async Task AddExistingFileAsync(string relativePath, CancellationToken ct)
    {
        string full = ResolvePath(relativePath);
        await using var s = File.OpenRead(full);
        byte[] hash = await SHA256.HashDataAsync(s, ct).ConfigureAwait(false);
        Register(relativePath, hash, new FileInfo(full).Length, 0, null, null, null, "secrets");
    }

    /// <summary>Writes <c>manifest.json</c>. The bundle is complete only after this call.</summary>
    public async Task CompleteAsync(CancellationToken ct)
    {
        if (_completed)
        {
            throw new InvalidOperationException("Bundle already completed.");
        }

        await CheckpointAsync(ct).ConfigureAwait(false);
        _completed = true;
    }

    /// <summary>
    /// Writes <c>manifest.json</c> atomically (temporary file, then replace), so a reader or a restart always sees a manifest
    /// that lists exactly the files that are complete. Used between history days.
    /// </summary>
    public async Task CheckpointAsync(CancellationToken ct)
    {
        lock (_files)
        {
            _manifest.Files = _files.OrderBy(f => f.Path, StringComparer.Ordinal).ToList();
        }

        string path = Path.Combine(_root, "manifest.json");
        string temp = path + ".tmp";
        await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(_manifest, BundleManifest.Json), new UTF8Encoding(false), ct).ConfigureAwait(false);
        File.Move(temp, path, overwrite: true);
    }

    public void Dispose()
    {
    }
}

/// <summary>Shared JSON options for bundle rows: camelCase, enums as strings, tolerant of unknown members on read.</summary>
public static class BundleJson
{
    public static JsonSerializerOptions Options { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
        WriteIndented = false,
    };
}

/// <summary>Streams rows to one NDJSON file while hashing the bytes written.</summary>
public sealed class NdjsonFileWriter<T> : IAsyncDisposable
{
    private readonly BundleWriter _bundle;
    private readonly string _relativePath;
    private readonly JsonSerializerOptions _options;
    private readonly string? _chunkFrom;
    private readonly string? _chunkTo;
    private readonly FileStream _file;
    private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private readonly System.Buffers.ArrayBufferWriter<byte> _buffer = new(4096);
    private long _rows;
    private long _bytes;
    private bool _closed;

    internal NdjsonFileWriter(BundleWriter bundle, string relativePath, JsonSerializerOptions options, string? chunkFrom, string? chunkTo)
    {
        _bundle = bundle;
        _relativePath = relativePath;
        _options = options;
        _chunkFrom = chunkFrom;
        _chunkTo = chunkTo;
        string full = bundle.ResolvePath(relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        _file = new FileStream(full, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.Asynchronous);
    }

    public long Rows => _rows;

    public long Bytes => _bytes;

    public async ValueTask WriteAsync(T row, CancellationToken ct)
    {
        _buffer.ResetWrittenCount();
        using (var w = new Utf8JsonWriter(_buffer))
        {
            JsonSerializer.Serialize(w, row, _options);
        }

        _buffer.Write("\n"u8);
        var data = _buffer.WrittenMemory;
        _hash.AppendData(data.Span);
        await _file.WriteAsync(data, ct).ConfigureAwait(false);
        _bytes += data.Length;
        _rows++;
    }

    public async ValueTask DisposeAsync()
    {
        if (_closed)
        {
            return;
        }

        _closed = true;
        await _file.FlushAsync().ConfigureAwait(false);
        await _file.DisposeAsync().ConfigureAwait(false);
        _bundle.Register(_relativePath, _hash.GetHashAndReset(), _bytes, _rows, _chunkFrom, _chunkTo);
        _hash.Dispose();
    }
}
