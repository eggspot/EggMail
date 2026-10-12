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

    public string Root => _root;

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

    internal void Register(string relativePath, byte[] sha256, long bytes, long rows, string? chunkFrom, string? chunkTo)
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
            });
        }
    }

    /// <summary>Registers a file that was written directly (the secrets files) so it is covered by the manifest.</summary>
    public async Task AddExistingFileAsync(string relativePath, CancellationToken ct)
    {
        string full = ResolvePath(relativePath);
        await using var s = File.OpenRead(full);
        byte[] hash = await SHA256.HashDataAsync(s, ct).ConfigureAwait(false);
        Register(relativePath, hash, new FileInfo(full).Length, 0, null, null);
    }

    /// <summary>Writes <c>manifest.json</c>. The bundle is complete only after this call.</summary>
    public async Task CompleteAsync(CancellationToken ct)
    {
        if (_completed)
        {
            throw new InvalidOperationException("Bundle already completed.");
        }

        lock (_files)
        {
            _manifest.Files = _files.OrderBy(f => f.Path, StringComparer.Ordinal).ToList();
        }

        await File.WriteAllTextAsync(Path.Combine(_root, "manifest.json"), JsonSerializer.Serialize(_manifest, BundleManifest.Json), new UTF8Encoding(false), ct).ConfigureAwait(false);
        _completed = true;
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
