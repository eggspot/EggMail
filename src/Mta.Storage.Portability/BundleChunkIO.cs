using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Mta.Storage.Portability;

/// <summary>Writes NDJSON lines that a table already serialized, hashing the bytes written; the file is registered when disposed.</summary>
public sealed class LineFileWriter : IAsyncDisposable
{
    private readonly BundleWriter _bundle;
    private readonly string _relativePath;
    private readonly string _table;
    private readonly string? _chunkFrom;
    private readonly string? _chunkTo;
    private readonly FileStream _file;
    private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private long _rows;
    private long _bytes;
    private bool _closed;

    internal LineFileWriter(BundleWriter bundle, string relativePath, string table, string? chunkFrom, string? chunkTo)
    {
        _bundle = bundle;
        _relativePath = relativePath;
        _table = table;
        _chunkFrom = chunkFrom;
        _chunkTo = chunkTo;
        string full = bundle.ResolvePath(relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        _file = new FileStream(full, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.Asynchronous);
    }

    public long Rows => _rows;

    public long Bytes => _bytes;

    public async ValueTask WriteLineAsync(string json, CancellationToken ct)
    {
        byte[] data = new byte[Encoding.UTF8.GetMaxByteCount(json.Length) + 1];
        int n = Encoding.UTF8.GetBytes(json, data);
        data[n++] = (byte)'\n';
        _hash.AppendData(data.AsSpan(0, n));
        await _file.WriteAsync(data.AsMemory(0, n), ct).ConfigureAwait(false);
        _bytes += n;
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
        _bundle.Register(_relativePath, _hash.GetHashAndReset(), _bytes, _rows, _chunkFrom, _chunkTo, _table, "rows");
        _hash.Dispose();
    }
}

/// <summary>
/// Writes the raw messages of one row chunk as a pack: an 8-byte magic, then for every row a little-endian 32-bit length and
/// the bytes, in the order of the rows of the chunk file with the same stem. One pack replaces thousands of single files.
/// </summary>
public sealed class BodyPackWriter : IAsyncDisposable
{
    internal static readonly byte[] Magic = "EGGBODY1"u8.ToArray();

    private readonly BundleWriter _bundle;
    private readonly string _relativePath;
    private readonly string _table;
    private readonly string? _chunkFrom;
    private readonly string? _chunkTo;
    private readonly FileStream _file;
    private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private long _rows;
    private long _bytes;
    private bool _closed;

    internal BodyPackWriter(BundleWriter bundle, string relativePath, string table, string? chunkFrom, string? chunkTo)
    {
        _bundle = bundle;
        _relativePath = relativePath;
        _table = table;
        _chunkFrom = chunkFrom;
        _chunkTo = chunkTo;
        string full = bundle.ResolvePath(relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        _file = new FileStream(full, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.Asynchronous);
        _hash.AppendData(Magic);
        _file.Write(Magic);
        _bytes = Magic.Length;
    }

    public long Bytes => _bytes;

    public async ValueTask WriteAsync(ReadOnlyMemory<byte> body, CancellationToken ct)
    {
        byte[] length = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(length, body.Length);
        _hash.AppendData(length);
        _hash.AppendData(body.Span);
        await _file.WriteAsync(length, ct).ConfigureAwait(false);
        await _file.WriteAsync(body, ct).ConfigureAwait(false);
        _bytes += 4 + body.Length;
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
        _bundle.Register(_relativePath, _hash.GetHashAndReset(), _bytes, _rows, _chunkFrom, _chunkTo, _table, "bodies");
        _hash.Dispose();
    }
}

/// <summary>Reads a body pack sequentially (the file is read once, in row order).</summary>
public sealed class BodyPackReader : IAsyncDisposable
{
    private readonly FileStream _file;
    private readonly string _path;

    private BodyPackReader(FileStream file, string path)
    {
        _file = file;
        _path = path;
    }

    public static async Task<BodyPackReader> OpenAsync(string path, CancellationToken ct)
    {
        var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        byte[] magic = new byte[BodyPackWriter.Magic.Length];
        try
        {
            await file.ReadExactlyAsync(magic, ct).ConfigureAwait(false);
        }
        catch (EndOfStreamException)
        {
            await file.DisposeAsync().ConfigureAwait(false);
            throw new BundleException($"{path}: not a body pack (too short).");
        }

        if (!magic.AsSpan().SequenceEqual(BodyPackWriter.Magic))
        {
            await file.DisposeAsync().ConfigureAwait(false);
            throw new BundleException($"{path}: not a body pack (bad header).");
        }

        return new BodyPackReader(file, path);
    }

    /// <summary>The next body, or null at the end of the pack.</summary>
    public async ValueTask<byte[]?> ReadNextAsync(CancellationToken ct)
    {
        byte[] length = new byte[4];
        int read = await _file.ReadAtLeastAsync(length, 4, throwOnEndOfStream: false, ct).ConfigureAwait(false);
        if (read == 0)
        {
            return null;
        }

        if (read < 4)
        {
            throw new BundleException($"{_path}: truncated body pack.");
        }

        int n = BinaryPrimitives.ReadInt32LittleEndian(length);
        if (n < 0)
        {
            throw new BundleException($"{_path}: negative body length.");
        }

        byte[] body = new byte[n];
        try
        {
            await _file.ReadExactlyAsync(body, ct).ConfigureAwait(false);
        }
        catch (EndOfStreamException)
        {
            throw new BundleException($"{_path}: truncated body pack.");
        }

        return body;
    }

    public ValueTask DisposeAsync() => _file.DisposeAsync();
}

public static class BundleReaderExtensions
{
    /// <summary>Streams the lines of a text file of a bundle (one JSON row per line); empty lines are skipped.</summary>
    public static async IAsyncEnumerable<string> ReadLinesAsync(this BundleReader reader, string relativePath, [EnumeratorCancellation] CancellationToken ct)
    {
        await using var s = new FileStream(reader.PathOf(relativePath), FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var text = new StreamReader(s, Encoding.UTF8, false, 64 * 1024);
        while (await text.ReadLineAsync(ct).ConfigureAwait(false) is { } line)
        {
            if (line.Length > 0)
            {
                yield return line;
            }
        }
    }

    /// <summary>Recomputes the SHA-256 and size of one file and compares them with the manifest. Throws <see cref="BundleException"/> on any difference.</summary>
    public static async Task VerifyFileAsync(this BundleReader reader, BundleFile file, CancellationToken ct)
    {
        string full = reader.PathOf(file.Path);
        if (!File.Exists(full))
        {
            throw new BundleException($"{file.Path}: file is missing from the bundle.");
        }

        await using var s = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (s.Length != file.Bytes)
        {
            throw new BundleException($"{file.Path}: size {s.Length} differs from the manifest ({file.Bytes}); the bundle is damaged or was modified.");
        }

        string hash = Convert.ToHexString(await SHA256.HashDataAsync(s, ct).ConfigureAwait(false)).ToLowerInvariant();
        if (!string.Equals(hash, file.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new BundleException($"{file.Path}: SHA-256 differs from the manifest; the bundle is damaged or was modified.");
        }
    }
}
