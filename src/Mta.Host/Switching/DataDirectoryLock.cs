namespace Mta.Host.Switching;

/// <summary>
/// An exclusive lock on a SQLite data directory (a lock file held open without sharing). Exactly one process may own the files
/// (design §4.4): the server holds the lock while it runs, and the offline <c>mta migrate-storage</c> commands take it, which
/// proves the server is stopped before they touch the files (opening them also clears leases, which would harm a live server).
/// </summary>
public sealed class DataDirectoryLock : IDisposable
{
    public const string FileName = ".eggmail.lock";

    private readonly FileStream _stream;

    private DataDirectoryLock(FileStream stream, string path)
    {
        _stream = stream;
        Path = path;
    }

    public string Path { get; }

    /// <summary>Takes the lock, or throws <see cref="IOException"/> naming the directory when another process owns it.</summary>
    public static DataDirectoryLock Acquire(string directory)
    {
        Directory.CreateDirectory(directory);
        string path = System.IO.Path.Combine(directory, FileName);
        try
        {
            var stream = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.None);
            return new DataDirectoryLock(stream, path);
        }
        catch (IOException ex)
        {
            throw new IOException($"Another process is using the data directory '{directory}' (lock file {path}). Stop the EggMail server that owns it first.", ex);
        }
    }

    public void Dispose() => _stream.Dispose();
}
