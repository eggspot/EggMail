namespace Mta.Core;

public enum MtaLogLevel : byte
{
    Trace = 0,
    Debug,
    Information,
    Warning,
    Error,
}

/// <summary>
/// Minimal logging seam for the package-free protocol stack (which cannot depend on logging packages).
/// The host adapts it to Microsoft.Extensions.Logging. Hot paths must check <see cref="IsEnabled"/> before formatting.
/// </summary>
public interface IMtaLog
{
    bool IsEnabled(MtaLogLevel level);

    void Write(MtaLogLevel level, string source, string message, Exception? exception = null);
}

public sealed class NullMtaLog : IMtaLog
{
    public static readonly NullMtaLog Instance = new();

    public bool IsEnabled(MtaLogLevel level) => false;

    public void Write(MtaLogLevel level, string source, string message, Exception? exception = null)
    {
    }
}
