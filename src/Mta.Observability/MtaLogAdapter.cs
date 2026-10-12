using Microsoft.Extensions.Logging;
using Mta.Core;

namespace Mta.Observability;

/// <summary>Adapts the package-free <see cref="IMtaLog"/> seam to Microsoft.Extensions.Logging.</summary>
public sealed class MtaLogAdapter : IMtaLog
{
    private readonly ILoggerFactory _factory;

    public MtaLogAdapter(ILoggerFactory factory) => _factory = factory;

    public bool IsEnabled(MtaLogLevel level) => _factory.CreateLogger("Mta").IsEnabled(Map(level));

    public void Write(MtaLogLevel level, string source, string message, Exception? exception = null)
    {
        var logger = _factory.CreateLogger("Mta." + source);
        var l = Map(level);
        if (logger.IsEnabled(l))
        {
            logger.Log(l, exception, "{Message}", message);
        }
    }

    private static LogLevel Map(MtaLogLevel level) => level switch
    {
        MtaLogLevel.Trace => LogLevel.Trace,
        MtaLogLevel.Debug => LogLevel.Debug,
        MtaLogLevel.Information => LogLevel.Information,
        MtaLogLevel.Warning => LogLevel.Warning,
        _ => LogLevel.Error,
    };
}
