using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Mta.Smtp.Server;

public enum ListenerMode : byte
{
    /// <summary>Plain text, STARTTLS offered (ports 587, 2525, 25).</summary>
    StartTls,

    /// <summary>TLS from the first byte (port 465, RFC 8314).</summary>
    Implicit,

    /// <summary>Plain only; for loopback or internal networks. No AUTH over plain unless explicitly allowed.</summary>
    Plain,
}

public enum ListenerRole : byte
{
    /// <summary>Authenticated clients submit mail for delivery.</summary>
    Submission,

    /// <summary>Unauthenticated bounce / DSN receiver (port 25). Policy is the handler's job.</summary>
    Bounce,
}

public sealed class SmtpListenerOptions
{
    public required string Name { get; init; }
    public IPAddress BindAddress { get; init; } = IPAddress.IPv6Any;
    public required int Port { get; init; }
    public ListenerMode Mode { get; init; } = ListenerMode.StartTls;
    public ListenerRole Role { get; init; } = ListenerRole.Submission;
    public bool AuthRequired { get; init; } = true;
    public bool Enabled { get; init; } = true;

    /// <summary>Permit AUTH on a <see cref="ListenerMode.Plain"/> listener (only sensible on loopback).</summary>
    public bool AllowInsecureAuth { get; init; }
}

/// <summary>Supplies the server certificate for a TLS handshake. Implementations hot-reload.</summary>
public interface IServerCertificateProvider
{
    /// <summary>Returns the certificate for the given SNI name (may be null) or null if none is available.</summary>
    X509Certificate2? GetCertificate(string? serverName);
}

public sealed class SmtpServerOptions
{
    /// <summary>Host name used in the greeting and Received headers.</summary>
    public string Hostname { get; init; } = "localhost";

    public string ProductName { get; init; } = "EggMail";

    public long MaxMessageSize { get; init; } = 25L * 1024 * 1024;
    public int MaxRecipients { get; init; } = 50;
    public int MaxLineLength { get; init; } = 2048;

    /// <summary>Errors (bad syntax, sequence, rejected recipients) tolerated per session before 421.</summary>
    public int MaxErrorsPerSession { get; init; } = 10;

    public int MaxMessagesPerSession { get; init; } = 1000;

    public TimeSpan GreetingTimeout { get; init; } = TimeSpan.FromSeconds(30);
    public TimeSpan CommandTimeout { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Per-read timeout while receiving message data (RFC 5321 §4.5.3.2.5 says 3 minutes).</summary>
    public TimeSpan DataTimeout { get; init; } = TimeSpan.FromMinutes(3);

    /// <summary>Upper bound for receiving one message (slowloris defense).</summary>
    public TimeSpan MaxDataDuration { get; init; } = TimeSpan.FromMinutes(15);

    public TimeSpan TlsHandshakeTimeout { get; init; } = TimeSpan.FromSeconds(30);

    public int MaxConnections { get; init; } = 2000;
    public int MaxConnectionsPerIp { get; init; } = 100;

    /// <summary>Global budget for bytes of messages being received at the same time; exhaustion yields 452.</summary>
    public long MaxInFlightBytes { get; init; } = 512L * 1024 * 1024;

    public bool Pipelining { get; init; } = true;
    public bool Chunking { get; init; } = true;
    public bool SmtpUtf8 { get; init; } = true;
    public bool EightBitMime { get; init; } = true;
    public bool EnhancedStatusCodes { get; init; } = true;
    public bool RejectNulInData { get; init; } = true;

    /// <summary>Delay applied after a failed AUTH attempt (brute-force tarpit).</summary>
    public TimeSpan AuthFailureDelay { get; init; } = TimeSpan.FromSeconds(1);

    public SslProtocols TlsProtocols { get; init; } = SslProtocols.Tls12 | SslProtocols.Tls13;

    public IServerCertificateProvider? Certificates { get; init; }

    public IReadOnlyList<SmtpListenerOptions> Listeners { get; init; } = [];
}
