using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using Mta.Core;
using Mta.Smtp.Protocol;

namespace Mta.Smtp.Client;

public enum SmtpTlsMode : byte
{
    /// <summary>No TLS is attempted.</summary>
    None = 0,

    /// <summary>Use STARTTLS when the server offers it; if it does not and <see cref="SmtpTlsPolicy.Require"/> is false, continue in plaintext.</summary>
    StartTls,

    /// <summary>TLS from the first byte (port 465 relays).</summary>
    Implicit,
}

/// <summary>TLS behavior for one connection, chosen by the delivery layer from the outbound TLS policy (MTA-STS, DANE, per-domain level).</summary>
public sealed class SmtpTlsPolicy
{
    public SmtpTlsMode Mode { get; init; } = SmtpTlsMode.StartTls;

    /// <summary>Fail (do not send in plaintext) when TLS cannot be negotiated.</summary>
    public bool Require { get; init; }

    /// <summary>Host name used for SNI and certificate name checks (keep stable per MX so session resumption works).</summary>
    public string? TargetHost { get; init; }

    public SslProtocols Protocols { get; init; } = SslProtocols.None;

    /// <summary>Certificate validation. Null accepts any certificate (opportunistic mode); the observed policy errors are still recorded.</summary>
    public RemoteCertificateValidationCallback? ValidationCallback { get; init; }

    public static readonly SmtpTlsPolicy Opportunistic = new();
    public static readonly SmtpTlsPolicy Disabled = new() { Mode = SmtpTlsMode.None };
}

public sealed class SmtpCredentials
{
    public required string UserName { get; init; }
    public required string Password { get; init; }
}

/// <summary>Where to connect and how.</summary>
public sealed class SmtpRemoteTarget
{
    /// <summary>Host name for logs and (by default) TLS.</summary>
    public required string Host { get; init; }

    public required IPAddress Address { get; init; }
    public int Port { get; init; } = 25;
    public SmtpTlsPolicy Tls { get; init; } = SmtpTlsPolicy.Opportunistic;
    public SmtpCredentials? Credentials { get; init; }

    /// <summary>Optional local address to bind (multi-IP sending).</summary>
    public IPAddress? LocalAddress { get; init; }

    /// <summary>Identity of this target in the connection pool (host, address, port, TLS policy, credentials).</summary>
    public string PoolKey => $"{Host}|{Address}|{Port}|{Tls.Mode}|{Tls.Require}|{Credentials?.UserName}";
}

public sealed class SmtpClientOptions
{
    /// <summary>Name announced in EHLO (must match PTR/forward DNS of the sending IP).</summary>
    public string HeloName { get; init; } = "localhost";

    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(30);

    // RFC 5321 §4.5.3.2 timeouts.
    public TimeSpan BannerTimeout { get; init; } = TimeSpan.FromMinutes(5);
    public TimeSpan CommandTimeout { get; init; } = TimeSpan.FromMinutes(5);
    public TimeSpan DataInitiationTimeout { get; init; } = TimeSpan.FromMinutes(2);
    public TimeSpan DataBlockTimeout { get; init; } = TimeSpan.FromMinutes(3);
    public TimeSpan EndOfDataTimeout { get; init; } = TimeSpan.FromMinutes(10);
    public TimeSpan TlsHandshakeTimeout { get; init; } = TimeSpan.FromSeconds(30);

    public bool Pipelining { get; init; } = true;

    /// <summary>Use BDAT when the server advertises CHUNKING (default false: DATA is the most compatible).</summary>
    public bool PreferChunking { get; init; }

    public int BdatChunkSize { get; init; } = 256 * 1024;

    /// <summary>Largest reply line count accepted from a server.</summary>
    public int MaxReplyLines { get; init; } = SmtpReplyParser.MaxLines;
}

public sealed record SmtpTlsSession(
    bool Used,
    string? Protocol,
    string? CipherSuite,
    string? PeerSubject,
    string? PeerIssuer,
    string? PeerSha256,
    SslPolicyErrors PolicyErrors,
    bool Verified,
    bool StartTlsAdvertised,
    bool PlaintextFallback);

public enum SmtpStage : byte
{
    Connect = 0,
    Banner,
    Ehlo,
    StartTls,
    Auth,
    MailFrom,
    RcptTo,
    Data,
    EndOfData,
    Rset,
}

public enum LocalFailure : byte
{
    None = 0,

    /// <summary>The message is larger than the server's declared SIZE limit; nothing was sent.</summary>
    MessageTooLarge,

    /// <summary>An address or header needs SMTPUTF8 and the server does not offer it.</summary>
    Smtputf8NotSupported,

    /// <summary>The message contains a bare CR/LF/NUL and cannot be transmitted without corruption.</summary>
    MalformedMessage,

    /// <summary>The message is 8-bit and the server lacks 8BITMIME.</summary>
    EightBitNotSupported,
}

public sealed record SmtpEnvelope(EmailAddress From, IReadOnlyList<EmailAddress> Recipients, bool SmtpUtf8, bool EightBit);

public sealed class SmtpRecipientResult
{
    public required EmailAddress Address { get; init; }
    public required SmtpReply Reply { get; init; }

    /// <summary>Accepted at RCPT time (and, if the transaction completed, delivered to the server's queue).</summary>
    public bool Accepted => Reply.IsPositiveCompletion;
}

/// <summary>Everything that happened during one mail transaction. Exactly one of the outcome shapes applies.</summary>
public sealed class SmtpSendResult
{
    public LocalFailure LocalFailure { get; init; }

    /// <summary>Stage at which the transaction stopped (the last stage reached when it succeeded is <see cref="SmtpStage.EndOfData"/>).</summary>
    public SmtpStage Stage { get; init; }

    /// <summary>Reply to MAIL FROM when it was rejected.</summary>
    public SmtpReply? SenderRejection { get; init; }

    public IReadOnlyList<SmtpRecipientResult> Recipients { get; init; } = [];

    /// <summary>Reply to DATA/BDAT when it was rejected before the message was sent.</summary>
    public SmtpReply? DataRejection { get; init; }

    /// <summary>Reply after the end of message data. A 2xx means every accepted recipient is queued by the server.</summary>
    public SmtpReply? FinalReply { get; init; }

    /// <summary>The terminating dot (or last BDAT chunk) was written. Needed to decide possible duplicates when the connection dies afterwards.</summary>
    public bool EndOfDataSent { get; init; }

    public bool Delivered => FinalReply is { IsPositiveCompletion: true };
}

public class SmtpClientException : Exception
{
    public SmtpClientException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>Network-level failure (refused, unreachable, reset, timeout) at <see cref="Stage"/>.</summary>
public sealed class SmtpConnectionException : SmtpClientException
{
    public SmtpStage Stage { get; }

    /// <summary>The terminating dot had been sent: the server may have accepted the message (possible duplicate).</summary>
    public bool EndOfDataSent { get; }

    public bool TimedOut { get; }

    public SmtpConnectionException(SmtpStage stage, string message, Exception? inner = null, bool endOfDataSent = false, bool timedOut = false)
        : base(message, inner)
    {
        Stage = stage;
        EndOfDataSent = endOfDataSent;
        TimedOut = timedOut;
    }
}

/// <summary>The server sent something that is not valid SMTP.</summary>
public sealed class SmtpProtocolException : SmtpClientException
{
    public SmtpProtocolException(string message) : base(message)
    {
    }
}

public enum TlsFailure : byte
{
    /// <summary>TLS was required but the server did not offer STARTTLS (possible stripping).</summary>
    NotAdvertised = 0,

    /// <summary>STARTTLS was refused with a non-2xx reply.</summary>
    Refused,

    /// <summary>The handshake or certificate validation failed.</summary>
    HandshakeFailed,
}

/// <summary>TLS could not be established as required by (or attempted under) the policy.</summary>
public sealed class SmtpTlsException : SmtpClientException
{
    public TlsFailure Failure { get; }
    public SmtpTlsSession? Session { get; }

    public SmtpTlsException(TlsFailure failure, string message, SmtpTlsSession? session = null, Exception? inner = null) : base(message, inner)
    {
        Failure = failure;
        Session = session;
    }
}

/// <summary>The remote server's greeting or EHLO was a failure reply (not an exception of the network).</summary>
public sealed class SmtpGreetingRejectedException : SmtpClientException
{
    public SmtpReply Reply { get; }
    public SmtpStage Stage { get; }

    public SmtpGreetingRejectedException(SmtpStage stage, SmtpReply reply) : base($"{stage} rejected: {reply}")
    {
        Stage = stage;
        Reply = reply;
    }
}
