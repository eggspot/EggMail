using System.Buffers;
using System.Net;
using Mta.Core;
using Mta.Smtp.Protocol;

namespace Mta.Smtp.Server;

/// <summary>Information about a connection, shared with the handler for the whole session.</summary>
public sealed class SmtpSessionContext
{
    public Guid SessionId { get; } = Ids.New();
    public required IPEndPoint RemoteEndPoint { get; init; }
    public required IPEndPoint LocalEndPoint { get; init; }
    public required string ListenerName { get; init; }
    public required ListenerRole Role { get; init; }
    public DateTimeOffset ConnectedAt { get; init; } = DateTimeOffset.UtcNow;

    public string? HeloName { get; internal set; }
    public bool UsedEhlo { get; internal set; }
    public bool TlsActive { get; internal set; }
    public string? TlsProtocol { get; internal set; }
    public string? TlsCipherSuite { get; internal set; }
    public string? AuthenticatedUser { get; internal set; }
    public bool SmtpUtf8 { get; internal set; }

    /// <summary>Free slot for the handler (for example per-session policy state).</summary>
    public object? HandlerState { get; set; }
}

public sealed class SmtpAuthResult
{
    public static readonly SmtpAuthResult Failed = new(false, null, null);

    public bool Success { get; }
    public string? UserName { get; }

    /// <summary>Optional reply override (for example 454 temporary failure or a lockout).</summary>
    public SmtpReply? Reply { get; }

    private SmtpAuthResult(bool success, string? user, SmtpReply? reply)
    {
        Success = success;
        UserName = user;
        Reply = reply;
    }

    public static SmtpAuthResult Succeeded(string userName) => new(true, userName, null);

    public static SmtpAuthResult Rejected(SmtpReply reply) => new(false, null, reply);
}

/// <summary>
/// The sender of the transaction and its MAIL FROM parameters. The server keeps one instance per session and reuses it for the next
/// transaction, so a handler that wants the values after its call returns must copy them.
/// </summary>
public sealed class MailFromInfo
{
    public EmailAddress Sender { get; internal set; }
    public MailParameters Parameters { get; internal set; }
}

/// <summary>
/// One accepted message ready to be handed to storage. The server keeps one instance per session and reuses it for the next message, and
/// <see cref="Body"/>, <see cref="ReceivedHeader"/> and <see cref="Recipients"/> are valid only during the handler call: a handler that keeps any
/// of them longer must copy it (<see cref="ToArray"/>, <c>ToArray()</c> on the header and the list).
/// </summary>
public sealed class SmtpMessage
{
    public SmtpSessionContext Session { get; internal set; } = null!;
    public EmailAddress Sender { get; internal set; }
    public MailParameters Parameters { get; internal set; }
    public IReadOnlyList<EmailAddress> Recipients { get; internal set; } = [];

    /// <summary>The unstuffed message exactly as received (CRLF line endings), without the Received header.</summary>
    public ReadOnlySequence<byte> Body { get; internal set; }

    /// <summary>Server-generated Received header (CRLF terminated) the handler should prepend to the stored copy.</summary>
    public ReadOnlyMemory<byte> ReceivedHeader { get; internal set; }

    public long Size => Body.Length;
    public DateTimeOffset ReceivedAt { get; internal set; }

    /// <summary>Drops the references to the per-message memory once the handler call has returned (the arrays behind <see cref="Body"/> go back to their pool).</summary>
    internal void Clear()
    {
        Body = default;
        ReceivedHeader = default;
        Recipients = [];
    }

    public byte[] ToArray() => Body.ToArray();
}

/// <summary>
/// Application policy and storage seam of the SMTP server. The server does protocol work only; every decision
/// (relay policy, authentication, spam/auth checks, durable enqueue) lives here. Return the reply to send.
/// </summary>
public interface ISmtpServerHandler
{
    /// <summary>Called after connect. Return null to send the normal greeting, or a 4xx/5xx reply to refuse the connection.</summary>
    ValueTask<SmtpReply?> OnConnectedAsync(SmtpSessionContext session, CancellationToken cancellationToken);

    ValueTask<SmtpAuthResult> AuthenticateAsync(SmtpSessionContext session, string authorizationId, string userName, string password, CancellationToken cancellationToken);

    ValueTask<SmtpReply> OnMailFromAsync(SmtpSessionContext session, MailFromInfo mail, CancellationToken cancellationToken);

    ValueTask<SmtpReply> OnRcptToAsync(SmtpSessionContext session, MailFromInfo mail, EmailAddress recipient, RcptParameters parameters, CancellationToken cancellationToken);

    /// <summary>
    /// Called with the complete message. Return <c>250</c> only after the message is durably accepted (decision 13/Lite semantics);
    /// return 4xx to make the client retry, 5xx to bounce.
    /// </summary>
    ValueTask<SmtpReply> OnMessageAsync(SmtpMessage message, CancellationToken cancellationToken);

    void OnDisconnected(SmtpSessionContext session);
}
