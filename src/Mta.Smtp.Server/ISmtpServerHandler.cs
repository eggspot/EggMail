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

    /// <summary>
    /// A lower limit for the message of the open transaction, set by the handler while it accepts recipients (for example the smallest limit among the domains of the accepted recipients).
    /// The session enforces the lower of this and the listener's limit while it reads the body, with the ordinary <c>552 5.3.4</c>, and clears it when the transaction ends.
    /// </summary>
    public long? TransactionMaxMessageSize { get; set; }

    internal Func<long, bool>? MemoryReserver { get; set; }

    internal long ExtraReserved { get; set; }

    /// <summary>
    /// Reserves <paramref name="bytes"/> of the server's in-flight memory budget (the one the message bytes themselves are counted in) for work the handler does on the message, for example copies it makes. The
    /// reservation is given back when the transaction ends. False when the budget (or the listener's share of it) cannot cover it: the handler refuses the message with <c>452</c> instead of allocating.
    /// </summary>
    public bool TryReserveMemory(long bytes)
    {
        if (bytes <= 0)
        {
            return true;
        }

        if (MemoryReserver is { } reserve && !reserve(bytes))
        {
            return false;
        }

        ExtraReserved += bytes;
        return true;
    }

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
    /// Called when the client starts the message data (<c>DATA</c>, or the first <c>BDAT</c> chunk), after the last <c>RCPT</c> and before any data is read. Return null to go on or a reply
    /// to refuse the message at once: the transaction ends, nothing is read into memory (a refused <c>BDAT</c> chunk is still read and discarded, as the protocol requires). The default goes on.
    /// </summary>
    ValueTask<SmtpReply?> OnDataStartAsync(SmtpSessionContext session, MailFromInfo mail, IReadOnlyList<EmailAddress> recipients, CancellationToken cancellationToken) =>
        ValueTask.FromResult<SmtpReply?>(null);

    /// <summary>
    /// Called with the complete message. Return <c>250</c> only after the message is durably accepted (decision 13/Lite semantics);
    /// return 4xx to make the client retry, 5xx to bounce.
    /// </summary>
    ValueTask<SmtpReply> OnMessageAsync(SmtpMessage message, CancellationToken cancellationToken);

    /// <summary>
    /// Called when the server itself refused the message data after it had been announced to the handler (<see cref="OnDataStartAsync"/> went on): the body grew past the size limit (<c>552</c>) or the global
    /// in-flight budget was exhausted (<c>452</c>). The handler never sees such a message, so this is where it can count it. The default does nothing.
    /// </summary>
    void OnMessageRefused(SmtpSessionContext session, SmtpReply reply)
    {
    }

    void OnDisconnected(SmtpSessionContext session);
}
