using Mta.Core;

namespace Mta.Smtp.Protocol;

public enum SmtpVerb : byte
{
    Unknown = 0,
    Helo,
    Ehlo,
    Mail,
    Rcpt,
    Data,
    Bdat,
    Rset,
    Noop,
    Quit,
    Vrfy,
    Expn,
    Help,
    StartTls,
    Auth,
}

/// <summary>Body type declared with MAIL FROM BODY= (RFC 6152 / RFC 3030).</summary>
public enum SmtpBodyType : byte
{
    SevenBit = 0,
    EightBitMime,
    BinaryMime,
}

/// <summary>Parameters of MAIL FROM (RFC 5321 §4.1.1.2 plus SIZE, BODY, SMTPUTF8, AUTH).</summary>
public readonly record struct MailParameters(
    long? Size,
    SmtpBodyType BodyType,
    bool SmtpUtf8,
    string? Auth,
    string? EnvelopeId,
    bool ReturnHeadersOnly);

/// <summary>Parameters of RCPT TO (DSN extension NOTIFY/ORCPT are parsed so they can be rejected or honored by policy).</summary>
public readonly record struct RcptParameters(string? Notify, string? OriginalRecipient);

/// <summary>A parsed client command. Only the members relevant to <see cref="Verb"/> are set.</summary>
public readonly record struct SmtpCommand
{
    public SmtpVerb Verb { get; init; }

    /// <summary>HELO/EHLO domain or address literal, VRFY/EXPN/HELP argument, AUTH mechanism.</summary>
    public string? Argument { get; init; }

    /// <summary>AUTH initial response (base64 text) when supplied with the command; "=" is a zero-length response.</summary>
    public string? InitialResponse { get; init; }

    /// <summary>MAIL FROM / RCPT TO path. <see cref="EmailAddress.Null"/> for <c>&lt;&gt;</c>.</summary>
    public EmailAddress Path { get; init; }

    public MailParameters Mail { get; init; }

    public RcptParameters Rcpt { get; init; }

    /// <summary>BDAT chunk size and LAST flag.</summary>
    public long ChunkSize { get; init; }

    public bool LastChunk { get; init; }
}

public enum SmtpParseError : byte
{
    None = 0,
    UnknownCommand,
    Syntax,
    BadParameter,
    ParameterNotImplemented,
    LineTooLong,
    InvalidCharacter,
}
