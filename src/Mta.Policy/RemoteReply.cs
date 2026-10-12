namespace Mta.Policy;

/// <summary>The point of the SMTP dialogue at which a reply (or a failure to get one) occurred.</summary>
public enum SmtpStage : byte
{
    /// <summary>Opening the connection and reading the greeting banner.</summary>
    Connect = 0,

    /// <summary>EHLO / STARTTLS / AUTH.</summary>
    Handshake,

    /// <summary>MAIL FROM.</summary>
    MailFrom,

    /// <summary>RCPT TO.</summary>
    RcptTo,

    /// <summary>The DATA (or BDAT) command itself, before the content is sent.</summary>
    Data,

    /// <summary>The reply to the end of message data (final dot or last BDAT chunk).</summary>
    EndOfData,
}

/// <summary>
/// A reply received from a remote SMTP server: basic code, optional RFC 3463 enhanced status code and the (joined) text.
/// Independent of the SMTP protocol library so the policy layer stays dependency-free.
/// </summary>
/// <param name="Code">Three digit reply code (for example 550).</param>
/// <param name="EnhancedCode">Enhanced status code such as "5.1.1", or null if the server did not send one (it may still be present at the start of <paramref name="Text"/>).</param>
/// <param name="Text">Reply text; multi-line replies joined with a space or newline.</param>
public readonly record struct RemoteReply(int Code, string? EnhancedCode, string? Text)
{
    /// <summary>Creates a reply with only a code and text.</summary>
    public RemoteReply(int code, string? text)
        : this(code, null, text)
    {
    }

    /// <summary>Parsed enhanced status code (from <see cref="EnhancedCode"/> or, if absent, the start of the text).</summary>
    public EnhancedStatus GetEnhancedStatus()
    {
        if (EnhancedStatus.TryParse(EnhancedCode, out var status))
        {
            return status;
        }

        return EnhancedStatus.TryParseLeading(Text, out status) ? status : default;
    }
}

/// <summary>An RFC 3463 enhanced status code (<c>class.subject.detail</c>). The default value means "none".</summary>
public readonly record struct EnhancedStatus(int Class, int Subject, int Detail)
{
    /// <summary>True when this holds a parsed code (class 2, 4 or 5).</summary>
    public bool IsValid => Class != 0;

    /// <inheritdoc />
    public override string ToString() => IsValid ? $"{Class}.{Subject}.{Detail}" : string.Empty;

    /// <summary>Parses exactly "d.ddd.ddd" (class 2, 4 or 5), surrounding whitespace ignored.</summary>
    public static bool TryParse(ReadOnlySpan<char> text, out EnhancedStatus status) =>
        TryParseCore(text.Trim(), requireWholeInput: true, out status);

    /// <summary>Parses an enhanced code at the very start of a reply text (leading whitespace allowed), as in "5.1.1 User unknown".</summary>
    public static bool TryParseLeading(ReadOnlySpan<char> text, out EnhancedStatus status) =>
        TryParseCore(text.TrimStart(), requireWholeInput: false, out status);

    private static bool TryParseCore(ReadOnlySpan<char> s, bool requireWholeInput, out EnhancedStatus status)
    {
        status = default;
        if (s.Length < 5 || s[0] is not ('2' or '4' or '5') || s[1] != '.')
        {
            return false;
        }

        int cls = s[0] - '0';
        int pos = 2;
        if (!ReadNumber(s, ref pos, out int subject) || pos >= s.Length || s[pos] != '.')
        {
            return false;
        }

        pos++;
        if (!ReadNumber(s, ref pos, out int detail))
        {
            return false;
        }

        if (pos < s.Length && (requireWholeInput || char.IsAsciiLetterOrDigit(s[pos]) || s[pos] == '.'))
        {
            return false;
        }

        status = new EnhancedStatus(cls, subject, detail);
        return true;
    }

    private static bool ReadNumber(ReadOnlySpan<char> s, ref int pos, out int value)
    {
        value = 0;
        int start = pos;
        while (pos < s.Length && char.IsAsciiDigit(s[pos]) && pos - start < 3)
        {
            value = (value * 10) + (s[pos] - '0');
            pos++;
        }

        return pos > start;
    }
}
