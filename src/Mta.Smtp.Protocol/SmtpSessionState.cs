namespace Mta.Smtp.Protocol;

/// <summary>
/// Pure state machine for the server side of an SMTP session: enforces command sequencing (RFC 5321 §4.1.4),
/// STARTTLS and AUTH rules. It performs no I/O and no policy; the server asks it whether a command is allowed now and
/// tells it what happened.
/// </summary>
public sealed class SmtpSessionState
{
    public bool Greeted { get; private set; }
    public bool UsedEhlo { get; private set; }
    public bool TlsActive { get; private set; }
    public bool Authenticated { get; private set; }

    /// <summary>MAIL FROM accepted, transaction open.</summary>
    public bool InTransaction { get; private set; }

    public int Recipients { get; private set; }

    /// <summary>A BDAT chunk sequence has started and not completed (DATA is then illegal).</summary>
    public bool Chunking { get; private set; }

    /// <summary>When true, MAIL is refused until the session is encrypted.</summary>
    public bool RequireTlsForMail { get; init; }

    /// <summary>When true, MAIL is refused until the client has authenticated.</summary>
    public bool RequireAuthForMail { get; init; }

    /// <summary>Whether STARTTLS can be offered at all on this listener.</summary>
    public bool StartTlsAvailable { get; init; }

    /// <summary>Allow AUTH before TLS (plain listeners on loopback only).</summary>
    public bool AllowInsecureAuth { get; init; }

    public bool AuthAvailable { get; init; }

    public int MaxRecipients { get; init; } = 100;

    /// <summary>Returns the reply to send when <paramref name="verb"/> is not acceptable now, or null when it is.</summary>
    public SmtpReply? Check(SmtpVerb verb)
    {
        switch (verb)
        {
            case SmtpVerb.Helo:
            case SmtpVerb.Ehlo:
                return Chunking ? SmtpReplies.BadSequence : null;

            case SmtpVerb.Noop:
            case SmtpVerb.Quit:
            case SmtpVerb.Help:
            case SmtpVerb.Vrfy:
            case SmtpVerb.Expn:
            case SmtpVerb.Rset:
                return null;

            case SmtpVerb.StartTls:
                if (!StartTlsAvailable) { return SmtpReplies.NotImplemented; }
                if (TlsActive || !Greeted || InTransaction || Authenticated) { return SmtpReplies.BadSequence; }
                return null;

            case SmtpVerb.Auth:
                if (!AuthAvailable) { return SmtpReplies.NotImplemented; }
                if (!Greeted || InTransaction || Authenticated) { return SmtpReplies.BadSequence; }
                if (!TlsActive && !AllowInsecureAuth) { return SmtpReplies.AuthNeedsTls; }
                return null;

            case SmtpVerb.Mail:
                if (!Greeted || InTransaction) { return SmtpReplies.BadSequence; }
                if (RequireTlsForMail && !TlsActive) { return SmtpReplies.TlsRequired; }
                if (RequireAuthForMail && !Authenticated) { return SmtpReplies.AuthRequired; }
                return null;

            case SmtpVerb.Rcpt:
                if (!InTransaction || Chunking) { return SmtpReplies.BadSequence; }
                if (Recipients >= MaxRecipients) { return SmtpReplies.TooManyRecipients; }
                return null;

            case SmtpVerb.Data:
                if (!InTransaction || Chunking) { return SmtpReplies.BadSequence; }
                if (Recipients == 0) { return SmtpReplies.NoValidRecipients; }
                return null;

            case SmtpVerb.Bdat:
                if (!InTransaction) { return SmtpReplies.BadSequence; }
                if (Recipients == 0) { return SmtpReplies.NoValidRecipients; }
                return null;

            default:
                return SmtpReplies.SyntaxError;
        }
    }

    public void OnGreeted(bool ehlo)
    {
        Greeted = true;
        UsedEhlo = ehlo;
        ResetTransaction();
    }

    public void OnMailAccepted()
    {
        InTransaction = true;
        Recipients = 0;
        Chunking = false;
    }

    public void OnRecipientAccepted() => Recipients++;

    public void OnChunkingStarted() => Chunking = true;

    /// <summary>Transaction finished (message accepted or refused) or reset.</summary>
    public void ResetTransaction()
    {
        InTransaction = false;
        Recipients = 0;
        Chunking = false;
    }

    /// <summary>After STARTTLS the session starts over (RFC 3207 §4.2): the client must re-issue EHLO.</summary>
    public void OnTlsEstablished()
    {
        TlsActive = true;
        Greeted = false;
        UsedEhlo = false;
        Authenticated = false;
        ResetTransaction();
    }

    /// <summary>For implicit-TLS listeners the session is encrypted from the first byte.</summary>
    public void MarkImplicitTls() => TlsActive = true;

    public void OnAuthenticated() => Authenticated = true;
}
