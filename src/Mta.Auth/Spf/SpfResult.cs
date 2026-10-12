using System.Net;

namespace Mta.Auth.Spf;

/// <summary>The result of an SPF check (RFC 7208 section 2.6).</summary>
public enum SpfResult
{
    /// <summary>No SPF record was published, or the domain is not a valid domain name.</summary>
    None = 0,

    /// <summary>The domain owner asserts nothing about the client (<c>?</c> qualifier or no mechanism matched).</summary>
    Neutral,

    /// <summary>The client is authorized to send for the domain.</summary>
    Pass,

    /// <summary>The client is explicitly not authorized (<c>-</c> qualifier).</summary>
    Fail,

    /// <summary>The client is probably not authorized (<c>~</c> qualifier).</summary>
    SoftFail,

    /// <summary>A transient error (usually DNS) prevented a decision; try again later.</summary>
    TempError,

    /// <summary>The published record is invalid, or a processing limit was exceeded.</summary>
    PermError,
}

/// <summary>The qualifier in front of an SPF mechanism (RFC 7208 section 4.6.2).</summary>
public enum SpfQualifier
{
    /// <summary><c>+</c> (the default): a match yields <see cref="SpfResult.Pass"/>.</summary>
    Pass,

    /// <summary><c>-</c>: a match yields <see cref="SpfResult.Fail"/>.</summary>
    Fail,

    /// <summary><c>~</c>: a match yields <see cref="SpfResult.SoftFail"/>.</summary>
    SoftFail,

    /// <summary><c>?</c>: a match yields <see cref="SpfResult.Neutral"/>.</summary>
    Neutral,
}

/// <summary>The input of RFC 7208 <c>check_host(ip, domain, sender)</c> plus the HELO identity used by macros.</summary>
/// <param name="ClientIp">The SMTP client address. IPv4-mapped IPv6 addresses are evaluated as IPv4.</param>
/// <param name="Domain">The domain whose SPF record is evaluated (the MAIL FROM domain, or the HELO domain).</param>
/// <param name="Sender">The full sender mailbox used by the <c>%{s}</c>, <c>%{l}</c> and <c>%{o}</c> macros (<c>postmaster@helo</c> for the null sender).</param>
/// <param name="HeloDomain">The HELO/EHLO argument (<c>%{h}</c>).</param>
public sealed record SpfCheckRequest(IPAddress ClientIp, string Domain, string Sender, string HeloDomain)
{
    /// <summary>Builds the request that checks the MAIL FROM identity (or the HELO identity when the reverse-path is null).</summary>
    /// <param name="clientIp">The SMTP client address.</param>
    /// <param name="heloDomain">The HELO/EHLO argument.</param>
    /// <param name="mailFrom">The MAIL FROM address without angle brackets; null or empty for the null reverse-path.</param>
    public static SpfCheckRequest ForMailFrom(IPAddress clientIp, string heloDomain, string? mailFrom)
    {
        ArgumentNullException.ThrowIfNull(clientIp);
        heloDomain ??= string.Empty;
        if (string.IsNullOrEmpty(mailFrom))
        {
            return new SpfCheckRequest(clientIp, heloDomain, "postmaster@" + heloDomain, heloDomain);
        }

        int at = mailFrom.LastIndexOf('@');
        string domain = at >= 0 ? mailFrom[(at + 1)..] : mailFrom;
        string sender = at >= 0 ? mailFrom : "postmaster@" + mailFrom;
        return new SpfCheckRequest(clientIp, domain, sender, heloDomain);
    }

    /// <summary>Builds the request that checks the HELO identity (sender <c>postmaster@helo</c>, RFC 7208 section 2.3).</summary>
    public static SpfCheckRequest ForHelo(IPAddress clientIp, string heloDomain)
    {
        ArgumentNullException.ThrowIfNull(clientIp);
        heloDomain ??= string.Empty;
        return new SpfCheckRequest(clientIp, heloDomain, "postmaster@" + heloDomain, heloDomain);
    }
}

/// <summary>The outcome of an SPF check, with the details a receiver logs or reports.</summary>
/// <param name="Result">The verdict.</param>
/// <param name="Domain">The domain that was checked (the identity the verdict is about), lower-case without a trailing dot.</param>
/// <param name="MatchedMechanism">The mechanism text that decided the result (for example <c>ip4:192.0.2.0/24</c> or <c>all</c>), or null when none matched.</param>
/// <param name="Explanation">The <c>exp=</c> explanation (or the default explanation) for a <see cref="SpfResult.Fail"/>, otherwise null.</param>
/// <param name="Reason">A short human-readable cause for None, TempError and PermError results (and for limits), otherwise null.</param>
/// <param name="DnsLookupCount">The number of DNS-querying terms evaluated (RFC 7208 limit: 10).</param>
/// <param name="VoidLookupCount">The number of void lookups seen (RFC 7208 limit: 2).</param>
public sealed record SpfCheckResult(
    SpfResult Result,
    string Domain,
    string? MatchedMechanism = null,
    string? Explanation = null,
    string? Reason = null,
    int DnsLookupCount = 0,
    int VoidLookupCount = 0)
{
    /// <summary>The lower-case result keyword used in Authentication-Results and reports (<c>pass</c>, <c>softfail</c>, ...).</summary>
    public string ResultKeyword => ToKeyword(Result);

    /// <summary>The lower-case keyword for a result, as used in <c>spf=</c> in Authentication-Results.</summary>
    public static string ToKeyword(SpfResult result) => result switch
    {
        SpfResult.None => "none",
        SpfResult.Neutral => "neutral",
        SpfResult.Pass => "pass",
        SpfResult.Fail => "fail",
        SpfResult.SoftFail => "softfail",
        SpfResult.TempError => "temperror",
        _ => "permerror",
    };
}

/// <summary>The SPF results for one SMTP transaction: the HELO identity and the MAIL FROM identity.</summary>
/// <param name="Helo">The result for the HELO/EHLO identity.</param>
/// <param name="MailFrom">The result for the MAIL FROM identity, or null when the reverse-path is null (then <see cref="Helo"/> is the effective identity).</param>
public sealed record SpfSessionResult(SpfCheckResult Helo, SpfCheckResult? MailFrom)
{
    /// <summary>The result DMARC uses: MAIL FROM when present, otherwise HELO (RFC 7489 section 3.1.2).</summary>
    public SpfCheckResult Effective => MailFrom ?? Helo;
}
