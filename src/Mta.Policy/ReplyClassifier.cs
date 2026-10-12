using System.Buffers;

namespace Mta.Policy;

/// <summary>
/// Classifies a remote SMTP reply into a <see cref="DeliveryClass"/>. Stateless, thread-safe and allocation-free.
/// </summary>
/// <remarks>
/// Evidence is used in this order: (1) the reply code's first digit decides temporary versus permanent (an enhanced code of a
/// different class is ignored as a misbehaving server); (2) specific RFC 3463 enhanced codes; (3) keyword heuristics on the text
/// (for generic codes, 5.7.x and replies without an enhanced code); (4) generic enhanced subjects; (5) the basic reply code and the
/// SMTP stage. Rules are listed in priority order in <see cref="Rules"/>; the first match wins. The keyword lists and the mapping
/// are proposed defaults based on typical provider texts (Gmail, Microsoft, Yahoo, Postfix, Exim), not an exhaustive standard.
/// </remarks>
public sealed class ReplyClassifier
{
    /// <summary>The shared default classifier.</summary>
    public static ReplyClassifier Default { get; } = new();

    /// <summary>Classifies <paramref name="reply"/> received at <paramref name="stage"/>.</summary>
    public ReplyClassification Classify(in RemoteReply reply, SmtpStage stage)
    {
        int code = reply.Code;
        int severity = code / 100;
        ReadOnlySpan<char> text = reply.Text;
        if (severity == 2)
        {
            return new ReplyClassification(DeliveryClass.Delivered, "accepted (2xx)");
        }

        if (severity == 3)
        {
            return code == 354 && stage == SmtpStage.Data
                ? new ReplyClassification(DeliveryClass.Delivered, "start mail input (354)")
                : new ReplyClassification(DeliveryClass.Transient, "unexpected intermediate reply (3xx)");
        }

        if (severity is not (4 or 5))
        {
            return new ReplyClassification(DeliveryClass.Transient, "unrecognized reply code; treated as temporary");
        }

        EnhancedStatus enhanced = reply.GetEnhancedStatus();
        if (enhanced.IsValid && enhanced.Class != severity)
        {
            enhanced = default; // contradicting enhanced class: the basic reply code wins
        }

        Rule[] rules = severity == 4 ? TransientRules : PermanentRules;
        foreach (ref readonly Rule rule in rules.AsSpan())
        {
            if (rule.Matches(stage, code, enhanced, text))
            {
                return new ReplyClassification(rule.Result, rule.Reason);
            }
        }

        // Unreachable: both tables end with a catch-all rule.
        return new ReplyClassification(severity == 4 ? DeliveryClass.Transient : DeliveryClass.PermanentPolicy, "no rule matched");
    }

    /// <summary>Classifies a reply that has no explicit stage context (assumed end of data).</summary>
    public ReplyClassification Classify(in RemoteReply reply) => Classify(reply, SmtpStage.EndOfData);

    /// <summary>The number of rules in the table (for diagnostics and tests).</summary>
    public static int RuleCount => TransientRules.Length + PermanentRules.Length;

    // ---------------------------------------------------------------------------------------------------------------
    // Rule table
    // ---------------------------------------------------------------------------------------------------------------

    private const int AnyStage = 0;
    private static int Stages(params SmtpStage[] stages)
    {
        int mask = 0;
        foreach (SmtpStage s in stages)
        {
            mask |= 1 << (int)s;
        }

        return mask;
    }

    private static int Except(SmtpStage stage) => ~(1 << (int)stage) & 0x3F;

    private static SearchValues<string> Words(params string[] words) =>
        SearchValues.Create(words, StringComparison.OrdinalIgnoreCase);

    // Keyword groups (case-insensitive substrings).
    private static readonly SearchValues<string> GreylistWords = Words("greylist", "graylist", "grey-list", "gray-list", "grey list", "gray list");

    private static readonly SearchValues<string> ThrottleWords = Words(
        "rate limit", "rate-limit", "ratelimit", "rate limited", "at a rate", "rate of", "throttl", "too many connections",
        "too many messages", "too many emails", "too many mails", "too many concurrent", "too many sessions", "too many errors",
        "too frequent", "slow down", "unusually high", "temporarily deferred", "temporarily rate", "connection limit",
        "concurrent connection", "concurrent session", "sending quota", "sending limit", "sending rate", "message rate",
        "exceeded the maximum number of connections", "thread limit", "server busy", "try again slower");

    private static readonly SearchValues<string> MailboxFullWords = Words(
        "mailbox full", "mailbox is full", "mailbox size limit", "mailbox over quota", "mailbox has exceeded", "over quota", "over the quota",
        "over its quota", "quota exceeded", "exceeded storage allocation", "exceeded its quota", "exceeds quota", "insufficient storage",
        "out of storage", "storage allocation", "disk quota", "user is over", "inbox is full", "mailbox quota");

    private static readonly SearchValues<string> TooManyRecipientsWords = Words("too many recipients", "recipient limit", "too many rcpt");

    private static readonly SearchValues<string> TooLargeWords = Words(
        "message too large", "message size exceeds", "message is too large", "size limit", "exceeds the maximum message size",
        "exceeds maximum message size", "message length exceeds", "too big", "maximum message size", "mail size exceeds",
        "message exceeds", "size exceeds", "exceeds the size");

    private static readonly SearchValues<string> SenderWords = Words(
        "sender verify", "sender verification", "sender address rejected", "sender rejected", "domain of sender",
        "sender domain", "sender's domain", "bad sender", "invalid sender", "sender address", "null sender");

    private static readonly SearchValues<string> SenderAuthWords = Words(
        "spf", "dkim", "dmarc", "not authenticated", "unauthenticated", "authentication checks", "sender authentication",
        "sender policy framework", "authentication-results", "not pass authentication", "does not pass", "fails authentication");

    private static readonly SearchValues<string> RelayAuthWords = Words(
        "authentication required", "auth required", "must authenticate", "smtp auth", "authentication failed", "invalid credentials",
        "authentication credentials", "authentication unsuccessful", "username and password not accepted");

    private static readonly SearchValues<string> RecipientWords = Words(
        "user unknown", "unknown user", "no such user", "no such recipient", "no such address", "no such mailbox", "recipient not found",
        "recipient unknown", "unknown recipient", "recipient address rejected: user", "does not exist", "doesn't exist", "doesnt exist",
        "invalid recipient", "invalid mailbox", "invalid address", "mailbox unavailable", "mailbox not found",
        "mailbox disabled", "account disabled", "account has been disabled", "account is disabled", "unrouteable address",
        "unroutable address", "bad destination", "no mailbox", "user not found", "unknown mailbox", "doesn't have a yahoo.com account",
        "not a valid mailbox", "address not found", "deactivated", "domain does not accept mail",
        "does not accept mail", "no such person", "not our customer", "undeliverable address");

    private static readonly SearchValues<string> BlocklistWords = Words(
        "spamhaus", "dnsbl", "blacklist", "blocklist", "block list", "black list", "barracuda", "sorbs", "spamcop", "listed at",
        "listed in", "reputation", "rbl", "banned", "ip address is blocked", "blocked using", "abuseat", "cbl.", "uceprotect", "invaluement");

    private static readonly SearchValues<string> ContentWords = Words(
        "spam", "unsolicited", "virus", "malware", "phishing", "suspicious", "infected", "content", "bulk mail", "message looks",
        "attachment", "executable", "prohibited url", "malicious", "dangerous", "message rejected as", "header", "rfc 5322",
        "rfc5322", "rfc 822", "does not comply");

    private static readonly SearchValues<string> PolicyWords = Words(
        "blocked", "denied", "rcpthosts", "not allowed", "not permitted", "refused", "relay", "relaying", "prohibit", "policy", "forbidden",
        "ptr", "reverse dns", "rdns", "not accepted", "administrative", "rejected due to", "tls required", "encryption required");

    // Declared after the keyword sets above: static field initializers run in textual order.
    private static readonly Rule[] TransientRules = BuildTransientRules();
    private static readonly Rule[] PermanentRules = BuildPermanentRules();

    private static Rule[] BuildTransientRules()
    {
        int notMailFrom = Except(SmtpStage.MailFrom);
        return
        [
            // 1. Text signals that must win over any generic enhanced code.
            Rule.Text(GreylistWords, DeliveryClass.TransientGreylist, "greylisting"),
            Rule.Text(ThrottleWords, DeliveryClass.TransientThrottle, "rate limiting / throttling text"),
            Rule.Text(MailboxFullWords, DeliveryClass.SoftBounceMailboxFull, "mailbox full / over quota", notMailFrom),
            Rule.Text(TooManyRecipientsWords, DeliveryClass.Transient, "too many recipients in one transaction"),

            // 2. Specific enhanced codes.
            Rule.Enh(2, 2, DeliveryClass.SoftBounceMailboxFull, "4.2.2 mailbox full"),
            Rule.Enh(5, 3, DeliveryClass.Transient, "4.5.3 too many recipients"),
            Rule.Enh(4, 5, DeliveryClass.TransientThrottle, "4.4.5 mail system congestion"),
            Rule.Enh(7, -1, DeliveryClass.Transient, "4.7.x during handshake (temporary auth/TLS problem)", Stages(SmtpStage.Handshake)),
            Rule.EnhSubject(7, DeliveryClass.TransientThrottle, "4.7.x temporary policy deferral / throttling"),
            Rule.EnhSubject(1, DeliveryClass.Transient, "4.1.x temporary address problem"),
            Rule.EnhSubject(2, DeliveryClass.Transient, "4.2.x temporary mailbox problem"),
            Rule.EnhSubject(3, DeliveryClass.Transient, "4.3.x temporary mail system problem"),
            Rule.EnhSubject(4, DeliveryClass.Transient, "4.4.x temporary network or routing problem"),
            Rule.EnhSubject(5, DeliveryClass.Transient, "4.5.x temporary protocol problem"),
            Rule.EnhSubject(6, DeliveryClass.Transient, "4.6.x temporary content problem"),
            Rule.EnhSubject(0, DeliveryClass.Transient, "4.0.x temporary failure"),

            // 3. Basic reply code only.
            Rule.Code(421, DeliveryClass.Transient, "421 service not available / closing channel"),
            Rule.Code(450, DeliveryClass.Transient, "450 mailbox temporarily unavailable"),
            Rule.Code(451, DeliveryClass.Transient, "451 local error in processing"),
            Rule.Code(452, DeliveryClass.Transient, "452 insufficient system storage or too many recipients"),
            Rule.Code(454, DeliveryClass.Transient, "454 TLS or authentication temporarily unavailable"),
            Rule.CatchAll(DeliveryClass.Transient, "temporary failure (4xx)"),
        ];
    }

    private static Rule[] BuildPermanentRules()
    {
        int notMailFrom = Except(SmtpStage.MailFrom);
        int rcptAndLater = Stages(SmtpStage.RcptTo, SmtpStage.Data, SmtpStage.EndOfData);
        return
        [
            // A. Specific enhanced codes (RFC 3463 and common provider extensions).
            Rule.Enh(1, 1, DeliveryClass.PermanentRecipient, "5.1.1 bad destination mailbox address"),
            Rule.Enh(1, 2, DeliveryClass.PermanentRecipient, "5.1.2 bad destination system address (domain)"),
            Rule.Enh(1, 3, DeliveryClass.PermanentRecipient, "5.1.3 bad destination mailbox address syntax"),
            Rule.Enh(1, 4, DeliveryClass.PermanentRecipient, "5.1.4 destination mailbox address ambiguous"),
            Rule.Enh(1, 6, DeliveryClass.PermanentRecipient, "5.1.6 mailbox has moved"),
            Rule.Enh(1, 7, DeliveryClass.PermanentSender, "5.1.7 bad sender mailbox address syntax"),
            Rule.Enh(1, 8, DeliveryClass.PermanentSender, "5.1.8 bad sender system address"),
            Rule.Enh(1, 10, DeliveryClass.PermanentRecipient, "5.1.10 recipient not found / domain accepts no mail"),
            Rule.Enh(2, 1, DeliveryClass.PermanentRecipient, "5.2.1 mailbox disabled / not accepting messages"),
            Rule.Enh(2, 2, DeliveryClass.SoftBounceMailboxFull, "5.2.2 mailbox full"),
            Rule.Enh(2, 3, DeliveryClass.PermanentConfigurationProblem, "5.2.3 message length exceeds administrative limit"),
            Rule.Enh(2, 4, DeliveryClass.PermanentRecipient, "5.2.4 mailing list expansion problem"),
            Rule.EnhSubject(3, DeliveryClass.PermanentConfigurationProblem, "5.3.x mail system problem (size, capability, configuration)", detailMin: 1),
            Rule.Enh(4, 1, DeliveryClass.PermanentRecipient, "5.4.1 recipient address rejected by directory", Stages(SmtpStage.RcptTo)),
            Rule.Enh(4, 5, DeliveryClass.PermanentPolicy, "5.4.5 sending quota exceeded"),
            Rule.EnhSubject(4, DeliveryClass.PermanentConfigurationProblem, "5.4.x routing or network problem", detailMin: 1),
            Rule.EnhSubject(5, DeliveryClass.PermanentConfigurationProblem, "5.5.x SMTP protocol problem", detailMin: 1),
            Rule.EnhSubject(6, DeliveryClass.PermanentContent, "5.6.x message content or media problem", detailMin: 1),
            Rule.Enh(7, 8, DeliveryClass.PermanentConfigurationProblem, "5.7.8 authentication credentials invalid"),
            Rule.Enh(7, 10, DeliveryClass.PermanentPolicy, "5.7.10 encryption required"),
            Rule.EnhRange(7, 20, 24, DeliveryClass.PermanentSender, "5.7.20-24 sender authentication (SPF/DKIM) failed"),
            Rule.Enh(7, 25, DeliveryClass.PermanentPolicy, "5.7.25 reverse DNS (PTR) required"),
            Rule.Enh(7, 26, DeliveryClass.PermanentSender, "5.7.26 sender not authenticated (SPF/DKIM/DMARC)"),
            Rule.Enh(7, 27, DeliveryClass.PermanentSender, "5.7.27 sender address has null MX"),
            Rule.Enh(7, 30, DeliveryClass.PermanentPolicy, "5.7.30 TLS required"),
            Rule.EnhRange(7, 500, 505, DeliveryClass.PermanentPolicy, "5.7.50x Microsoft policy rejection"),
            Rule.Enh(7, 509, DeliveryClass.PermanentSender, "5.7.509 sending domain fails DMARC"),
            Rule.Enh(7, 510, DeliveryClass.PermanentPolicy, "5.7.510 recipient does not accept mail from this sender"),
            Rule.Enh(7, 511, DeliveryClass.PermanentPolicy, "5.7.511 sender banned"),
            Rule.Enh(7, 512, DeliveryClass.PermanentContent, "5.7.512 message not RFC 5322 compliant"),
            Rule.EnhRange(7, 600, 799, DeliveryClass.PermanentPolicy, "5.7.6xx/7xx Microsoft IP or domain block"),

            // B. Text heuristics (replies with a generic enhanced code, 5.7.0/5.7.1 and similar, or no enhanced code).
            Rule.Text(SenderWords, DeliveryClass.PermanentSender, "sender address or domain rejected", AnyStage),
            Rule.Text(SenderAuthWords, DeliveryClass.PermanentSender, "sender authentication (SPF/DKIM/DMARC) failure"),
            Rule.Text(RelayAuthWords, DeliveryClass.PermanentConfigurationProblem, "authentication required or failed for this route"),
            Rule.Text(ThrottleWords, DeliveryClass.PermanentPolicy, "permanent rate or sending limit rejection"),
            Rule.Text(MailboxFullWords, DeliveryClass.SoftBounceMailboxFull, "mailbox full / over quota", notMailFrom),
            Rule.Text(TooLargeWords, DeliveryClass.PermanentConfigurationProblem, "message too large"),
            Rule.Text(RecipientWords, DeliveryClass.PermanentRecipient, "recipient unknown or mailbox disabled", notMailFrom),
            Rule.Text(BlocklistWords, DeliveryClass.PermanentPolicy, "blocklisted or poor reputation"),
            Rule.Text(ContentWords, DeliveryClass.PermanentContent, "content rejected (spam, virus, malformed)", rcptAndLater),
            Rule.Text(PolicyWords, DeliveryClass.PermanentPolicy, "rejected by policy"),

            // C. Generic enhanced subjects.
            Rule.EnhSubject(7, DeliveryClass.PermanentPolicy, "5.7.x security or policy rejection"),
            Rule.EnhSubject(3, DeliveryClass.PermanentConfigurationProblem, "5.3.0 mail system problem"),
            Rule.EnhSubject(4, DeliveryClass.PermanentConfigurationProblem, "5.4.0 routing problem"),
            Rule.EnhSubject(5, DeliveryClass.PermanentConfigurationProblem, "5.5.0 protocol problem"),
            Rule.EnhSubject(6, DeliveryClass.PermanentContent, "5.6.0 content problem"),

            // D. Basic reply code and stage.
            Rule.Code(521, DeliveryClass.PermanentRecipient, "521 host does not accept mail", AnyStage),
            Rule.Code(556, DeliveryClass.PermanentRecipient, "556 domain does not accept mail", AnyStage),
            Rule.Code(552, DeliveryClass.SoftBounceMailboxFull, "552 exceeded storage allocation", Stages(SmtpStage.RcptTo)),
            Rule.Code(552, DeliveryClass.PermanentConfigurationProblem, "552 message size exceeded"),
            Rule.Code(500, DeliveryClass.PermanentConfigurationProblem, "500 syntax error"),
            Rule.Code(501, DeliveryClass.PermanentConfigurationProblem, "501 syntax error in parameters"),
            Rule.Code(502, DeliveryClass.PermanentConfigurationProblem, "502 command not implemented"),
            Rule.Code(503, DeliveryClass.PermanentConfigurationProblem, "503 bad sequence of commands"),
            Rule.Code(504, DeliveryClass.PermanentConfigurationProblem, "504 parameter not implemented"),
            Rule.Code(530, DeliveryClass.PermanentConfigurationProblem, "530 authentication or STARTTLS required"),
            Rule.Code(534, DeliveryClass.PermanentConfigurationProblem, "534 authentication mechanism too weak"),
            Rule.Code(535, DeliveryClass.PermanentConfigurationProblem, "535 authentication credentials rejected"),
            Rule.Stage(SmtpStage.Handshake, DeliveryClass.PermanentConfigurationProblem, "permanent failure during EHLO/STARTTLS/AUTH"),
            Rule.Stage(SmtpStage.Connect, DeliveryClass.PermanentPolicy, "connection or greeting refused"),
            Rule.Stage(SmtpStage.MailFrom, DeliveryClass.PermanentSender, "sender refused"),
            Rule.CodeAtStage(550, SmtpStage.RcptTo, DeliveryClass.PermanentRecipient, "550 mailbox unavailable"),
            Rule.CodeAtStage(551, SmtpStage.RcptTo, DeliveryClass.PermanentRecipient, "551 user not local"),
            Rule.CodeAtStage(553, SmtpStage.RcptTo, DeliveryClass.PermanentRecipient, "553 mailbox name not allowed"),
            Rule.Stage(SmtpStage.RcptTo, DeliveryClass.PermanentPolicy, "recipient refused by policy"),
            Rule.Stage(SmtpStage.Data, DeliveryClass.PermanentContent, "message refused at DATA"),
            Rule.Stage(SmtpStage.EndOfData, DeliveryClass.PermanentContent, "message refused after content"),
            Rule.CatchAll(DeliveryClass.PermanentPolicy, "permanent failure (5xx)"),
        ];
    }

    private readonly struct Rule
    {
        private readonly int _stageMask;
        private readonly int _code;
        private readonly int _subject;
        private readonly int _detailMin;
        private readonly int _detailMax;
        private readonly SearchValues<string>? _words;

        public DeliveryClass Result { get; }

        public string Reason { get; }

        private Rule(int stageMask, int code, int subject, int detailMin, int detailMax, SearchValues<string>? words, DeliveryClass result, string reason)
        {
            _stageMask = stageMask;
            _code = code;
            _subject = subject;
            _detailMin = detailMin;
            _detailMax = detailMax;
            _words = words;
            Result = result;
            Reason = reason;
        }

        /// <summary>Exact enhanced subject and detail (class is implied by the table).</summary>
        public static Rule Enh(int subject, int detail, DeliveryClass result, string reason, int stageMask = AnyStage) =>
            new(stageMask, 0, subject, detail, detail < 0 ? int.MaxValue : detail, null, result, reason);

        /// <summary>Any detail of an enhanced subject (optionally from <paramref name="detailMin"/> up).</summary>
        public static Rule EnhSubject(int subject, DeliveryClass result, string reason, int detailMin = 0) =>
            new(AnyStage, 0, subject, detailMin, int.MaxValue, null, result, reason);

        public static Rule EnhRange(int subject, int detailMin, int detailMax, DeliveryClass result, string reason) =>
            new(AnyStage, 0, subject, detailMin, detailMax, null, result, reason);

        public static Rule Text(SearchValues<string> words, DeliveryClass result, string reason, int stageMask = AnyStage) =>
            new(stageMask, 0, -1, 0, int.MaxValue, words, result, reason);

        public static Rule Code(int code, DeliveryClass result, string reason, int stageMask = AnyStage) =>
            new(stageMask, code, -1, 0, int.MaxValue, null, result, reason);

        public static Rule CodeAtStage(int code, SmtpStage stage, DeliveryClass result, string reason) =>
            new(1 << (int)stage, code, -1, 0, int.MaxValue, null, result, reason);

        public static Rule Stage(SmtpStage stage, DeliveryClass result, string reason) =>
            new(1 << (int)stage, 0, -1, 0, int.MaxValue, null, result, reason);

        public static Rule CatchAll(DeliveryClass result, string reason) =>
            new(AnyStage, 0, -1, 0, int.MaxValue, null, result, reason);

        public bool Matches(SmtpStage stage, int code, EnhancedStatus enhanced, ReadOnlySpan<char> text)
        {
            if (_stageMask != 0 && (_stageMask & (1 << (int)stage)) == 0)
            {
                return false;
            }

            if (_code != 0 && _code != code)
            {
                return false;
            }

            if (_subject >= 0)
            {
                if (!enhanced.IsValid || enhanced.Subject != _subject)
                {
                    return false;
                }

                if (_detailMin >= 0 && (enhanced.Detail < _detailMin || enhanced.Detail > _detailMax))
                {
                    return false;
                }
            }

            return _words is null || text.ContainsAny(_words);
        }
    }
}
