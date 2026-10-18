using System.Security.Cryptography.X509Certificates;

namespace Mta.RemoteMta.Tests.Harness;

/// <summary>
/// Ready made personalities. They reproduce the banner, extension list and the shapes of the replies that Gmail, Microsoft (Exchange Online),
/// Postfix and Exim are publicly documented to use (documentation, postmaster pages, default configurations). They are NOT captured traffic and
/// carry no live policy: a real Gmail answers differently tomorrow, and what a real provider decides about a real IP is exactly what these tests cannot show.
/// </summary>
public static class Personalities
{
    private const string Gsmtp = "5b1f17b1804b1-4711a5c6b3esm1234567wmb.12 - gsmtp";

    /// <summary>A bare peer: ESMTP with a few extensions, no TLS unless given a certificate.</summary>
    public static MtaPersonality Plain(string hostname = "mx.fake.test", X509Certificate2? certificate = null) => new()
    {
        Name = "plain",
        Hostname = hostname,
        Certificate = certificate is null ? null : _ => certificate,
    };

    public static MtaPersonality Gmail(X509Certificate2? certificate = null) => new()
    {
        Name = "gmail",
        Hostname = "mx.google.test",
        Greeting = _ => Step.Reply(220, null, $"mx.google.test ESMTP {Gsmtp}"),
        SizeAdvertised = 157_286_400,
        Chunking = true,
        Certificate = certificate is null ? null : _ => certificate,
        OnEndOfData = (_, _) => Step.Reply(250, "2.0.0", $"OK  1760000000 {Gsmtp}"),
    };

    public static MtaPersonality Outlook(X509Certificate2? certificate = null) => new()
    {
        Name = "outlook",
        Hostname = "mail.protection.outlook.test",
        Greeting = _ => Step.Reply(220, null, "BN8NAM04FT055.mail.protection.outlook.test Microsoft ESMTP MAIL Service ready at Fri, 16 Oct 2026 12:00:00 +0000"),
        SizeAdvertised = 157_286_400,
        Chunking = true,
        Dsn = true,
        Certificate = certificate is null ? null : _ => certificate,
        OnEndOfData = (_, _) => Step.Reply(250, "2.6.0", "<m1@example.org> [InternalId=51539607552, Hostname=BN8NAM04FT055.mail.protection.outlook.test] 4711 bytes in 0.123, 37.401 KB/sec Queued mail for delivery"),
    };

    public static MtaPersonality Postfix(X509Certificate2? certificate = null) => new()
    {
        Name = "postfix",
        Hostname = "mx.postfix.test",
        Greeting = _ => Step.Reply(220, null, "mx.postfix.test ESMTP Postfix (Ubuntu)"),
        SizeAdvertised = 10_240_000,
        Chunking = true,
        Dsn = true,
        ExtraCapabilities = { "VRFY", "ETRN" },
        Certificate = certificate is null ? null : _ => certificate,
        OnEndOfData = (_, _) => Step.Reply(250, "2.0.0", "Ok: queued as 4F2E5C0A21"),
    };

    /// <summary>Exim in its default configuration: no ENHANCEDSTATUSCODES and no enhanced codes in any reply, so a classifier cannot lean on them.</summary>
    public static MtaPersonality Exim(X509Certificate2? certificate = null) => new()
    {
        Name = "exim",
        Hostname = "mx.exim.test",
        Greeting = _ => Step.Reply(220, null, "mx.exim.test ESMTP Exim 4.96 Fri, 16 Oct 2026 12:00:00 +0000"),
        EnhancedStatusCodes = false,
        SizeAdvertised = 52_428_800,
        Chunking = true,
        ExtraCapabilities = { "PIPE_CONNECT", "PRDR" },
        Certificate = certificate is null ? null : _ => certificate,
        OnEndOfData = (_, _) => Step.Reply(250, null, "OK id=1vAbCd-0004Ef-3G"),
    };

    /// <summary>Reply formats of Gmail (Google's "SMTP error reference" and bulk sender pages).</summary>
    public static class GmailReplies
    {
        public static Step RateLimited => Step.Reply(421, "4.7.28",
            "[203.0.113.7] Gmail has detected an unusual rate of unsolicited mail originating from your IP address. To protect our users from spam, mail sent from your IP address has been temporarily rate limited.",
            "Please visit https://support.google.com/mail/?p=UnsolicitedRateLimitError to review our Bulk Email Senders Guidelines. " + Gsmtp);

        public static Step Unauthenticated => Step.Reply(550, "5.7.26",
            "This mail has been blocked because the sender is unauthenticated.",
            "Gmail requires all senders to authenticate with either SPF or DKIM.",
            "Authentication results: DKIM = did not pass; SPF [example.org] with ip: [203.0.113.7] = did not pass",
            "For instructions on setting up authentication, go to https://support.google.com/mail/answer/81126#authentication " + Gsmtp);

        public static Step LikelySpam => Step.Reply(550, "5.7.1",
            "Our system has detected that this message is likely unsolicited mail. To reduce the amount of spam sent to Gmail, this message has been blocked.",
            "For more information, go to https://support.google.com/mail/?p=UnsolicitedMessageError " + Gsmtp);

        public static Step LowIpReputation => Step.Reply(550, "5.7.1",
            "[203.0.113.7] Gmail has detected that this message is likely suspicious due to the very low reputation of the sending IP address.",
            "To best protect our users from spam, the message has been blocked. " + Gsmtp);

        public static Step NoSuchUser => Step.Reply(550, "5.1.1",
            "The email account that you tried to reach does not exist. Please try double-checking the recipient's email address for typos or unnecessary spaces.",
            "For more information, go to https://support.google.com/mail/?p=NoSuchUser " + Gsmtp);

        public static Step TooLarge => Step.Reply(552, "5.2.3",
            "Your message exceeded Google's message size limits. Please visit https://support.google.com/mail/?p=MaxSizeError " + Gsmtp);
    }

    /// <summary>Reply formats of Exchange Online Protection (Microsoft's NDR reference).</summary>
    public static class OutlookReplies
    {
        public static Step BlockedByDnsbl => Step.Reply(550, "5.7.1",
            "Service unavailable, Client host [203.0.113.7] blocked using Spamhaus. To request removal from this list see https://www.spamhaus.org/lookup/ (S3150) [BN8NAM04FT055.mail.protection.outlook.test 2026-10-16T12:00:00.000Z]");

        public static Step BannedIp => Step.Reply(550, "5.7.606",
            "Access denied, banned sending IP [203.0.113.7]. To request removal from this list please visit https://sender.office.com/ and follow the directions.");

        public static Step ServerBusy => Step.Reply(451, "4.7.500",
            "Server busy. Please try again later from [203.0.113.7]. (S77)");

        public static Step TemporarilyRateLimited => Step.Reply(451, "4.7.650",
            "The mail server [203.0.113.7] has been temporarily rate limited due to IP reputation. For e-mail delivery information, see https://postmaster.live.com (S775)");

        public static Step RecipientNotFound => Step.Reply(550, "5.1.10",
            "RESOLVER.ADR.RecipientNotFound; Recipient not found by SMTP address lookup");

        public static Step DmarcReject => Step.Reply(550, "5.7.509",
            "Access denied, sending domain example.org does not pass DMARC verification and has a DMARC policy of reject.");
    }

    /// <summary>Reply formats of Postfix with common restrictions (postgrey, anvil, relay control, DNSBL).</summary>
    public static class PostfixReplies
    {
        public static Step Greylisted(string recipient, string domain) => Step.Reply(450, "4.2.0",
            $"<{recipient}>: Recipient address rejected: Greylisted, see http://postgrey.schweikert.ch/help/{domain}.html");

        public static Step UserUnknown(string recipient) => Step.Reply(550, "5.1.1", $"<{recipient}>: Recipient address rejected: User unknown in virtual mailbox table");

        public static Step RelayDenied(string recipient) => Step.Reply(554, "5.7.1", $"<{recipient}>: Relay access denied");

        public static Step ClientBlocked => Step.Reply(554, "5.7.1", "Service unavailable; Client host [203.0.113.7] blocked using zen.spamhaus.org; https://www.spamhaus.org/query/ip/203.0.113.7");

        public static Step TooMuchMail => Step.Reply(450, "4.7.1", "Error: too much mail from 203.0.113.7");

        public static Step TooManyConnections => Step.Reply(421, "4.7.0", "Error: too many connections from 203.0.113.7");

        public static Step MessageTooBig => Step.Reply(552, "5.3.4", "Error: message file too big");

        public static Step MailboxFull(string recipient) => Step.Reply(452, "4.2.2", $"<{recipient}>: Recipient address rejected: Mailbox full");
    }

    /// <summary>Reply formats of Exim: no enhanced status codes at all.</summary>
    public static class EximReplies
    {
        public static Step AdministrativeProhibition => Step.Reply(550, null, "Administrative prohibition");

        /// <summary>The answer to an unknown recipient.</summary>
        public static Step UnroutableAddress => Step.Reply(550, null, "Unrouteable address");

        /// <summary>The three line answer of Exim's sender verification ACL, which is about the envelope sender, not the recipient.</summary>
        public static Step SenderVerifyFailed => Step.Reply(550, null, "Verification failed for <sender@example.org>", "Unrouteable address", "Sender verify failed");

        public static Step TemporaryLocalProblem => Step.Reply(451, null, "Temporary local problem - please try later");

        public static Step RateLimited => Step.Reply(450, null, "Rate limit exceeded");

        public static Step LostInput(string host) => Step.Reply(421, null, $"{host} lost input connection");

        public static Step TooLarge => Step.Reply(552, null, "Message size exceeds maximum permitted");

        public static Step Greylisted => Step.Reply(450, null, "Greylisted, please try again later");
    }
}
