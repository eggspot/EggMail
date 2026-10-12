namespace Mta.Policy.Tests;

public class ReplyClassifierTests
{
    private static readonly ReplyClassifier Classifier = ReplyClassifier.Default;

    private const SmtpStage Conn = SmtpStage.Connect;
    private const SmtpStage Hand = SmtpStage.Handshake;
    private const SmtpStage Mail = SmtpStage.MailFrom;
    private const SmtpStage Rcpt = SmtpStage.RcptTo;
    private const SmtpStage Data = SmtpStage.Data;
    private const SmtpStage Eod = SmtpStage.EndOfData;

    private const DeliveryClass Ok = DeliveryClass.Delivered;
    private const DeliveryClass Soft = DeliveryClass.Transient;
    private const DeliveryClass Thr = DeliveryClass.TransientThrottle;
    private const DeliveryClass Grey = DeliveryClass.TransientGreylist;
    private const DeliveryClass Rec = DeliveryClass.PermanentRecipient;
    private const DeliveryClass Snd = DeliveryClass.PermanentSender;
    private const DeliveryClass Pol = DeliveryClass.PermanentPolicy;
    private const DeliveryClass Con = DeliveryClass.PermanentContent;
    private const DeliveryClass Full = DeliveryClass.SoftBounceMailboxFull;
    private const DeliveryClass Cfg = DeliveryClass.PermanentConfigurationProblem;

    private static object?[] Row(SmtpStage stage, int code, string? enhanced, string text, DeliveryClass expected) =>
        [stage, code, enhanced, text, expected];

    /// <summary>
    /// Representative samples written from knowledge of typical provider and MTA texts (Gmail, Outlook/Exchange, Yahoo, Postfix, Exim, others).
    /// They are NOT verbatim captures and may differ from what a provider sends today; they exist to pin the classification rules.
    /// </summary>
    public static IEnumerable<object?[]> Samples()
    {
        // ---- Gmail style -------------------------------------------------------------------------------------------
        yield return Row(Rcpt, 550, "5.1.1", "The email account that you tried to reach does not exist. Please try double-checking the recipient's email address for typos or unnecessary spaces.", Rec);
        yield return Row(Rcpt, 550, "5.1.1", "The email account that you tried to reach does not exist. Learn more at https://support.google.com/mail/?p=NoSuchUser", Rec);
        yield return Row(Eod, 550, "5.7.1", "[203.0.113.5] Our system has detected that this message is likely unsolicited mail. To reduce the amount of spam sent to Gmail, this message has been blocked.", Con);
        yield return Row(Eod, 550, "5.7.26", "This message does not have authentication information or fails to pass authentication checks (SPF or DKIM).", Snd);
        yield return Row(Eod, 550, "5.7.26", "Unauthenticated email from example.com is not accepted due to domain's DMARC policy.", Snd);
        yield return Row(Eod, 421, "4.7.28", "Gmail has detected an unusually high rate of unsolicited mail originating from your SPF domain.", Thr);
        yield return Row(Rcpt, 421, "4.7.0", "[203.0.113.5] Our system has detected an unusual rate of unsolicited mail originating from your IP address. To protect our users from spam, mail sent from your IP address has been temporarily rate limited.", Thr);
        yield return Row(Rcpt, 450, "4.2.1", "The user you are trying to contact is receiving mail at a rate that prevents additional messages from being delivered. Please resend your message at a later time.", Thr);
        yield return Row(Rcpt, 452, "4.2.2", "The email account that you tried to reach is over quota.", Full);
        yield return Row(Rcpt, 552, "5.2.2", "The email account that you tried to reach is over quota.", Full);
        yield return Row(Eod, 552, "5.2.3", "Your message exceeded Google's message size limits.", Cfg);
        yield return Row(Eod, 552, "5.3.4", "Your message exceeded Google's message size limits.", Cfg);
        yield return Row(Eod, 550, "5.4.5", "Daily user sending quota exceeded.", Pol);
        yield return Row(Conn, 421, "4.3.0", "Temporary System Problem. Try again later (10).", Soft);
        yield return Row(Eod, 451, "4.3.0", "Mail server temporarily rejected message.", Soft);
        yield return Row(Rcpt, 550, "5.7.1", "The IP you're using to send mail is not authorized to send email directly to our servers. Please use the SMTP relay at your service provider instead.", Pol);
        yield return Row(Eod, 550, "5.7.25", "The IP address sending this message does not have a PTR record setup.", Pol);
        yield return Row(Rcpt, 553, "5.1.2", "We weren't able to find the recipient domain. Please check for any spelling errors.", Rec);
        yield return Row(Rcpt, 550, "5.2.1", "The email account that you tried to reach is disabled.", Rec);

        // ---- Outlook / Exchange style ------------------------------------------------------------------------------
        yield return Row(Rcpt, 550, "5.1.10", "RESOLVER.ADR.RecipientNotFound; Recipient not found by SMTP address lookup", Rec);
        yield return Row(Rcpt, 550, "5.4.1", "Recipient address rejected: Access denied. AS(201806281)", Rec);
        yield return Row(Eod, 550, "5.7.1", "Service unavailable, Client host [203.0.113.5] blocked using Spamhaus. To request removal from this list see https://www.spamhaus.org/lookup/", Pol);
        yield return Row(Conn, 550, "5.7.606", "Access denied, banned sending IP [203.0.113.5]. To request removal from this list please visit https://sender.office.com/", Pol);
        yield return Row(Eod, 550, "5.7.509", "Access denied, sending domain example.com does not pass DMARC verification and has a DMARC policy of reject.", Snd);
        yield return Row(Conn, 550, "5.7.511", "Access denied, banned sender [203.0.113.5]. To request removal from this list please forward this message to delist@microsoft.com", Pol);
        yield return Row(Rcpt, 451, "4.7.500", "Server busy. Please try again later from [203.0.113.5]. (S77719)", Thr);
        yield return Row(Rcpt, 451, "4.7.650", "The mail server [203.0.113.5] has been temporarily rate limited due to IP reputation.", Thr);
        yield return Row(Rcpt, 432, "4.3.2", "STOREDRV.Deliver; recipient thread limit exceeded", Thr);
        yield return Row(Rcpt, 550, "5.2.2", "STOREDRV.Deliver.Exception:QuotaExceededException.MapiExceptionShutoffQuotaExceeded; Failed to process message due to a permanent exception", Full);
        yield return Row(Eod, 552, "5.3.4", "Message size exceeds fixed limit", Cfg);
        yield return Row(Conn, 421, "4.4.1", "Connection timed out", Soft);
        yield return Row(Eod, 554, "5.6.0", "STOREDRV.Deliver; Corrupt message content", Con);
        yield return Row(Conn, 550, "5.7.708", "Service unavailable. Access denied, traffic not accepted from this IP.", Pol);
        yield return Row(Rcpt, 550, "5.7.1", "Delivery not authorized, message refused", Pol);
        yield return Row(Eod, 550, "5.7.512", "Access denied, message must be RFC 5322 section 3.6.2 compliant", Con);

        // ---- Yahoo style -------------------------------------------------------------------------------------------
        yield return Row(Rcpt, 554, null, "delivery error: dd This user doesn't have a yahoo.com account (x@yahoo.com) [0] - mta1234.mail.yahoo.com", Rec);
        yield return Row(Rcpt, 421, "4.7.0", "[TSS04] Messages from 203.0.113.5 temporarily deferred due to unexpected volume or user complaints - 4.16.55.1; see https://postmaster.yahooinc.com/error-codes", Thr);
        yield return Row(Rcpt, 421, "4.7.1", "[GL01] Message from (203.0.113.5) temporarily deferred - 4.16.50. Please refer to the Yahoo Postmaster", Thr);
        yield return Row(Eod, 553, "5.7.2", "[TSS09] All messages from 203.0.113.5 will be permanently deferred; Retrying will NOT succeed. See https://postmaster.yahooinc.com/error-codes", Pol);
        yield return Row(Eod, 554, "5.7.9", "Message not accepted for policy reasons. See https://postmaster.yahooinc.com/error-codes", Pol);
        yield return Row(Conn, 553, "5.7.1", "[BL21] Connections will not be accepted from 203.0.113.5, because the ip is in Spamhaus's list; see http://postmaster.yahoo.com/550-bl23.html", Pol);
        yield return Row(Rcpt, 552, null, "1 Requested mail action aborted, mailbox not found", Rec);
        yield return Row(Eod, 451, null, "Message temporarily deferred - [160]", Thr); // Yahoo defers for reputation: back off
        yield return Row(Eod, 554, null, "30 Sorry, your message was rejected as spam", Con);
        yield return Row(Rcpt, 421, "4.7.0", "[TS01] Messages from 203.0.113.5 temporarily deferred due to user complaints - 4.16.55.1", Thr);

        // ---- Postfix style -----------------------------------------------------------------------------------------
        yield return Row(Rcpt, 550, "5.1.1", "<nobody@example.org>: Recipient address rejected: User unknown in virtual mailbox table", Rec);
        yield return Row(Rcpt, 450, "4.2.0", "<x@example.org>: Recipient address rejected: Greylisted, see http://postgrey.schweikert.ch/help/example.org.html", Grey);
        yield return Row(Rcpt, 554, "5.7.1", "<x@example.org>: Relay access denied", Pol);
        yield return Row(Mail, 450, "4.1.8", "<s@bad.invalid>: Sender address rejected: Domain not found", Soft);
        yield return Row(Mail, 553, "5.7.1", "<s@example.net>: Sender address rejected: not owned by user", Snd);
        yield return Row(Rcpt, 450, "4.7.1", "<x@example.org>: Helo command rejected: Host not found", Thr);
        yield return Row(Eod, 552, "5.3.4", "Message size exceeds fixed maximum message size of 10240000", Cfg);
        yield return Row(Rcpt, 452, "4.2.2", "Mailbox full", Full);
        yield return Row(Conn, 421, "4.3.2", "System not accepting network messages", Soft);
        yield return Row(Conn, 554, "5.7.1", "Service unavailable; Client host [203.0.113.5] blocked using zen.spamhaus.org; https://www.spamhaus.org/sbl/query/SBLCSS", Pol);
        yield return Row(Rcpt, 550, "5.1.2", "<x@nonexistent.invalid>: Recipient address rejected: Domain not found", Rec);
        yield return Row(Eod, 554, "5.7.1", "Message rejected as spam by Content Filtering", Con);
        yield return Row(Eod, 554, "5.4.14", "Hop count exceeded - possible mail loop", Cfg);
        yield return Row(Rcpt, 550, "5.7.1", "<x@example.org>: Recipient address rejected: Access denied", Pol);
        yield return Row(Rcpt, 450, "4.2.0", "<x@example.org>: Recipient address rejected: Try again later", Soft);

        // ---- Exim style (frequently without enhanced codes) --------------------------------------------------------
        yield return Row(Rcpt, 550, null, "Unrouteable address", Rec);
        yield return Row(Rcpt, 550, null, "No Such User Here", Rec);
        yield return Row(Rcpt, 550, null, "relay not permitted", Pol);
        yield return Row(Rcpt, 451, null, "Temporary local problem - please try later", Soft);
        yield return Row(Rcpt, 450, null, "Greylisted - please try again in 300 seconds", Grey);
        yield return Row(Conn, 554, null, "5.7.1 Rejected: your host is listed at zen.spamhaus.org", Pol);
        yield return Row(Eod, 550, null, "Message rejected because it looks like spam (score 12.3)", Con);
        yield return Row(Mail, 550, null, "Sender verify failed", Snd);
        yield return Row(Rcpt, 452, null, "Too many recipients", Soft);
        yield return Row(Eod, 552, null, "Message too big", Cfg);
        yield return Row(Rcpt, 550, null, "Administrative prohibition", Pol);
        yield return Row(Rcpt, 550, null, "Mailbox quota exceeded", Full);
        yield return Row(Rcpt, 550, null, "Mailbox size limit exceeded", Full);
        yield return Row(Eod, 554, null, "Transaction failed", Con);
        yield return Row(Rcpt, 550, null, "Requested action not taken: mailbox unavailable", Rec);
        yield return Row(Rcpt, 553, null, "sorry, that domain isn't in my list of allowed rcpthosts", Pol);

        // ---- Generic servers, SMTP dialogue problems and edge cases -------------------------------------------------
        yield return Row(Hand, 502, "5.5.1", "Error: command not implemented", Cfg);
        yield return Row(Hand, 535, "5.7.8", "Error: authentication failed: UGFzc3dvcmQ6", Cfg);
        yield return Row(Hand, 454, "4.7.0", "TLS not available due to temporary reason", Soft);
        yield return Row(Data, 554, "5.5.1", "Error: no valid recipients", Cfg);
        yield return Row(Data, 503, "5.5.1", "Error: need RCPT command", Cfg);
        yield return Row(Eod, 250, "2.0.0", "Ok: queued as ABC123", Ok);
        yield return Row(Mail, 250, "2.1.0", "Sender OK", Ok);
        yield return Row(Rcpt, 250, null, "OK", Ok);
        yield return Row(Data, 354, null, "End data with <CR><LF>.<CR><LF>", Ok);
        yield return Row(Eod, 451, "4.3.0", "Error: queue file write error", Soft);
        yield return Row(Conn, 421, null, "Too many connections from your IP", Thr);
        yield return Row(Conn, 421, null, "mail.example.com service not available, closing transmission channel", Soft);
        yield return Row(Rcpt, 550, "5.2.1", "Mailbox disabled, not accepting messages", Rec);
        yield return Row(Rcpt, 450, "5.1.1", "User unknown", Soft); // contradicting class: the basic code wins
        yield return Row(Rcpt, 550, "4.2.2", "Mailbox full", Full); // contradicting class: text still says mailbox full
        yield return Row(Eod, 600, null, "Weird server", Soft);
        yield return Row(Eod, 0, null, "", Soft);
        yield return Row(Hand, 334, null, "VXNlcm5hbWU6", Soft);
        yield return Row(Rcpt, 556, null, "Domain does not accept mail (nullMX)", Rec);
        yield return Row(Conn, 521, null, "Host does not accept mail", Rec);
        yield return Row(Eod, 554, "5.7.1", "Message contains a prohibited attachment (.exe)", Con);
        yield return Row(Rcpt, 550, "5.7.1", "Mail from IP 203.0.113.5 rejected, poor reputation", Pol);
        yield return Row(Conn, 554, null, "Your access to this mail system has been rejected due to the sending MTA's poor reputation.", Pol);
        yield return Row(Eod, 550, "5.7.1", "Your message was rejected because it contains a suspicious URL", Con);
        yield return Row(Eod, 550, "5.7.1", "Email rejected per DMARC policy for example.com", Snd);
        yield return Row(Eod, 550, "5.7.1", "Sender Policy Framework (SPF) validation failed", Snd);
        yield return Row(Rcpt, 550, "5.7.1", "Unable to relay", Pol);
        yield return Row(Rcpt, 552, null, "Requested mail action aborted: exceeded storage allocation", Full);
        yield return Row(Mail, 552, null, "Message size exceeds maximum permitted", Cfg);
        yield return Row(Mail, 553, null, "Domain name required for sender address", Snd);
        yield return Row(Rcpt, 501, null, "Syntax error in parameters or arguments", Cfg);
        yield return Row(Conn, 554, null, "No SMTP service here", Pol);
        yield return Row(Rcpt, 4, null, "x", Soft);
    }

    [Theory]
    [MemberData(nameof(Samples))]
    public void Classifies_representative_reply(SmtpStage stage, int code, string? enhanced, string text, DeliveryClass expected)
    {
        var result = Classifier.Classify(new RemoteReply(code, enhanced, text), stage);
        Assert.True(result.Class == expected, $"{stage} {code} {enhanced} '{text}' => {result.Class} ({result.Reason}), expected {expected}");
        Assert.False(string.IsNullOrEmpty(result.Reason));
    }

    [Fact]
    public void Sample_table_has_at_least_80_replies_covering_every_class()
    {
        var rows = Samples().ToList();
        Assert.True(rows.Count >= 80, $"only {rows.Count} samples");
        var covered = rows.Select(r => (DeliveryClass)r[4]!).Distinct().ToHashSet();
        foreach (DeliveryClass c in Enum.GetValues<DeliveryClass>())
        {
            Assert.Contains(c, covered);
        }
    }

    [Fact]
    public void Enhanced_code_in_text_is_used_when_not_given_separately()
    {
        var r = Classifier.Classify(new RemoteReply(550, "5.1.1 <x@y.example>: Recipient address rejected"), Rcpt);
        Assert.Equal(Rec, r.Class);
        var m = Classifier.Classify(new RemoteReply(452, "4.2.2 anything at all"), Rcpt);
        Assert.Equal(Full, m.Class);
    }

    [Fact]
    public void Text_matching_is_case_insensitive()
    {
        Assert.Equal(Grey, Classifier.Classify(new RemoteReply(450, "4.2.0", "GREYLISTED, COME BACK LATER"), Rcpt).Class);
        Assert.Equal(Rec, Classifier.Classify(new RemoteReply(550, null, "USER UNKNOWN"), Rcpt).Class);
    }

    [Fact]
    public void Null_text_is_handled()
    {
        Assert.Equal(Soft, Classifier.Classify(new RemoteReply(451, null, null), Rcpt).Class);
        Assert.Equal(Rec, Classifier.Classify(new RemoteReply(550, null, null), Rcpt).Class);
        Assert.Equal(Snd, Classifier.Classify(new RemoteReply(550, null, null), Mail).Class);
        Assert.Equal(Con, Classifier.Classify(new RemoteReply(554, null, null), Eod).Class);
    }

    [Fact]
    public void Same_permanent_reply_depends_on_stage_when_nothing_else_is_known()
    {
        var reply = new RemoteReply(550, null, "no");
        Assert.Equal(Rec, Classifier.Classify(reply, Rcpt).Class);
        Assert.Equal(Snd, Classifier.Classify(reply, Mail).Class);
        Assert.Equal(Con, Classifier.Classify(reply, Data).Class);
        Assert.Equal(Pol, Classifier.Classify(reply, Conn).Class);
        Assert.Equal(Cfg, Classifier.Classify(reply, Hand).Class);
    }

    [Fact]
    public void Recipient_keywords_do_not_fire_at_mail_from()
    {
        // A sender-stage refusal that happens to say "does not exist" must not suppress a recipient.
        var r = Classifier.Classify(new RemoteReply(550, null, "The sender domain does not exist"), Mail);
        Assert.NotEqual(Rec, r.Class);
        Assert.Equal(Snd, r.Class);
    }

    [Theory]
    [InlineData(DeliveryClass.PermanentRecipient, true)]
    [InlineData(DeliveryClass.PermanentSender, false)]
    [InlineData(DeliveryClass.PermanentPolicy, false)]
    [InlineData(DeliveryClass.PermanentContent, false)]
    [InlineData(DeliveryClass.PermanentConfigurationProblem, false)]
    [InlineData(DeliveryClass.SoftBounceMailboxFull, false)]
    [InlineData(DeliveryClass.Transient, false)]
    [InlineData(DeliveryClass.Delivered, false)]
    public void Only_recipient_hard_bounces_suppress(DeliveryClass cls, bool suppress) =>
        Assert.Equal(suppress, cls.ShouldSuppressRecipient());

    [Fact]
    public void Class_helpers_describe_handling()
    {
        Assert.True(DeliveryClass.SoftBounceMailboxFull.ShouldRetry());
        Assert.False(DeliveryClass.SoftBounceMailboxFull.ShouldRetry(retryMailboxFull: false));
        Assert.True(DeliveryClass.SoftBounceMailboxFull.CountsAsSoftBounce());
        Assert.True(DeliveryClass.TransientGreylist.ShouldRetry());
        Assert.False(DeliveryClass.PermanentContent.ShouldRetry());
        Assert.True(DeliveryClass.PermanentContent.IsPermanentFailure());
        Assert.False(DeliveryClass.SoftBounceMailboxFull.IsPermanentFailure());
        Assert.True(DeliveryClass.TransientThrottle.IsThrottleSignal());
    }

    [Theory]
    [InlineData("5.1.1", 5, 1, 1)]
    [InlineData("4.7.650", 4, 7, 650)]
    [InlineData(" 2.0.0 ", 2, 0, 0)]
    public void Enhanced_status_parses(string text, int cls, int subject, int detail)
    {
        Assert.True(EnhancedStatus.TryParse(text, out var s));
        Assert.Equal(new EnhancedStatus(cls, subject, detail), s);
    }

    [Theory]
    [InlineData("")]
    [InlineData("3.1.1")]
    [InlineData("5.1")]
    [InlineData("5.1.1.1")]
    [InlineData("5.a.1")]
    [InlineData("550")]
    [InlineData("5.1.1 trailing")]
    public void Enhanced_status_rejects_garbage(string text) => Assert.False(EnhancedStatus.TryParse(text, out _));

    [Theory]
    [InlineData("5.1.1 User unknown", true)]
    [InlineData("  4.2.2 Mailbox full", true)]
    [InlineData("5.1.1", true)]
    [InlineData("User unknown 5.1.1", false)]
    [InlineData("5.1.1x", false)]
    [InlineData("version 4.2.0", false)]
    public void Enhanced_status_parses_leading(string text, bool expected) =>
        Assert.Equal(expected, EnhancedStatus.TryParseLeading(text, out _));

    [Fact]
    public void Classification_does_not_allocate()
    {
        var reply = new RemoteReply(550, "5.7.1", "Service unavailable, Client host [203.0.113.5] blocked using Spamhaus.");
        for (int i = 0; i < 100; i++)
        {
            Classifier.Classify(reply, Eod); // warm up
        }

        long before = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 1000; i++)
        {
            Classifier.Classify(reply, Eod);
        }

        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.True(allocated < 1024, $"allocated {allocated} bytes");
    }

    [Fact]
    public void Rule_table_is_present() => Assert.True(ReplyClassifier.RuleCount > 50);
}
