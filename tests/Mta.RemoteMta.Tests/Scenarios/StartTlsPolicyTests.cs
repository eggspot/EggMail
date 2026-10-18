using System.Security.Cryptography.X509Certificates;
using Mta.RemoteMta.Tests.Harness;
using Mta.Storage;
using Mta.Tls;

namespace Mta.RemoteMta.Tests.Scenarios;

/// <summary>
/// STARTTLS offered, required, stripped, refused, interrupted, and certificates that are valid, expired, for another name, or from an unknown CA, under the three
/// configured levels: <c>may</c> (opportunistic), <c>encrypt</c> (TLS required, nothing checked) and <c>verify</c> (TLS required and the certificate must be good).
/// </summary>
public class StartTlsPolicyTests
{
    public enum CertKind { Valid, Expired, WrongName, UntrustedCa }

    public static X509Certificate2 Make(MtaLab lab, CertKind kind, string host = "mx.dest.example") => kind switch
    {
        CertKind.Valid => TestPki.Leaf(lab.Ca, [host]).ForServer(),
        CertKind.Expired => TestPki.Leaf(lab.Ca, [host], DateTimeOffset.UtcNow.AddDays(-60), DateTimeOffset.UtcNow.AddDays(-2)).ForServer(),
        CertKind.WrongName => TestPki.Leaf(lab.Ca, ["mail.somebody-else.example"]).ForServer(),
        _ => TestPki.Leaf(TestPki.CreateRoot("Some Other CA"), [host]).ForServer(),
    };

    private static MtaLab NewLab(TlsSecurityLevel level, MtaPersonality peer, out FakeMta mx)
    {
        var lab = new MtaLab(new LabSettings { TlsLevel = level });
        mx = lab.AddMta("mx.dest.example", peer);
        lab.Mx("dest.example", 10, "mx.dest.example");
        return lab;
    }

    private static TlsInfo TlsOf(IReadOnlyList<MessageEvent> events, MessageEventType type = MessageEventType.Delivered) => events.Single(e => e.Type == type).Tls!;

    // ------------------------------------------------------------------------------------------------ may

    [Fact]
    public async Task Opportunistic_tls_encrypts_when_offered_even_with_a_certificate_nobody_trusts_and_records_that_it_was_not_verified()
    {
        var peer = Personalities.Postfix(TestPki.SelfSigned("mx.dest.example").ForServer());
        await using var lab = NewLab(TlsSecurityLevel.May, peer, out var mx);

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var events = await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.True(Assert.Single(mx.Messages).Tls);
        var tls = TlsOf(events);
        Assert.True(tls.Used);
        Assert.False(tls.Verified);
        Assert.True(tls.StartTlsAdvertised);
        Assert.False(tls.PlaintextFallback);
    }

    [Fact]
    public async Task Opportunistic_delivery_continues_in_plaintext_to_a_peer_that_never_offers_starttls_and_says_so_in_the_record()
    {
        await using var lab = NewLab(TlsSecurityLevel.May, Personalities.Exim(), out var mx);

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var events = await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.False(Assert.Single(mx.Messages).Tls);
        var tls = TlsOf(events);
        Assert.False(tls.Used);
        Assert.False(tls.StartTlsAdvertised);
        Assert.True(tls.PlaintextFallback);
    }

    // ----------------------------------------------------------------------- certificates under each level

    public static TheoryData<TlsSecurityLevel, CertKind, bool> CertificateMatrix => new()
    {
        { TlsSecurityLevel.May, CertKind.Valid, true },
        { TlsSecurityLevel.May, CertKind.Expired, true },
        { TlsSecurityLevel.May, CertKind.WrongName, true },
        { TlsSecurityLevel.May, CertKind.UntrustedCa, true },
        { TlsSecurityLevel.Encrypt, CertKind.Valid, true },
        { TlsSecurityLevel.Encrypt, CertKind.Expired, true },
        { TlsSecurityLevel.Encrypt, CertKind.WrongName, true },
        { TlsSecurityLevel.Encrypt, CertKind.UntrustedCa, true },
        { TlsSecurityLevel.Verify, CertKind.Valid, true },
        { TlsSecurityLevel.Verify, CertKind.Expired, false },
        { TlsSecurityLevel.Verify, CertKind.WrongName, false },
        { TlsSecurityLevel.Verify, CertKind.UntrustedCa, false },
    };

    [Theory]
    [MemberData(nameof(CertificateMatrix))]
    public async Task A_certificate_is_checked_only_when_the_level_is_verify_and_a_failed_check_defers_instead_of_sending_in_plaintext(TlsSecurityLevel level, CertKind kind, bool delivered)
    {
        var peer = Personalities.Postfix();
        await using var lab = NewLab(level, peer, out var mx);
        peer.Certificate = _ => Make(lab, kind);

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        if (delivered)
        {
            var events = await lab.WaitForEventAsync(id, MessageEventType.Delivered);
            Assert.True(Assert.Single(mx.Messages).Tls);
            Assert.Equal(level == TlsSecurityLevel.Verify, TlsOf(events).Verified);
            return;
        }

        var due = await lab.WaitForRetryScheduleAsync(id);
        var deferred = (await lab.EventsAsync(id)).Single(e => e.Type == MessageEventType.Deferred);
        Assert.Equal(451, deferred.SmtpCode);
        Assert.Equal("4.7.5", deferred.EnhancedCode);
        Assert.Empty(mx.Messages);   // not sent over the failed session and not retried in plaintext
        Assert.Equal(1, mx.ConnectionCount);
        Assert.DoesNotContain(await lab.EventsAsync(id), e => e.Type == MessageEventType.Bounced);

        // The operator of the peer fixes the certificate; the next attempt goes through with a verified session.
        peer.Certificate = _ => Make(lab, CertKind.Valid);
        lab.Advance(due - lab.Clock.UtcNow);
        var final = await lab.WaitForEventAsync(id, MessageEventType.Delivered);
        Assert.True(TlsOf(final).Verified);
        Assert.True(Assert.Single(mx.Messages).Tls);
    }

    // -------------------------------------------------------------------------------- required, refused, stripped

    [Theory]
    [InlineData(TlsSecurityLevel.Encrypt)]
    [InlineData(TlsSecurityLevel.Verify)]
    public async Task When_tls_is_required_a_peer_without_starttls_is_never_sent_the_message_and_gets_it_once_it_offers_tls(TlsSecurityLevel level)
    {
        var peer = Personalities.Postfix();
        await using var lab = NewLab(level, peer, out var mx);
        peer.Certificate = _ => Make(lab, CertKind.Valid);
        bool offer = false;
        peer.OffersStartTls = _ => offer;

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var due = await lab.WaitForRetryScheduleAsync(id);
        var deferred = (await lab.EventsAsync(id)).Single(e => e.Type == MessageEventType.Deferred);

        Assert.Equal(451, deferred.SmtpCode);
        Assert.Equal("4.7.5", deferred.EnhancedCode);
        Assert.Empty(mx.Messages);

        offer = true;
        lab.Advance(due - lab.Clock.UtcNow);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);
        Assert.True(Assert.Single(mx.Messages).Tls);
    }

    [Theory]
    [InlineData(TlsSecurityLevel.May, true)]
    [InlineData(TlsSecurityLevel.Encrypt, false)]
    [InlineData(TlsSecurityLevel.Verify, false)]
    public async Task A_454_answer_to_starttls_is_survived_in_plaintext_only_by_the_opportunistic_level(TlsSecurityLevel level, bool deliveredInPlaintext)
    {
        var peer = Personalities.Postfix();
        await using var lab = NewLab(level, peer, out var mx);
        peer.Certificate = _ => Make(lab, CertKind.Valid);
        peer.StartTls = StartTlsBehaviour.Refuses454;

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        if (deliveredInPlaintext)
        {
            var events = await lab.WaitForEventAsync(id, MessageEventType.Delivered);
            Assert.False(Assert.Single(mx.Messages).Tls);
            Assert.True(TlsOf(events).PlaintextFallback);
        }
        else
        {
            await lab.WaitForEventAsync(id, MessageEventType.Deferred);
            Assert.Empty(mx.Messages);
        }
    }

    [Fact]
    public async Task A_peer_that_stops_offering_starttls_after_first_contact_is_followed_into_plaintext_by_the_opportunistic_level_which_is_what_opportunistic_means()
    {
        var peer = Personalities.Postfix();
        await using var lab = NewLab(TlsSecurityLevel.May, peer, out var mx);
        peer.Certificate = _ => Make(lab, CertKind.Valid);
        peer.OffersStartTls = s => s.Index == 0;

        var first = await lab.SendAsync(["one@dest.example"]);
        await lab.WaitForEventAsync(first, MessageEventType.Delivered);
        mx.DropOpenConnections();
        var second = await lab.SendAsync(["two@dest.example"]);
        await lab.WaitForEventAsync(second, MessageEventType.Delivered);

        Assert.Equal([true, false], mx.Messages.Select(m => m.Tls));   // a downgrade is invisible to opportunistic TLS; MTA-STS or DANE exist to close this gap
    }

    [Theory]
    [InlineData(TlsSecurityLevel.Encrypt)]
    [InlineData(TlsSecurityLevel.Verify)]
    public async Task A_starttls_downgrade_after_first_contact_is_refused_when_tls_is_required(TlsSecurityLevel level)
    {
        var peer = Personalities.Postfix();
        await using var lab = NewLab(level, peer, out var mx);
        peer.Certificate = _ => Make(lab, CertKind.Valid);
        peer.OffersStartTls = s => s.Index == 0;

        var first = await lab.SendAsync(["one@dest.example"]);
        await lab.WaitForEventAsync(first, MessageEventType.Delivered);
        mx.DropOpenConnections();
        var second = await lab.SendAsync(["two@dest.example"]);
        await lab.WaitForEventAsync(second, MessageEventType.Deferred);

        Assert.Equal([true], mx.Messages.Select(m => m.Tls));
        var deferred = (await lab.EventsAsync(second)).Single(e => e.Type == MessageEventType.Deferred);
        Assert.Equal("4.7.5", deferred.EnhancedCode);
    }

    // ---------------------------------------------------------------------------- the handshake itself breaks

    public static TheoryData<StartTlsBehaviour> BrokenHandshakes => new()
    {
        StartTlsBehaviour.ClosesAfter220,
        StartTlsBehaviour.PlainTextAfter220,
        StartTlsBehaviour.ResetsMidHandshake,
        StartTlsBehaviour.InjectsAfter220,
    };

    [Theory]
    [MemberData(nameof(BrokenHandshakes))]
    public async Task A_handshake_that_breaks_after_the_220_does_not_keep_opportunistic_mail_from_being_delivered_in_plaintext_on_a_new_connection(StartTlsBehaviour behaviour)
    {
        var peer = Personalities.Postfix();
        await using var lab = NewLab(TlsSecurityLevel.May, peer, out var mx);
        peer.Certificate = _ => Make(lab, CertKind.Valid);
        peer.StartTls = behaviour;

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var events = await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        var message = Assert.Single(mx.Messages);
        Assert.False(message.Tls);
        Assert.Equal(2, mx.ConnectionCount);   // the failed upgrade, then a connection that does not try STARTTLS
        var tls = TlsOf(events);
        Assert.False(tls.Used);
        Assert.True(tls.StartTlsAdvertised);
        Assert.True(tls.PlaintextFallback);
        Assert.DoesNotContain(events, e => e.Type == MessageEventType.Deferred);
    }

    [Theory]
    [InlineData(TlsSecurityLevel.Encrypt, StartTlsBehaviour.ClosesAfter220)]
    [InlineData(TlsSecurityLevel.Encrypt, StartTlsBehaviour.ResetsMidHandshake)]
    [InlineData(TlsSecurityLevel.Verify, StartTlsBehaviour.PlainTextAfter220)]
    [InlineData(TlsSecurityLevel.Verify, StartTlsBehaviour.InjectsAfter220)]
    public async Task A_handshake_that_breaks_when_tls_is_required_defers_and_never_falls_back_to_plaintext(TlsSecurityLevel level, StartTlsBehaviour behaviour)
    {
        var peer = Personalities.Postfix();
        await using var lab = NewLab(level, peer, out var mx);
        peer.Certificate = _ => Make(lab, CertKind.Valid);
        peer.StartTls = behaviour;

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Deferred);

        Assert.Empty(mx.Messages);
        Assert.Equal(1, mx.ConnectionCount);
        Assert.Equal("4.7.5", (await lab.EventsAsync(id)).Single(e => e.Type == MessageEventType.Deferred).EnhancedCode);
    }

    [Fact]
    public async Task Data_injected_before_the_tls_handshake_is_never_read_as_a_reply()
    {
        var peer = Personalities.Postfix();
        await using var lab = NewLab(TlsSecurityLevel.Encrypt, peer, out var mx);
        peer.Certificate = _ => Make(lab, CertKind.Valid);
        peer.StartTls = StartTlsBehaviour.InjectsAfter220;

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Deferred);

        var deferred = (await lab.EventsAsync(id)).Single(e => e.Type == MessageEventType.Deferred);
        Assert.Contains("injection", deferred.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(mx.Messages);
    }

    [Fact]
    public async Task A_peer_that_only_speaks_old_smtp_with_helo_is_delivered_to_without_extensions_or_tls()
    {
        var peer = Personalities.Plain("mx.dest.example");
        peer.Esmtp = false;
        await using var lab = NewLab(TlsSecurityLevel.May, peer, out var mx);

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Single(mx.Messages);
        Assert.Equal(["EHLO", "HELO"], mx.Sessions.Single().Verbs.Take(2));
    }
}
