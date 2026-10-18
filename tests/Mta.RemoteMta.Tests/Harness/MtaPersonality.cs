using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Mta.RemoteMta.Tests.Harness;

/// <summary>How a fake MTA misbehaves around STARTTLS.</summary>
public enum StartTlsBehaviour
{
    /// <summary>Answers 220 and performs the handshake.</summary>
    Normal,

    /// <summary>Advertises STARTTLS, then answers <c>454 4.7.0 TLS not available due to temporary reason</c>.</summary>
    Refuses454,

    /// <summary>Answers 220 and closes the connection at once (a middlebox that kills the upgrade).</summary>
    ClosesAfter220,

    /// <summary>Answers 220 and then sends plain text where the handshake should be (a broken or hostile peer).</summary>
    PlainTextAfter220,

    /// <summary>Answers 220, reads the start of the ClientHello and drops the connection in the middle of the handshake.</summary>
    ResetsMidHandshake,

    /// <summary>Answers 220 and sends a banner-like line in the clear before the handshake (the STARTTLS injection attack).</summary>
    InjectsAfter220,
}

/// <summary>What the fake sees when the end of the message data arrived.</summary>
public sealed class EndOfDataContext(ReceivedMessage message)
{
    public ReceivedMessage Message { get; } = message;

    /// <summary>Set when the server has stored the message whatever it answers (a server that accepted and then lost the connection).</summary>
    public bool Keep { get; set; }
}

/// <summary>
/// The behaviour of one fake remote MTA: its banner, extensions and replies, and hooks that script anything else. The ready made
/// personalities in <see cref="Personalities"/> use the reply formats that Gmail, Outlook, Postfix and Exim are publicly documented to send.
/// Properties may be changed while a test runs, so a script can make a peer change its mind after first contact.
/// </summary>
public sealed class MtaPersonality
{
    public string Name { get; init; } = "generic";

    public string Hostname { get; set; } = "mx.fake.test";

    /// <summary>The banner. Default: <c>220 host ESMTP</c>.</summary>
    public Func<FakeSession, Step>? Greeting { get; set; }

    /// <summary>False makes the peer an old SMTP-only server: EHLO is answered <c>500</c> and HELO works.</summary>
    public bool Esmtp { get; set; } = true;

    public bool EnhancedStatusCodes { get; set; } = true;

    public bool Pipelining { get; set; } = true;

    public bool EightBitMime { get; set; } = true;

    public bool SmtpUtf8 { get; set; } = true;

    public bool Chunking { get; set; }

    public bool Dsn { get; set; }

    /// <summary>The limit advertised with <c>SIZE</c>; null leaves the extension out, 0 advertises it without a limit.</summary>
    public long? SizeAdvertised { get; set; }

    /// <summary>The limit actually enforced (552 5.3.4), at MAIL when the client declares a size and at the end of the data otherwise; null enforces nothing.</summary>
    public long? SizeEnforced { get; set; }

    /// <summary>Most recipients per transaction before <c>452 4.5.3</c>.</summary>
    public int? MaxRecipientsPerTransaction { get; set; }

    /// <summary>After this many accepted messages on one connection the next MAIL gets <c>421 4.7.0</c> and the connection closes (a per-connection cap).</summary>
    public int? MaxMessagesPerConnection { get; set; }

    /// <summary>Extra capability lines placed after the standard ones.</summary>
    public List<string> ExtraCapabilities { get; } = [];

    /// <summary>The certificate for STARTTLS; null means the peer has no TLS at all and does not advertise it.</summary>
    public Func<string?, X509Certificate2>? Certificate { get; set; }

    /// <summary>Whether this session's EHLO advertises STARTTLS (before TLS). Default: when there is a certificate. A script flips it to model a downgrade.</summary>
    public Func<FakeSession, bool>? OffersStartTls { get; set; }

    public StartTlsBehaviour StartTls { get; set; }

    public SslProtocols TlsProtocols { get; set; } = SslProtocols.None;

    /// <summary>First look at every command line; a non-null step replaces the normal handling of that command (garbage, hangs, drops).</summary>
    public Func<FakeSession, string, Step?>? OnCommand { get; set; }

    /// <summary><c>MAIL FROM</c>: the reverse path and the parameters. Null accepts.</summary>
    public Func<FakeSession, string, IReadOnlyDictionary<string, string>, Step?>? OnMail { get; set; }

    /// <summary><c>RCPT TO</c>: the forward path. Null accepts.</summary>
    public Func<FakeSession, string, Step?>? OnRcpt { get; set; }

    /// <summary>The answer to <c>DATA</c> (instead of <c>354</c>); a non-positive-intermediate reply ends the transaction.</summary>
    public Func<FakeSession, Step?>? OnData { get; set; }

    /// <summary>The verdict on the message. Null accepts with <c>250 2.0.0 Ok: queued as ...</c>.</summary>
    public Func<FakeSession, EndOfDataContext, Step?>? OnEndOfData { get; set; }

    /// <summary>The answer to <c>RSET</c> and <c>NOOP</c> (a peer that dies when asked). Null answers 250.</summary>
    public Func<FakeSession, string, Step?>? OnHousekeeping { get; set; }

    /// <summary>Connections accepted beyond this many at once are answered <c>421 4.7.0 Too many connections</c> (a per-IP connection limit).</summary>
    public int? MaxConcurrentConnections { get; set; }
}
