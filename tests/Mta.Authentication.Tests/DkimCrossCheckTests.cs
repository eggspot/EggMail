using System.Security.Cryptography;
using System.Text;
using MimeKit;
using MimeKit.Cryptography;
using DkimSigner = Mta.Dkim.DkimSigner;
using Mta.Core;
using Mta.Dkim;
using Mta.Dns;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using MkVerifier = MimeKit.Cryptography.DkimVerifier;
using OurVerifier = Mta.Dkim.DkimVerifier;

namespace Mta.Authentication.Tests;

/// <summary>
/// A DKIM signature made by Mta.Dkim, judged by four code paths that share nothing with it: Mta.Dkim's own verifier, MimeKit (which uses BouncyCastle), a from-scratch
/// reading of RFC 6376 in <see cref="IndependentDkim"/> that signs again with the BCL and must produce byte-identical <c>b=</c>, and the <c>openssl</c> command line.
/// </summary>
public class DkimCrossCheckTests
{
    private static readonly RSA Key = RSA.Create(2048);
    private static readonly DateTimeOffset Now = new(2026, 10, 12, 12, 0, 0, TimeSpan.Zero);

    private sealed class FixedClock(DateTimeOffset now) : IClock
    {
        public DateTimeOffset UtcNow => now;
        public long Timestamp => now.Ticks;
    }

    private sealed class DictionaryKeyLocator(RSA key) : DkimPublicKeyLocatorBase
    {
        public override AsymmetricKeyParameter LocatePublicKey(string methods, string domain, string selector, CancellationToken cancellationToken = default) =>
            PublicKeyFactory.CreateKey(key.ExportSubjectPublicKeyInfo());

        public override Task<AsymmetricKeyParameter> LocatePublicKeyAsync(string methods, string domain, string selector, CancellationToken cancellationToken = default) =>
            Task.FromResult(LocatePublicKey(methods, domain, selector, cancellationToken));
    }

    private const string Head = "From: Alice <alice@example.com>\r\nTo: Bob <bob@example.net>\r\nDate: Mon, 12 Oct 2026 12:00:00 +0000\r\nMessage-ID: <m1@example.com>\r\nMIME-Version: 1.0\r\n";

    /// <summary>The shapes that have caught real verifiers out: folding, blank lines, empty body, odd white space, repeated headers, long lines, 8-bit text.</summary>
    public static readonly (string Name, string Message)[] Shapes =
    [
        ("plain", Head + "Subject: Plain\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello,\r\n\r\nThis is the body.\r\n"),
        ("folded-subject", Head + "Subject: A rather long subject line that will need to be folded\r\n because it is longer than seventy eight characters\r\n\tand even uses a tab for continuation\r\nContent-Type: text/plain\r\n\r\nbody\r\n"),
        ("white-space-everywhere", Head + "Subject:\tTabbed   subject  \r\nContent-Type: text/plain\r\n\r\nbody   with   spaces  \r\nand\ttabs\t\r\n"),
        ("trailing-blank-lines", Head + "Subject: t\r\nContent-Type: text/plain\r\n\r\nline one\r\n\r\nline three\r\n\r\n\r\n\r\n"),
        ("leading-blank-lines", Head + "Subject: t\r\nContent-Type: text/plain\r\n\r\n\r\n\r\nafter blanks\r\n"),
        ("white-space-only-last-lines", Head + "Subject: t\r\nContent-Type: text/plain\r\n\r\ntext\r\n   \r\n\t\r\n"),
        ("empty-body", Head + "Subject: Empty body\r\nContent-Type: text/plain\r\n\r\n"),
        ("single-crlf-body", Head + "Subject: Only a CRLF\r\nContent-Type: text/plain\r\n\r\n\r\n"),
        ("no-trailing-newline", Head + "Subject: No final newline\r\nContent-Type: text/plain\r\n\r\nlast line without a line break"),
        ("empty-header-value", Head + "Subject:\r\nX-Empty:\r\nContent-Type: text/plain\r\n\r\nbody\r\n"),
        ("repeated-headers", Head + "Subject: Duplicates\r\nComments: first\r\nComments: second\r\nContent-Type: text/plain\r\n\r\nbody\r\n"),
        ("long-lines", Head + "Subject: Long\r\nContent-Type: text/plain\r\n\r\n" + new string('x', 900) + "\r\n" + string.Join("\r\n", Enumerable.Range(0, 200).Select(i => "row " + i + "  ")) + "\r\n"),
        ("multipart", Head + "Subject: Multipart\r\nContent-Type: multipart/alternative; boundary=\"bound\"\r\n\r\n--bound\r\nContent-Type: text/plain\r\n\r\nplain part\r\n--bound\r\nContent-Type: text/html\r\n\r\n<p>html  part</p>\r\n--bound--\r\n"),
        ("eight-bit-body", Head + "Subject: Eight bit\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: 8bit\r\n\r\nGrüße aus München\r\n"),
        ("two-from-headers", Head + "From: Mallory <mallory@example.net>\r\nSubject: Two From\r\nContent-Type: text/plain\r\n\r\nbody\r\n"),
    ];

    public static TheoryData<string, DkimCanonicalization, DkimCanonicalization> ShapesAndCanonicalizations()
    {
        var data = new TheoryData<string, DkimCanonicalization, DkimCanonicalization>();
        foreach (var (name, _) in Shapes)
        {
            foreach (var header in Enum.GetValues<DkimCanonicalization>())
            {
                foreach (var body in Enum.GetValues<DkimCanonicalization>())
                {
                    data.Add(name, header, body);
                }
            }
        }

        return data;
    }

    private static string Message(string name) => Shapes.Single(s => s.Name == name).Message;

    private static (string Signed, string SignatureField) Sign(string message, DkimCanonicalization header, DkimCanonicalization body)
    {
        using var signer = new DkimSigner(new DkimSignerOptions { Domain = "example.com", Selector = "sel", HeaderCanonicalization = header, BodyCanonicalization = body, Clock = new FixedClock(Now) }, Key);
        string field = signer.Sign(Encoding.Latin1.GetBytes(message));
        return (field + message, field);
    }

    private static StaticDnsResolver Dns() => new StaticDnsResolver().AddTxt("sel._domainkey.example.com", DkimKeyTools.FormatDnsTxtValue(Key));

    private static OurVerifier Ours() => new(Dns(), new DkimVerifierOptions { Clock = new FixedClock(Now) });

    private static MimeMessage Load(string raw)
    {
        using var ms = new MemoryStream(Encoding.Latin1.GetBytes(raw));
        return MimeMessage.Load(ms);
    }

    private static readonly FormatOptions Wire = new Func<FormatOptions>(() =>
    {
        var o = FormatOptions.Default.Clone();
        o.NewLineFormat = NewLineFormat.Dos;
        return o;
    })();

    private static bool MimeKitSays(string signed)
    {
        var message = Load(signed);
        var header = message.Headers.First(h => h.Id == HeaderId.DkimSignature);
        return new MkVerifier(new DictionaryKeyLocator(Key)).Verify(Wire, message, header);
    }

    [Theory]
    [MemberData(nameof(ShapesAndCanonicalizations))]
    public async Task All_independent_readings_of_the_rfc_accept_what_our_signer_makes_and_agree_on_the_signature_bytes(string shape, DkimCanonicalization header, DkimCanonicalization body)
    {
        var (signed, field) = Sign(Message(shape), header, body);

        var verdict = Assert.Single(await Ours().VerifyAsync(Encoding.Latin1.GetBytes(signed)));
        Assert.True(verdict.IsPass, $"Mta.Dkim: {verdict.Status} {verdict.Reason}");
        Assert.True(MimeKitSays(signed), "MimeKit rejected the signature");
        Assert.Equal([true], IndependentDkim.Verify(signed, Key));

        // RSASSA-PKCS1-v1_5 is deterministic: signing the independently built input must reproduce b= exactly.
        string b = IndependentDkim.Tags(field)["b"].Replace(" ", string.Empty);
        Assert.Equal(IndependentDkim.ExpectedB(signed, field, Key), b);
    }

    [OpenSslTheory]
    [MemberData(nameof(ShapesAndCanonicalizations))]
    public void The_openssl_command_line_verifies_the_signature_over_the_independently_built_input(string shape, DkimCanonicalization header, DkimCanonicalization body)
    {
        var (signed, field) = Sign(Message(shape), header, body);
        byte[] signature = Convert.FromBase64String(IndependentDkim.Tags(field)["b"].Replace(" ", string.Empty));

        Assert.True(OpenSsl.Verify(IndependentDkim.SigningInput(signed, field), signature, Key));
        signature[5] ^= 0x01;
        Assert.False(OpenSsl.Verify(IndependentDkim.SigningInput(signed, field), signature, Key));   // and the check is not vacuous
    }

    // ------------------------------------------------------------------------------------------ tampering

    public static TheoryData<string, string> Tamperings => new()
    {
        { "plain", "body-text" },
        { "plain", "subject" },
        { "plain", "removed-subject" },
        { "plain", "appended-body-line" },
        { "plain", "extra-from-header" },
        { "plain", "flipped-signature-character" },
        { "trailing-blank-lines", "text-before-the-blank-lines" },
        { "white-space-only-last-lines", "visible-text-on-a-blank-line" },
        { "multipart", "html-part" },
    };

    private static string Tamper(string signed, string how) => how switch
    {
        "body-text" => signed.Replace("This is the body.", "This is the b0dy."),
        "subject" => signed.Replace("Subject: Plain", "Subject: Plain!"),
        "removed-subject" => signed.Replace("Subject: Plain\r\n", string.Empty),
        "appended-body-line" => signed + "one more line\r\n",
        "extra-from-header" => "From: Mallory <mallory@example.net>\r\n" + signed,   // above the signature: the oversigned From list must catch it
        "flipped-signature-character" => FlipSignature(signed),
        "text-before-the-blank-lines" => signed.Replace("line three", "line THREE"),
        "visible-text-on-a-blank-line" => signed.Replace("text\r\n   \r\n", "text\r\n x \r\n"),
        "html-part" => signed.Replace("html  part", "evil  part"),
        _ => throw new ArgumentOutOfRangeException(nameof(how)),
    };

    private static string FlipSignature(string signed)
    {
        int b = signed.IndexOf("\tb=", StringComparison.Ordinal);
        if (b < 0)
        {
            b = signed.IndexOf(" b=", StringComparison.Ordinal);
        }

        int at = b + 5;
        char flipped = signed[at] == 'A' ? 'B' : 'A';
        return signed[..at] + flipped + signed[(at + 1)..];
    }

    [Theory]
    [MemberData(nameof(Tamperings))]
    public async Task A_modified_message_is_rejected_by_every_reading_in_every_canonicalization(string shape, string how)
    {
        foreach (var header in Enum.GetValues<DkimCanonicalization>())
        {
            foreach (var body in Enum.GetValues<DkimCanonicalization>())
            {
                var (signed, _) = Sign(Message(shape), header, body);
                string tampered = Tamper(signed, how);
                Assert.NotEqual(signed, tampered);
                string label = $"{how} under {header}/{body}";

                var verdict = (await Ours().VerifyAsync(Encoding.Latin1.GetBytes(tampered))).Single();
                Assert.False(verdict.IsPass, $"Mta.Dkim accepted {label}");
                Assert.DoesNotContain(true, IndependentDkim.Verify(tampered, Key));
                Assert.False(SafeMimeKit(tampered), $"MimeKit accepted {label}");
            }
        }
    }

    private static bool SafeMimeKit(string signed)
    {
        try
        {
            return MimeKitSays(signed);
        }
        catch (Exception ex) when (ex is FormatException or InvalidOperationException or ArgumentException)
        {
            return false;
        }
    }

    [Fact]
    public async Task Changes_that_canonicalization_is_defined_to_ignore_do_not_break_a_relaxed_signature_in_any_reading()
    {
        var (signed, _) = Sign(Message("white-space-everywhere"), DkimCanonicalization.Relaxed, DkimCanonicalization.Relaxed);
        string rewritten = signed
            .Replace("Subject:\tTabbed   subject  \r\n", "Subject: Tabbed subject\r\n")                  // header white space
            .Replace("body   with   spaces  \r\n", "body with spaces\r\n")                              // body white space and trailing white space
            + "\r\n\r\n";                                                                                // trailing empty lines

        Assert.True((await Ours().VerifyAsync(Encoding.Latin1.GetBytes(rewritten))).Single().IsPass);
        Assert.Equal([true], IndependentDkim.Verify(rewritten, Key));
        Assert.True(MimeKitSays(rewritten));
    }

    [Fact]
    public async Task The_same_changes_break_a_simple_signature_in_every_reading()
    {
        var (signed, _) = Sign(Message("white-space-everywhere"), DkimCanonicalization.Simple, DkimCanonicalization.Simple);
        string rewritten = signed.Replace("body   with   spaces  \r\n", "body with spaces\r\n");

        Assert.False((await Ours().VerifyAsync(Encoding.Latin1.GetBytes(rewritten))).Single().IsPass);
        Assert.Equal([false], IndependentDkim.Verify(rewritten, Key));
        Assert.False(MimeKitSays(rewritten));
    }

    // ------------------------------------------------------------------------------- l= and multiple From

    [Fact]
    public async Task A_body_length_limit_signed_by_someone_else_is_understood_the_same_way_by_every_reading()
    {
        // Mta.Dkim never signs with l=, so the signature is made by the independent implementation with the BCL: relaxed/relaxed, covering the first 20 bytes of the body.
        string message = Message("plain");
        string bodyHash = IndependentDkim.BodyHash(message, new Dictionary<string, string> { ["c"] = "relaxed/relaxed", ["l"] = "20" });
        string unsigned = "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel; l=20; h=from:to:subject:date:message-id; bh=" + bodyHash + "; b=\r\n";
        string signature = IndependentDkim.ExpectedB(unsigned + message, unsigned, Key);
        string signed = unsigned.TrimEnd('\r', '\n') + signature + "\r\n" + message;

        string appended = signed + "an advertisement that nobody signed\r\n";
        var ours = (await Ours().VerifyAsync(Encoding.Latin1.GetBytes(appended))).Single();
        Assert.True(ours.IsPass);
        Assert.True(ours.BodyLengthLimited);   // passes, and says that part of the body is not covered
        Assert.Equal([true], IndependentDkim.Verify(appended, Key));
        Assert.True(MimeKitSays(appended));

        string altered = signed.Replace("Hello,", "Hullo,");
        Assert.False((await Ours().VerifyAsync(Encoding.Latin1.GetBytes(altered))).Single().IsPass);
        Assert.Equal([false], IndependentDkim.Verify(altered, Key));
        Assert.False(MimeKitSays(altered));
    }

    [Fact]
    public async Task Two_from_headers_are_both_signed_and_a_third_added_afterwards_is_caught()
    {
        var (signed, field) = Sign(Message("two-from-headers"), DkimCanonicalization.Relaxed, DkimCanonicalization.Relaxed);
        Assert.True(IndependentDkim.Tags(field)["h"].Split(':').Count(h => h.Trim().Equals("from", StringComparison.OrdinalIgnoreCase)) >= 3, "both From headers and one more (oversigning) are listed");

        Assert.True((await Ours().VerifyAsync(Encoding.Latin1.GetBytes(signed))).Single().IsPass);
        string withThird = "From: Eve <eve@example.net>\r\n" + signed;
        Assert.False((await Ours().VerifyAsync(Encoding.Latin1.GetBytes(withThird))).Single().IsPass);
        Assert.Equal([false], IndependentDkim.Verify(withThird, Key));
    }
}
