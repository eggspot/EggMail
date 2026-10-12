using System.Security.Cryptography;
using System.Text;
using MimeKit;
using MimeKit.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using MkSigner = MimeKit.Cryptography.DkimSigner;
using MkVerifier = MimeKit.Cryptography.DkimVerifier;

namespace Mta.Dkim.Tests;

/// <summary>
/// Differential tests against MimeKit's DKIM implementation, used as an independent oracle in both directions.
/// </summary>
public class MimeKitInteropTests
{
    private static readonly FormatOptions Wire = CreateWireOptions();

    private static FormatOptions CreateWireOptions()
    {
        var o = FormatOptions.Default.Clone();
        o.NewLineFormat = NewLineFormat.Dos;
        return o;
    }

    private sealed class DictionaryKeyLocator : DkimPublicKeyLocatorBase
    {
        private readonly Dictionary<string, AsymmetricKeyParameter> _keys = new(StringComparer.OrdinalIgnoreCase);

        public DictionaryKeyLocator Add(string domain, string selector, RSA key)
        {
            _keys[$"{selector}._domainkey.{domain}"] = PublicKeyFactory.CreateKey(key.ExportSubjectPublicKeyInfo());
            return this;
        }

        public override AsymmetricKeyParameter LocatePublicKey(string methods, string domain, string selector, CancellationToken cancellationToken = default) =>
            _keys[$"{selector}._domainkey.{domain}"];

        public override Task<AsymmetricKeyParameter> LocatePublicKeyAsync(string methods, string domain, string selector, CancellationToken cancellationToken = default) =>
            Task.FromResult(LocatePublicKey(methods, domain, selector, cancellationToken));
    }

    public static IEnumerable<object[]> Messages()
    {
        string head = "From: Alice <alice@example.com>\r\nTo: Bob <bob@example.net>\r\nDate: Mon, 12 Oct 2026 12:00:00 +0000\r\nMessage-ID: <m1@example.com>\r\nMIME-Version: 1.0\r\n";
        var list = new List<string>
        {
            head + "Subject: Plain\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello,\r\n\r\nThis is the body.\r\n",
            head + "Subject: A rather long subject line that will need to be folded because it is longer than seventy eight characters\r\nContent-Type: text/plain\r\n\r\nbody\r\n",
            head + "Subject:\tTabbed   subject  \r\nContent-Type: text/plain\r\n\r\nbody   with   spaces  \r\nand\ttabs\t\r\n",
            head + "Subject: Trailing blank lines\r\nContent-Type: text/plain\r\n\r\nline one\r\n\r\nline three\r\n\r\n\r\n\r\n",
            head + "Subject: Leading blank lines\r\nContent-Type: text/plain\r\n\r\n\r\n\r\nafter blanks\r\n",
            head + "Subject: Whitespace-only trailing lines\r\nContent-Type: text/plain\r\n\r\ntext\r\n   \r\n\t\r\n",
            head + "Subject: Empty body\r\nContent-Type: text/plain\r\n\r\n",
            head + "Subject: Multipart\r\nContent-Type: multipart/alternative; boundary=\"bound\"\r\n\r\n--bound\r\nContent-Type: text/plain\r\n\r\nplain part\r\n--bound\r\nContent-Type: text/html\r\n\r\n<p>html  part</p>\r\n--bound--\r\n",
            head + "Subject: Duplicates\r\nComments: first\r\nComments: second\r\nContent-Type: text/plain\r\n\r\nbody\r\n",
            head + "Subject: Long lines\r\nContent-Type: text/plain\r\n\r\n" + new string('x', 900) + "\r\n" + string.Join("\r\n", Enumerable.Range(0, 300).Select(i => "row " + i + "  ")) + "\r\n",
            head + "Subject: Reply\r\nIn-Reply-To: <a@example.org>\r\nReferences: <a@example.org>\r\n <b@example.org>\r\nReply-To: Alice <alice@example.com>\r\nContent-Type: text/plain\r\n\r\nreply body\r\n",
        };

        foreach (string m in list) { yield return [m]; }
    }

    private static readonly string[] MimeKitHeaders = ["From", "To", "Subject", "Date", "Message-ID", "MIME-Version", "Content-Type", "In-Reply-To", "References", "Reply-To"];

    private static byte[] ToWire(MimeMessage message)
    {
        using var ms = new MemoryStream();
        message.WriteTo(Wire, ms);
        return ms.ToArray();
    }

    private static MimeMessage Load(string raw)
    {
        using var ms = new MemoryStream(Encoding.Latin1.GetBytes(raw));
        return MimeMessage.Load(ms);
    }

    private static MimeMessage Load(byte[] raw)
    {
        using var ms = new MemoryStream(raw);
        return MimeMessage.Load(ms);
    }

    private static MkSigner MimeKitSigner(RSA key, DkimCanonicalizationAlgorithm headerCanon, DkimCanonicalizationAlgorithm bodyCanon)
    {
        string pem = key.ExportRSAPrivateKeyPem();
        using var ms = new MemoryStream(Encoding.ASCII.GetBytes(pem));
        return new MkSigner(ms, "example.com", "sel", DkimSignatureAlgorithm.RsaSha256)
        {
            HeaderCanonicalizationAlgorithm = headerCanon,
            BodyCanonicalizationAlgorithm = bodyCanon,
        };
    }

    public static IEnumerable<object[]> MessagesWithCanonicalizations()
    {
        var combos = new[]
        {
            (DkimCanonicalizationAlgorithm.Relaxed, DkimCanonicalizationAlgorithm.Relaxed),
            (DkimCanonicalizationAlgorithm.Simple, DkimCanonicalizationAlgorithm.Simple),
            (DkimCanonicalizationAlgorithm.Relaxed, DkimCanonicalizationAlgorithm.Simple),
            (DkimCanonicalizationAlgorithm.Simple, DkimCanonicalizationAlgorithm.Relaxed),
        };

        foreach (var m in Messages())
        {
            foreach (var (h, b) in combos) { yield return [m[0], h, b]; }
        }
    }

    [Theory]
    [MemberData(nameof(MessagesWithCanonicalizations))]
    public async Task Mimekit_signed_messages_verify_with_our_verifier(string raw, DkimCanonicalizationAlgorithm headerCanon, DkimCanonicalizationAlgorithm bodyCanon)
    {
        var signer = MimeKitSigner(TestKeys.Rsa2048, headerCanon, bodyCanon);
        var message = Load(raw);
        signer.Sign(Wire, message, MimeKitHeaders);
        byte[] wire = ToWire(message);

        var results = await Msg.Verifier(Msg.Dns(TestKeys.Rsa2048)).VerifyAsync(wire);
        var r = Assert.Single(results);
        Assert.True(r.Status == DkimStatus.Pass, $"{headerCanon}/{bodyCanon}: {r.Status} {r.Reason}\n{Encoding.Latin1.GetString(wire, 0, Math.Min(wire.Length, 2000)).Replace("\r", "\\r")}");
        Assert.Equal(2048, r.KeyBits);
    }

    [Theory]
    [MemberData(nameof(Messages))]
    public async Task Mimekit_signed_messages_fail_with_our_verifier_after_tampering(string raw)
    {
        var signer = MimeKitSigner(TestKeys.Rsa2048, DkimCanonicalizationAlgorithm.Relaxed, DkimCanonicalizationAlgorithm.Relaxed);
        var message = Load(raw);
        signer.Sign(Wire, message, MimeKitHeaders);
        string wire = Encoding.Latin1.GetString(ToWire(message));

        var verifier = Msg.Verifier(Msg.Dns(TestKeys.Rsa2048));
        Assert.Equal(DkimFailure.SignatureMismatch, (await Msg.VerifyOne(verifier, Msg.ReplaceFirst(wire, "From: ", "From: x"))).Failure);
        Assert.NotEqual(DkimStatus.Pass, (await Msg.VerifyOne(verifier, wire + "tampered\r\n")).Status);
    }

    [Theory]
    [MemberData(nameof(Messages))]
    public async Task Our_signatures_verify_with_mimekit_for_every_canonicalization(string raw)
    {
        var locator = new DictionaryKeyLocator().Add("example.com", "sel", TestKeys.Rsa2048);
        var verifier = new MkVerifier(locator);
        foreach (var header in new[] { DkimCanonicalization.Relaxed, DkimCanonicalization.Simple })
        {
            foreach (var body in new[] { DkimCanonicalization.Relaxed, DkimCanonicalization.Simple })
            {
                foreach (bool oversign in new[] { true, false })
                {
                    var ours = Msg.Signer(header: header, body: body, oversign: oversign);
                    byte[] signed = Msg.Bytes(Msg.Sign(ours, raw));

                    var message = Load(signed);
                    var sigHeader = message.Headers.First(h => h.Id == HeaderId.DkimSignature);
                    Assert.True(verifier.Verify(Wire, message, sigHeader), $"MimeKit rejected our {header}/{body} oversign={oversign} signature:\n{Encoding.Latin1.GetString(signed, 0, Math.Min(signed.Length, 1200))}");
                }
            }
        }
    }

    [Theory]
    [MemberData(nameof(Messages))]
    public void Mimekit_rejects_what_we_reject(string raw)
    {
        var locator = new DictionaryKeyLocator().Add("example.com", "sel", TestKeys.Rsa2048);
        var verifier = new MkVerifier(locator);
        string signed = Msg.Sign(Msg.Signer(), raw);

        var tamperedBody = Load(Msg.Bytes(signed + "appended\r\n"));
        Assert.False(verifier.Verify(Wire, tamperedBody, tamperedBody.Headers.First(h => h.Id == HeaderId.DkimSignature)));

        var tamperedHeader = Load(Msg.Bytes(Msg.ReplaceFirst(signed, "From: ", "From: x")));
        Assert.False(verifier.Verify(Wire, tamperedHeader, tamperedHeader.Headers.First(h => h.Id == HeaderId.DkimSignature)));
    }

    [Fact]
    public void Mimekit_agrees_that_oversigning_blocks_header_injection_and_that_plain_signatures_do_not()
    {
        var locator = new DictionaryKeyLocator().Add("example.com", "sel", TestKeys.Rsa2048);
        var verifier = new MkVerifier(locator);
        string message = Msg.Simple();

        string injected = "Subject: injected\r\n" + Msg.Sign(Msg.Signer(oversign: true), message);
        var m1 = Load(Msg.Bytes(injected));
        Assert.False(verifier.Verify(Wire, m1, m1.Headers.First(h => h.Id == HeaderId.DkimSignature)));

        string injectedPlain = "Subject: injected\r\n" + Msg.Sign(Msg.Signer(oversign: false), message);
        var m2 = Load(Msg.Bytes(injectedPlain));
        Assert.True(verifier.Verify(Wire, m2, m2.Headers.First(h => h.Id == HeaderId.DkimSignature)));
    }

    [Fact]
    public async Task Both_implementations_agree_on_one_hundred_random_messages()
    {
        var rng = new Random(2026);
        var locator = new DictionaryKeyLocator().Add("example.com", "sel", TestKeys.Rsa2048);
        var mimekitVerifier = new MkVerifier(locator);
        var ourVerifier = Msg.Verifier(Msg.Dns(TestKeys.Rsa2048));
        string[] words = ["alpha", "beta", " ", "  ", "\t", "gamma ", " delta", "x\ty"];

        for (int i = 0; i < 100; i++)
        {
            var body = new StringBuilder();
            int lines = rng.Next(0, 12);
            for (int l = 0; l < lines; l++)
            {
                int n = rng.Next(0, 6);
                for (int w = 0; w < n; w++) { body.Append(words[rng.Next(words.Length)]); }
                body.Append("\r\n");
            }

            if (rng.Next(4) == 0) { body.Append("no final newline"); }
            string raw = Msg.Simple(body.ToString());
            var headerCanon = (DkimCanonicalization)rng.Next(2);
            var bodyCanon = (DkimCanonicalization)rng.Next(2);

            // ours -> MimeKit and ours
            string signed = Msg.Sign(Msg.Signer(header: headerCanon, body: bodyCanon), raw);
            var parsed = Load(Msg.Bytes(signed));
            Assert.True(mimekitVerifier.Verify(Wire, parsed, parsed.Headers.First(h => h.Id == HeaderId.DkimSignature)), $"iteration {i}: MimeKit rejected ours ({headerCanon}/{bodyCanon})");
            Assert.Equal(DkimStatus.Pass, (await Msg.VerifyOne(ourVerifier, signed)).Status);

            // MimeKit -> ours
            var mk = MimeKitSigner(TestKeys.Rsa2048, (DkimCanonicalizationAlgorithm)(int)headerCanon, (DkimCanonicalizationAlgorithm)(int)bodyCanon);
            var message = Load(raw);
            mk.Sign(Wire, message, MimeKitHeaders);
            byte[] wire = ToWire(message);
            var r = (await ourVerifier.VerifyAsync(wire)).Single();
            Assert.True(r.Status == DkimStatus.Pass, $"iteration {i}: we rejected MimeKit ({headerCanon}/{bodyCanon}): {r.Reason}");
        }
    }
}
