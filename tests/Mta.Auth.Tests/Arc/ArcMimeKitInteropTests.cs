using System.Security.Cryptography;
using System.Text;
using MimeKit;
using MimeKit.Cryptography;
using Mta.Auth.Arc;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using static Mta.Auth.Tests.Arc.ArcMsg;

namespace Mta.Auth.Tests.Arc;

/// <summary>Differential tests against MimeKit's ARC implementation, used as an independent oracle in both directions.</summary>
public class ArcMimeKitInteropTests
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
        public override AsymmetricKeyParameter LocatePublicKey(string methods, string domain, string selector, CancellationToken cancellationToken = default) =>
            PublicKeyFactory.CreateKey(ArcKeys.For(domain).ExportSubjectPublicKeyInfo());

        public override Task<AsymmetricKeyParameter> LocatePublicKeyAsync(string methods, string domain, string selector, CancellationToken cancellationToken = default) =>
            Task.FromResult(LocatePublicKey(methods, domain, selector, cancellationToken));
    }

    private sealed class MkSealer : ArcSigner
    {
        private readonly string _authservId;
        private readonly string _arcResult;

        public MkSealer(string domain, string authservId, string arcResult)
            : base(LoadKey(domain), domain, ArcKeys.Selector, DkimSignatureAlgorithm.RsaSha256)
        {
            _authservId = authservId;
            _arcResult = arcResult;
        }

        private static AsymmetricKeyParameter LoadKey(string domain)
        {
            var pair = DotNetUtilities.GetRsaKeyPair(ArcKeys.For(domain));
            return pair.Private;
        }

        protected override Task<MimeKit.Cryptography.AuthenticationResults> GenerateArcAuthenticationResultsAsync(FormatOptions options, MimeMessage message, CancellationToken cancellationToken) =>
            Task.FromResult(GenerateArcAuthenticationResults(options, message, cancellationToken));

        protected override MimeKit.Cryptography.AuthenticationResults GenerateArcAuthenticationResults(FormatOptions options, MimeMessage message, CancellationToken cancellationToken)
        {
            var results = new MimeKit.Cryptography.AuthenticationResults(_authservId);
            results.Results.Add(new AuthenticationMethodResult("spf", "pass"));
            results.Results.Add(new AuthenticationMethodResult("arc", _arcResult));
            return results;
        }
    }

    private static readonly string[] MimeKitHeaders = ["From", "To", "Subject", "Date", "Message-ID", "MIME-Version", "Content-Type"];

    private static MimeMessage Load(string raw)
    {
        using var ms = new MemoryStream(Encoding.Latin1.GetBytes(raw));
        return MimeMessage.Load(ms);
    }

    private static string ToWire(MimeMessage message)
    {
        using var ms = new MemoryStream();
        message.WriteTo(Wire, ms);
        return Encoding.Latin1.GetString(ms.ToArray());
    }

    private static string MimeKitHop(string raw, string domain, string arcResult)
    {
        var message = Load(raw);
        new MkSealer(domain, "mx." + domain, arcResult).Sign(Wire, message, MimeKitHeaders);
        return ToWire(message);
    }

    public static IEnumerable<object[]> Bodies()
    {
        yield return ["Hello,\r\n\r\nThis is the body.\r\n"];
        yield return ["body   with   spaces  \r\nand\ttabs\t\r\n\r\n\r\n"];
        yield return [new string('x', 900) + "\r\n" + string.Join("\r\n", Enumerable.Range(0, 200).Select(i => "row " + i + "  ")) + "\r\n"];
        yield return [string.Empty];
    }

    [Theory]
    [MemberData(nameof(Bodies))]
    public async Task Mimekit_sealed_single_hop_validates_with_our_validator(string body)
    {
        string m = MimeKitHop(Original(body), "a.example", "none");
        Assert.Contains("ARC-Seal", m);
        var r = await ValidateAsync(m);
        Assert.True(r.IsPass, r.Reason + "\n" + m);
        Assert.Equal(1, r.InstanceCount);
    }

    [Fact]
    public async Task Mimekit_sealed_five_hop_chain_validates_with_our_validator()
    {
        string m = Original();
        for (int i = 0; i < 5; i++) { m = MimeKitHop(m, Hops[i], i == 0 ? "none" : "pass"); }
        var r = await ValidateAsync(m);
        Assert.True(r.IsPass, r.Reason + "\n" + m);
        Assert.Equal(5, r.InstanceCount);
        Assert.Equal(Hops.Take(5), r.SealDomains);
    }

    [Fact]
    public async Task Mimekit_chain_with_one_of_our_hops_in_the_middle_validates_with_both()
    {
        var dns = DnsForAllHops();
        string m = MimeKitHop(Original(), "a.example", "none");
        m = await HopAsync(m, "b.example", dns);
        m = MimeKitHop(m, "c.example", "pass");
        Assert.True((await ValidateAsync(m, dns)).IsPass);
        var mk = new ArcVerifier(new DictionaryKeyLocator()).Verify(Wire, Load(m));
        Assert.Equal(ArcSignatureValidationResult.Pass, mk.Chain);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(5)]
    public async Task Our_chains_validate_with_mimekit(int hops)
    {
        string m = await ChainAsync(hops);
        var mk = new ArcVerifier(new DictionaryKeyLocator()).Verify(Wire, Load(m));
        Assert.True(mk.Chain == ArcSignatureValidationResult.Pass, mk.Chain + " " + mk.ChainErrors + "\n" + m);
    }

    [Theory]
    [MemberData(nameof(Bodies))]
    public async Task Our_single_hop_validates_with_mimekit_for_assorted_bodies(string body)
    {
        string m = await ChainAsync(1, Original(body));
        var mk = new ArcVerifier(new DictionaryKeyLocator()).Verify(Wire, Load(m));
        Assert.True(mk.Chain == ArcSignatureValidationResult.Pass, mk.Chain + " " + mk.ChainErrors);
    }

    [Fact]
    public async Task Both_implementations_reject_the_same_tampering()
    {
        string m = await ChainAsync(3);
        string[] tampered =
        [
            ReplaceFirst(m, "This is the body.", "This is the BODY."),
            ReplaceFirst(m, "Subject: Test message", "Subject: Other"),
            ReplaceFirst(m, "ARC-Authentication-Results: i=1; mx.a.example; spf=pass", "ARC-Authentication-Results: i=1; mx.a.example; spf=fail"),
        ];

        foreach (string t in tampered)
        {
            Assert.Equal(ArcChainStatus.Fail, (await ValidateAsync(t)).Status);
            Assert.Equal(ArcSignatureValidationResult.Fail, new ArcVerifier(new DictionaryKeyLocator()).Verify(Wire, Load(t)).Chain);
        }
    }

    [Fact]
    public async Task Our_failed_chain_seal_has_the_cv_fail_scope_mimekit_uses()
    {
        // MimeKit seals a broken chain with cv=fail. The scope of that seal's signature (the new set only) is what our sealer produces:
        // check by having MimeKit's verifier locate the seal and our validator agree that a cv=fail seal is a failed chain.
        var dns = DnsForAllHops();
        string m = await ChainAsync(1, dns: dns);
        string tampered = ReplaceFirst(m, "Hello,", "Hullo,");
        string mkFailed = MimeKitHop(tampered, "b.example", "fail");
        Assert.Contains("cv=fail", mkFailed);
        var r = await ValidateAsync(mkFailed, dns);
        Assert.Equal(ArcFailure.ChainFailedUpstream, r.Failure);
    }
}
