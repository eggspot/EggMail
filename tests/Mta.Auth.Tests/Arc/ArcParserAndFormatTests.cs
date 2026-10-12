using System.Net;
using System.Text;
using Mta.Auth.Arc;
using Mta.Auth.AuthenticationResults;
using Mta.Dkim;
using static Mta.Auth.Tests.Arc.ArcMsg;

namespace Mta.Auth.Tests.Arc;

public class ArcParserAndFormatTests
{
    private const string Sig = "QUJDREVGR0g=";

    [Theory]
    [InlineData("i=1; a=rsa-sha256; cv=none; d=Example.COM; s=sel; t=1700000000; b=" + Sig)]
    [InlineData("  i=50 ;a=rsa-sha256;\r\n\tcv=PASS;d=example.com;s=sel;b=QUJD\r\n REVGR0g=  ;")]
    [InlineData("i=2; a=rsa-sha256; cv=fail; d=example.com; s=sel; x_unknown=whatever; b=" + Sig)]
    public void Valid_seals_parse(string value)
    {
        Assert.True(ArcSealHeader.TryParse(value, out var seal, out string? error), error);
        Assert.Equal("example.com", seal.Domain.ToLowerInvariant());
        Assert.Equal("rsa-sha256", seal.Algorithm);
        Assert.Equal(8, seal.Signature.Length);
    }

    [Theory]
    [InlineData("")]
    [InlineData("a=rsa-sha256; cv=none; d=example.com; s=sel; b=" + Sig)]
    [InlineData("i=0; a=rsa-sha256; cv=none; d=example.com; s=sel; b=" + Sig)]
    [InlineData("i=51; a=rsa-sha256; cv=none; d=example.com; s=sel; b=" + Sig)]
    [InlineData("i=1x; a=rsa-sha256; cv=none; d=example.com; s=sel; b=" + Sig)]
    [InlineData("i=1; cv=none; d=example.com; s=sel; b=" + Sig)]
    [InlineData("i=1; a=rsa-sha256; d=example.com; s=sel; b=" + Sig)]
    [InlineData("i=1; a=rsa-sha256; cv=unknown; d=example.com; s=sel; b=" + Sig)]
    [InlineData("i=1; a=rsa-sha256; cv=none; s=sel; b=" + Sig)]
    [InlineData("i=1; a=rsa-sha256; cv=none; d=example; s=sel; b=" + Sig)]
    [InlineData("i=1; a=rsa-sha256; cv=none; d=example.com; b=" + Sig)]
    [InlineData("i=1; a=rsa-sha256; cv=none; d=example.com; s=sel")]
    [InlineData("i=1; a=rsa-sha256; cv=none; d=example.com; s=sel; b=***")]
    [InlineData("i=1; a=rsa-sha256; cv=none; d=example.com; s=sel; t=abc; b=" + Sig)]
    [InlineData("i=1; a=rsa-sha256; cv=none; cv=pass; d=example.com; s=sel; b=" + Sig)]
    [InlineData("i=1; a=rsa-sha256; cv=none; d=example.com; s=sel; h=from; b=" + Sig)]
    [InlineData("i=1;; a=rsa-sha256; cv=none; d=example.com; s=sel; b=" + Sig)]
    [InlineData("i=1; a=rsa-sha256; cv none; d=example.com; s=sel; b=" + Sig)]
    public void Invalid_seals_are_rejected(string value)
    {
        Assert.False(ArcSealHeader.TryParse(value, out var seal, out string? error));
        Assert.Null(seal);
        Assert.False(string.IsNullOrEmpty(error));
    }

    [Fact]
    public void Message_signature_parses_canonicalization_and_header_list()
    {
        Assert.True(ArcMessageSignatureHeader.TryParse(
            "i=3; a=rsa-sha256; c=relaxed/simple; d=example.com; s=sel; t=1; h=From : To:Subject:from; bh=" + Sig + "; b=" + Sig, out var ams, out string? error), error);
        Assert.Equal(3, ams.Instance);
        Assert.Equal(DkimCanonicalization.Relaxed, ams.HeaderCanonicalization);
        Assert.Equal(DkimCanonicalization.Simple, ams.BodyCanonicalization);
        Assert.Equal(["from", "to", "subject", "from"], ams.SignedHeaderNames);

        Assert.True(ArcMessageSignatureHeader.TryParse("i=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=" + Sig + "; b=" + Sig, out var defaults, out _));
        Assert.Equal(DkimCanonicalization.Simple, defaults.HeaderCanonicalization);
        Assert.Equal(DkimCanonicalization.Simple, defaults.BodyCanonicalization);
        Assert.True(ArcMessageSignatureHeader.TryParse("i=1; a=rsa-sha256; c=relaxed; d=example.com; s=sel; h=from; bh=" + Sig + "; b=" + Sig, out var one, out _));
        Assert.Equal(DkimCanonicalization.Relaxed, one.HeaderCanonicalization);
        Assert.Equal(DkimCanonicalization.Simple, one.BodyCanonicalization);
    }

    [Theory]
    [InlineData("i=1; a=rsa-sha256; d=example.com; s=sel; bh=" + Sig + "; b=" + Sig)]
    [InlineData("i=1; a=rsa-sha256; d=example.com; s=sel; h=from; b=" + Sig)]
    [InlineData("i=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=" + Sig)]
    [InlineData("i=1; a=rsa-sha256; c=weird/relaxed; d=example.com; s=sel; h=from; bh=" + Sig + "; b=" + Sig)]
    [InlineData("i=1; a=rsa-sha256; d=example.com; s=sel; h=from::to; bh=" + Sig + "; b=" + Sig)]
    [InlineData("i=1; a=rsa-sha256; d=example.com; s=sel; h=from:ARC-Seal; bh=" + Sig + "; b=" + Sig)]
    [InlineData("i=1; a=rsa-sha256; d=example.com; s=sel; h=arc-message-signature; bh=" + Sig + "; b=" + Sig)]
    [InlineData("i=1; a=rsa-sha256; d=example.com; s=sel; l=10; h=from; bh=" + Sig + "; b=" + Sig)]
    [InlineData("i=1; a=rsa-sha256; d=example.com; s=sel; h=fr om; bh=" + Sig + "; b=" + Sig)]
    public void Invalid_message_signatures_are_rejected(string value)
    {
        Assert.False(ArcMessageSignatureHeader.TryParse(value, out _, out string? error));
        Assert.False(string.IsNullOrEmpty(error));
    }

    [Theory]
    [InlineData("i=1; mx.example.com; spf=pass smtp.mailfrom=a@b.example", 1, "mx.example.com")]
    [InlineData(" i = 7 ;\r\n\tmx.example.com;\r\n\tdkim=pass header.d=b.example", 7, "mx.example.com")]
    [InlineData("i=50; mx.example.com; none", 50, "mx.example.com")]
    public void Valid_results_headers_parse(string value, int instance, string authserv)
    {
        Assert.True(ArcAuthenticationResultsHeader.TryParse(value, out var aar, out string? error), error);
        Assert.Equal(instance, aar.Instance);
        Assert.Equal(authserv, aar.AuthservId);
        Assert.DoesNotContain('\n', aar.Body);
    }

    [Theory]
    [InlineData("")]
    [InlineData("mx.example.com; none")]
    [InlineData("i=; mx.example.com; none")]
    [InlineData("i=1 mx.example.com")]
    [InlineData("i=1;")]
    [InlineData("i=1;   \r\n ")]
    [InlineData("i=0; mx.example.com; none")]
    [InlineData("i=51; mx.example.com; none")]
    [InlineData("i=1; mx.example.com;\u0001 none")]
    public void Invalid_results_headers_are_rejected(string value)
    {
        Assert.False(ArcAuthenticationResultsHeader.TryParse(value, out _, out string? error));
        Assert.False(string.IsNullOrEmpty(error));
    }

    [Fact]
    public void A_results_body_that_is_not_rfc_8601_is_kept_but_has_no_parsed_results()
    {
        Assert.True(ArcAuthenticationResultsHeader.TryParse("i=1; this is ;; not (( valid", out var aar, out _));
        Assert.Equal("this is ;; not (( valid", aar.Body);
        Assert.Null(aar.Results);
        Assert.Null(aar.AuthservId);
    }

    [Fact]
    public void Header_length_limit_is_enforced()
    {
        string value = "i=1; a=rsa-sha256; cv=none; d=example.com; s=sel; b=" + Sig;
        Assert.True(ArcSealHeader.TryParse(Encoding.ASCII.GetBytes(value), out _, out _, 1000));
        Assert.False(ArcSealHeader.TryParse(Encoding.ASCII.GetBytes(value), out _, out string? error, 20));
        Assert.Contains("too long", error);
    }

    [Fact]
    public void Non_ascii_input_never_throws()
    {
        Assert.False(ArcSealHeader.TryParse("i=1; a=rsa-sha256; cv=none; d=exämple.com; s=sel; b=" + Sig, out _, out _));
        Assert.False(ArcMessageSignatureHeader.TryParse((string?)null, out _, out _));
        Assert.False(ArcAuthenticationResultsHeader.TryParse((string?)null, out _, out _));
    }

    [Fact]
    public void Authentication_results_fragments_have_the_expected_shape_and_parse_back()
    {
        var pass = new ArcChainResult(ArcChainStatus.Pass, "ok") { OldestPassingInstance = 2, InstanceCount = 3 };
        Assert.Equal("arc=pass header.oldest-pass=2", ArcAuthenticationResults.Format(pass));
        Assert.Equal("arc=pass header.oldest-pass=2 smtp.remote-ip=192.0.2.1", ArcAuthenticationResults.Format(pass, IPAddress.Parse("192.0.2.1")));
        Assert.Equal("arc=pass header.oldest-pass=2 smtp.remote-ip=192.0.2.1", ArcAuthenticationResults.Format(pass, IPAddress.Parse("::ffff:192.0.2.1")));
        Assert.Equal("arc=pass header.oldest-pass=2 smtp.remote-ip=\"2001:db8::1\"", ArcAuthenticationResults.Format(pass, IPAddress.Parse("2001:db8::1")));
        Assert.Equal("arc=none", ArcAuthenticationResults.Format(new ArcChainResult(ArcChainStatus.None, "x")));
        Assert.Equal("arc=pass", ArcAuthenticationResults.Format(new ArcChainResult(ArcChainStatus.Pass, "x")));
        string fail = ArcAuthenticationResults.Format(new ArcChainResult(ArcChainStatus.Fail, "ARC-Seal did not verify", ArcFailure.SealMismatch));
        Assert.Equal("arc=fail reason=\"ARC-Seal did not verify\"", fail);

        foreach (string fragment in new[] { ArcAuthenticationResults.Format(pass, IPAddress.Parse("2001:db8::1")), fail, "arc=none" })
        {
            var builder = new AuthenticationResultsBuilder("mx.example.com").AddArc(fragment);
            Assert.True(AuthenticationResultsHeader.TryParse(builder.BuildFieldBody(), out var parsed));
            Assert.Single(parsed.ForMethod("arc"));
        }

        var roundTrip = AuthenticationResultsHeader.TryParse("mx.example.com; " + ArcAuthenticationResults.Format(pass, IPAddress.Parse("192.0.2.1")), out var h) ? h : null;
        var arc = Assert.Single(roundTrip!.ForMethod("arc"));
        Assert.Equal("pass", arc.Result);
        Assert.Equal("2", arc.GetProperty("header", "oldest-pass"));
        Assert.Equal("192.0.2.1", arc.GetProperty("smtp", "remote-ip"));
    }

    [Fact]
    public async Task Builder_output_can_be_used_directly_as_the_sealed_results()
    {
        var dns = DnsForAllHops();
        var incoming = new ArcChainResult(ArcChainStatus.None, "none");
        var builder = new AuthenticationResultsBuilder("mx.a.example")
            .AddFragment("spf=pass smtp.mailfrom=alice@origin.example")
            .AddArc(ArcAuthenticationResults.Format(incoming, IPAddress.Parse("192.0.2.7")));
        using var sealer = Sealer("a.example");
        var sealedMessage = sealer.Seal(Bytes(Original()), builder, incoming);
        Assert.True((await ValidateAsync(sealedMessage.Headers + Original(), dns)).IsPass);
        Assert.Contains("arc=none", sealedMessage.Headers.Replace("\r\n\t", " "));
    }

    [Fact]
    public async Task Sealing_allocation_does_not_grow_with_the_body_size()
    {
        using var sealer = Sealer("a.example");
        var none = new ArcChainResult(ArcChainStatus.None, "none");
        byte[] small = Bytes(Original(new string('x', 1000) + "\r\n"));
        byte[] big = Bytes(Original(string.Concat(Enumerable.Repeat(new string('x', 998) + "\r\n", 1000))));

        long Measure(byte[] message)
        {
            for (int i = 0; i < 20; i++) { _ = sealer.Seal(message, "mx.a.example; none", none); }
            long before = GC.GetAllocatedBytesForCurrentThread();
            for (int i = 0; i < 50; i++) { _ = sealer.Seal(message, "mx.a.example; none", none); }
            return (GC.GetAllocatedBytesForCurrentThread() - before) / 50;
        }

        long smallBytes = Measure(small);
        long bigBytes = Measure(big);
        Assert.True(bigBytes < smallBytes + 512, $"allocation grew with the body: {smallBytes} -> {bigBytes}");
        Assert.True(smallBytes < 24 * 1024, $"sealing allocated {smallBytes} bytes");
        await Task.CompletedTask;
    }
}
