using System.Security.Cryptography;
using System.Text;
using Mta.Dkim;
using Mta.Dns;
using OurVerifier = Mta.Dkim.DkimVerifier;

namespace Mta.Authentication.Tests;

/// <summary>
/// Known-answer vectors from the RFCs, typed in from the RFC text (not produced by this code): the RFC 6376 appendix A example message with its signature and the public
/// key of appendix C, and the SHA-256 body hashes of an empty body under both body canonicalizations (RFC 6376 section 3.4.3 and 3.4.4).
/// </summary>
public class Rfc6376VectorTests
{
    /// <summary>
    /// The body of the appendix A example. The RFC prints "game.  Are" with two spaces; the body hash printed with it (<c>2jUSOH9N...</c>) is the SHA-256 of the body with ONE space, so
    /// the typesetting of the RFC added the second one. The signature of that example cannot be reproduced from the printed text either: no combination of the folding
    /// white space of the signature and the Received field (five spaces, eight, a tab), of the double space in "client1.football.example.com  [192.0.2.1]", or of the
    /// trailing semicolon verifies against the printed key, and the RFC publishes no private key to sign it again. So only the body hash is a usable known answer from there.
    /// </summary>
    private const string AppendixABody = "Hi.\r\n\r\nWe lost the game. Are you hungry yet?\r\n\r\nJoe.\r\n";

    [Fact]
    public void The_appendix_a_body_hash_is_what_the_rfc_prints_under_simple_canonicalization()
    {
        Assert.Equal("2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=", Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(IndependentDkim.CanonBody(AppendixABody, relaxed: false)))));
    }

    [Fact]
    public async Task Our_verifier_does_not_blame_the_body_hash_for_the_appendix_a_example()
    {
        const string PublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB";
        string message = "DKIM-Signature: v=1; a=rsa-sha256; s=brisbane; d=example.com;\r\n     c=simple/simple; q=dns/txt; i=joe@football.example.com;\r\n     h=Received : From : To : Subject : Date : Message-ID;\r\n     bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n     b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB\r\n     4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut\r\n     KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV\r\n     4bmp/YzhwvcubU4=;\r\n"
            + "Received: from client1.football.example.com  [192.0.2.1]\r\n     by submitserver.example.com with SUBMISSION;\r\n     Fri, 11 Jul 2003 21:01:54 -0700 (PDT)\r\n"
            + "From: Joe SixPack <joe@football.example.com>\r\nTo: Suzie Q <suzie@shopping.example.net>\r\nSubject: Is dinner ready?\r\nDate: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\nMessage-ID: <20030712040037.46341.5F8J@football.example.com>\r\n\r\n"
            + AppendixABody;
        var dns = new StaticDnsResolver().AddTxt("brisbane._domainkey.example.com", "v=DKIM1; p=" + PublicKey);

        var verdict = Assert.Single(await new OurVerifier(dns).VerifyAsync(Encoding.ASCII.GetBytes(message)));

        Assert.NotEqual(DkimFailure.BodyHashMismatch, verdict.Failure);   // the body hash is the one thing in the example that is right
        Assert.Equal("brisbane", verdict.Selector);
        Assert.Equal("joe@football.example.com", verdict.Identity);
    }

    [Theory]
    [InlineData(false, "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=")]   // simple: an empty body is a single CRLF
    [InlineData(true, "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")]    // relaxed: an empty body is empty (the SHA-256 of nothing)
    public void The_body_hash_of_an_empty_body_is_the_published_constant(bool relaxed, string expected)
    {
        foreach (string body in new[] { string.Empty, "\r\n", "\r\n\r\n\r\n", " \r\n\t\r\n" }.Where(b => !(relaxed == false && b is " \r\n\t\r\n")))
        {
            Assert.Equal(expected, Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(IndependentDkim.CanonBody(body, relaxed)))));
        }
    }

    [Theory]
    [InlineData("", "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=", "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")]
    [InlineData("\r\n\r\n\r\n", "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=", "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")]
    public async Task Our_signer_and_verifier_produce_and_accept_the_published_empty_body_hashes(string body, string simple, string relaxed)
    {
        using var key = RSA.Create(2048);
        var dns = new StaticDnsResolver().AddTxt("s._domainkey.example.com", DkimKeyTools.FormatDnsTxtValue(key));
        foreach (var (canon, expected) in new[] { (DkimCanonicalization.Simple, simple), (DkimCanonicalization.Relaxed, relaxed) })
        {
            using var signer = new DkimSigner(new DkimSignerOptions { Domain = "example.com", Selector = "s", BodyCanonicalization = canon }, key);
            string message = "From: a@example.com\r\nSubject: s\r\n\r\n" + body;
            string field = signer.Sign(Encoding.ASCII.GetBytes(message));

            Assert.Equal(expected, IndependentDkim.Tags(field)["bh"]);
            Assert.True(Assert.Single(await new OurVerifier(dns).VerifyAsync(Encoding.ASCII.GetBytes(field + message))).IsPass);
        }
    }
}
